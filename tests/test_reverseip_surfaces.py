"""Reverse IP on the operator's surfaces: the refresh job and /healthz, and
the `reverse_ip` key of an IP lookup.

The suite runs with REVERSEIP_ENABLED=false; a test that wants the feature
asks for the `reverseip_enabled` fixture (conftest), or builds its own manager.
"""

import copy
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from mcp.types import CallToolResult

import config
import lookup
import main
import mcp_server
import subdomains
from reverseip import ReverseIpManager, parse_sources
from reverseip_fixtures import NOW, build_manager

client = TestClient(main.app)
CURL = {"user-agent": "curl/8"}
HOUR = 3600
LISTED_IP = "93.184.215.14"
DOMAIN = "example.com"


def _reasons(body: dict) -> dict:
    return {reason["code"]: reason for reason in body["reasons"]}


def _location(ip):
    return {
        "ip": ip,
        "country_code": "US",
        "country_name": "United States",
        "city_name": "Norwell",
        "asn_name": "EDGECAST",
        "asn_number": 15133,
        "is_private": False,
    }


@pytest.fixture
def legs():
    """Every outbound leg of a lookup answered locally (WHOIS, PTR, the DNS
    sweep, the A query, TLS) and GeoLite2 answering with a fixed location. A
    domain resolves to LISTED_IP."""
    resolver = MagicMock()
    resolver.resolve.return_value = [LISTED_IP]
    location = AsyncMock(side_effect=lambda ip: copy.deepcopy(_location(ip)))
    whois = AsyncMock(return_value={"source": "rdap", "name": "EXAMPLE"})
    with ExitStack() as stack:
        stack.enter_context(patch("lookup.lookup_whois", whois))
        stack.enter_context(patch("main.lookup_whois", whois))
        stack.enter_context(patch("lookup.lookup_location", location))
        stack.enter_context(patch("main.lookup_location", location))
        stack.enter_context(
            patch("lookup._recursive_resolver", MagicMock(return_value=resolver))
        )
        stack.enter_context(
            patch.object(lookup.domain_manager, "get_records", return_value={})
        )
        stack.enter_context(
            patch.object(
                lookup.domain_manager, "perform_reverse_lookup", return_value=None
            )
        )
        stack.enter_context(
            patch("managers.SSLManager.get_ssl_info", return_value=None)
        )
        yield


def test_an_ip_lookup_carries_reverse_ip(reverseip_enabled, legs):
    body = client.get(f"/{LISTED_IP}", headers=CURL).json()
    assert body["reverse_ip"] == reverseip_enabled.for_address(LISTED_IP)
    assert body["reverse_ip"]["total"] == 4
    assert body["reverse_ip"]["attribution"] == config.OPENINTEL_ATTRIBUTION


def test_a_domain_lookup_does_not(reverseip_enabled, legs):
    body = client.get(f"/{DOMAIN}", headers=CURL).json()
    assert "reverse_ip" not in body


def test_disabled_adds_no_key(legs):
    assert lookup.reverse_ip_manager.enabled is False
    assert "reverse_ip" not in client.get(f"/{LISTED_IP}", headers=CURL).json()


async def test_gather_skips_the_leg_unless_asked(reverseip_enabled, legs):
    asked = await lookup.gather(LISTED_IP, legs={"geo", "reverseip"})
    assert asked["reverse_ip"]["total"] == 4
    skipped = await lookup.gather(LISTED_IP, legs={"geo"})
    assert skipped["reverse_ip"] is None
    domain = await lookup.gather(DOMAIN)
    assert domain["reverse_ip"] is None


def test_the_lookup_helpers_are_none_while_disabled():
    assert lookup.reverse_ip_manager.enabled is False
    assert lookup.address_reverse_ip(LISTED_IP) is None
    assert lookup.top_list_subdomains(DOMAIN) is None


def test_the_lookup_helpers_read_the_manager(reverseip_enabled):
    assert lookup.address_reverse_ip(LISTED_IP) == reverseip_enabled.for_address(
        LISTED_IP
    )
    assert lookup.top_list_subdomains(DOMAIN) == reverseip_enabled.names_under(DOMAIN)
    assert lookup.top_list_subdomains(DOMAIN) is not None


def test_the_job_is_scheduled_and_skipped_when_disabled():
    job = main.scheduler.get_job("refresh-reverseip")
    assert job is not None
    assert job.max_instances == 1
    assert job.coalesce is True
    # Due at import, run when the lifespan starts the scheduler.
    assert job.misfire_grace_time is None
    assert (
        job.trigger.interval.total_seconds() == config.REVERSEIP_CHECK_INTERVAL_SECONDS
    )
    assert job.func.__name__ == "refresh"
    assert job.func.__self__ is lookup.reverse_ip_manager
    assert "reverseip" not in main._refresh_failures

    # The suite runs with the feature off: the job starts no child process.
    assert lookup.reverse_ip_manager.enabled is False
    assert job.func() is True
    assert lookup.reverse_ip_manager.build_attempted is False


def test_healthz_reports_the_sources(reverseip_enabled):
    body = client.get("/healthz").json()
    assert body["reverseip"] == reverseip_enabled.status()
    assert body["reverseip"]["sources"]["tranco"]["stale"] is False
    assert "reverseip_unavailable" not in _reasons(body)
    assert "reverseip_source_stale" not in _reasons(body)


def test_healthz_a_stale_source_degrades(reverseip_enabled, monkeypatch, tmp_path):
    (tmp_path / "later").mkdir()
    later = build_manager(tmp_path / "later")
    later._clock = lambda: NOW + 5 * 24 * HOUR
    monkeypatch.setattr(main, "reverse_ip_manager", later)
    body = client.get("/healthz").json()
    stale = [r for r in body["reasons"] if r["code"] == "reverseip_source_stale"]
    assert body["status"] == "degraded"
    assert [r["message"] for r in stale] == later.stale_sources()
    assert len(stale) == 1
    assert body["reverseip"]["sources"]["tranco"]["stale"] is True


def test_healthz_no_database_after_a_build_attempt_degrades(tmp_path, monkeypatch):
    manager = ReverseIpManager(str(tmp_path / "empty"), enabled=True)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    manager.build_attempted = True
    body = client.get("/healthz").json()
    assert body["status"] == "degraded"
    assert "reverseip_unavailable" in _reasons(body)
    # Its absence is reported once, not once per source.
    assert "reverseip_source_stale" not in _reasons(body)


def test_healthz_a_fresh_volume_is_not_degraded(tmp_path, monkeypatch):
    manager = ReverseIpManager(str(tmp_path / "empty"), enabled=True)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    body = client.get("/healthz").json()
    assert body["reverseip"]["database"] is False
    assert not [r for r in body["reasons"] if r["code"].startswith("reverseip")]


def test_healthz_a_database_that_will_not_read_degrades(tmp_path, monkeypatch):
    (tmp_path / "built").mkdir()
    built = build_manager(tmp_path / "built")
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / built.path.rsplit("/", 1)[-1]).write_bytes(b"not sqlite" * 100)
    manager = ReverseIpManager(str(broken), enabled=True)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    body = client.get("/healthz").json()
    assert body["reverseip"]["database"] is False
    assert "reverseip_unavailable" in _reasons(body)


def test_healthz_says_nothing_when_it_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(
        main,
        "reverse_ip_manager",
        ReverseIpManager(str(tmp_path), enabled=False),
    )
    body = client.get("/healthz").json()
    assert body["reverseip"] == {"enabled": False}
    assert not [r for r in body["reasons"] if r["code"].startswith("reverseip")]


BROWSER = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130 Safari/537.36"}


def test_the_page_panel(reverseip_enabled, legs):
    html = client.get(f"/{LISTED_IP}", headers=BROWSER).text
    assert 'id="acc-reverseip"' in html
    assert (
        '<a class="lookup-link" href="/example.com" rel="nofollow">example.com</a>'
        in html
    )
    assert config.OPENINTEL_ATTRIBUTION in html
    assert 'href="/static/licenses/openintel-terms.html"' in html
    assert f'href="{config.OPENINTEL_LICENSE_URL}" rel="noopener noreferrer"' in html
    assert html.index('id="acc-geoip"') < html.index('id="acc-reverseip"')


def test_the_page_panel_unknown_still_carries_the_licence_lines(
    reverseip_enabled, legs, monkeypatch
):
    monkeypatch.setattr(reverseip_enabled, "_availability", lambda *a: ({}, {}))
    html = client.get(f"/{LISTED_IP}", headers=BROWSER).text
    assert 'id="acc-reverseip"' in html
    assert 'title="unknown"' in html
    assert config.OPENINTEL_ATTRIBUTION in html
    assert 'href="/static/licenses/openintel-terms.html"' in html


def test_no_panel_on_a_domain_or_the_self_page(reverseip_enabled, legs):
    assert 'id="acc-reverseip"' not in client.get(f"/{DOMAIN}", headers=BROWSER).text
    assert 'id="acc-reverseip"' not in client.get("/", headers=BROWSER).text


def test_no_panel_while_disabled(legs):
    assert 'id="acc-reverseip"' not in client.get(f"/{LISTED_IP}", headers=BROWSER).text


# --- MCP lookup and ?fields= -------------------------------------------------

JSON = {"user-agent": "curl/8", "accept": "application/json"}
LICENCE = [
    "CC BY-NC-SA 4.0",
    config.OPENINTEL_ATTRIBUTION,
    config.REVERSEIP_TERMS_URL,
]


async def test_mcp_lookup_carries_compact_reverse_ip(reverseip_enabled, legs):
    result = await mcp_server.lookup(LISTED_IP)
    rip = result["reverse_ip"]
    assert rip["total"] == 4 and rip["names"][0] == "example.com"
    assert rip["license"] == "CC BY-NC-SA 4.0"
    assert rip["attribution"] == config.OPENINTEL_ATTRIBUTION
    assert rip["terms_url"] == config.REVERSEIP_TERMS_URL
    assert set(rip) == {
        "total",
        "names",
        "truncated",
        "block",
        "as_of",
        "unavailable",
        "coverage",
        "license",
        "license_url",
        "attribution",
        "terms_url",
    }
    assert rip["license_url"] == config.OPENINTEL_LICENSE_URL


async def test_mcp_lookup_has_no_reverse_ip_for_a_domain_or_when_disabled(
    reverseip_enabled, legs
):
    assert "reverse_ip" not in await mcp_server.lookup(DOMAIN)


def test_compact_reverse_ip_cuts_at_the_limit():
    info = {"total": 25, "names": [f"n{i}.test" for i in range(25)], "block": None}
    out = mcp_server.compact_reverse_ip(info, limit=20)
    assert len(out["names"]) == 20 and out["truncated"] is True
    whole = mcp_server.compact_reverse_ip({**info, "total": 3, "names": ["a"] * 3})
    assert whole["truncated"] is False
    assert mcp_server.compact_reverse_ip(None) is None


def test_compact_reverse_ip_unknown_is_null_not_empty():
    out = mcp_server.compact_reverse_ip(
        {
            "total": None,
            "names": None,
            "unavailable": [{"source": "tranco", "label": "Tranco", "reason": "old"}],
        }
    )
    assert out["total"] is None and out["names"] is None and out["truncated"] is None
    assert out["unavailable"] == [{"source": "Tranco", "reason": "old"}]


def test_the_lookup_description_says_empty_is_not_none():
    doc = " ".join(mcp_server.lookup.__doc__.split())
    assert "not no domains" in doc
    assert "Repeat `attribution`, `license` and `terms_url`" in doc


def test_the_lookup_description_orders_the_names_truly():
    # only the CrUX lists carry a rank: the others' names follow in file order
    doc = " ".join(mcp_server.lookup.__doc__.split())
    assert "most popular" not in doc
    assert "names ranked by Chrome UX Report first" in doc


def test_fields_bring_the_licence_lines(reverseip_enabled, legs):
    text = client.get(f"/{LISTED_IP}?fields=reverse_ip_total,ip&format=text").text
    assert text.splitlines() == ["4", LISTED_IP, *LICENCE]


def test_fields_json_carries_them_too(reverseip_enabled, legs):
    body = client.get(
        f"/{LISTED_IP}?fields=reverse_ip_block_names", headers=JSON
    ).json()
    assert body == {
        "reverse_ip_block_names": 7,
        "reverse_ip_license": LICENCE[0],
        "reverse_ip_attribution": LICENCE[1],
        "reverse_ip_terms_url": LICENCE[2],
    }


def test_fields_names_are_comma_joined(reverseip_enabled, legs):
    value = client.get(f"/{LISTED_IP}?fields=reverse_ip_names&format=text").text
    assert value.splitlines()[0].startswith("example.com,")


def test_unknown_is_a_question_mark_with_the_reason(
    reverseip_enabled, legs, monkeypatch
):
    monkeypatch.setattr(reverseip_enabled, "_availability", lambda *a: ({}, {}))
    lines = client.get(
        f"/{LISTED_IP}?fields=reverse_ip_total,reverse_ip_names&format=text"
    ).text.splitlines()
    assert lines[:2] == ["?", "?"]
    assert lines[2:] == LICENCE


def test_not_in_the_text_block(reverseip_enabled, legs):
    assert "reverse_ip" not in client.get(f"/{LISTED_IP}?format=text").text


@pytest.fixture
def partial(monkeypatch, tmp_path, legs, stock_sqlite):
    """A realistic partial state: the database built from Tranco alone, the
    manager configured with Tranco and Umbrella (Umbrella never arrived)."""
    build_manager(tmp_path, sources="tranco")
    manager = ReverseIpManager(
        str(tmp_path),
        parse_sources("tranco,umbrella"),
        enabled=True,
        clock=lambda: NOW,
    )
    monkeypatch.setattr(lookup, "reverse_ip_manager", manager)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    return manager


EMPTY_IP = "175.214.27.215"


def test_the_page_says_which_lists_were_not_checked(partial):
    html = client.get(f"/{LISTED_IP}", headers=BROWSER).text
    assert "Not checked: Cisco Umbrella (not in the database)" in html
    assert 'title="4 names"' in html
    assert "Names on the Tranco top list only." in html
    assert "Cisco Umbrella and" not in html


def test_the_page_none_found_counts_the_lists_read(partial):
    html = client.get(f"/{EMPTY_IP}", headers=BROWSER).text
    assert 'title="none in 1 of 2 lists"' in html
    assert "none in top lists" not in html
    assert "Not checked: Cisco Umbrella (not in the database)" in html
    assert "No name on these lists resolved to this address" in html


def test_a_complete_answer_has_no_not_checked_line(reverseip_enabled, legs):
    html = client.get(f"/{EMPTY_IP}", headers=BROWSER).text
    assert 'title="none in top lists"' in html
    assert "Not checked:" not in html


def test_fields_unavailable_names_the_lists_not_read(partial):
    lines = client.get(
        f"/{EMPTY_IP}?fields=reverse_ip_total,reverse_ip_unavailable&format=text"
    ).text.splitlines()
    assert lines == ["0", "Cisco Umbrella: not in the database", *LICENCE]


def test_fields_unavailable_is_dash_when_every_list_was_read(reverseip_enabled, legs):
    text = client.get(f"/{LISTED_IP}?fields=reverse_ip_unavailable&format=text").text
    assert text.splitlines() == ["-"]
    body = client.get(f"/{LISTED_IP}?fields=reverse_ip_unavailable", headers=JSON)
    assert body.json() == {"reverse_ip_unavailable": None}


def test_fields_unavailable_when_nothing_was_read(reverseip_enabled, legs, tmp_path):
    reverseip_enabled._clock = lambda: NOW + 5 * 24 * HOUR
    text = client.get(f"/{LISTED_IP}?fields=reverse_ip_unavailable&format=text").text
    assert text.splitlines() == [
        "Tranco: last measured 2026-10-20, older than 96 hours"
    ]


def test_fields_unavailable_is_dash_for_a_domain_and_the_self_route(
    reverseip_enabled, legs
):
    assert client.get(
        f"/{DOMAIN}?fields=reverse_ip_unavailable&format=text"
    ).text.splitlines() == ["-"]
    assert client.get(
        "/?fields=reverse_ip_unavailable&format=text",
        headers={"x-real-ip": LISTED_IP},
    ).text.splitlines() == ["-"]


def test_fields_unavailable_is_asked_for_by_name_only(reverseip_enabled, legs):
    import textfmt

    assert "reverse_ip_unavailable" not in textfmt.parse_fields(
        ["reverse_ip_total,reverse_ip_names"]
    )
    assert textfmt.parse_fields(["reverse_ip_unavailable"]) == [
        "reverse_ip_unavailable"
    ]
    assert "reverse_ip_unavailable" not in textfmt.block_fields("ip", as_info=True)


def test_a_domain_reads_dash(reverseip_enabled, legs):
    fields = ",".join(
        ["reverse_ip_total", "reverse_ip_license", "reverse_ip_terms_url"]
    )
    text = client.get(f"/{DOMAIN}?fields={fields}&format=text").text
    assert text.splitlines()[:3] == ["-", "-", "-"]


def test_the_self_route_reads_dash(reverseip_enabled, legs):
    text = client.get(
        "/?fields=reverse_ip_total&format=text", headers={"x-real-ip": LISTED_IP}
    ).text
    assert set(text.split()) == {"-"}


def test_asking_for_a_licence_field_alone_adds_nothing():
    import textfmt

    assert textfmt.parse_fields(["reverse_ip_license"]) == ["reverse_ip_license"]
    assert textfmt.parse_fields(["reverse_ip_names,ip,reverse_ip_license"]) == [
        "reverse_ip_names",
        "ip",
        "reverse_ip_license",
        "reverse_ip_attribution",
        "reverse_ip_terms_url",
    ]


# --- Subdomains from the lists -------------------------------------------


@pytest.fixture
def crtsh_store(tmp_path):
    subdomains.reset_state(store_path=str(tmp_path / "s.sqlite3"))
    yield
    subdomains.reset_state()


@pytest.fixture
def crtsh_returns(monkeypatch, crtsh_store):
    def install(names):
        async def fake(domain):
            return list(names), len(names)

        monkeypatch.setattr(subdomains, "fetch_from_source", fake)

    return install


@pytest.fixture
def crtsh_fails(monkeypatch, crtsh_store):
    async def fake(domain):
        raise subdomains.SubdomainError("crt.sh timed out")

    monkeypatch.setattr(subdomains, "fetch_from_source", fake)


LISTED = ["a.b.example.com", "norank.example.com"]


def test_only_mode_carries_openintel(reverseip_enabled, crtsh_returns):
    crtsh_returns(["www.example.com"])
    body = client.get("/example.com?subdomains=only").json()
    assert body["subdomains"]["names"] == ["www.example.com"]
    assert body["subdomains"]["openintel"]["names"] == LISTED
    assert body["subdomains"]["openintel"]["attribution"] == (
        config.OPENINTEL_ATTRIBUTION
    )


def test_include_mode_carries_it_too(reverseip_enabled, crtsh_returns, legs):
    crtsh_returns(["www.example.com"])
    body = client.get(f"/{DOMAIN}?subdomains=include", headers=CURL).json()
    assert body["subdomains"]["names"] == ["www.example.com"]
    assert body["subdomains"]["openintel"]["names"] == LISTED


def test_disabled_leaves_the_crtsh_answer_as_it_was(crtsh_returns):
    crtsh_returns(["www.example.com"])
    body = client.get("/example.com?subdomains=only").json()
    assert "openintel" not in body["subdomains"]


def test_a_crtsh_error_keeps_its_error_beside_the_names(reverseip_enabled, crtsh_fails):
    sub = client.get("/example.com?subdomains=only").json()["subdomains"]
    assert sub["error"]
    assert sub["openintel"]["names"] == LISTED


def test_the_answer_is_a_new_dict_and_the_cached_one_is_untouched(
    reverseip_enabled, crtsh_returns
):
    import asyncio

    crtsh_returns(["www.example.com"])
    first = asyncio.run(subdomains.get_subdomains("example.com"))
    answer = asyncio.run(main._subdomain_answer("example.com"))
    assert answer is not first
    assert "openintel" in answer
    assert "openintel" not in first


async def test_mcp_subdomains_with_openintel(reverseip_enabled, crtsh_returns):
    crtsh_returns(["www.example.com"])
    result = await mcp_server.subdomains("example.com")
    assert result["names"] == ["www.example.com"]
    assert result["openintel"]["names"] == LISTED
    assert result["openintel"]["truncated"] is False
    assert result["openintel"]["terms_url"] == config.REVERSEIP_TERMS_URL
    assert result["openintel"]["attribution"] == config.OPENINTEL_ATTRIBUTION
    assert result["openintel"]["license_url"] == config.OPENINTEL_LICENSE_URL
    assert set(result["openintel"]) == {
        "names",
        "count",
        "truncated",
        "as_of",
        "unavailable",
        "license",
        "license_url",
        "attribution",
        "terms_url",
    }


async def test_mcp_subdomains_reads_a_padded_name_as_the_gate_does(
    reverseip_enabled, crtsh_returns
):
    crtsh_returns(["www.example.com"])
    result = await mcp_server.subdomains(" example.com ")
    assert result["openintel"]["names"] == LISTED
    assert result["openintel"]["count"] == 2


async def test_mcp_openintel_honours_limit(reverseip_enabled, crtsh_returns):
    crtsh_returns(["www.example.com"])
    result = await mcp_server.subdomains("example.com", limit=1)
    assert result["openintel"]["names"] == LISTED[:1]
    assert result["openintel"]["count"] == 2
    assert result["openintel"]["truncated"] is True


async def test_mcp_disabled_has_no_openintel_key(crtsh_returns):
    crtsh_returns(["www.example.com"])
    result = await mcp_server.subdomains("example.com")
    assert "openintel" not in result


async def test_mcp_crtsh_failure_with_listed_names_is_a_result(
    reverseip_enabled, crtsh_fails
):
    result = await mcp_server.subdomains("example.com")
    assert not isinstance(result, CallToolResult)
    assert result["names"] is None and result["count"] is None
    assert result["truncated"] is None
    assert result["error"] and result["openintel"]["count"] == 2
    assert result["source"] == subdomains.SOURCE


async def test_mcp_crtsh_failure_without_listed_names_is_an_error(
    reverseip_enabled, crtsh_fails
):
    result = await mcp_server.subdomains("1kko.com")
    assert isinstance(result, CallToolResult) and result.is_error


async def test_mcp_crtsh_failure_with_lists_off_is_an_error(crtsh_fails):
    result = await mcp_server.subdomains("example.com")
    assert isinstance(result, CallToolResult) and result.is_error


def test_the_tool_title_names_both_sources():
    tool = next(
        t for t in mcp_server.mcp._tool_manager.list_tools() if t.name == "subdomains"
    )
    assert tool.title == "Subdomains from Certificate Transparency and DNS top lists"
    assert "`terms_url`" in tool.description


def test_a_crtsh_error_with_listed_names_still_renders_the_panel(
    reverseip_enabled, crtsh_fails, legs
):
    html = client.get(f"/{DOMAIN}?subdomains=include", headers=BROWSER).text
    assert 'id="subdomains-rendered"' in html
    assert "crt.sh lookup failed: crt.sh timed out" in html
    assert "Lookup failed:" not in html


def test_both_sources_failing_is_still_a_failed_panel(crtsh_fails, legs):
    html = client.get(f"/{DOMAIN}?subdomains=include", headers=BROWSER).text
    assert 'id="subdomains-rendered"' not in html
    assert "Lookup failed: crt.sh timed out" in html
