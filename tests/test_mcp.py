"""MCP endpoint tests.

Every test here uses `with TestClient(app)` rather than a module-level client.
The MCP session manager is started by the app lifespan, and TestClient only
runs the lifespan when used as a context manager; without it the first request
fails with "RuntimeError: Task group is not initialized".
"""

import asyncio
import datetime
import re
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import config
import eppstatus
import lookup
import main
import mcp_server
from config import (
    MCP_ICON_URL,
    MCP_SERVER_DESCRIPTION,
    MCP_SERVER_TITLE,
    MCP_WEBSITE_URL,
)
from main import app
from managers import _asn1_time

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "ip.1kko.com",
}


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def _rpc(client, method, params=None, id_=2):
    body = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=MCP_HEADERS)


MODERN_VERSION = "2026-07-28"
# The per-request envelope of that revision, which has no initialize: every
# request names its protocol version and client capabilities in params._meta.
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _modern_rpc(client, method, params=None, id_=2):
    """One 2026-07-28 request. The transport routes on the MCP-Protocol-Version
    header (a handshake-era value, or none, takes the initialize path instead)
    and the SDK's inbound ladder requires Mcp-Method to match the body."""
    body = {
        "jsonrpc": "2.0",
        "id": id_,
        "method": method,
        "params": {**(params or {}), "_meta": MODERN_META},
    }
    return client.post(
        "/mcp",
        json=body,
        headers={
            **MCP_HEADERS,
            "MCP-Protocol-Version": MODERN_VERSION,
            "Mcp-Method": method,
        },
    )


def test_initialize_handshake():
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["serverInfo"]["name"] == "whatismyip"
        assert "tools" in result["capabilities"]
        # The card a client shows for this server: the same one as server.json
        # (tests/test_mcp_registry.py ties the two), not a bare name.
        info = result["serverInfo"]
        assert info["title"] == MCP_SERVER_TITLE
        assert info["description"] == MCP_SERVER_DESCRIPTION
        assert info["websiteUrl"] == MCP_WEBSITE_URL
        assert info["icons"] == [
            {"src": MCP_ICON_URL, "mimeType": "image/png", "sizes": ["512x512"]}
        ]
        # Server-level instructions, for the clients that read them: the two
        # caveats the tools already carry, from the same constants, so the
        # copies cannot drift. No sentence of their own.
        instructions = result["instructions"]
        assert mcp_server._NOT_SAFE in instructions
        assert mcp_server._CALLER_ORIGIN in instructions


def test_mcp_initialize_reports_the_deployed_version():
    """The initialize response names the same deployed build as /healthz."""
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 200
    server_info = response.json()["result"]["serverInfo"]
    assert server_info["name"] == "whatismyip"
    assert server_info["version"] == config.APP_VERSION
    assert server_info["version"]


def test_a_2026_client_reads_the_same_card_from_server_discover():
    """A 2026-07-28 client never sends initialize. It reads the server's card
    from server/discover, and every result after that carries serverInfo in
    _meta, so the card has to be right there too."""
    with TestClient(app) as client:
        result = _modern_rpc(client, "server/discover").json()["result"]
        info = result["_meta"]["io.modelcontextprotocol/serverInfo"]
        assert info["title"] == MCP_SERVER_TITLE
        assert info["websiteUrl"] == MCP_WEBSITE_URL
        assert info["icons"][0]["src"] == MCP_ICON_URL


def test_whoami_caller_and_instructions_share_one_caveat():
    """The description is where every client reads the caveat; instructions is
    where the few that honour it read it once per session. One constant, so
    neither copy can be edited without the other, on both wires."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        listed = _rpc(client, "tools/list").json()["result"]["tools"]
        tools = {tool["name"]: tool for tool in listed}
        description = tools["whoami_caller"]["description"]
        assert mcp_server._CALLER_ORIGIN in description
        # The rest of what the docstring said survives the move to __doc__,
        # the privacy promise above all.
        assert "the caller's own address is not sent to anyone" in description
        discover = _modern_rpc(client, "server/discover").json()["result"]
        assert mcp_server._CALLER_ORIGIN in discover["instructions"]
        assert mcp_server._NOT_SAFE in discover["instructions"]


def test_tools_list_exposes_the_five_tools():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = _rpc(client, "tools/list")
        listed = response.json()["result"]["tools"]
        # Registration order, which is also the order of the page's mcp-tools
        # tag (registered_tool_names()). TestPageToolList only compares the
        # page with tools/list, so a registration moved elsewhere in
        # mcp_server.py shows up here and nowhere else.
        assert [tool["name"] for tool in listed] == [
            "lookup",
            "dns_records",
            "ssl_certificate",
            "subdomains",
            "whoami_caller",
        ]
        # Without annotations the spec has a client assume readOnlyHint=false
        # and destructiveHint=true: five write tools on a server that only
        # looks things up. Hints a client may ignore, not guarantees.
        for tool in listed:
            name = tool["name"]
            assert tool["title"], name
            assert tool["annotations"]["readOnlyHint"] is True, name
            assert tool["annotations"]["destructiveHint"] is False, name
            assert tool["annotations"]["idempotentHint"] is True, name
            # whoami_caller reads the GeoIP database and the lists in memory
            # and sends nothing anywhere; every other tool asks another system.
            assert tool["annotations"]["openWorldHint"] is (name != "whoami_caller"), (
                name
            )


def test_tools_list_tells_a_2026_client_how_long_to_keep_it():
    """SEP-2549 cache hints ride only the 2026-07-28 wire: the handshake-era
    tools/list that _rpc sends has no ttlMs field to carry them, which is why
    the hint is read through the per-request envelope and the handshake-era
    list is checked to carry none. A day, and shared: there is no
    authentication, so every caller gets the same list. The cost is that a
    renamed or removed tool, or SUBDOMAIN_ENABLED=false, reaches a client that
    cached the list up to a day late."""
    with TestClient(app) as client:
        result = _modern_rpc(client, "tools/list").json()["result"]
        assert result["ttlMs"] == 86_400_000
        assert result["ttlMs"] == mcp_server.TOOLS_LIST_TTL_MS
        assert result["cacheScope"] == "public"
        assert "lookup" in {tool["name"] for tool in result["tools"]}
        # A handshake-era client (2025-11-25 and earlier, which is every client
        # today) gets no hint: its tools/list has no field to carry one.
        legacy = _rpc(client, "tools/list").json()["result"]
        assert "ttlMs" not in legacy
        assert "cacheScope" not in legacy
        assert "lookup" in {tool["name"] for tool in legacy["tools"]}


def test_bad_host_header_is_rejected():
    """transport_security must allowlist the real hostname.

    Without it the SDK arms DNS-rebinding protection with a localhost-only
    allowlist and answers every production request with 421 — the single most
    likely silent misconfiguration in this feature.
    """
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json=INIT,
            headers={**MCP_HEADERS, "Host": "evil.example.com"},
        )
        assert response.status_code == 421


FAKE_LOOKUP = {
    "address": "example.com",
    "domain": {"a": ["93.184.216.34"], "mx": [], "ns": [], "txt": [], "spf": []},
    "location": {
        "ip": "93.184.216.34",
        "country_code": "US",
        "country_name": "United States",
        "country_source": "located",
        "city_name": "Norwell",
        "subdivision_name": "Massachusetts",
        "lat": 42.1596,
        "lon": -70.8217,
        "accuracy_km": 20,
        "time_zone": "America/New_York",
        "cidr": "93.184.216.0/24",
        "asn_number": 15133,
        "asn_name": "EDGECAST",
        "asn_cidr": "93.184.216.0/24",
        "precision": "city",
    },
    "whois": {
        "source": "rdap",
        "name": "example.com",
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "registrant": None,
        "abuse_email": "abuse@iana.org",
        "status": ["client delete prohibited"],
        "created": "1995-08-14T04:00:00+00:00",
        "expires": "2026-08-13T04:00:00+00:00",
        "updated": None,
    },
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}


def test_lookup_tool_returns_a_compact_result():
    async def fake_gather(target, legs=None):
        return FAKE_LOOKUP

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["ip"] == "93.184.216.34"
        assert payload["geo"]["country_code"] == "US"
        assert payload["geo"]["precision"] == "city"
        assert payload["geo"]["lat"] == 42.1596  # a city-level fix keeps its numbers
        assert payload["geo"]["time_zone"] == "America/New_York"
        assert payload["network"]["asn_number"] == 15133
        assert payload["registration"]["registrar"].startswith("RESERVED")
        registration = payload["registration"]
        assert registration["status"] == ["client delete prohibited"]  # raw, as before
        assert registration["status_explained"] == [
            {
                "code": "clientDeleteProhibited",
                "meaning": eppstatus.STATUS_MEANINGS["clientDeleteProhibited"][0],
                "severity": "success",
            }
        ]
        # Render-only data must never reach an LLM context.
        for forbidden in ("map", "distance_km", "origin"):
            assert forbidden not in payload


# gather() for 8.8.8.8: its PTR name, dns.google., and the sweep of that name,
# whose A records include the address.
FAKE_IP_LOOKUP = {
    "address": "8.8.8.8",
    "domain": {
        "queried_name": "dns.google",
        "a": [{"ip": "8.8.4.4", "ttl": 300}, {"ip": "8.8.8.8", "ttl": 300}],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "status": {"a": "ok", "aaaa": "noanswer"},
    },
    "location": {
        "ip": "8.8.8.8",
        "country_code": "US",
        "country_name": "United States",
        "asn_number": 15169,
        "asn_name": "GOOGLE",
        "reverse_dns": "dns.google.",
    },
    "whois": {"source": "rdap", "name": "GOGL", "registrant": "Google LLC"},
    "ssl": None,
    "resolved_ip": "8.8.8.8",
    "resolution": "literal",
    "reverse_dns": "dns.google.",
}


def _lookup_payload(gathered, target):
    async def fake_gather(_target, legs=None):
        return gathered

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": target}},
            )
    return response.json()["result"]["structuredContent"]


def _ip_lookup(a_records, a_status="ok", reverse_dns="dns.google."):
    domain = {
        **FAKE_IP_LOOKUP["domain"],
        "a": [{"ip": ip, "ttl": 300} for ip in a_records],
        "status": {"a": a_status, "aaaa": "noanswer"},
    }
    return {
        **FAKE_IP_LOOKUP,
        "domain": domain if reverse_dns else {},
        "location": {**FAKE_IP_LOOKUP["location"], "reverse_dns": reverse_dns},
        "reverse_dns": reverse_dns,
    }


@pytest.mark.parametrize(
    ("gathered", "expected"),
    [
        (_ip_lookup(["8.8.4.4", "8.8.8.8"]), "confirmed"),
        (_ip_lookup(["216.239.32.10"]), "unconfirmed"),
        (_ip_lookup([], a_status="timeout"), "unknown"),
        (_ip_lookup([], reverse_dns=None), "no_ptr"),
    ],
    ids=["confirmed", "unconfirmed", "unknown", "no_ptr"],
)
def test_lookup_says_whether_an_ips_ptr_points_back(gathered, expected):
    payload = _lookup_payload(gathered, "8.8.8.8")
    assert payload["reverse_dns"] == gathered["reverse_dns"]
    assert payload["reverse_dns_confirmed"] == expected


def test_lookup_has_no_ptr_verdict_for_a_domain():
    """A domain's sweep is of the domain itself, not of a PTR name."""
    payload = _lookup_payload(FAKE_LOOKUP, "example.com")
    assert "reverse_dns_confirmed" in payload
    assert payload["reverse_dns_confirmed"] is None


def test_fields_and_mcp_give_the_same_verdict():
    """?fields=reverse_dns_confirmed and the lookup tool read one verdict off
    the same gather() result."""

    async def fake_gather(_target, legs=None):
        return _ip_lookup(["216.239.32.10"])

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with (
            patch("mcp_server.gather", fake_gather),
            patch("main.gather", fake_gather),
        ):
            tool = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "8.8.8.8"}},
            )
            fields = client.get(
                "/8.8.8.8?fields=reverse_dns_confirmed",
                headers={"user-agent": "curl/8.0"},
            )
    verdict = tool.json()["result"]["structuredContent"]["reverse_dns_confirmed"]
    assert verdict == fields.json()["reverse_dns_confirmed"] == "unconfirmed"


def test_the_lookup_description_explains_the_verdict():
    doc = " ".join(mcp_server.lookup.__doc__.split())
    assert "reverse_dns_confirmed" in doc
    assert re.search(r'"unknown" when .*query failed', doc)
    assert "does not point back" in doc


# GeoLite2's answer for 8.8.8.8: the US centroid, ± 1000 km, no city, and a
# time zone that is the centroid's (America/Chicago), not the address's.
US_CENTROID_LOOKUP = {
    **FAKE_LOOKUP,
    "address": "8.8.8.8",
    "resolved_ip": "8.8.8.8",
    "location": {
        **FAKE_LOOKUP["location"],
        "ip": "8.8.8.8",
        "city_name": "",
        "subdivision_name": "",
        "lat": 37.751,
        "lon": -97.822,
        "accuracy_km": 1000,
        "time_zone": "America/Chicago",
        "precision": "country",
    },
}

# GeoLite2's answer for 1.1.1.1: only the country the block is registered in.
REGISTERED_ONLY_LOOKUP = {
    **FAKE_LOOKUP,
    "address": "1.1.1.1",
    "resolved_ip": "1.1.1.1",
    "location": {
        **FAKE_LOOKUP["location"],
        "ip": "1.1.1.1",
        "country_code": "AU",
        "country_name": "Australia",
        "country_source": "registered",
        "city_name": "",
        "subdivision_name": "",
        "lat": None,
        "lon": None,
        "accuracy_km": None,
        "time_zone": None,
        "precision": None,
    },
}


def _lookup_geo(client, data):
    async def fake_gather(target, legs=None):  # gather()'s own signature
        return data

    with patch("mcp_server.gather", fake_gather):
        response = _rpc(
            client,
            "tools/call",
            {"name": "lookup", "arguments": {"target": data["address"]}},
        )
    return response.json()["result"]["structuredContent"]["geo"]


def test_lookup_tool_keeps_only_the_country_of_a_country_level_fix():
    """Production `lookup 185.199.108.153` handed a model lat 37.751,
    accuracy_km 1000 and America/Chicago with nothing saying the first and
    last are a centroid's. A model reads a number as a place, so a fix that
    is not city-level keeps its grade and its country, and nothing it cannot
    support. The HTTP JSON keeps the numbers; this is the MCP shape only."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        geo = _lookup_geo(client, US_CENTROID_LOOKUP)
    assert geo["precision"] == "country"
    assert geo["country_source"] == "located"
    assert (geo["country_code"], geo["country_name"]) == ("US", "United States")
    assert geo["lat"] is None
    assert geo["lon"] is None
    assert geo["time_zone"] is None
    assert geo["accuracy_km"] == 1000  # the radius is why; it stays


def test_lookup_tool_marks_a_registered_only_country():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        geo = _lookup_geo(client, REGISTERED_ONLY_LOOKUP)
    assert geo["country_code"] == "AU"
    assert geo["country_source"] == "registered"
    assert geo["precision"] is None
    assert geo["lat"] is None and geo["lon"] is None and geo["time_zone"] is None


def test_the_tool_descriptions_say_what_a_country_level_fix_is_worth():
    """The grade only helps if the model is told to read it. The description
    is the raw docstring, wrapped wherever its lines end, so it is compared
    with its whitespace collapsed, as test_reputation.py reads lookup's."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        tools = {
            tool["name"]: " ".join(tool["description"].split())
            for tool in _rpc(client, "tools/list").json()["result"]["tools"]
        }
    for name in ("lookup", "whoami_caller"):
        assert "precision" in tools[name], name
        assert "only the country" in tools[name], name


def test_lookup_tool_reports_private_targets_as_an_error():
    async def boom(target, legs=None):
        raise lookup.PrivateAddressError(target)

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "10.0.0.1"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload


def test_mcp_uses_its_own_rate_bucket_and_never_bans():
    """A shared provider egress IP must never be banned.

    Every user of a hosted AI client arrives from the same handful of
    addresses, so escalating an MCP rate-limit breach to a ban would take all
    of them offline at once. Over-limit is 429 and nothing more.
    """
    limit = main.mcp_rate_limiter.requests_per_minute

    with TestClient(app, client=("203.0.113.7", 41234)) as client:
        statuses = [
            client.post("/mcp", json=INIT, headers=MCP_HEADERS).status_code
            for _ in range(limit + 5)
        ]

    assert 429 in statuses, "the MCP bucket never engaged"
    assert "203.0.113.7" not in main.ip_ban_manager.banned_ips


def test_mcp_response_carries_no_csp():
    """CSP is for the HTML page; the MCP response is JSON."""
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert "Content-Security-Policy" not in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_domain_starting_with_mcp_keeps_its_csp_header():
    """A bare startswith("/mcp") in the CSP skip would also match
    "/mcpfoo.com" — a syntactically valid domain, and a real, reachable page
    via the /{domain_ip} catch-all, not the MCP transport. That page must keep
    its CSP header."""

    async def fake_gather(target):
        return {
            "address": "mcpfoo.com",
            "domain": {
                "a": [{"ip": "93.184.216.34", "ttl": 300}],
                "mx": [],
                "ns": [],
                "txt": [],
                "cname": None,
            },
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city_name": None,
                "lat": None,
                "lon": None,
                "is_private": False,
            },
            "whois": {"source": "rdap", "name": "mcpfoo.com"},
            "ssl": None,
            "resolved_ip": "93.184.216.34",
            "reverse_dns": None,
        }

    async def fake_lookup_location(ip):
        return {
            "country_code": "US",
            "country_name": "United States",
            "city_name": None,
            "lat": None,
            "lon": None,
            "is_private": False,
        }

    with TestClient(app) as client:
        with (
            patch("main.gather", fake_gather),
            patch("main.lookup_location", fake_lookup_location),
        ):
            response = client.get("/mcpfoo.com", headers={"user-agent": "curl/8.0"})
        assert response.status_code == 200
        assert "Content-Security-Policy" in response.headers


def test_manual_ban_still_blocks_mcp():
    """The one MCP security behaviour this branch relies on but never tested
    directly: a pre-existing manual ban must still 403 /mcp requests."""
    main.ip_ban_manager.ban_ip("testclient", reason="manual", duration=3600)
    try:
        with TestClient(app) as client:
            response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert response.status_code == 403
    finally:
        # Otherwise this persists to BANNED_IPS_FILE and 403s every other
        # test's requests in later, separate pytest invocations.
        main.ip_ban_manager.unban_ip("testclient")


def test_get_mcp_is_rejected_without_opening_a_stream():
    """A GET here would otherwise reach the SDK's `_handle_get_request` and
    open a standalone SSE stream that `stateless_http=True` never tears down
    — see McpDispatch's and McpBarePathRoute's method guards."""
    with TestClient(app) as client:
        for path in ("/mcp", "/mcp/"):
            response = client.get(path, headers=MCP_HEADERS)
            assert response.status_code == 405
            assert response.headers["allow"] == "POST"


def test_delete_mcp_is_also_rejected():
    with TestClient(app) as client:
        response = client.delete("/mcp", headers=MCP_HEADERS)
        assert response.status_code == 405


def test_oversized_mcp_body_is_rejected_with_413():
    huge_target = "a" * (main.MCP_MAX_BODY_BYTES + 1)
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "lookup", "arguments": {"target": huge_target}},
    }
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = client.post("/mcp", json=body, headers=MCP_HEADERS)
    assert response.status_code == 413


def test_mcp_body_within_the_limit_still_passes():
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 200


def test_mcp_body_with_no_content_length_is_rejected_with_413():
    """Chunked transfer-encoding has no advertised length to check against the
    cap, so it is rejected outright rather than read and measured after the
    fact."""

    def stream():
        yield b'{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": '
        yield b'{"protocolVersion": "2026-07-28", "capabilities": {}, '
        yield b'"clientInfo": {"name": "pytest", "version": "0"}}}'

    with TestClient(app) as client:
        response = client.post("/mcp", headers=MCP_HEADERS, content=stream())
    assert response.status_code == 413


def test_mcp_rate_limiter_cleanup_is_scheduled():
    """Without this job, allow_request() prunes each IP's own timestamps but
    never deletes the (now empty) key, so /mcp leaks one dict entry per
    distinct caller IP for the life of the process."""
    funcs = [job.func for job in main.scheduler.get_jobs()]
    assert main.mcp_rate_limiter.cleanup_old_records in funcs


def test_dns_records_returns_the_full_sweep():
    async def fake_gather(target, legs=None):
        return {
            **FAKE_LOOKUP,
            "domain": {
                "a": ["93.184.216.34"],
                "mx": [{"host": "mail.example.com", "priority": 10}],
                "ns": ["a.iana-servers.net"],
                "txt": ["v=spf1 -all"],
                "spf": ["v=spf1 -all"],
                "cname": None,
                "ptr": [],
            },
        }

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "dns_records", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["records"]["ns"] == ["a.iana-servers.net"]
        assert payload["records"]["txt"] == ["v=spf1 -all"]


def test_dns_records_narrows_to_requested_types():
    async def fake_gather(target, legs=None):
        return {
            **FAKE_LOOKUP,
            "domain": {"a": ["1.2.3.4"], "mx": [], "ns": ["ns1.example.com"]},
        }

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {
                    "name": "dns_records",
                    "arguments": {"domain": "example.com", "types": ["ns"]},
                },
            )
        payload = response.json()["result"]["structuredContent"]
        assert set(payload["records"]) == {"ns"}


def test_dns_records_with_an_explicit_empty_type_list_returns_nothing():
    """types=[] is a different request from omitting the argument: "narrow to
    nothing", not "everything". Truthiness would conflate the two."""

    async def fake_gather(target, legs=None):
        return {
            **FAKE_LOOKUP,
            "domain": {"a": ["1.2.3.4"], "mx": [], "ns": ["ns1.example.com"]},
        }

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {
                    "name": "dns_records",
                    "arguments": {"domain": "example.com", "types": []},
                },
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["records"] == {}


def test_dns_records_reports_private_targets_as_an_error():
    async def boom(target, legs=None):
        raise lookup.PrivateAddressError(target)

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "dns_records", "arguments": {"domain": "10.0.0.1"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload


def test_dns_records_rejects_a_type_it_never_queries():
    """types=["caa"] must not come back as {} — indistinguishable from a
    genuinely empty answer, and a confident false negative if relayed to a
    user asking "which CAs may issue for this domain?"."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = _rpc(
            client,
            "tools/call",
            {
                "name": "dns_records",
                "arguments": {"domain": "example.com", "types": ["caa"]},
            },
        )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload
        assert "caa" in payload["error"]


def test_lookup_tool_reports_a_timeout():
    async def hang(target, legs=None):
        raise TimeoutError()

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", hang):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"] == "Lookup timed out"


async def test_bounded_gather_forwards_the_legs_it_is_given():
    """The one seam the tools narrow gather() through. None goes through as
    None, so a tool that passes nothing still gets every leg."""
    asked = []

    async def fake_gather(target, legs=None):
        asked.append((target, legs))
        return FAKE_LOOKUP

    with patch("mcp_server.gather", fake_gather):
        await mcp_server._bounded_gather(
            "example.com", legs=frozenset({"resolve", "dns"})
        )
        await mcp_server._bounded_gather("example.com")
    assert asked == [("example.com", {"resolve", "dns"}), ("example.com", None)]


async def test_a_narrowed_call_keeps_the_same_wall_clock_ceiling():
    """One ceiling (_GATHER_TIMEOUT_SECONDS) for every tool: the narrow tools'
    legs carry budgets of their own (DNS_QUERY_LIFETIME per query; for TLS,
    TLS_CONNECT_TIMEOUT_SECONDS on the connect and TIMEOUT_SECONDS on the
    handshake), so there is no second knob to get wrong."""

    async def stuck(target, legs=None):
        await asyncio.sleep(5)
        return FAKE_LOOKUP

    with (
        patch("mcp_server.gather", stuck),
        patch("mcp_server._GATHER_TIMEOUT_SECONDS", 0.01),
    ):
        with pytest.raises(TimeoutError):
            await mcp_server._bounded_gather(
                "example.com", legs=frozenset({"resolve", "dns"})
            )


def test_each_tool_asks_gather_for_the_legs_it_reads():
    """dns_records reads `domain`, ssl_certificate reads `ssl`, lookup reads
    everything, and each asks gather() for exactly that (lookup.LEGS). A DNS
    question costs no RDAP query, TLS handshake or AbuseIPDB request, and a
    certificate question no DNS sweep; the answer shapes do not change."""
    asked = []

    async def fake_gather(target, legs=None):
        asked.append(legs)
        return FAKE_LOOKUP

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            for name, arguments in (
                ("lookup", {"target": "example.com"}),
                ("dns_records", {"domain": "example.com"}),
                ("ssl_certificate", {"domain": "example.com"}),
            ):
                response = _rpc(
                    client, "tools/call", {"name": name, "arguments": arguments}
                )
                assert response.status_code == 200
    assert asked == [None, {"resolve", "dns"}, {"resolve", "tls"}]


def test_ssl_certificate_reports_the_expiry_clock():
    cert = {
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "protocol": "TLSv1.3",
    }

    async def fake_gather(target, legs=None):
        return {**FAKE_LOOKUP, "ssl": cert, "resolved_ip": "93.184.216.34"}

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["issuer"] == "Let's Encrypt"
        assert payload["san"] == ["example.com", "www.example.com"]
        assert payload["days_remaining"] > 0


def _days_ago(days: float) -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)


AGED_CERT = {
    "issuer": ((("organizationName", "Let's Encrypt"),),),
    "subject": ((("commonName", "example.com"),),),
    "notBefore": _asn1_time(_days_ago(10)),
    "notAfter": "Dec 31 23:59:59 2099 GMT",
    "protocol": "TLSv1.3",
    "trusted": True,
}


def test_lookup_tool_reports_registration_and_certificate_age():
    """A model handed only dates has to do the arithmetic to notice that a
    name is days old; age_days does it for it."""
    gathered = {
        **FAKE_LOOKUP,
        "whois": {**FAKE_LOOKUP["whois"], "created": _days_ago(25)},
        "ssl": AGED_CERT,
    }

    async def fake_gather(target, legs=None):
        return gathered

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["registration"]["age_days"] == 25
        assert payload["tls"]["age_days"] == 10


def test_ssl_certificate_reports_the_certificate_age():
    async def fake_gather(target, legs=None):
        return {**FAKE_LOOKUP, "ssl": AGED_CERT, "resolved_ip": "93.184.216.34"}

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["age_days"] == 10
        assert payload["not_before"] == AGED_CERT["notBefore"]


def test_a_certificate_without_a_readable_start_has_no_age():
    from mcp_server import compact_ssl

    unstarted = {k: v for k, v in AGED_CERT.items() if k != "notBefore"}
    assert compact_ssl(unstarted)["age_days"] is None
    assert compact_ssl({**AGED_CERT, "notBefore": "garbage"})["age_days"] is None


def test_ssl_certificate_without_a_certificate_is_an_error():
    async def fake_gather(target, legs=None):
        return {**FAKE_LOOKUP, "ssl": None}

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "example.com"}},
            )
        assert "error" in response.json()["result"]["structuredContent"]


def test_ssl_certificate_reports_private_targets_as_an_error():
    async def boom(target, legs=None):
        raise lookup.PrivateAddressError(target)

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "10.0.0.1"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload


def test_whoami_caller_reports_the_connecting_peer_not_the_user():
    async def fake_location(ip):
        return {
            "ip": ip,
            "country_code": "US",
            "country_name": "United States",
            "city_name": "Ashburn",
            "lat": 39.0,
            "lon": -77.5,
        }

    with TestClient(app, client=("203.0.113.9", 41234)) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.lookup_location", fake_location):
            response = _rpc(
                client,
                "tools/call",
                {"name": "whoami_caller", "arguments": {}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["ip"] == "203.0.113.9"
        assert payload["geo"]["country_code"] == "US"
        # The honesty contract. An earlier version of this note asserted the
        # address is "normally the AI provider's infrastructure rather than the
        # user's own machine" — which is false for the client `claude mcp add`
        # configures. Claude Code is a local CLI, so it connects from the user's
        # own network and the tool returns their real IP. Calling it against
        # production returned a Korea Telecom address, not a datacenter.
        #
        # So the contract is no longer "it isn't yours" but "it depends, and
        # this server cannot tell". Both branches must stay named, or the note
        # is wrong for half its callers again.
        note = payload["note"]
        assert "own machine" in note  # the local-client case
        assert "datacenter" in note  # the hosted-client case
        assert "cannot tell" in note  # the server does not know which
        assert "in a browser" in note  # where to get a definitive answer
        # Asserted on meaning rather than a hostname substring: `"host" in url`
        # is the shape CodeQL flags as bypassable URL sanitisation
        # (py/incomplete-url-substring-sanitization), and a test should not
        # model a check we would never write in production.


def test_whoami_caller_grades_the_callers_fix_the_same_way():
    async def fake_location(ip):
        return {
            "ip": ip,
            "country_code": "US",
            "country_name": "United States",
            "country_source": "located",
            "city_name": "",
            "lat": 37.751,
            "lon": -97.822,
            "accuracy_km": 1000,
            "time_zone": "America/Chicago",
            "precision": "country",
        }

    with TestClient(app, client=("203.0.113.9", 41234)) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.lookup_location", fake_location):
            response = _rpc(
                client, "tools/call", {"name": "whoami_caller", "arguments": {}}
            )
        geo = response.json()["result"]["structuredContent"]["geo"]
    assert geo["precision"] == "country"
    assert geo["country_code"] == "US"
    assert geo["lat"] is None and geo["lon"] is None and geo["time_zone"] is None


def test_whoami_caller_reports_unavailable_when_the_peer_is_unknown():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.client_ip_from_scope", return_value="unknown"):
            response = _rpc(
                client,
                "tools/call",
                {"name": "whoami_caller", "arguments": {}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"] == "Caller address unavailable"


def test_whoami_caller_reports_an_error_when_location_lookup_fails():
    async def boom(ip):
        raise RuntimeError("geoip database unavailable")

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.lookup_location", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "whoami_caller", "arguments": {}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"] == "Location lookup failed"


SUBDOMAIN_PAYLOAD = {
    "names": [f"h{i}.example.com" for i in range(300)],
    "count": 300,
    "truncated": False,
    "source": "crt.sh",
    "fetched_at": "2026-09-29T00:00:00+00:00",
    "stale": False,
    "error": None,
}


def test_the_subdomains_tool_caps_the_list_and_reports_the_true_total():
    """Context budget is the binding constraint: nasa.gov's 2,585 names are
    roughly 20,000 tokens."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch(
            "mcp_server.get_subdomains",
            new_callable=AsyncMock,
            return_value=SUBDOMAIN_PAYLOAD,
        ):
            response = _rpc(
                client,
                "tools/call",
                {"name": "subdomains", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert len(payload["names"]) == 200
        assert payload["count"] == 300
        assert payload["truncated"] is True


def test_subdomains_limit_is_honoured_and_clamped():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch(
            "mcp_server.get_subdomains",
            new_callable=AsyncMock,
            return_value=SUBDOMAIN_PAYLOAD,
        ):
            small = _rpc(
                client,
                "tools/call",
                {
                    "name": "subdomains",
                    "arguments": {"domain": "example.com", "limit": 5},
                },
            ).json()["result"]["structuredContent"]
            huge = _rpc(
                client,
                "tools/call",
                {
                    "name": "subdomains",
                    "arguments": {"domain": "example.com", "limit": 99999},
                },
            ).json()["result"]["structuredContent"]
        assert len(small["names"]) == 5
        assert len(huge["names"]) == 300  # clamped to the ceiling, then to what exists


def test_a_subdomains_source_failure_is_an_error_never_an_empty_list():
    """The most important test here. A model reading names=[] would tell the
    user the domain has no subdomains — a confident falsehood built from an
    outage. Mirrors dns_records refusing to answer an unsupported type."""
    failed = dict(
        SUBDOMAIN_PAYLOAD, names=[], count=0, error="source request timed out"
    )
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch(
            "mcp_server.get_subdomains", new_callable=AsyncMock, return_value=failed
        ):
            response = _rpc(
                client,
                "tools/call",
                {"name": "subdomains", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"]
        assert "names" not in payload or payload["names"] == []


def test_subdomains_tool_reports_staleness_so_a_model_can_qualify_its_answer():
    stale = dict(SUBDOMAIN_PAYLOAD, stale=True)
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch(
            "mcp_server.get_subdomains", new_callable=AsyncMock, return_value=stale
        ):
            response = _rpc(
                client,
                "tools/call",
                {"name": "subdomains", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["stale"] is True
        assert payload["fetched_at"]


def test_lookup_description_says_whose_registration_a_subdomain_gets():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        tools = _rpc(client, "tools/list").json()["result"]["tools"]
    description = next(t["description"] for t in tools if t["name"] == "lookup")
    assert "registrable_domain" in description
    assert "registered: false" in description


def test_lookup_answers_a_subdomain_with_the_registration_covering_it():
    asked = []

    def rdap(target):
        asked.append(target)
        return {"source": "rdap", "name": target, "registrar": "Example Registrar"}

    with TestClient(app) as client, patch("lookup.lookup_rdap", rdap):
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = _rpc(
            client,
            "tools/call",
            {"name": "lookup", "arguments": {"target": "www.example.com"}},
        )
    result = response.json()["result"]
    assert result["isError"] is False
    registration = result["structuredContent"]["registration"]
    assert asked == ["example.com"]
    assert registration["registrar"] == "Example Registrar"
    assert registration["registrable_domain"] == "example.com"
    assert registration["queried_name"] == "www.example.com"
    assert "registered" not in registration


class TestRegistrationShaping:
    """`not registered` is an answer, not a failure, and the distinction costs
    more here than in the browser: handed `error`, a model reports that the
    lookup broke and suggests retrying; handed `registered: false`, it can say
    the registrable domain has no registration. A subdomain gets the covering
    domain's labelled record instead.
    """

    def test_a_real_failure_is_still_an_error(self):
        from mcp_server import compact_registration

        out = compact_registration({"error": "WHOIS lookup timed out"})
        assert out == {"error": "WHOIS lookup timed out"}

    def test_not_registered_is_not_reported_as_an_error(self):
        from mcp_server import compact_registration

        out = compact_registration({"error": "not registered", "name": "x.example.com"})
        assert "error" not in out
        assert out["registered"] is False
        assert out["name"] == "x.example.com"

    def test_a_successful_record_is_unchanged(self):
        from mcp_server import compact_registration

        out = compact_registration({"source": "rdap", "registrar": "Example Registrar"})
        assert out["registrar"] == "Example Registrar"
        assert "registered" not in out
        assert "error" not in out

    def test_age_days_counts_whole_days_since_created(self):
        from mcp_server import compact_registration

        created = _days_ago(25)
        out = compact_registration({"source": "rdap", "created": created})
        assert out["age_days"] == 25
        assert out["created"] == created.isoformat()

    def test_age_days_reads_an_iso_string_and_is_null_otherwise(self):
        """The WHOIS fallback can hand back a string; one that is not ISO 8601
        has no age rather than a guessed one."""
        from mcp_server import compact_registration

        iso = _days_ago(3).isoformat()
        out = compact_registration({"source": "whois", "created": iso})
        assert out["age_days"] == 3
        for created in ("before Aug-1996", None):
            out = compact_registration({"source": "whois", "created": created})
            assert out["age_days"] is None

    def test_a_record_names_the_registration_that_answered(self):
        from mcp_server import compact_registration

        out = compact_registration(
            {
                "source": "rdap",
                "name": "example.com",
                "registrar": "Example Registrar",
                "queried_name": "www.example.com",
                "registrable_domain": "example.com",
            }
        )
        assert out["registrable_domain"] == "example.com"
        assert out["queried_name"] == "www.example.com"
        assert out["registrar"] == "Example Registrar"
        assert "registered" not in out

    def test_not_registered_names_the_registrable_domain_that_is_missing(self):
        from mcp_server import compact_registration

        out = compact_registration(
            {
                "error": "not registered",
                "queried_name": "www.nosuch-name.com",
                "registrable_domain": "nosuch-name.com",
            }
        )
        assert out["registered"] is False
        assert out["registrable_domain"] == "nosuch-name.com"
        assert out["queried_name"] == "www.nosuch-name.com"
        assert "error" not in out

    def test_a_failure_keeps_the_labels_too(self):
        from mcp_server import compact_registration

        out = compact_registration(
            {
                "error": "WHOIS lookup timed out",
                "queried_name": "www.example.com",
                "registrable_domain": "example.com",
            }
        )
        assert out["error"] == "WHOIS lookup timed out"
        assert out["registrable_domain"] == "example.com"

    def test_a_thin_record_says_so(self):
        from mcp_server import compact_registration

        thin = {
            "source": "whois",
            "name": "admin.ch",
            "thin": True,
            "queried_name": "www.admin.ch",
            "registrable_domain": "admin.ch",
        }
        out = compact_registration(thin)
        assert out["thin"] is True
        assert out["note"] == "WHOIS answered with no details beyond the name"
        assert out["name"] == "admin.ch"
        assert out["registrar"] is None
        assert out["queried_name"] == "www.admin.ch"
        assert out["registrable_domain"] == "admin.ch"
        assert "error" not in out and "registered" not in out

    def test_status_is_explained_beside_the_raw_list(self):
        from mcp_server import compact_registration

        line = "clientHold https://icann.org/epp#clientHold"
        out = compact_registration(
            {"source": "whois", "registrar": "x", "status": [line, "connect"]}
        )
        assert out["status"] == [line, "connect"]
        assert out["status_explained"] == [
            {
                "code": "clientHold",
                "meaning": eppstatus.STATUS_MEANINGS["clientHold"][0],
                "severity": "danger",
            },
            {"code": "connect", "meaning": None, "severity": None},
        ]

    def test_a_domain_without_statuses_gets_an_empty_list(self):
        from mcp_server import compact_registration

        out = compact_registration({"source": "rdap", "registrar": "Example Registrar"})
        assert out["status"] == [] and out["status_explained"] == []

    def test_an_ip_allocation_gets_no_epp_gloss(self):
        from mcp_server import compact_registration

        out = compact_registration(
            {"source": "rdap", "name": "GOGL", "rir": "arin", "status": ["active"]}
        )
        assert out["status"] == ["active"]
        assert "status_explained" not in out

    def test_the_lookup_description_explains_the_gloss(self):
        import mcp_server

        doc = " ".join(mcp_server.lookup.__doc__.split())
        assert "status_explained" in doc
        assert "clientHold" in doc and "RFC 8056" in doc
