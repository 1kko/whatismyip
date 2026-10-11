"""Unit tests for the extracted lookup orchestration."""

from types import SimpleNamespace

import pytest

import lookup
from config import WHOIS_CACHE_ERROR_TTL
from rdap import NOT_REGISTERED


def test_normalize_lookup_target_strips_scheme_and_path():
    assert lookup.normalize_lookup_target("https://example.com/a?b#c") == "example.com"
    assert lookup.normalize_lookup_target("  example.com  ") == "example.com"


def test_normalize_lookup_target_is_idempotent():
    # get_ip_info normalizes once (so the request log records the resolved
    # target) and gather() normalizes again (so it stays self-contained for
    # its MCP callers). That double call only stays correct if a second pass
    # is a no-op, so pin it here rather than leaving it as an assumption a
    # future reader might "clean up".
    for raw in (
        "https://example.com/a?b#c",
        "  example.com  ",
        "8.8.8.8",
        "google.com/foo",
        "http://[2001:db8::1]:8443/path",
        "[[2001:db8::1]",
        "",
        "NASA.GOV.",
        "münchen.de",
        "straße.de",
        "_dmarc.example.com",
        "８。８。８。８",
        "８.８",
        "nasa.gov。",
        "münchen．de",
        "nasa.gov｡",
        "example.com..",
        "a..b.com",
    ):
        once = lookup.normalize_lookup_target(raw)
        twice = lookup.normalize_lookup_target(once)
        assert once == twice


@pytest.mark.parametrize(
    "typed, canonical",
    [
        ("NASA.GOV.", "nasa.gov"),
        ("Example.COM", "example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("MÜNCHEN.DE", "xn--mnchen-3ya.de"),
        ("straße.de", "xn--strae-oqa.de"),
        ("한국.kr", "xn--3e0b707e.kr"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("8.8.8.8.", "8.8.8.8"),
        ("８。８。８。８", "8.8.8.8"),
        ("2001:DB8::1", "2001:db8::1"),
        ("nasa.gov。", "nasa.gov"),
        ("münchen．de", "xn--mnchen-3ya.de"),
        ("nasa.gov｡", "nasa.gov"),
    ],
)
def test_canonical_hostname_gives_one_spelling(typed, canonical):
    assert lookup.canonical_hostname(typed) == canonical


@pytest.mark.parametrize(
    "typed",
    [
        "a..b.com",
        "A..B.COM",
        "example.com..",
        "a" * 64 + ".com",
        "nasa.gov.。",
    ],
)
def test_canonical_hostname_leaves_an_invalid_label_alone(typed):
    assert lookup.canonical_hostname(typed) == typed
    assert lookup.classify_target(typed) == "invalid"


def test_normalize_lookup_target_applies_the_canonical_spelling():
    assert lookup.normalize_lookup_target("https://NASA.GOV./path?q=1") == "nasa.gov"
    assert lookup.normalize_lookup_target("straße.de") == "xn--strae-oqa.de"
    assert lookup.normalize_lookup_target("８。８。８。８") == "8.8.8.8"
    assert lookup.normalize_lookup_target("８.８") == "8.8"
    assert lookup.classify_target(lookup.normalize_lookup_target("８.８")) == "invalid"
    assert lookup.normalize_lookup_target("[2001:DB8::1]:8443") == "2001:db8::1"


def test_is_safe_ip_rejects_private_and_garbage():
    assert lookup.is_safe_ip("8.8.8.8") is True
    assert lookup.is_safe_ip("10.0.0.1") is False
    assert lookup.is_safe_ip("127.0.0.1") is False
    assert lookup.is_safe_ip("not-an-ip") is False


@pytest.mark.asyncio
async def test_gather_rejects_private_ip_target(monkeypatch):
    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: False)
    monkeypatch.setattr(lookup.domain_manager, "is_ipv4", lambda d: True)
    with pytest.raises(lookup.PrivateAddressError):
        await lookup.gather("10.0.0.1")


@pytest.mark.asyncio
async def test_gather_returns_no_map_keys(monkeypatch):
    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: False)
    monkeypatch.setattr(lookup.domain_manager, "is_ipv4", lambda d: True)
    monkeypatch.setattr(
        lookup.domain_manager, "perform_reverse_lookup", lambda ip: "dns.google"
    )
    monkeypatch.setattr(lookup.domain_manager, "get_records", lambda *a, **k: {"a": []})
    monkeypatch.setattr(
        lookup.geo_ip_manager,
        "fetch_location",
        lambda ip: {"ip": ip, "country_code": "US"},
    )

    async def fake_whois(target):
        return {"source": "rdap", "name": target}

    monkeypatch.setattr(lookup, "lookup_whois", fake_whois)

    result = await lookup.gather("8.8.8.8")
    assert result["resolved_ip"] == "8.8.8.8"
    assert result["reverse_dns"] == "dns.google"
    assert result["location"]["reverse_dns"] == "dns.google"
    for forbidden in ("map", "distance_km", "origin"):
        assert forbidden not in result


class TestRegistrationTarget:
    """Registration uses one labelled record for a domain and its hosts."""

    RECORD = {"source": "rdap", "registrar": "Example Registrar"}

    @pytest.fixture
    def rdap(self, monkeypatch):
        asked = []

        def fake(target):
            asked.append(target)
            return {**self.RECORD, "name": target}

        monkeypatch.setattr(lookup, "lookup_rdap", fake)
        return asked

    @pytest.fixture
    def port43(self, monkeypatch):
        asked = []

        def fake(target, **kwargs):
            asked.append(target)
            return {"domain_name": target, "registrar": "Example Registrar"}

        monkeypatch.setattr(lookup.whois, "whois", fake)
        return asked

    def test_registration_target_floors_a_hostname_on_its_registrable_domain(self):
        assert lookup.registration_target("www.example.com") == "example.com"
        assert lookup.registration_target("a.b.example.co.uk") == "example.co.uk"
        assert lookup.registration_target("example.com") == "example.com"
        assert lookup.registration_target("co.uk") == "co.uk"
        assert lookup.registration_target("8.8.8.8") == "8.8.8.8"
        assert lookup.registration_target("2001:db8::1") == "2001:db8::1"

    @pytest.mark.asyncio
    async def test_a_hostname_is_asked_as_its_registrable_domain_and_labelled(
        self, rdap
    ):
        out = await lookup.lookup_whois("www.example.com")

        assert rdap == ["example.com"]
        assert out["name"] == "example.com"
        assert out["registrar"] == "Example Registrar"
        assert out["queried_name"] == "www.example.com"
        assert out["registrable_domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_the_cache_holds_the_bare_record_under_the_registrable_domain(
        self, rdap
    ):
        await lookup.lookup_whois("www.example.com")

        assert lookup._whois_cache.get("www.example.com") is None
        cached = lookup._whois_cache.get("example.com")
        assert cached["name"] == "example.com"
        assert "queried_name" not in cached
        assert "registrable_domain" not in cached

    @pytest.mark.asyncio
    async def test_variants_share_one_lookup_and_each_gets_its_own_label(self, rdap):
        first = await lookup.lookup_whois("www.example.com")
        second = await lookup.lookup_whois("api.example.com")
        third = await lookup.lookup_whois("example.com")

        assert rdap == ["example.com"]
        assert [r["queried_name"] for r in (first, second, third)] == [
            "www.example.com",
            "api.example.com",
            "example.com",
        ]
        assert {r["registrable_domain"] for r in (first, second, third)} == {
            "example.com"
        }

    @pytest.mark.asyncio
    async def test_the_registrable_domain_and_a_public_suffix_are_asked_as_is(
        self, rdap
    ):
        own = await lookup.lookup_whois("example.com")
        suffix = await lookup.lookup_whois("co.uk")

        assert rdap == ["example.com", "co.uk"]
        assert own["queried_name"] == own["registrable_domain"] == "example.com"
        assert suffix["queried_name"] == suffix["registrable_domain"] == "co.uk"

    @pytest.mark.asyncio
    async def test_case_and_a_trailing_dot_do_not_split_the_cache(self, rdap):
        out = await lookup.lookup_whois("WWW.Example.COM.")

        assert rdap == ["example.com"]
        assert out["queried_name"] == "www.example.com."
        assert out["registrable_domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_an_unregistered_registrable_domain_is_not_registered(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            lookup, "lookup_rdap", lambda target: {"error": NOT_REGISTERED}
        )

        out = await lookup.lookup_whois("www.nosuch-name.com")

        assert out == {
            "error": NOT_REGISTERED,
            "queried_name": "www.nosuch-name.com",
            "registrable_domain": "nosuch-name.com",
        }

    @pytest.mark.asyncio
    async def test_a_private_suffix_floors_on_the_operators_domain(self, rdap):
        out = await lookup.lookup_whois("foo.github.io")

        assert rdap == ["github.io"]
        assert out["registrable_domain"] == "github.io"
        assert out["queried_name"] == "foo.github.io"

    @pytest.mark.asyncio
    async def test_port43_fallback_asks_for_the_registrable_domain(
        self, monkeypatch, port43
    ):
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: None)

        out = await lookup.lookup_whois("www.naver.co.kr")

        assert port43 == ["naver.co.kr"]
        assert out["source"] == "whois"
        assert out["name"] == "naver.co.kr"
        assert out["queried_name"] == "www.naver.co.kr"
        assert out["registrable_domain"] == "naver.co.kr"

    @pytest.mark.asyncio
    async def test_a_failed_lookup_is_shared_by_the_names_under_it(self, monkeypatch):
        asked = []
        now = [1000.0]

        def down(target):
            asked.append(target)
            return None

        monkeypatch.setattr(lookup, "lookup_rdap", down)
        monkeypatch.setattr(lookup, "time", SimpleNamespace(time=lambda: now[0]))
        first = await lookup.lookup_whois("www.example.com")
        second = await lookup.lookup_whois("api.example.com")

        assert asked == ["example.com"]
        assert first["error"] == second["error"] == "WHOIS lookup failed"
        assert second["queried_name"] == "api.example.com"
        assert second["registrable_domain"] == "example.com"

        now[0] += WHOIS_CACHE_ERROR_TTL + 1
        await lookup.lookup_whois("mail.example.com")
        assert asked == ["example.com", "example.com"]

    @pytest.mark.asyncio
    async def test_a_thin_record_uses_the_short_retry_ttl(self, monkeypatch):
        asked = []
        now = [1000.0]

        def thin(target):
            asked.append(target)
            return {"source": "whois", "name": target, "thin": True}

        monkeypatch.setattr(lookup, "lookup_rdap", thin)
        monkeypatch.setattr(lookup, "time", SimpleNamespace(time=lambda: now[0]))

        first = await lookup.lookup_whois("www.example.com")
        second = await lookup.lookup_whois("api.example.com")
        assert asked == ["example.com"]
        assert first["thin"] is True and second["thin"] is True

        now[0] += WHOIS_CACHE_ERROR_TTL + 1
        await lookup.lookup_whois("mail.example.com")
        assert asked == ["example.com", "example.com"]

    @pytest.mark.asyncio
    async def test_a_suffix_list_that_cannot_load_asks_about_the_name_as_given(
        self, rdap, monkeypatch
    ):
        def unloadable(domain):
            raise TypeError("'NoneType' object is not subscriptable")

        monkeypatch.setattr(lookup.domain_manager, "registrable_domain", unloadable)

        out = await lookup.lookup_whois("www.example.com")

        assert rdap == ["www.example.com"]
        assert out["queried_name"] == out["registrable_domain"] == "www.example.com"

    @pytest.mark.asyncio
    async def test_an_address_is_asked_as_itself_with_no_labels(self, rdap):
        out = await lookup.lookup_whois("8.8.8.8")

        assert rdap == ["8.8.8.8"]
        assert "queried_name" not in out
        assert "registrable_domain" not in out
        assert lookup.cached_whois("8.8.8.8") == out

    @pytest.mark.asyncio
    async def test_gather_carries_the_labels(self, rdap):
        result = await lookup.gather("www.example.com", legs={"whois"})

        assert rdap == ["example.com"]
        assert result["whois"]["queried_name"] == "www.example.com"
        assert result["whois"]["registrable_domain"] == "example.com"


@pytest.mark.asyncio
async def test_lookup_location_grades_the_coordinates(monkeypatch):
    """Every reader of a location -- gather() for the page, the JSON and
    ?fields=, the self page, the MCP tools -- gets it through here, so this is
    where the coordinates get their grade. GeoLite2 gives a city record a
    20-200 km radius and a country centroid 1000 km (8.8.8.8: 37.751,
    -97.822); a block it has no coordinates for (1.1.1.1) gets none."""
    records = {
        "89.160.20.112": {"lat": 59.31, "lon": 14.1027, "accuracy_km": 50},
        "8.8.8.8": {"lat": 37.751, "lon": -97.822, "accuracy_km": 1000},
        "1.1.1.1": {"lat": None, "lon": None, "accuracy_km": None},
    }
    monkeypatch.setattr(
        lookup.geo_ip_manager,
        "fetch_location",
        lambda ip: {"ip": ip, "country_code": "XX", **records[ip]},
    )
    assert (await lookup.lookup_location("89.160.20.112"))["precision"] == "city"
    assert (await lookup.lookup_location("8.8.8.8"))["precision"] == "country"
    assert (await lookup.lookup_location("1.1.1.1"))["precision"] is None


@pytest.mark.asyncio
async def test_gather_carries_the_precision_and_country_source(monkeypatch):
    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: False)
    monkeypatch.setattr(lookup.domain_manager, "is_ipv4", lambda d: True)
    monkeypatch.setattr(
        lookup.domain_manager, "perform_reverse_lookup", lambda ip: None
    )
    monkeypatch.setattr(lookup.domain_manager, "get_records", lambda *a, **k: {})
    monkeypatch.setattr(
        lookup.geo_ip_manager,
        "fetch_location",
        lambda ip: {
            "ip": ip,
            "country_code": "US",
            "country_name": "United States",
            "country_source": "located",
            "lat": 37.751,
            "lon": -97.822,
            "accuracy_km": 1000,
        },
    )

    async def fake_whois(target):
        return {"source": "rdap", "name": target}

    monkeypatch.setattr(lookup, "lookup_whois", fake_whois)

    result = await lookup.gather("8.8.8.8")
    assert result["location"]["precision"] == "country"
    assert result["location"]["country_source"] == "located"
    # The numbers are untouched: only a grade was added.
    assert (result["location"]["lat"], result["location"]["accuracy_km"]) == (
        37.751,
        1000,
    )
