"""Unit tests for the extracted lookup orchestration."""

import pytest

import lookup


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
