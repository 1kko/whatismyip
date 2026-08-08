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
        "",
    ):
        once = lookup.normalize_lookup_target(raw)
        twice = lookup.normalize_lookup_target(once)
        assert once == twice


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
