"""RDAP normalisation and the RDAP-first / WHOIS-fallback routing.

All pure and deterministic: no network. Live RDAP shapes are captured as
fixtures so the mapping is pinned even when the registries are unreachable.
"""

import asyncio
import datetime

import pytest

import main
import rdap

UTC = datetime.timezone.utc

# A trimmed real whoisit.domain() result (google.com), enough to pin the mapping.
RDAP_DOMAIN = {
    "name": "google.com",
    "handle": "2138514_DOMAIN_COM-VRSN",
    "status": ["client transfer prohibited", "client delete prohibited"],
    "nameservers": ["ns1.google.com", "ns2.google.com"],
    "registration_date": datetime.datetime(1997, 9, 15, 7, 0, tzinfo=UTC),
    "last_changed_date": datetime.datetime(2024, 8, 2, 2, 17, tzinfo=UTC),
    "expiration_date": datetime.datetime(2028, 9, 13, 7, 0, tzinfo=UTC),
    "dnssec": False,
    "whois_server": "whois.markmonitor.com",
    "url": "https://rdap.markmonitor.com/rdap/domain/google.com",
    "entities": {
        "registrar": [{"name": "Markmonitor Inc.", "handle": "292"}],
        "registrant": [{"name": "Google LLC"}],
        "abuse": [{"name": "Markmonitor", "email": "abuse@example.com"}],
    },
}

# A trimmed real whoisit.ip() result (8.8.8.8).
RDAP_IP = {
    "name": "GOGL",
    "handle": "NET-8-8-8-0-2",
    "network": "8.8.8.0/24",
    "country": "",
    "rir": "arin",
    "registration_date": datetime.datetime(2023, 12, 28, 17, 24, tzinfo=UTC),
    "last_changed_date": datetime.datetime(2023, 12, 28, 17, 24, tzinfo=UTC),
    "entities": {"registrant": [{"name": "Google LLC"}]},
}


class TestIsIp:
    def test_ipv4_and_ipv6_are_ips(self):
        assert rdap.is_ip("8.8.8.8")
        assert rdap.is_ip("2001:4860:4860::8888")

    def test_domain_is_not_an_ip(self):
        assert not rdap.is_ip("google.com")
        assert not rdap.is_ip("")


class TestNormalizeRdapDomain:
    def test_maps_entities_dates_and_lists(self):
        out = rdap._normalize_rdap_domain(RDAP_DOMAIN, "google.com")
        assert out["source"] == "rdap"
        assert out["name"] == "google.com"
        assert out["registrar"] == "Markmonitor Inc."
        assert out["registrant"] == "Google LLC"
        assert out["abuse_email"] == "abuse@example.com"
        assert out["name_servers"] == ["ns1.google.com", "ns2.google.com"]
        assert out["created"] == datetime.datetime(1997, 9, 15, 7, 0, tzinfo=UTC)
        assert out["expires"] == datetime.datetime(2028, 9, 13, 7, 0, tzinfo=UTC)
        assert out["dnssec"] is False

    def test_missing_entities_do_not_raise(self):
        out = rdap._normalize_rdap_domain({"name": "x.com"}, "x.com")
        assert out["registrar"] is None
        assert out["status"] == []
        assert out["name_servers"] == []


class TestNormalizeRdapIp:
    def test_maps_network_and_registrant(self):
        out = rdap._normalize_rdap_ip(RDAP_IP, "8.8.8.8")
        assert out["source"] == "rdap"
        assert out["network"] == "8.8.8.0/24"
        assert out["registrant"] == "Google LLC"
        assert out["rir"] == "arin"
        assert out["country"] is None  # empty string collapses to None
        assert "name_servers" not in out  # IP records have no NS


class TestNormalizeWhois:
    def test_folds_lists_and_keeps_datetimes(self):
        raw = {
            "domain_name": ["NAVER.CO.KR", "naver.co.kr"],
            "registrar": "Korea Registry",
            "org": "NAVER Corp",
            "name_servers": ["NS1.NAVER.COM", "NS1.NAVER.COM", "NS2.NAVER.COM"],
            "creation_date": datetime.datetime(2003, 6, 2, 0, 0, tzinfo=UTC),
            "expiration_date": [datetime.datetime(2027, 6, 2, 0, 0, tzinfo=UTC)],
            "emails": ["abuse@navercorp.com"],
        }
        out = rdap.normalize_whois(raw, "naver.co.kr")
        assert out["source"] == "whois"
        assert out["name"] == "NAVER.CO.KR"
        assert out["registrant"] == "NAVER Corp"
        assert out["name_servers"] == ["ns1.naver.com", "ns2.naver.com"]  # deduped
        assert out["created"] == datetime.datetime(2003, 6, 2, 0, 0, tzinfo=UTC)
        assert out["expires"] == datetime.datetime(2027, 6, 2, 0, 0, tzinfo=UTC)
        assert out["abuse_email"] == "abuse@navercorp.com"

    def test_error_and_empty_pass_through(self):
        assert rdap.normalize_whois({"error": "boom"}, "x")["error"] == "boom"
        assert rdap.normalize_whois(None, "x")["error"]
        assert rdap.normalize_whois({}, "x")["error"]


class TestLookupWhoisRouting:
    """lookup_whois() must prefer RDAP and only pay for WHOIS when RDAP can't
    answer. These patch the two lookups so nothing touches the network."""

    def setup_method(self):
        main._whois_cache._data.clear()

    def test_rdap_hit_skips_whois(self, monkeypatch):
        canonical = {"source": "rdap", "name": "google.com"}
        monkeypatch.setattr(main, "lookup_rdap", lambda target: canonical)

        def boom(*a, **k):
            raise AssertionError("WHOIS must not run when RDAP answers")

        monkeypatch.setattr(main.whois, "whois", boom)
        out = asyncio.run(main.lookup_whois("google.com"))
        assert out == canonical

    def test_rdap_miss_falls_back_to_whois(self, monkeypatch):
        monkeypatch.setattr(main, "lookup_rdap", lambda target: None)
        monkeypatch.setattr(
            main.whois,
            "whois",
            lambda target, quiet=True: {"domain_name": "naver.co.kr"},
        )
        out = asyncio.run(main.lookup_whois("naver.co.kr"))
        assert out["source"] == "whois"
        assert out["name"] == "naver.co.kr"

    def test_result_is_cached(self, monkeypatch):
        calls = {"n": 0}

        def once(target):
            calls["n"] += 1
            return {"source": "rdap", "name": target}

        monkeypatch.setattr(main, "lookup_rdap", once)
        asyncio.run(main.lookup_whois("example.com"))
        asyncio.run(main.lookup_whois("example.com"))
        assert calls["n"] == 1  # second call served from cache


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
