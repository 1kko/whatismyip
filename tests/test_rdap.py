"""RDAP normalisation and the RDAP-first / WHOIS-fallback routing.

All pure and deterministic: no network. Live RDAP shapes are captured as
fixtures so the mapping is pinned even when the registries are unreachable.

whoisit's bootstrap registry is module-global state. Synthetic registries are
cleared before and after each test that loads one.
"""

import asyncio
import copy
import datetime
import importlib
import json
import threading
import time

import pytest
import whoisit

import lookup
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

KRNIC_RDAP_JSON = {
    "objectClassName": "domain",
    "ldhName": "kisa.or.kr",
    "rdapConformance": ["rdap_level_0", "redacted", "jscontact"],
    "status": [
        "server delete prohibited",
        "server transfer prohibited",
        "server update prohibited",
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1996-07-19T15:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-05-09T08:31:52Z"},
        {"eventAction": "expiration", "eventDate": "9999-12-30T15:00:00Z"},
    ],
    "nameservers": [
        {"objectClassName": "nameserver", "ldhName": "rhea.kisa.or.kr"},
        {"objectClassName": "nameserver", "ldhName": "center.kisa.or.kr"},
    ],
    "secureDNS": {"delegationSigned": True},
    "port43": "whois.kisa.or.kr",
    "entities": [
        {
            "objectClassName": "entity",
            "roles": ["registrant"],
            "jscontact_card": {
                "name": {"full": "Korea Internet &amp; Security Agency"},
                "organizations": {
                    "org": {"name": "Korea Internet &amp; Security Agency"}
                },
            },
        },
        {
            "objectClassName": "entity",
            "roles": ["registrar"],
            "jscontact_card": {
                "name": {"full": "KISA"},
                "organizations": {"org": {"name": "KISA"}},
            },
        },
    ],
}

RDAP_DOMAIN_JSCONTACT = {
    "name": "kisa.or.kr",
    "handle": "",
    "status": list(KRNIC_RDAP_JSON["status"]),
    "nameservers": ["rhea.kisa.or.kr", "center.kisa.or.kr"],
    "registration_date": datetime.datetime(1996, 7, 19, 15, 0, tzinfo=UTC),
    "last_changed_date": datetime.datetime(2025, 5, 9, 8, 31, 52, tzinfo=UTC),
    "expiration_date": datetime.datetime(9999, 12, 30, 15, 0, tzinfo=UTC),
    "dnssec": True,
    "whois_server": "whois.kisa.or.kr",
    "url": "",
    "entities": {
        "registrant": [{"type": "entity"}],
        "registrar": [{"type": "entity"}],
    },
    "raw": KRNIC_RDAP_JSON,
}


def _registry_json(timestamp: int) -> str:
    return json.dumps(
        {
            "timestamp": timestamp,
            "asn": {"services": [[["1-10"], ["https://rdap.example.net/"]]]},
            "dns": {
                "services": [
                    [["com"], ["https://rdap.verisign.com/com/v1/"]],
                    [["kr"], ["https://rdap.nic.or.kr/"]],
                ]
            },
            "ipv4": {"services": [[["192.0.2.0/24"], ["https://rdap.example.net/"]]]},
            "ipv6": {"services": [[["2001:db8::/32"], ["https://rdap.example.net/"]]]},
            "object": {"services": [[["EXAMPLE"], ["https://rdap.example.net/"]]]},
        }
    )


@pytest.fixture
def clean_whoisit():
    whoisit.clear_bootstrapping()
    yield
    whoisit.clear_bootstrapping()


@pytest.fixture
def stale_registry(clean_whoisit):
    whoisit.load_bootstrap_data(_registry_json(0), overrides=True)


def _whoisit_like_bootstrap(calls: list, fresh_timestamp: int):
    def fake(**kwargs):
        calls.append(dict(kwargs))
        if whoisit.is_bootstrapped():
            return
        whoisit.load_bootstrap_data(
            _registry_json(fresh_timestamp), overrides=bool(kwargs.get("overrides"))
        )

    return fake


def _half_loaded(calls: list):
    def fake(**kwargs):
        calls.append(dict(kwargs))
        broken = json.loads(_registry_json(int(time.time())))
        broken["dns"] = {"services": []}
        whoisit.load_bootstrap_data(json.dumps(broken), overrides=True)

    return fake


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

    def test_a_record_with_nothing_beyond_the_name_is_thin(self):
        refusal = {
            "domain_name": None,
            "registrant_name": None,
            "registrant_address": None,
            "registrar": None,
            "creation_date": None,
            "dnssec": None,
            "tech-c": None,
            "name_servers": None,
        }
        out = rdap.normalize_whois(refusal, "admin.ch")
        assert out["source"] == "whois"
        assert out["name"] == "admin.ch"
        assert out["thin"] is True
        assert "error" not in out
        assert "thin" not in rdap.CANONICAL_FIELDS

    def test_a_record_with_any_detail_is_not_thin(self):
        named = rdap.normalize_whois(
            {"domain_name": "example.ch", "registrar": "cyon AG"}, "example.ch"
        )
        assert "thin" not in named
        dated = rdap.normalize_whois(
            {"creation_date": datetime.datetime(2001, 1, 1, tzinfo=UTC)}, "x.ch"
        )
        assert "thin" not in dated


class TestLookupWhoisRouting:
    """lookup_whois() must prefer RDAP and only pay for WHOIS when RDAP can't
    answer. These patch the two lookups so nothing touches the network."""

    def test_rdap_hit_skips_whois(self, monkeypatch):
        canonical = {"source": "rdap", "name": "google.com"}
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: canonical)

        def boom(*a, **k):
            raise AssertionError("WHOIS must not run when RDAP answers")

        monkeypatch.setattr(lookup.whois, "whois", boom)
        out = asyncio.run(main.lookup_whois("google.com"))
        assert out == {
            **canonical,
            "queried_name": "google.com",
            "registrable_domain": "google.com",
        }

    def test_rdap_miss_falls_back_to_whois(self, monkeypatch):
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: None)
        monkeypatch.setattr(
            lookup.whois,
            "whois",
            lambda target, quiet=True, timeout=None: {"domain_name": "naver.co.kr"},
        )
        out = asyncio.run(main.lookup_whois("naver.co.kr"))
        assert out["source"] == "whois"
        assert out["name"] == "naver.co.kr"

    def test_result_is_cached(self, monkeypatch):
        calls = {"n": 0}

        def once(target):
            calls["n"] += 1
            return {"source": "rdap", "name": target}

        monkeypatch.setattr(lookup, "lookup_rdap", once)
        asyncio.run(main.lookup_whois("example.com"))
        asyncio.run(main.lookup_whois("example.com"))
        assert calls["n"] == 1  # second call served from cache

    def test_a_port43_refusal_reaches_the_api_as_a_thin_record(self, monkeypatch):
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: None)
        monkeypatch.setattr(
            lookup.whois,
            "whois",
            lambda target, quiet=True, timeout=None: {
                "domain_name": None,
                "registrar": None,
                "name_servers": None,
            },
        )
        out = asyncio.run(main.lookup_whois("admin.ch"))
        assert out["source"] == "whois"
        assert out["thin"] is True
        assert "error" not in out


class TestRdapOverrides:
    def test_the_table_routes_tlds_iana_omits(self, stale_registry):
        assert rdap._rdap_host("admin.ch", "domain") == "rdap.nic.ch"
        assert rdap._rdap_host("github.io", "domain") == (
            "rdap.identitydigital.services"
        )
        assert rdap._rdap_host("example.de", "domain") == "rdap.denic.de"
        assert rdap._rdap_host("example.com", "domain") == "rdap.verisign.com"
        assert rdap._rdap_host("kisa.or.kr", "domain") == "rdap.nic.or.kr"

    def test_without_the_table_the_same_name_is_unsupported(self, clean_whoisit):
        whoisit.load_bootstrap_data(_registry_json(0), overrides=False)
        with pytest.raises(whoisit.errors.UnsupportedError):
            rdap._rdap_host("admin.ch", "domain")

    def test_a_first_bootstrap_asks_whoisit_for_the_table(
        self, clean_whoisit, monkeypatch
    ):
        calls = []

        def fake_bootstrap(**kwargs):
            calls.append(dict(kwargs))
            whoisit.load_bootstrap_data(_registry_json(int(time.time())), **kwargs)

        monkeypatch.setattr(whoisit, "bootstrap", fake_bootstrap)
        assert rdap.bootstrap_rdap() is True
        assert calls == [{"overrides": True}]
        assert rdap._rdap_host("admin.ch", "domain") == "rdap.nic.ch"

    @pytest.mark.parametrize(
        "target, registrar",
        [("admin.ch", "cyon AG"), ("github.io", "MarkMonitor Inc.")],
    )
    def test_a_name_iana_omits_is_asked_over_rdap_not_port_43(
        self, stale_registry, monkeypatch, target, registrar
    ):
        asked = []

        def fake_domain(name, **kwargs):
            asked.append(name)
            return {
                "name": name,
                "handle": "",
                "status": ["active"],
                "nameservers": [f"ns1.{name}", f"ns2.{name}"],
                "dnssec": True,
                "entities": {"registrar": [{"name": registrar}]},
            }

        def no_port43(*args, **kwargs):
            raise AssertionError("port 43 must not be asked when RDAP answers")

        monkeypatch.setattr(whoisit, "domain", fake_domain)
        monkeypatch.setattr(lookup.whois, "whois", no_port43)
        out = asyncio.run(lookup.lookup_whois(target))
        assert asked == [target]
        assert out["source"] == "rdap"
        assert out["registrar"] == registrar
        assert out["status"] == ["active"]


class TestJscontactCardNames:
    def test_registrar_and_registrant_come_from_the_cards(self):
        out = rdap._normalize_rdap_domain(RDAP_DOMAIN_JSCONTACT, "kisa.or.kr")
        assert out["registrar"] == "KISA"
        assert out["registrant"] == "Korea Internet & Security Agency"
        assert out["dnssec"] is True


class TestBootstrapRefresh:
    def test_a_forced_refresh_replaces_the_loaded_registry(
        self, stale_registry, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(
            whoisit, "bootstrap", _whoisit_like_bootstrap(calls, int(time.time()))
        )
        assert rdap.bootstrap_rdap(force=True) is True
        assert calls == [{"overrides": True}]
        assert not whoisit.bootstrap_is_older_than(7)
        assert rdap._rdap_host("admin.ch", "domain") == "rdap.nic.ch"

    def test_a_failed_refresh_keeps_the_registry_it_had(
        self, stale_registry, monkeypatch
    ):
        def unreachable(**kwargs):
            raise whoisit.errors.BootstrapError("data.iana.org did not answer")

        monkeypatch.setattr(whoisit, "bootstrap", unreachable)
        assert rdap.bootstrap_rdap(force=True) is True
        assert rdap._rdap_host("admin.ch", "domain") == "rdap.nic.ch"
        assert whoisit.bootstrap_is_older_than(7)

    def test_the_daily_job_refetches_a_registry_older_than_a_week(
        self, stale_registry, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(
            whoisit, "bootstrap", _whoisit_like_bootstrap(calls, int(time.time()))
        )
        rdap.refresh_rdap_bootstrap()
        assert calls == [{"overrides": True}]
        assert not whoisit.bootstrap_is_older_than(7)

    def test_the_daily_job_leaves_a_fresh_registry_alone(
        self, clean_whoisit, monkeypatch
    ):
        whoisit.load_bootstrap_data(_registry_json(int(time.time())), overrides=True)
        calls = []
        monkeypatch.setattr(
            whoisit, "bootstrap", _whoisit_like_bootstrap(calls, int(time.time()))
        )
        rdap.refresh_rdap_bootstrap()
        assert calls == []

    def test_a_forced_fetch_with_nothing_loaded_has_nothing_to_restore(
        self, clean_whoisit, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(
            whoisit, "bootstrap", _whoisit_like_bootstrap(calls, int(time.time()))
        )
        assert rdap.bootstrap_rdap(force=True) is True
        assert calls == [{"overrides": True}]

    def test_a_refresh_that_fails_after_loading_keeps_the_old_registry(
        self, stale_registry, monkeypatch
    ):
        monkeypatch.setattr(whoisit, "bootstrap", _half_loaded([]))
        assert rdap.bootstrap_rdap(force=True) is True
        assert rdap._rdap_host("admin.ch", "domain") == "rdap.nic.ch"
        assert rdap._rdap_host("kisa.or.kr", "domain") == "rdap.nic.or.kr"
        assert whoisit.bootstrap_is_older_than(7)

    def test_a_first_fetch_that_fails_after_loading_leaves_nothing_loaded(
        self, clean_whoisit, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(whoisit, "bootstrap", _half_loaded(calls))
        assert rdap.bootstrap_rdap() is False
        assert not whoisit.is_bootstrapped()
        assert rdap.bootstrap_rdap() is False
        assert len(calls) == 2

    def test_a_lookup_during_a_refresh_waits_for_the_new_registry(
        self, stale_registry, monkeypatch
    ):
        fetching, release = threading.Event(), threading.Event()
        fetch = _whoisit_like_bootstrap([], int(time.time()))

        def slow_fetch(**kwargs):
            fetching.set()
            release.wait(5)
            fetch(**kwargs)

        monkeypatch.setattr(whoisit, "bootstrap", slow_fetch)
        monkeypatch.setattr(whoisit, "domain", lambda name, **kw: dict(RDAP_DOMAIN))
        answers = []
        refresh = threading.Thread(target=rdap.bootstrap_rdap, kwargs={"force": True})
        asking = threading.Thread(
            target=lambda: answers.append(rdap.lookup_rdap("admin.ch"))
        )
        refresh.start()
        assert fetching.wait(5)
        asking.start()
        asking.join(0.2)
        waited = asking.is_alive()
        release.set()
        refresh.join(5)
        asking.join(5)
        assert waited
        assert answers[0]["registrar"] == "Markmonitor Inc."
        assert not whoisit.bootstrap_is_older_than(7)

    def test_the_registry_fetch_retries_no_more_than_a_query(
        self, clean_whoisit, monkeypatch
    ):
        retries = []

        def first_request(session, url, *args, **kwargs):
            retries.append(session.get_adapter(url).max_retries.total)
            raise whoisit.errors.BootstrapError("no network in the test suite")

        monkeypatch.setattr(whoisit, "bootstrap", whoisit._bootstrap.bootstrap)
        monkeypatch.setattr(
            importlib.import_module("whoisit.bootstrap"), "http_request", first_request
        )
        assert rdap.bootstrap_rdap() is False
        assert retries == [rdap.RDAP_HTTP_RETRIES]


class TestJscontactEntities:
    def test_a_vcard_name_still_wins(self):
        out = rdap._normalize_rdap_domain(dict(RDAP_DOMAIN, raw=KRNIC_RDAP_JSON), "x")
        assert out["registrar"] == "Markmonitor Inc."
        assert out["registrant"] == "Google LLC"

    def test_no_card_no_name(self):
        no_card = {"entities": [{"roles": ["registrar"]}]}
        empty = {"entities": [{"roles": ["registrar"], "jscontact_card": {}}]}
        for record in (no_card, empty, {}, None):
            assert rdap._jscontact_name(record, "registrar") is None

    def test_a_record_without_raw_normalises_as_before(self):
        out = rdap._normalize_rdap_domain({"name": "x.com"}, "x.com")
        assert out["registrar"] is None
        assert out["registrant"] is None

    def test_a_nested_entity_is_searched(self):
        nested = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "jscontact_card": {"name": {"full": "Abuse Desk"}},
                        }
                    ],
                }
            ]
        }
        assert rdap._jscontact_name(nested, "abuse") == "Abuse Desk"

    def test_an_organisation_fills_in_for_a_missing_full_name(self):
        record = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "jscontact_card": {
                        "organizations": {"org": {"name": "Example Registry"}}
                    },
                }
            ]
        }
        assert rdap._jscontact_name(record, "registrar") == "Example Registry"

    def test_whoisit_parses_the_handleless_record_only_under_overrides(
        self, clean_whoisit
    ):
        def parse():
            return whoisit.parse(
                whoisit._bootstrap,
                "domain",
                "kisa.or.kr",
                copy.deepcopy(KRNIC_RDAP_JSON),
                include_raw=True,
            )

        whoisit.load_bootstrap_data(_registry_json(0), overrides=False)
        with pytest.raises(whoisit.errors.ParseError):
            parse()
        whoisit.clear_bootstrapping()
        whoisit.load_bootstrap_data(_registry_json(0), overrides=True)
        parsed = parse()
        assert parsed["handle"] == ""
        assert parsed["entities"]["registrar"] == [{"type": "entity"}]
        assert rdap._normalize_rdap_domain(parsed, "kisa.or.kr")["registrar"] == "KISA"

    def test_lookup_rdap_asks_whoisit_for_the_raw_response(
        self, stale_registry, monkeypatch
    ):
        seen = {}

        def fake_domain(target, **kwargs):
            seen.update(kwargs)
            return dict(RDAP_DOMAIN_JSCONTACT)

        monkeypatch.setattr(whoisit, "domain", fake_domain)
        out = rdap.lookup_rdap("kisa.or.kr")
        assert seen == {"include_raw": True}
        assert out["registrar"] == "KISA"

    def test_kisa_or_kr_keeps_its_registrar_over_rdap(
        self, stale_registry, monkeypatch
    ):
        def krnic(name, include_raw=False, **kwargs):
            return whoisit.parse(
                whoisit._bootstrap,
                "domain",
                name,
                copy.deepcopy(KRNIC_RDAP_JSON),
                include_raw=include_raw,
            )

        monkeypatch.setattr(whoisit, "domain", krnic)
        monkeypatch.setattr(
            lookup.whois,
            "whois",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("port 43 must not be asked")
            ),
        )
        out = asyncio.run(lookup.lookup_whois("kisa.or.kr"))
        assert out["source"] == "rdap"
        assert out["registrar"] == "KISA"
        assert out["registrant"] == "Korea Internet & Security Agency"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
