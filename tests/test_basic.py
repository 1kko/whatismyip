"""Smoke tests for the two public endpoints.

These used to hit a separately-launched server on localhost:8000; they now run
against FastAPI's TestClient with the lookups they check (RDAP/WHOIS, GeoIP,
DNS) mocked, so no server has to be running. What they leave unmocked fails
as it would offline (tests/conftest.py), and nothing reaches the network.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

import main
from main import app

# A public peer address so the self-lookup is treated as a routable client.
client = TestClient(app, client=("8.8.8.8", 41234))

MOCK_LOCATION = {
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States",
    "city_name": "Mountain View",
    "lat": 37.386,
    "lon": -122.084,
    "accuracy_km": 20,
    "cidr": "8.8.8.0/24",
    "asn_name": "Google LLC",
    "is_private": False,
}
MOCK_WHOIS = {"source": "rdap", "name": "google.com", "registrar": "Markmonitor Inc."}


class TestBasic:
    @patch("lookup.lookup_rdap", return_value=dict(MOCK_WHOIS, name="8.8.8.0/24"))
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_get_self_info(self, mock_rev, mock_geo, mock_rdap):
        response = client.get("/", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        data = response.json()
        assert "address" in data
        assert "location" in data
        assert "whois" in data

    @patch("lookup.lookup_rdap", return_value=dict(MOCK_WHOIS))
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_get_domain_info(self, mock_rev, mock_geo, mock_rdap):
        response = client.get("/google.com", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        data = response.json()
        # RDAP-first now, so the registration record is the canonical shape.
        assert data["whois"]["source"] == "rdap"
        assert data["whois"]["name"] == "google.com"

    @patch("lookup.lookup_rdap", return_value=dict(MOCK_WHOIS, name="8.8.8.0/24"))
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_get_ip_info(self, mock_rev, mock_geo, mock_rdap):
        response = client.get("/8.8.8.8", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        assert response.json()["location"]["ip"] == "8.8.8.8"

    def test_not_found(self):
        response = client.get("/admin/nonexistent", headers={"user-agent": "curl/8"})
        assert response.status_code == 404

    def test_healthz_reports_database_status(self):
        # /healthz must win over the /{domain_ip} catch-all and expose which
        # GeoIP databases are actually loaded (bundled fallback is a real
        # production failure mode, not a hypothetical).
        response = client.get("/healthz", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        data = response.json()
        # Which one depends on what this machine downloaded at import (the free
        # GeoLite2-ASN mirror alone reads as degraded); test_healthz_degraded
        # pins each reason.
        assert data["status"] in ("ok", "degraded")
        databases = data["databases"]
        # "bundled" while the geoip2fast fallback answers country, "unused"
        # once GeoLite2-City does.
        assert databases["geoip2fast"]["source"] in ("unused", "bundled")
        assert set(databases["city_overlay"]) == {"loaded", "build"}
        assert set(databases["asn_overlay"]) == {"loaded", "build"}


class TestRefreshRetry:
    """A failed refresh schedules exactly one short-interval retry instead of
    waiting out the 3-day interval; a successful one schedules nothing."""

    def test_failure_schedules_a_single_deduped_retry(self, monkeypatch):
        added = []
        monkeypatch.setattr(main.scheduler, "add_job", lambda *a, **k: added.append(k))
        main._refresh_with_retry(lambda: False, "test-db")()
        assert len(added) == 1
        assert added[0]["id"] == "retry-test-db"
        assert added[0]["replace_existing"] is True

    def test_success_schedules_nothing(self, monkeypatch):
        added = []
        monkeypatch.setattr(main.scheduler, "add_job", lambda *a, **k: added.append(k))
        main._refresh_with_retry(lambda: True, "test-db")()
        assert added == []


class TestBootFetch:
    """GeoLite2-City is where the country comes from, so boot fetches any
    GeoLite2 database that did not open, not only one whose file is missing: a
    truncated download left on the volume used to wait out the 3-day interval."""

    def _run(self, monkeypatch, city_reader, asn_reader):
        fetched = []
        monkeypatch.setattr(main.geo_ip_manager, "city_reader", city_reader)
        monkeypatch.setattr(main.geo_ip_manager, "asn_reader", asn_reader)
        monkeypatch.setattr(main, "refresh_city_db", lambda: fetched.append("city"))
        monkeypatch.setattr(main, "refresh_asn_db", lambda: fetched.append("asn"))
        main._fetch_unloaded_geoip_dbs()
        return fetched

    def test_an_unloaded_database_is_fetched(self, monkeypatch):
        assert self._run(monkeypatch, None, None) == ["city", "asn"]

    def test_a_loaded_database_is_left_to_the_schedule(self, monkeypatch):
        assert self._run(monkeypatch, object(), object()) == []
        assert self._run(monkeypatch, object(), None) == ["asn"]
