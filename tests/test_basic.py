"""Smoke tests for the two public endpoints.

These used to hit a separately-launched server on localhost:8000; they now run
against FastAPI's TestClient with the external lookups (RDAP/WHOIS, GeoIP, DNS)
mocked, so the whole suite runs offline and deterministically.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

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
    @patch("main.lookup_rdap", return_value=dict(MOCK_WHOIS, name="8.8.8.0/24"))
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_get_self_info(self, mock_rev, mock_geo, mock_rdap):
        response = client.get("/", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        data = response.json()
        assert "address" in data
        assert "location" in data
        assert "whois" in data

    @patch("main.lookup_rdap", return_value=dict(MOCK_WHOIS))
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_get_domain_info(self, mock_rev, mock_geo, mock_rdap):
        response = client.get("/google.com", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        data = response.json()
        # RDAP-first now, so the registration record is the canonical shape.
        assert data["whois"]["source"] == "rdap"
        assert data["whois"]["name"] == "google.com"

    @patch("main.lookup_rdap", return_value=dict(MOCK_WHOIS, name="8.8.8.0/24"))
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_get_ip_info(self, mock_rev, mock_geo, mock_rdap):
        response = client.get("/8.8.8.8", headers={"user-agent": "curl/8"})
        assert response.status_code == 200
        assert response.json()["location"]["ip"] == "8.8.8.8"

    def test_not_found(self):
        response = client.get("/admin/nonexistent", headers={"user-agent": "curl/8"})
        assert response.status_code == 404
