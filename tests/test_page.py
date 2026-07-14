from fastapi.testclient import TestClient

from main import app

JSON_UA = {"user-agent": "curl/8.0"}
SEOUL_IP = "118.235.14.201"

# get_client_ip() only honours x-real-ip from a trusted proxy peer, so the
# visitor's address is set as the TestClient's own peer address instead.
client = TestClient(app, client=(SEOUL_IP, 41234))
local_client = TestClient(app, client=("127.0.0.1", 41234))


class TestMapPayload:
    def test_remote_lookup_has_distance_and_route(self):
        response = client.get("/8.8.8.8", headers=JSON_UA)
        assert response.status_code == 200
        body = response.json()

        assert body["origin"]["precision"] in ("city", "country")
        assert body["distance_km"] > 1000
        desktop = body["map"]["desktop"]
        assert desktop["origin"] is not None
        assert len(desktop["line"]) >= 32
        assert desktop["tiles"][0]["url"].startswith("https://tile.openstreetmap.org/")
        assert body["map"]["mobile"]["width"] == 350

    def test_self_lookup_has_no_distance_and_no_line(self):
        body = client.get("/", headers=JSON_UA).json()

        assert body["distance_km"] is None
        assert body["map"]["desktop"]["line"] is None
        assert body["map"]["desktop"]["origin"] is None
        assert body["map"]["desktop"]["zoom"] == 10

    def test_private_client_gets_no_map(self):
        body = local_client.get("/", headers=JSON_UA).json()

        assert body["map"] is None
        assert body["distance_km"] is None
        assert body["origin"] is None

    def test_nearby_target_is_city_mode_not_route(self):
        # Visitor looks up their own address: one pin, no arc, no distance.
        body = client.get(f"/{SEOUL_IP}", headers=JSON_UA).json()

        assert body["map"]["desktop"]["line"] is None
        assert body["map"]["desktop"]["origin"] is None
        assert body["distance_km"] is None

    def test_legacy_keys_are_untouched(self):
        body = client.get("/8.8.8.8", headers=JSON_UA).json()
        for key in (
            "address",
            "datetime",
            "domain",
            "location",
            "whois",
            "ssl",
            "headers",
        ):
            assert key in body


class TestSecurityHeaders:
    def test_csp_allows_only_the_osm_tile_host(self):
        csp = client.get("/", headers=JSON_UA).headers["content-security-policy"]
        assert "img-src 'self' data: https://tile.openstreetmap.org" in csp
        assert "script-src 'self' 'nonce-" in csp
