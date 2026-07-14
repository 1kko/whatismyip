import re
from pathlib import Path

from fastapi.testclient import TestClient

from main import app

CSS = Path("static/css/whatismyip.css")

REQUIRED_TOKENS = {
    "--bg": "#0B0D12",
    "--surface": "#151922",
    "--surface-2": "#1B2130",
    "--border": "#232A36",
    "--border-strong": "#2E3746",
    "--text-primary": "#E8ECF3",
    "--text-secondary": "#8B97AC",
    "--text-muted": "#606C82",
    "--accent": "#5B8CFF",
    "--success": "#34D399",
    "--warning": "#FBBF24",
    "--danger": "#FB7185",
}

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


BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}


class TestBrowserPage:
    def test_server_renders_the_answer_without_javascript(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "WhatIsMyIP" in html
        assert "8.8.8.8" in html
        assert "LOOKUP" in html
        assert "NETWORK" in html
        assert "Raw JSON" in html

    def test_no_inline_event_handlers(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert "onclick=" not in html
        assert "onsubmit=" not in html

    def test_footer_reports_timing_and_links_github_as_an_icon(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "resolved in" in html
        assert "UTC" in html
        assert 'aria-label="Source on GitHub"' in html
        # The curl example moved into the Raw JSON accordion.
        assert "curl" not in html.split("<footer")[1]

    def test_curl_example_lives_in_the_raw_json_accordion(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        raw_block = html.split('id="acc-raw"')[1]
        assert 'id="curl-example"' in raw_block
        assert "curl http://testserver/8.8.8.8" in raw_block

    def test_curl_example_uses_the_scheme_the_visitor_actually_used(self):
        # Behind a TLS-terminating proxy the ASGI scope still says http://, so a
        # copied command would point at the wrong scheme.
        html = local_client.get(
            "/8.8.8.8", headers={**BROWSER_UA, "x-forwarded-proto": "https"}
        ).text
        assert "curl https://testserver/8.8.8.8" in html

    def test_forwarded_proto_from_an_untrusted_peer_is_ignored(self):
        html = client.get(
            "/8.8.8.8", headers={**BROWSER_UA, "x-forwarded-proto": "https"}
        ).text
        assert "curl http://testserver/8.8.8.8" in html

    def test_public_base_url_wins_when_the_proxy_forwards_nothing(self, monkeypatch):
        import main

        monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://ip.1kko.com")
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "curl https://ip.1kko.com/8.8.8.8" in html

    def test_place_name_links_out_to_openstreetmap(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert 'class="origin__place" href="https://www.openstreetmap.org/#map=' in html
        assert 'target="_blank" rel="noopener noreferrer"' in html

    def test_osm_attribution_is_rendered_on_the_map(self):
        # OSM only requires attribution on or beside the map; map.js paints the
        # chip, so the footer no longer repeats it.
        css = CSS.read_text(encoding="utf-8")
        assert ".map__attribution" in css
        js = Path("static/js/map.js").read_text(encoding="utf-8")
        assert "openstreetmap.org/copyright" in js
        assert "contributors" in js

    def test_json_editor_is_not_loaded_eagerly(self):
        html = client.get("/", headers=BROWSER_UA).text
        # The tree only boots when Raw JSON is opened.
        assert 'id="raw-json"' in html
        assert "new JSONEditor(" not in html
        assert "jsoneditor.min.js" not in html

    def test_search_form_targets_the_root_path(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert 'id="lookup-form"' in html
        assert 'id="lookup-input"' in html

    def test_pending_lookup_has_somewhere_to_report_itself(self):
        # A lookup is a full navigation that takes ~1s; the page must be able to
        # say so instead of sitting there looking broken.
        html = client.get("/", headers=BROWSER_UA).text
        assert 'id="progress"' in html
        assert 'id="lookup-status"' in html
        assert 'id="lookup-error"' in html
        assert 'role="alert"' in html


class TestDesignTokens:
    def test_all_tokens_are_defined_with_the_spec_values(self):
        css = CSS.read_text(encoding="utf-8")
        for token, value in REQUIRED_TOKENS.items():
            assert re.search(rf"{token}:\s*{value};", css, re.IGNORECASE), token

    def test_every_font_file_referenced_by_css_exists(self):
        css = CSS.read_text(encoding="utf-8")
        sources = re.findall(r"url\(['\"]?(/static/fonts/[^'\")]+)", css)
        assert sources, "no @font-face sources found"
        for source in sources:
            assert Path(source.lstrip("/")).is_file(), source

    def test_no_light_mode_branch(self):
        assert "prefers-color-scheme" not in CSS.read_text(encoding="utf-8")
