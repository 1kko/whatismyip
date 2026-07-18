import re
from pathlib import Path

from fastapi.testclient import TestClient

from main import app, build_map_payload, normalize_lookup_target
from main import _is_route

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


class TestNormalizeLookupTarget:
    """Server-side host normalisation, mirroring static/js/app.js so a pasted URL
    behaves the same whether it comes through the search box or straight to the
    API. (A full URL with slashes still 404s at the router; this covers what
    actually reaches the handler: schemes, trailing paths, queries, whitespace.)"""

    def test_strips_scheme_path_query_and_fragment(self):
        assert (
            normalize_lookup_target("https://google.com/?q=asdasdasd") == "google.com"
        )
        assert normalize_lookup_target("http://a.b.co.kr/deep/path#frag") == "a.b.co.kr"

    def test_plain_host_and_ip_pass_through(self):
        assert normalize_lookup_target("google.com") == "google.com"
        assert normalize_lookup_target("8.8.8.8") == "8.8.8.8"

    def test_path_or_query_without_a_scheme(self):
        assert normalize_lookup_target("google.com/foo") == "google.com"
        assert normalize_lookup_target("google.com?q=1") == "google.com"

    def test_trims_surrounding_whitespace(self):
        assert normalize_lookup_target("  google.com  ") == "google.com"

    def test_ipv6_is_left_intact(self):
        # No scheme and no '/?#', so the IPv6 literal must survive untouched.
        assert normalize_lookup_target("2001:db8::1") == "2001:db8::1"

    def test_empty_and_scheme_only_collapse_to_empty(self):
        assert normalize_lookup_target("") == ""
        assert normalize_lookup_target("https://") == ""


class TestRouteVsCityMode:
    """Now GeoIP is city-level, two different cities draw home -> destination even
    when they are closer than the 25 km trip threshold."""

    def _loc(self, name, lat, lon):
        return {
            "country_code": "KR",
            "city_name": name,
            "lat": lat,
            "lon": lon,
            "accuracy_km": 20,
            "is_private": False,
        }

    def test_far_apart_is_always_a_route(self):
        assert _is_route(9000, {"city_name": "Seoul"}, {"city_name": "Mountain View"})

    def test_different_nearby_cities_now_route(self):
        # ~15 km apart, different city names -> route (was city mode before).
        assert _is_route(15, {"city_name": "Seoul"}, {"city_name": "Seongnam-si"})

    def test_same_city_stays_city_mode(self):
        assert not _is_route(15, {"city_name": "Seoul"}, {"city_name": "Seoul"})

    def test_case_insensitive_same_city(self):
        assert not _is_route(15, {"city_name": "SEOUL"}, {"city_name": "seoul"})

    def test_essentially_the_same_spot_is_not_a_route(self):
        # Different names but within the floor: same-place GeoIP jitter.
        assert not _is_route(3, {"city_name": "Seoul"}, {"city_name": "Incheon"})

    def test_unknown_target_city_falls_back_to_distance(self):
        assert not _is_route(15, {"city_name": "Seoul"}, {"city_name": ""})
        assert _is_route(40, {"city_name": "Seoul"}, {"city_name": ""})

    def test_payload_draws_both_pins_for_nearby_different_cities(self):
        # Seoul -> a point ~15 km east, different city: origin + arc must appear.
        origin = self._loc("Seoul", 37.5665, 126.978)
        target = self._loc("Seongnam-si", 37.5665, 127.15)
        payload, distance_km, origin_obj, _ = build_map_payload(target, origin)
        assert 5 < distance_km < 25  # closer than the old threshold...
        assert origin_obj is not None  # ...yet still a route
        assert payload["desktop"]["origin"] is not None
        assert payload["desktop"]["line"] is not None


class TestMapPayload:
    def test_remote_lookup_has_distance_and_route(self):
        response = client.get("/8.8.8.8", headers=JSON_UA)
        assert response.status_code == 200
        body = response.json()

        assert body["origin"]["ip"] == SEOUL_IP
        assert body["origin"]["lat"] is not None
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

    def test_target_and_origin_ips_live_in_location_and_origin(self):
        body = client.get("/8.8.8.8", headers=JSON_UA).json()
        assert body["location"]["ip"] == "8.8.8.8"
        assert body["origin"]["ip"] == SEOUL_IP

    def test_self_lookup_has_target_location_and_no_origin(self):
        body = client.get("/", headers=JSON_UA).json()
        assert body["location"]["ip"] == SEOUL_IP
        assert body["origin"] is None


class TestDnsRows:
    DOMAIN = {
        "a": [{"ip": "223.130.192.248", "ttl": 300}],
        "mx": [
            {
                "preference": 10,
                "hostname": "mx1.mail.naver.com.",
                "ttl": 300,
                "ip": "223.130.202.36",
            }
        ],
        "ns": [{"hostname": "ns1.naver.com.", "ttl": 20675, "ip": "61.247.220.6"}],
        "txt": [{"text": ["google-site-verification=fK9dDF"], "ttl": 300}],
        "cname": None,
    }

    def _rows(self):
        from main import _dns_rows

        return _dns_rows({"address": "naver.com", "domain": self.DOMAIN})

    def test_records_are_rendered_not_dumped_as_python_dicts(self):
        for row in self._rows():
            assert "{" not in row["value"], row
            assert "'" not in row["value"], row

    def test_each_record_type_reads_the_fields_that_matter(self):
        values = {row["type"]: row["value"] for row in self._rows()}
        assert values["A"] == "223.130.192.248"
        assert values["MX"] == "10 mx1.mail.naver.com."
        assert values["NS"] == "ns1.naver.com."
        assert values["TXT"] == "google-site-verification=fK9dDF"

    def test_ttl_comes_from_the_record(self):
        ttls = {row["type"]: row["ttl"] for row in self._rows()}
        assert ttls["NS"] == 20675
        assert ttls["A"] == 300

    def test_cname_is_listed_when_present(self):
        from main import _dns_rows

        rows = _dns_rows(
            {"address": "www.example.com", "domain": {"cname": "example.com."}}
        )
        assert rows == [
            {
                "type": "CNAME",
                "name": "www.example.com",
                "value": "example.com.",
                "ttl": "",
            }
        ]


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
        assert "IPv4" in html  # a hero tag, rendered above the address
        assert "NETWORK" in html
        assert "Raw JSON" in html

    def test_no_inline_event_handlers(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert "onclick=" not in html
        assert "onsubmit=" not in html

    def test_ssl_certificate_section_renders_and_reports_absence_for_an_ip(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "SSL certificate" in html  # the accordion is always present
        # An IP lookup never has a certificate, so the section says so.
        section = html.split('id="acc-ssl"')[1].split("</details>")[0]
        assert "No certificate" in section

    def test_footer_wordmark_shows_the_current_domain(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert '<span class="wordmark">testserver</span>' in html

    def test_footer_wordmark_falls_back_when_host_is_a_bare_ip(self):
        html = client.get(
            "/8.8.8.8", headers={**BROWSER_UA, "host": "203.0.113.9"}
        ).text
        assert '<span class="wordmark">ip.1kko.com</span>' in html

    def test_footer_wordmark_uses_the_public_base_url_domain(self, monkeypatch):
        import main

        monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://ip.1kko.com")
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert '<span class="wordmark">ip.1kko.com</span>' in html

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


class TestFingerprintPanel:
    def test_self_page_shows_the_browser_fingerprint_panel(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert 'id="acc-fingerprint"' in html
        assert "UNIQUE ID" in html
        assert 'id="fp-hash"' in html
        assert "/static/js/fingerprint.js" in html
        assert "noscript" in html  # JS-required fallback lives in the accordion

    def test_fingerprint_accordion_sits_above_whois(self):
        # The Fingerprint accordion renders first in the accordion list, ahead
        # of WHOIS (the first server-side accordion).
        html = client.get("/", headers=BROWSER_UA).text
        assert html.index('id="acc-fingerprint"') < html.index('id="acc-whois"')

    def test_lookup_page_has_no_fingerprint_panel(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert 'id="acc-fingerprint"' not in html
        assert "/static/js/fingerprint.js" not in html

    def test_fingerprint_panel_does_not_change_the_csp(self):
        # Same-origin computation only; the tile-host CSP must be untouched.
        csp = client.get("/", headers=BROWSER_UA).headers["content-security-policy"]
        assert "img-src 'self' data: https://tile.openstreetmap.org" in csp
        assert "connect-src" not in csp  # no external calls were opened up

    def test_device_panel_is_styled(self):
        css = CSS.read_text(encoding="utf-8")
        assert ".device__hash" in css
        assert ".device__grid" in css
        assert ".device__bits" in css

    def test_module_is_display_only(self):
        js = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        assert "fetch(" not in js
        assert "XMLHttpRequest" not in js
        assert "sendBeacon" not in js
        assert "localStorage" not in js
        assert "sessionStorage" not in js

    def test_module_collects_the_expected_signals(self):
        js = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        assert "WEBGL_debug_renderer_info" in js  # GPU
        assert "toDataURL" in js  # canvas entropy
        assert "OfflineAudioContext" in js  # audio entropy
        assert "hardwareConcurrency" in js  # CPU cores
        assert "getSupportedExtensions" in js  # WebGL params
        assert "offsetWidth" in js  # font probe
        assert "subtle" in js and "cyrb53" in js  # SHA-256 + fallback

    def test_module_no_ops_off_the_self_page(self):
        js = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        # Must bail immediately if the fingerprint accordion isn't on the page.
        assert 'getElementById("acc-fingerprint")' in js
        assert "if (!panel) return" in js

    def test_fingerprint_id_hashes_only_stable_signals(self):
        js = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        # The ID must be reproducible across reloads, so the hash material is
        # built from stable signals only (volatile ones are tagged stable=false).
        assert "stable = true" in js
        assert "signals.filter((s) => s.stable)" in js

    def test_copy_button_is_disabled_until_the_id_is_ready(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert 'id="fp-copy"' in html
        # The button ships disabled so an early click can't copy an empty value.
        button = html.split('id="fp-copy"')[1].split(">")[0]
        assert "disabled" in button
        # JS re-enables it only after the fingerprint ID is set.
        js = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        assert "copyBtn.disabled = false" in js


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
