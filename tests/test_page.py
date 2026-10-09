import re
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import mcp_server
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

    # The shape fetch_cname() actually returns. This fixture used to be a bare
    # string, which is why the page could print the whole dict's repr unnoticed.
    CNAME = {"cname": "example.com.", "ttl": 300}

    def test_cname_is_listed_when_present(self):
        from main import _dns_rows

        rows = _dns_rows(
            {"address": "www.example.com", "domain": {"cname": dict(self.CNAME)}}
        )
        assert rows == [
            {
                "type": "CNAME",
                "name": "www.example.com",
                "value": "example.com.",
                "ttl": 300,
            }
        ]

    def test_cname_row_renders_target_and_ttl_in_their_own_cells(self):
        gathered = {
            **GATHERED,
            "address": "www.example.com",
            "domain": {**GATHERED["domain"], "cname": dict(self.CNAME)},
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/www.example.com", headers=BROWSER_UA).text

        row = re.search(r"<tr>\s*<td>CNAME</td>.*?</tr>", html, re.S)
        assert row, "no CNAME row in the DNS table"
        cells = re.findall(r"<td>(.*?)</td>", row.group(0), re.S)
        assert cells == ["CNAME", "www.example.com", "example.com.", "300"]
        # Jinja autoescapes the quotes, so a leaked repr shows up either way.
        assert "{'cname'" not in html
        assert "{&#39;cname&#39;" not in html


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

    def test_head_carries_agent_discovery_metadata(self):
        # An agent that lands on the HTML should find the machine interface
        # without scraping the page. The footer link was removed, so this block
        # is now the only in-markup pointer to the MCP endpoint.
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        head = html.split("</head>")[0]
        assert '<meta name="description"' in head
        assert 'name="mcp-endpoint"' in head and "/mcp" in head
        assert 'name="mcp-transport" content="streamable-http"' in head
        assert 'name="mcp-tools"' in head
        assert 'name="mcp-install"' in head
        # RFC 8631 registered relation, not an invented one.
        assert 'rel="service-doc"' in head

    def test_head_mcp_note_does_not_overstate_whose_ip_it_is(self):
        # Same honesty contract as the tool and the page copy. An agent reads
        # this to decide how to relay the answer, so it is the highest-leverage
        # place for the claim to be wrong.
        head = client.get("/", headers=BROWSER_UA).text.split("</head>")[0]
        note = head.split('name="mcp-note" content="')[1].split('"')[0]
        assert "own machine" in note  # local client
        assert "datacenter" in note  # hosted client
        # A datacenter-list hit is only "likely hosted"; nothing is certain.
        assert "likely a hosted client" in note
        assert "cannot be sure" in note

    def test_footer_no_longer_carries_the_mcp_link(self):
        # A bare "MCP server" link told a visitor nothing and left the site to
        # explain itself. The JSON accordion and the head metadata carry it now.
        html = client.get("/", headers=BROWSER_UA).text
        footer = html.split("<footer")[1].split("</footer>")[0]
        assert "MCP" not in footer
        assert "github.com/1kko/whatismyip" in footer  # the source link stays

    def test_json_accordion_advertises_the_mcp_endpoint(self):
        # A visitor's route to the MCP server. It sits with the curl example
        # because both answer the same question: how do I use this from
        # something that isn't a browser?
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        body = html.split('id="acc-raw"')[1].split("</details>")[0]
        assert 'id="mcp-endpoint"' in body
        assert "/mcp</pre>" in body
        assert "claude mcp add --transport http whatismyip" in body
        # Both blocks must be copyable; the handler binds to .copy-btn[data-value].
        assert body.count('class="copy-btn"') >= 3  # curl + endpoint + install

    def test_mcp_note_says_whose_ip_it_reports(self):
        # The honesty contract, on the page where someone decides to install it.
        # This service is called "what is my IP", so a visitor will assume the
        # MCP server tells their agent their address. The truth is conditional:
        # a local client (Claude Code) connects from their machine and does
        # return their IP; a hosted one (claude.ai) does not. Both branches have
        # to survive, because stating only one of them is how this note was
        # wrong the first time.
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        body = html.split('id="acc-raw"')[1].split("</details>")[0]
        assert "whoami_caller" in body
        assert "your own machine" in body  # local client
        assert "datacenter" in body  # hosted client
        assert "browser" in body  # the definitive answer

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

    def test_osm_tiles_send_an_origin_only_referer(self):
        # OSM's tile usage policy requires web pages to send a Referer; a tile
        # requested without one comes back as a 403 "Access blocked" image. The
        # page itself stays no-referrer, so the tile <img> overrides it with
        # strict-origin: OSM sees https://ip.1kko.com/, never the lookup path.
        js = Path("static/js/map.js").read_text(encoding="utf-8")
        assert 'img.referrerPolicy = "strict-origin";' in js
        assert 'img.referrerPolicy = "no-referrer"' not in js

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

    def test_fingerprint_identifier_is_styled(self):
        css = CSS.read_text(encoding="utf-8")
        assert ".copy-icon" in css  # inline copy icon on the UNIQUE ID row
        assert ".fp-id" in css  # the UNIQUE ID row layout
        assert ".device__note" in css  # the entropy / estimate caption

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


# gather() is patched throughout this class. tests/test_page.py has no mocking
# layer — every existing test here uses an IP target — and "/example.com" would
# otherwise drive real DNS, a real TLS handshake and a real RDAP query, putting
# the network on the suite's critical path. The payload below is the shape
# gather() returns for a domain.
GATHERED = {
    "address": "example.com",
    # "a" holds the same shape DomainManager.get_dns_records() returns
    # (managers.py) -- dicts with an "ip" key, not bare strings -- because
    # viewmodel._tags() reads first_a["ip"] when rendering an HTML page for a
    # domain target.
    "domain": {
        "a": [{"ip": "93.184.216.34", "ttl": 300}],
        "mx": [],
        "ns": [],
        "txt": [],
    },
    "location": {"country_code": "US", "country_name": "United States"},
    "whois": {"registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}


class TestSubdomainsParameter:
    FAKE = {
        "names": ["a.example.com"],
        "count": 1,
        "truncated": False,
        "source": "crt.sh",
        "fetched_at": "2026-09-29T00:00:00+00:00",
        "stale": False,
        "error": None,
    }

    def test_absent_parameter_leaves_the_response_unchanged(self):
        """The regression test that guards the whole design."""
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch("main.get_subdomains", new_callable=AsyncMock) as fetch:
                response = client.get("/example.com", headers=JSON_UA)
        assert response.status_code == 200
        assert "subdomains" not in response.json()
        fetch.assert_not_called()

    def test_include_adds_the_key_without_disturbing_the_others(self):
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch(
                "main.get_subdomains", new_callable=AsyncMock, return_value=self.FAKE
            ):
                plain = client.get("/example.com", headers=JSON_UA).json()
                enriched = client.get(
                    "/example.com?subdomains=include", headers=JSON_UA
                ).json()
        assert enriched["subdomains"]["names"] == ["a.example.com"]
        for key in plain:
            if key not in ("datetime", "elapsed_ms"):
                assert enriched[key] == plain[key]

    def test_include_on_an_ip_target_skips_the_fetch_but_still_looks_up(self):
        """Review M1. `only` already rejects an IP target outright (see
        test_only_rejects_an_ip_address); `include` is additive and must
        not: an IP still gets its normal lookup, just without a subdomains
        fetch that can only fail and would otherwise burn a budget slot and
        a crt.sh round trip for nothing.
        """
        ip_gathered = {**GATHERED, "address": "8.8.8.8", "domain": {}}
        with patch("main.gather", new_callable=AsyncMock, return_value=ip_gathered):
            with patch("main.get_subdomains", new_callable=AsyncMock) as fetch:
                response = client.get("/8.8.8.8?subdomains=include", headers=JSON_UA)
        assert response.status_code == 200
        assert "subdomains" not in response.json()
        fetch.assert_not_called()

    def test_only_returns_json_to_a_browser_user_agent(self):
        """Content negotiation is user-agent based, so a fetch() from our own
        page would otherwise receive a full HTML document."""
        browser = {"user-agent": "Mozilla/5.0 (Macintosh)"}
        with patch(
            "main.get_subdomains", new_callable=AsyncMock, return_value=self.FAKE
        ):
            response = client.get("/example.com?subdomains=only", headers=browser)
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["subdomains"]["names"] == ["a.example.com"]

    def test_only_skips_the_rest_of_the_pipeline(self):
        with patch("main.gather", new_callable=AsyncMock) as gather_mock:
            with patch(
                "main.get_subdomains", new_callable=AsyncMock, return_value=self.FAKE
            ):
                response = client.get("/example.com?subdomains=only", headers=JSON_UA)
        gather_mock.assert_not_called()
        assert set(response.json()) == {"address", "subdomains"}

    def test_only_rejects_an_ip_address(self):
        response = client.get("/8.8.8.8?subdomains=only", headers=JSON_UA)
        assert response.status_code == 400

    def test_only_rejects_an_invalid_domain(self):
        response = client.get("/not-a-domain?subdomains=only", headers=JSON_UA)
        assert response.status_code == 400

    def test_an_unrecognised_value_is_rejected_rather_than_ignored(self):
        response = client.get("/example.com?subdomains=1", headers=JSON_UA)
        assert response.status_code == 400
        assert "include" in response.json()["detail"]

    def test_exclude_is_accepted_explicitly(self):
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            response = client.get("/example.com?subdomains=exclude", headers=JSON_UA)
        assert response.status_code == 200
        assert "subdomains" not in response.json()

    def test_the_parameter_is_rejected_when_the_feature_is_disabled(self):
        """SUBDOMAIN_ENABLED=false must turn the surface off, not leave one that
        accepts the parameter and returns nothing useful."""
        with patch("main.SUBDOMAIN_ENABLED", False):
            response = client.get("/example.com?subdomains=include", headers=JSON_UA)
        assert response.status_code == 400

    def test_disabling_the_feature_leaves_an_ordinary_lookup_untouched(self):
        with patch("main.SUBDOMAIN_ENABLED", False):
            with patch(
                "main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)
            ):
                response = client.get("/example.com", headers=JSON_UA)
        assert response.status_code == 200
        assert "subdomains" not in response.json()


class TestSubdomainPanel:
    """BROWSER_UA is required on every request here. Content negotiation is
    user-agent based, and TestClient's default UA ("testclient") is not a
    browser — without the header these calls return JSON and every HTML
    assertion below fails. GATHERED and the gather() patch come from
    TestSubdomainsParameter's rationale: no network in the suite.
    """

    def test_the_panel_renders_collapsed_and_inert_for_a_domain(self):
        """Discoverable but costing nothing: no fetch happens until it opens."""
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch("main.get_subdomains", new_callable=AsyncMock) as fetch:
                html = client.get("/example.com", headers=BROWSER_UA).text
        assert 'id="acc-subdomains"' in html
        assert "?subdomains=include" in html  # the no-JavaScript path
        fetch.assert_not_called()

    def test_the_rendered_list_is_capped(self):
        """Review Focus 3. nasa.gov yields 2,585 names (~64 KiB of markup); the
        rendered <ul> must cap what it shows and say how many there really are.

        Scoped to the <ul id="subdomains-list"> markup rather than the whole
        page: main.py separately embeds the complete, uncapped response_data
        (subdomains included) as pageData for the Raw JSON accordion -- that
        is that feature's job (showing the true raw response) and is out of
        scope here, so h499 legitimately still appears elsewhere in `html`.
        """
        many = {
            "names": [f"h{i}.example.com" for i in range(500)],
            "count": 500,
            "truncated": False,
            "source": "crt.sh",
            "fetched_at": "2026-09-29T00:00:00+00:00",
            "stale": False,
            "error": None,
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch(
                "main.get_subdomains", new_callable=AsyncMock, return_value=many
            ):
                html = client.get(
                    "/example.com?subdomains=include", headers=BROWSER_UA
                ).text
        list_markup = html.split('id="subdomains-list"')[1].split("</ul>")[0]
        # Counted on the anchor, not the bare name: each entry now renders its
        # name twice, once in the href and once as the link text.
        assert list_markup.count('<a href="/h0.example.com">') == 1
        assert "h499.example.com" not in list_markup
        assert "500" in html

    def test_each_rendered_name_links_to_its_own_lookup(self):
        """A subdomain is itself a lookup target, so the list is navigable
        rather than a wall of text to copy out by hand."""
        payload = {
            "names": ["api-watch.example.com"],
            "count": 1,
            "truncated": False,
            "source": "crt.sh",
            "fetched_at": "2026-09-29T00:00:00+00:00",
            "stale": False,
            "error": None,
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch(
                "main.get_subdomains", new_callable=AsyncMock, return_value=payload
            ):
                html = client.get(
                    "/example.com?subdomains=include", headers=BROWSER_UA
                ).text
        list_markup = html.split('id="subdomains-list"')[1].split("</ul>")[0]
        assert (
            '<a href="/api-watch.example.com">api-watch.example.com</a>' in list_markup
        )

    def test_the_summary_hint_reports_the_count_once_loaded(self):
        payload = {
            "names": ["a.example.com"],
            "count": 29,
            "truncated": False,
            "source": "crt.sh",
            "fetched_at": "2026-09-29T00:00:00+00:00",
            "stale": False,
            "error": None,
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch(
                "main.get_subdomains", new_callable=AsyncMock, return_value=payload
            ):
                html = client.get(
                    "/example.com?subdomains=include", headers=BROWSER_UA
                ).text
        assert "29 subdomains found" in html

    def test_the_unopened_panel_says_click_to_lookup(self):
        """static/js/app.js rewrites this hint by id once its fetch lands, so
        the id has to be in the markup for the lazy path to work at all."""
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch("main.get_subdomains", new_callable=AsyncMock):
                html = client.get("/example.com", headers=BROWSER_UA).text
        assert 'id="hint-subdomains"' in html
        assert "click to lookup" in html

    def test_a_failed_fetch_is_reported_not_rendered_as_empty(self):
        """Review I2. static/js/app.js reaches this same JSON endpoint from
        the browser via fetch(); a non-200 (429 rate limit, 403 ban, 400 when
        the feature is disabled) must never be read as "no subdomains" --
        response.ok must gate before the payload is used, and a payload with
        no `subdomains` key must not fall through to an empty {} that
        renders "undefined found". No JS runtime in this suite (see the
        map.js/fingerprint.js tests above), so this checks the source text
        the same way those do.
        """
        js = Path("static/js/app.js").read_text(encoding="utf-8")
        assert "response.ok" in js
        assert "payload.subdomains || {}" not in js

    def test_disabling_the_feature_removes_the_panel_and_the_tool_advertisement(self):
        """Review M2. SUBDOMAIN_ENABLED=false already turns off the route and
        the MCP tool registration (main.py, mcp_server.py); the page must not
        keep selling a feature that is off -- no accordion to click, and no
        discovery meta tag telling an agent the tool still exists. The flag
        gets flipped exactly when something is on fire, the worst moment to
        find the UI still advertising it.

        The page lists the tools the server registered (mcp_server.py), and
        the flag skips registering subdomains at import, so both halves of
        the flag are switched off here.
        """
        with patch("main.SUBDOMAIN_ENABLED", False):
            with patch.dict(mcp_server.mcp._tool_manager._tools):
                mcp_server.mcp.remove_tool("subdomains")
                with patch(
                    "main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)
                ):
                    html = client.get("/example.com", headers=BROWSER_UA).text
        assert 'id="acc-subdomains"' not in html
        meta = html.split('name="mcp-tools"')[1].split(">")[0]
        assert "subdomains" not in meta
