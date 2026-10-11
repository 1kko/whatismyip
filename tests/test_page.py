import copy
import json
import re
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import config
import lookup
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
    "--text-muted": "#748097",
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

# GeoLite2-City's records, as GeoIpManager.fetch_location flattens them.
# US_CENTROID is 8.8.8.8 in the 2026-07-31 build: a country with coordinates
# in the middle of Kansas and a 1000 km radius. REGISTERED_ONLY is 1.1.1.1:
# only the country the block is registered in, nothing else. MOUNTAIN_VIEW
# and SEOUL are ordinary city records.
US_CENTROID = {
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States",
    "country_source": "located",
    "city_name": "",
    "subdivision_name": "",
    "subdivision_code": "",
    "lat": 37.751,
    "lon": -97.822,
    "accuracy_km": 1000,
    "time_zone": "America/Chicago",
    "cidr": "8.8.8.0/24",
    "asn_name": "GOOGLE",
    "asn_cidr": "8.8.8.0/24",
    "asn_number": 15169,
    "is_private": False,
    "hostname": "",
}
MOUNTAIN_VIEW = {
    **US_CENTROID,
    "city_name": "Mountain View",
    "subdivision_name": "California",
    "subdivision_code": "CA",
    "lat": 37.386,
    "lon": -122.084,
    "accuracy_km": 20,
    "time_zone": "America/Los_Angeles",
}
REGISTERED_ONLY = {
    **US_CENTROID,
    "ip": "1.1.1.1",
    "country_code": "AU",
    "country_name": "Australia",
    "country_source": "registered",
    "lat": None,
    "lon": None,
    "accuracy_km": None,
    "time_zone": None,
    "cidr": "1.1.1.0/24",
    "asn_name": "CLOUDFLARENET",
    "asn_cidr": "1.1.1.0/24",
    "asn_number": 13335,
}
SEOUL = {
    **US_CENTROID,
    "ip": SEOUL_IP,
    "country_code": "KR",
    "country_name": "South Korea",
    "city_name": "Seoul",
    "subdivision_name": "Seoul",
    "subdivision_code": "11",
    "lat": 37.5665,
    "lon": 126.978,
    "accuracy_km": 20,
    "time_zone": "Asia/Seoul",
    "cidr": "118.235.0.0/16",
    "asn_name": "SK Telecom",
    "asn_cidr": "118.235.0.0/16",
    "asn_number": 9644,
}
# A visitor a carrier's CGNAT pool places only in a country.
SEOUL_COARSE = {
    **SEOUL,
    "city_name": "",
    "subdivision_name": "",
    "subdivision_code": "",
    "lat": 36.5,
    "lon": 127.75,
    "accuracy_km": 1000,
}


@contextmanager
def geolite2(*records):
    """GeoLite2's answer for each address in `records`, in place of the data/
    files (or the bundled country snapshot on CI). Patched at the manager so
    both ends go through lookup.lookup_location, which grades them as in
    production; any other address still gets the real answer (the security
    middleware's geo check looks the visitor up too)."""
    by_ip = {record["ip"]: record for record in records}
    real = lookup.geo_ip_manager.fetch_location

    def fake(ip):
        return dict(by_ip[ip]) if ip in by_ip else real(ip)

    with patch.object(lookup.geo_ip_manager, "fetch_location", fake):
        yield


def _embedded_json(html, element_id):
    """The JSON the page embeds for app.js (#page-data) and map.js (#map-data)."""
    raw = re.search(
        rf'<script type="application/json" id="{element_id}"[^>]*>(.*?)</script>',
        html,
        re.S,
    ).group(1)
    return json.loads(raw.replace("<\\/", "</"))


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


class TestPrecisionOnThePage:
    """Backlog #2. 8.8.8.8 drew a crisp pin in Kansas with "≈ 10,462 km from
    you"; 1.1.1.1 an Australian flag over the outback. The page now says what
    the fix is worth, the map draws it dashed, and the chip goes; the JSON
    keeps every value it had and gains only the two markers."""

    def test_a_country_centroid_target_is_called_approximate(self):
        with geolite2(US_CENTROID, SEOUL):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "approximate · country-level" in html
        assert "registered in" not in html
        map_data = _embedded_json(html, "map-data")
        assert map_data["target_precision"] == "country"
        assert map_data["origin_precision"] == "city"
        assert map_data["distance_text"] is None  # no map__distance chip
        page = _embedded_json(html, "page-data")
        assert page["location"]["precision"] == "country"
        assert page["location"]["lat"] == 37.751
        assert page["location"]["accuracy_km"] == 1000
        assert page["distance_km"] > 1000  # the arc is still drawn
        assert page["origin"]["precision"] == "city"

    def test_a_registered_only_target_says_registered_in(self):
        with geolite2(REGISTERED_ONLY, SEOUL):
            html = client.get("/1.1.1.1", headers=BROWSER_UA).text
        assert "registered in Australia · location unknown" in html
        hero = re.search(r'<div class="origin">.*?</section>', html, re.S).group(0)
        assert "anycast" not in hero.lower()  # GeoLite2 has no such trait
        map_data = _embedded_json(html, "map-data")
        assert map_data["target_precision"] == "country"
        assert map_data["distance_text"] is None
        page = _embedded_json(html, "page-data")
        assert page["location"]["country_code"] == "AU"
        assert page["location"]["country_source"] == "registered"
        assert page["location"]["precision"] == "country"
        # The gazetteer's centroid, as before: the map still has a pin.
        assert page["location"]["lat"] is not None

    def test_a_city_fix_is_unchanged(self):
        with geolite2(MOUNTAIN_VIEW, SEOUL):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "Mountain View · California" in html
        assert "approximate" not in html
        map_data = _embedded_json(html, "map-data")
        assert map_data["target_precision"] == "city"
        assert map_data["origin_precision"] == "city"
        assert map_data["distance_text"].startswith("≈ ")
        assert map_data["distance_text"].endswith(" km from you")

    def test_a_country_level_visitor_gets_no_distance(self):
        """The other end of the arc: a visitor placed only in a country sees
        no "≈ N km from you" either, and their home pin is dashed."""
        with geolite2(MOUNTAIN_VIEW, SEOUL_COARSE):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        map_data = _embedded_json(html, "map-data")
        assert map_data["target_precision"] == "city"
        assert map_data["origin_precision"] == "country"
        assert map_data["distance_text"] is None

    def test_the_self_page_grades_the_visitors_own_fix(self):
        with geolite2(SEOUL_COARSE):
            body = client.get("/", headers=JSON_UA).json()
            html = client.get("/", headers=BROWSER_UA).text
        assert body["location"]["precision"] == "country"
        assert body["location"]["country_source"] == "located"
        assert "approximate · country-level" in html

    def test_json_gains_only_the_markers(self):
        with geolite2(US_CENTROID, SEOUL):
            body = client.get("/8.8.8.8", headers=JSON_UA).json()
        assert body["location"]["precision"] == "country"
        assert body["location"]["country_source"] == "located"
        assert body["location"]["lat"] == 37.751
        assert body["location"]["lon"] == -97.822
        assert body["location"]["accuracy_km"] == 1000
        assert body["location"]["time_zone"] == "America/Chicago"
        assert body["distance_km"] > 1000
        assert body["origin"]["precision"] == "city"
        assert body["origin"]["lat"] == 37.5665
        assert body["origin"]["accuracy_km"] == 20

    def test_text_and_fields_are_untouched(self):
        """textfmt.FIELDS has no coordinate field, so neither format changes."""
        with geolite2(US_CENTROID, SEOUL):
            text = client.get("/8.8.8.8?format=text", headers=JSON_UA).text
            fields = client.get("/8.8.8.8?fields=country_code", headers=JSON_UA).json()
        assert "precision" not in text
        assert "approximate" not in text
        assert fields == {"country_code": "US"}

    def test_the_css_dashes_the_approximate_pin(self):
        css = CSS.read_text(encoding="utf-8")
        assert ".map__pin--approx .map__pin-halo" in css
        rule = css.split(".map__pin--approx .map__pin-halo", 1)[1].split("}", 1)[0]
        assert "stroke-dasharray" in rule


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

    # The shape get_records() returns for a name below its zone apex: NS was
    # asked of the zone, and the MX fell back to the zone's, labelled.
    ZONE_DOMAIN = {
        "queried_name": "www.example.com",
        "zone": "example.com",
        "a": [{"ip": "93.184.216.34", "ttl": 300}],
        "mx": [
            {
                "preference": 10,
                "hostname": "mail.example.com.",
                "ttl": 3600,
                "from_zone": "example.com",
            }
        ],
        "ns": [{"hostname": "a.iana-servers.net.", "ttl": 86400}],
        "txt": [{"text": ["v=spf1 include:_spf.example.net -all"], "ttl": 300}],
        "cname": None,
        "status": {},
    }

    def test_zone_rows_carry_the_zone_name_and_the_marker(self):
        from main import _dns_rows

        rows = _dns_rows({"address": "www.example.com", "domain": self.ZONE_DOMAIN})
        by_type = {row["type"]: row for row in rows}
        # The name's own records keep the queried name and the pinned shape.
        assert by_type["A"] == {
            "type": "A",
            "name": "www.example.com",
            "value": "93.184.216.34",
            "ttl": 300,
        }
        assert "from_zone" not in by_type["TXT"]
        # NS is always the zone's; this MX is, because get_records said so.
        assert by_type["NS"]["name"] == "example.com"
        assert by_type["NS"]["from_zone"] is True
        assert by_type["MX"]["name"] == "example.com"
        assert by_type["MX"]["from_zone"] is True

    def test_a_failed_ns_query_is_the_zones_too(self):
        # NS is asked of the zone whether or not it answers, so the failure row
        # is the zone's as well. (A failed MX stays on the queried name: the
        # response cannot say which of the two MX queries raised.)
        from main import _dns_rows

        domain = {**self.ZONE_DOMAIN, "ns": [], "status": {"ns": "timeout"}}
        rows = _dns_rows({"address": "www.example.com", "domain": domain})
        assert [row for row in rows if row["type"] == "NS"] == [
            {
                "type": "NS",
                "name": "example.com",
                "value": "(timed out)",
                "ttl": "",
                "from_zone": True,
                "tone": "warning",
            }
        ]

    def test_the_apex_names_itself_everywhere_without_a_marker(self):
        from main import _dns_rows

        domain = {
            **self.ZONE_DOMAIN,
            "queried_name": "example.com",
            "mx": [{"preference": 10, "hostname": "mail.example.com.", "ttl": 3600}],
        }
        rows = _dns_rows({"address": "example.com", "domain": domain})
        assert {row["name"] for row in rows} == {"example.com"}
        assert not any("from_zone" in row for row in rows)

    def test_an_ip_targets_rows_name_the_ptr_name_the_sweep_was_of(self):
        # lookup._run_legs sweeps the PTR name, not the address, so that is
        # the name every row was asked of.
        from main import _dns_rows

        rows = _dns_rows(
            {
                "address": "8.8.8.8",
                "domain": {
                    "queried_name": "dns.google",
                    "zone": "dns.google",
                    "a": [{"ip": "8.8.8.8", "ttl": 300}],
                    "ns": [{"hostname": "ns1.zdns.google.", "ttl": 300}],
                },
            }
        )
        assert {row["name"] for row in rows} == {"dns.google"}
        assert not any("from_zone" in row for row in rows)

    def test_the_json_domain_is_the_gathered_one_untouched(self):
        # Rendering the rows must not write into the response: the JSON API
        # and MCP dns_records read the same dict, and their contract is fixed.
        gathered = {
            **GATHERED,
            "address": "www.example.com",
            "domain": copy.deepcopy(self.ZONE_DOMAIN),
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            assert client.get("/www.example.com", headers=BROWSER_UA).status_code == 200
            body = client.get("/www.example.com", headers=JSON_UA).json()
        assert body["domain"] == self.ZONE_DOMAIN

    def test_the_page_captions_the_queried_name_and_marks_zone_rows(self):
        gathered = {
            **GATHERED,
            "address": "www.example.com",
            "domain": self.ZONE_DOMAIN,
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/www.example.com", headers=BROWSER_UA).text

        table = re.search(
            r'<table class="records records--dns">.*?</table>', html, re.S
        ).group(0)
        caption = re.search(
            r'<caption class="records__caption">(.*?)</caption>', table, re.S
        )
        assert caption, "no caption on the DNS table"
        assert " ".join(caption.group(1).split()) == (
            "records for www.example.com · NS/MX from zone example.com"
        )
        # HTML wants the caption first, and it keeps the row regexes elsewhere
        # in the suite (thead, then rows) matching as before.
        assert table.index("<caption") < table.index("<thead>")

        mx = re.search(r"<tr>\s*<td>MX</td>.*?</tr>", table, re.S).group(0)
        assert "<td>example.com</td>" in mx
        assert '10 mail.example.com. <span class="tone-muted">(zone)</span>' in mx
        ns = re.search(r"<tr>\s*<td>NS</td>.*?</tr>", table, re.S).group(0)
        assert "<td>example.com</td>" in ns
        assert "(zone)" in ns
        # The name's own records: no marker, and the NAME cell stays a bare
        # <td> (test_the_page_lists_aaaa_records matches on exactly that).
        a_row = re.search(r"<tr>\s*<td>A</td>.*?</tr>", table, re.S).group(0)
        assert "(zone)" not in a_row
        assert "<td>www.example.com</td>" in a_row

    def test_the_apex_page_has_neither_the_zone_note_nor_the_marker(self):
        # At the apex NS is asked of the name itself and the MX is its own, so
        # every row, NS included, is the queried name's: nothing is marked.
        domain = {
            **self.ZONE_DOMAIN,
            "queried_name": "example.com",
            "mx": [{"preference": 10, "hostname": "mail.example.com.", "ttl": 3600}],
        }
        gathered = {**GATHERED, "address": "example.com", "domain": domain}
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/example.com", headers=BROWSER_UA).text

        table = re.search(
            r'<table class="records records--dns">.*?</table>', html, re.S
        ).group(0)
        caption = re.search(
            r'<caption class="records__caption">(.*?)</caption>', table, re.S
        )
        assert caption, "no caption on the DNS table"
        assert caption.group(1).strip() == "records for example.com"
        ns = re.search(r"<tr>\s*<td>NS</td>.*?</tr>", table, re.S)
        assert ns, "no NS row in the DNS table"
        assert "<td>example.com</td>" in ns.group(0)
        assert "NS/MX from zone" not in html
        assert "(zone)" not in html

    def test_an_ip_without_a_ptr_gets_a_caption_over_no_records(self):
        # conftest's offline defaults fail the PTR, so gather() hands the page
        # domain={}: the caption falls back to the address, nothing is marked.
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        table = re.search(
            r'<table class="records records--dns">.*?</table>', html, re.S
        ).group(0)
        assert "records for 8.8.8.8" in table
        assert "No records" in table
        assert "NS/MX from zone" not in table
        assert "(zone)" not in table

    def test_a_hostile_ptr_name_is_escaped_in_the_caption_and_name_cells(self):
        # Whoever holds an address writes its PTR record, and dnspython keeps
        # "<" and ">" in a name. get_records hands the swept name back as
        # queried_name, which now fills the caption and every NAME cell: both
        # must reach the page through Jinja's autoescape, never as markup.
        hostile = "<b>x</b>.evil.example"
        gathered = {
            **GATHERED,
            "address": "8.8.8.8",
            "domain": {
                "queried_name": hostile,
                "zone": hostile,
                "a": [{"ip": "8.8.8.8", "ttl": 300}],
                "ns": [{"hostname": "ns1.evil.example.", "ttl": 300}],
            },
        }
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text

        table = re.search(
            r'<table class="records records--dns">.*?</table>', html, re.S
        ).group(0)
        caption = re.search(
            r'<caption class="records__caption">(.*?)</caption>', table, re.S
        )
        assert caption, "no caption on the DNS table"
        escaped = "&lt;b&gt;x&lt;/b&gt;.evil.example"
        assert caption.group(1).strip() == f"records for {escaped}"
        assert re.findall(r"<tr>\s*<td>\w+</td>\s*<td>([^<]*)</td>", table) == [
            escaped,
            escaped,
        ]
        assert "<b>" not in table

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

    # The shape fetch_a() puts in cname_chain: DNS text per hop, as `cname`.
    CHAIN = [
        {"name": "www.example.com.", "target": "alias.example.net.", "ttl": 300},
        {"name": "alias.example.net.", "target": "edge.example.net.", "ttl": 60},
    ]

    def test_a_chain_is_one_row_per_hop_with_its_own_name_and_ttl(self):
        from main import _dns_rows

        rows = _dns_rows(
            {
                "address": "www.example.com",
                "domain": {
                    "cname": {"cname": "alias.example.net.", "ttl": 300},
                    "cname_chain": [dict(hop) for hop in self.CHAIN],
                },
            }
        )
        # The first hop is the `cname` record: one row for it, not two.
        assert rows == [
            {
                "type": "CNAME",
                "name": "www.example.com",
                "value": "alias.example.net.",
                "ttl": 300,
            },
            {
                "type": "CNAME",
                "name": "alias.example.net",
                "value": "edge.example.net.",
                "ttl": 60,
                "hop_of": "alias.example.net",
            },
        ]

    def test_an_empty_chain_leaves_the_cname_row_as_it_was(self):
        from main import _dns_rows

        rows = _dns_rows(
            {
                "address": "www.example.com",
                "domain": {"cname": dict(self.CNAME), "cname_chain": []},
            }
        )
        assert rows == [
            {
                "type": "CNAME",
                "name": "www.example.com",
                "value": "example.com.",
                "ttl": 300,
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

    def test_the_stylesheet_url_carries_the_deployed_version(self):
        """A deploy changes the query, so a returning browser fetches the new
        stylesheet instead of reusing its cached copy."""
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        hrefs = re.findall(r'<link rel="stylesheet" href="([^"]+)"', html)
        assert hrefs == [f"/static/css/whatismyip.css?v={config.APP_VERSION}"]

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


def _media_blocks(css, query):
    """The bodies of every `@media (<query>) { ... }` block in the stylesheet,
    joined. A media block nests rule blocks, so the braces are balanced by
    hand; a regex over `[^}]*` would stop at the first rule's closing brace."""
    bodies = []
    needle = f"@media ({query})"
    start = css.find(needle)
    while start != -1:
        open_brace = css.index("{", start)
        depth = 0
        end = open_brace
        for end in range(open_brace, len(css)):
            if css[end] == "{":
                depth += 1
            elif css[end] == "}":
                depth -= 1
                if depth == 0:
                    break
        bodies.append(css[open_brace + 1 : end])
        start = css.find(needle, end)
    return "\n".join(bodies)


class TestMobileLayout:
    """Three defects measured at 390px (docs/images/mobile.png and the
    2026-10-09 self-mobile screenshot), each fixed by a CSS rule. The suite has
    no layout engine (see the map.js and fingerprint.js source checks above),
    so the rules are pinned by text, and the media block a rule lives in is
    what keeps it off the desktop: the 440px box and its 14px must not move."""

    def test_inputs_are_16px_under_900px_so_ios_does_not_zoom(self):
        # iOS Safari zooms a focused field whose text is under 16px, and the
        # visitor pinches back or submits to undo it.
        css = CSS.read_text(encoding="utf-8")
        mobile = _media_blocks(css, "max-width: 900px")
        assert re.search(r"\.search input[^{]*\{[^}]*font-size:\s*16px", mobile)
        assert re.search(r"\.subdomains__filter[^{]*\{[^}]*font-size:\s*16px", mobile)
        # Each 16px rule must come after its base rule: the selectors share a
        # specificity, so the later one wins, and the filter's base rule sits
        # far below the main 900px block.
        search_base = css.index("font: 500 14px/1 var(--font-mono)")
        filter_base = css.index("font: 500 12.5px/1.4 var(--font-mono)")
        search_rule = re.search(r"\.search input[^{]*\{\s*font-size:\s*16px", css)
        filter_rule = re.search(r"\.subdomains__filter[^{]*\{\s*font-size:\s*16px", css)
        assert search_rule.start() > search_base
        assert filter_rule.start() > filter_base

    def test_the_desktop_box_is_unchanged(self):
        css = CSS.read_text(encoding="utf-8")
        assert re.search(r"\.search-wrap\s*\{[^}]*width:\s*440px", css)
        assert "font: 500 14px/1 var(--font-mono)" in css
        assert "font: 500 12.5px/1.4 var(--font-mono)" in css

    def test_pinch_zoom_is_still_allowed(self):
        # The other way to stop the zoom is `maximum-scale=1`, which also stops
        # a visitor zooming on purpose. The fix is the font size, so the
        # viewport meta stays as it is on every page that has the search box.
        for name in ("browser.html", "error.html", "privacy.html"):
            page = Path("templates", name).read_text(encoding="utf-8")
            assert 'content="width=device-width, initial-scale=1.0"' in page, name
            assert "maximum-scale" not in page, name
            assert "user-scalable" not in page, name

    def test_the_keyboard_badge_is_hidden_on_a_touch_screen(self):
        css = CSS.read_text(encoding="utf-8")
        touch = _media_blocks(css, "hover: none")
        assert re.search(r"\.search__hint\s*\{[^}]*display:\s*none", touch)
        # The badge goes, not the key: a tablet with a keyboard still has "/",
        # so the keydown handler stays and does not ask about hover itself.
        js = Path("static/js/app.js").read_text(encoding="utf-8")
        handler = js.split('document.addEventListener("keydown"')[1].split("});")[0]
        assert 'event.key === "/"' in handler
        assert "hover" not in handler
        assert "matchMedia" not in handler
        # One include serves every page with the box, so one rule covers them.
        for name in ("browser.html", "error.html", "privacy.html"):
            page = Path("templates", name).read_text(encoding="utf-8")
            assert '{% include "_search.html" %}' in page, name

    def test_accordion_titles_stay_on_one_line(self):
        css = CSS.read_text(encoding="utf-8")
        assert re.search(r"\.accordion__title\s*\{[^}]*white-space:\s*nowrap", css)
        hint = re.search(r"^\.hint\s*\{([^}]*)\}", css, re.M).group(1)
        for declaration in (
            "min-width: 0",
            "overflow: hidden",
            "text-overflow: ellipsis",
            "white-space: nowrap",
        ):
            assert declaration in hint, declaration

    def test_a_truncated_hint_keeps_its_full_text_in_title(self):
        # The ellipsis is visual: the DOM text stays whole for a screen reader,
        # and the span's title repeats it for a pointer's hover. Jinja escapes
        # both the same way, so the two strings are equal as markup.
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        spans = re.findall(
            r'<span class="hint" id="(hint-[a-z]+)" title="([^"]*)">([^<]*)</span>',
            html,
        )
        assert {name for name, _, _ in spans} >= {
            "hint-whois",
            "hint-dns",
            "hint-ssl",
            "hint-geoip",
            "hint-headers",
            "hint-raw",
        }
        for name, title, text in spans:
            assert title == text, name
        self_page = client.get("/", headers=BROWSER_UA).text
        assert (
            '<span class="hint" id="fp-acc-hint" title="browser signals">'
            "browser signals</span>" in self_page
        )

    def test_a_quote_in_a_hint_cannot_leave_its_title(self):
        # A registrar name is third-party text, and the WHOIS hint prints it.
        # Jinja escapes the attribute and the text the same way, so a quote
        # cannot end title="..." early and the two stay equal as markup;
        # app.js writes .title as a property, which needs no escaping.
        registrar = 'Acme "Names" <b>&</b> Co\'s'
        gathered = {**GATHERED, "whois": {"registrar": registrar}}
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/example.com", headers=BROWSER_UA).text
        escaped = "Acme &#34;Names&#34; &lt;b&gt;&amp;&lt;/b&gt; Co&#39;s"
        assert (
            f'<span class="hint" id="hint-whois" title="{escaped}">{escaped}</span>'
            in html
        )

    def test_the_scripts_that_rewrite_a_hint_rewrite_its_title(self):
        # app.js fills the WHOIS hint on the self page and the Subdomains hint
        # when that panel opens; fingerprint.js fills the Fingerprint hint. No
        # JS runtime here (see the fingerprint.js checks above), so by source
        # text, the way tests/test_subdomain_panel.py pins app.js's wiring.
        js = Path("static/js/app.js").read_text(encoding="utf-8")
        for name, element in (
            ("setWhoisHint", "hint"),
            ("setSubdomainHint", "subdomainHint"),
        ):
            body = re.search(rf"^function {name}\(.*?^\}}$", js, re.M | re.S).group(0)
            assert f"{element}.textContent = text" in body, name
            assert f"{element}.title = text" in body, name
        fp = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        assert 'setHint("fp-acc-hint"' in fp
        assert "el.title = text" in fp

    def test_the_copy_icon_is_a_24px_target(self):
        # WCAG 2.2 target size (minimum, 2.5.8) is 24px: the 14px icon plus 5px
        # of padding each side. 4px made a 22px target.
        css = CSS.read_text(encoding="utf-8")
        icon = re.search(r"^\.copy-icon\s*\{([^}]*)\}", css, re.M).group(1)
        assert re.search(r"padding:\s*5px;", icon)
        html = client.get("/", headers=BROWSER_UA).text
        button = html.split('id="fp-copy"')[1].split("</button>")[0]
        assert 'width="14" height="14"' in button


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


class TestSubdomainRegistration:
    RECORD = {
        "source": "rdap",
        "name": "example.com",
        "registrar": "Example Registrar",
    }

    def test_the_json_carries_the_registrable_domains_record_with_labels(self):
        asked = []

        def rdap(target):
            asked.append(target)
            return dict(self.RECORD)

        with patch("lookup.lookup_rdap", rdap):
            response = client.get("/www.example.com", headers=JSON_UA)

        assert response.status_code == 200
        whois = response.json()["whois"]
        assert asked == ["example.com"]
        assert whois["registrar"] == "Example Registrar"
        assert whois["queried_name"] == "www.example.com"
        assert whois["registrable_domain"] == "example.com"

    def test_the_page_says_whose_registration_it_shows(self):
        with patch("lookup.lookup_rdap", lambda target: dict(self.RECORD)):
            html = client.get("/www.example.com", headers=BROWSER_UA).text

        hint = (
            'id="hint-whois" title="registration of example.com · Example Registrar">'
            "registration of example.com · Example Registrar<"
        )
        assert hint in html
        assert '<td>Registration of</td><td colspan="3">example.com</td>' in html
        assert "not registered" not in html
        assert "no registration record" not in html


class TestWhoisColumnWording:
    # gather()'s shape for an IP whose RIR answered: the WHOIS column reads it.
    GATHERED_IP = {
        "address": "8.8.8.8",
        "domain": {},
        "location": {"country_code": "US", "country_name": "United States"},
        "whois": {
            "source": "rdap",
            "name": "GOGL",
            "registrant": "Google LLC",
            "network": "8.8.8.0/24",
            "rir": "arin",
            "status": ["active"],
        },
        "ssl": None,
        "resolved_ip": "8.8.8.8",
        "reverse_dns": None,
    }

    def test_a_found_record_is_not_called_available(self):
        """The column's Status is the lookup's, and "available" beside an
        address or a name reads as "available to register", so it says what
        the lookup did. The accordion keeps an IP allocation's own word."""
        with patch(
            "main.gather", new_callable=AsyncMock, return_value=self.GATHERED_IP
        ):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert 'class="kv-value tone-success">record found<' in html
        assert ">available<" not in html
        assert '<td>Status</td><td colspan="3">active</td>' in html


class TestThePageGlossesAndTheJsonDoesNot:
    """The item's contract in one place: the page rewords a domain's registry
    status and the reputation level, and the JSON API keeps both as they were
    (whois.status in the registry's spelling, reputation.level `none`)."""

    PORT43 = "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
    GATHERED_DOMAIN = {
        **GATHERED,
        "whois": {
            "source": "whois",
            "name": "example.com",
            "registrar": "Example Registrar",
            "status": [PORT43],
        },
        "reputation": {
            "level": "none",
            "signals": [],
            "checked": [
                {
                    "id": "tor_exit",
                    "label": "Tor exit",
                    "source": "Tor Project",
                    "as_of": "2026-10-09T06:13:20Z",
                }
            ],
            "unavailable": [],
            "attribution": [],
        },
    }

    def test_the_page_rewords_and_the_json_does_not(self):
        with patch(
            "main.gather",
            new_callable=AsyncMock,
            return_value=dict(self.GATHERED_DOMAIN),
        ):
            html = client.get("/example.com", headers=BROWSER_UA).text
            body = client.get("/example.com", headers=JSON_UA).json()
        assert (
            '<td>Status</td><td colspan="3">clientTransferProhibited — transfer '
            "lock set by the registrar (a common setting)</td>"
        ) in html
        assert 'class="tone-default">No signals<' in html
        assert ">None<" not in html
        assert body["whois"]["status"] == [self.PORT43]
        assert "status_explained" not in body["whois"]
        assert body["reputation"]["level"] == "none"


class TestDnsTableStyles:
    # Exactly the rule inside the 900px media block, indentation included.
    MOBILE_NAME_RULE = (
        "  table.records--dns th:nth-child(2),\n"
        "  table.records--dns td:nth-child(2) { display: none; }\n"
    )

    def test_the_caption_is_styled(self):
        css = CSS.read_text(encoding="utf-8")
        rule = re.search(r"\.records__caption \{([^}]*)\}", css)
        assert rule, "no .records__caption rule"
        assert "text-align: left" in rule.group(1)
        assert "var(--text-secondary)" in rule.group(1)

    def test_mobile_hides_the_name_column_and_desktop_keeps_it(self):
        css = CSS.read_text(encoding="utf-8")
        hidden = css.find(self.MOBILE_NAME_RULE)
        assert hidden >= 0, "no mobile rule hiding the NAME column"
        # Inside a 900px block and no other: the last @media opened before the
        # rule is that one (the two-space indent is the block's).
        assert css.rfind("@media", 0, hidden) == css.rfind(
            "@media (max-width: 900px)", 0, hidden
        )
        # Above 900px the column keeps its width: the phone layout is the only
        # place the name is folded into the caption.
        desktop = css[: css.index("@media (max-width: 900px)")]
        assert re.search(
            r"table\.records--dns td:nth-child\(2\) \{\s*width: 170px;", desktop
        )
        column = re.search(
            r"table\.records--dns td:nth-child\(2\) \{([^}]*)\}", desktop
        )
        assert "display: none" not in column.group(1)


class TestReverseDnsVerdict:
    """The REVERSE DNS column says whether an IP's PTR name points back to it,
    read off the sweep of that name the lookup already made."""

    @staticmethod
    def _sweep(name, a_records, aaaa_records=()):
        # The shape DomainManager.get_records() returns for the PTR name.
        return {
            "queried_name": name,
            "a": [{"ip": ip, "ttl": 300} for ip in a_records],
            "aaaa": [{"ip": ip, "ttl": 300} for ip in aaaa_records],
            "mx": [],
            "ns": [],
            "txt": [],
            "cname": None,
            "status": {
                "a": "ok" if a_records else "noanswer",
                "aaaa": "ok" if aaaa_records else "noanswer",
            },
        }

    def _ip_gathered(self, a_records):
        return {
            **GATHERED,
            "address": "8.8.8.8",
            "resolved_ip": "8.8.8.8",
            "resolution": "literal",
            "reverse_dns": "dns.google.",
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "reverse_dns": "dns.google.",
            },
            "domain": self._sweep("dns.google", a_records),
            "whois": {"source": "rdap", "name": "GOGL"},
        }

    @staticmethod
    def _self_page(visitor, sweep, headers=BROWSER_UA):
        """GET / as `visitor`, with its PTR (host.example.net.), the sweep of
        that name and its registration stubbed. lookup.domain_manager is the
        object main's _self_lookup calls."""
        with (
            patch.object(
                lookup.domain_manager,
                "perform_reverse_lookup",
                return_value="host.example.net.",
            ),
            patch.object(lookup.domain_manager, "get_records", return_value=sweep),
            patch(
                "main.lookup_whois",
                new_callable=AsyncMock,
                return_value={"source": "rdap", "name": "KORNET"},
            ),
        ):
            return visitor.get("/", headers=headers).text

    def test_an_ip_whose_ptr_points_back_reads_confirmed(self):
        gathered = self._ip_gathered(["8.8.4.4", "8.8.8.8"])
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert (
            '<span class="kv-value tone-success">dns.google. → confirmed</span>' in html
        )

    def test_an_ip_whose_ptr_points_elsewhere_does_not_point_back(self):
        gathered = self._ip_gathered(["216.239.32.10"])
        with patch("main.gather", new_callable=AsyncMock, return_value=gathered):
            html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert (
            '<span class="kv-value tone-warning">'
            "dns.google. → does not point back</span>" in html
        )
        assert "spoof" not in html.lower()

    def test_the_self_page_shows_the_visitors_own_verdict(self):
        """_self_lookup already sweeps the visitor's PTR name, and build_view
        gives the self page the same column."""
        html = self._self_page(client, self._sweep("host.example.net", [SEOUL_IP]))
        assert (
            '<span class="kv-value tone-success">host.example.net. → confirmed</span>'
            in html
        )

    def test_a_dual_stack_visitor_is_judged_as_the_ipv4_address_it_carries(self):
        """A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d, and the
        self page takes the address as it comes, not through gather()."""
        dual_stack = TestClient(app, client=(f"::ffff:{SEOUL_IP}", 41234))
        html = self._self_page(dual_stack, self._sweep("host.example.net", [SEOUL_IP]))
        assert (
            '<span class="kv-value tone-success">host.example.net. → confirmed</span>'
            in html
        )

    def test_an_ipv6_visitor_is_judged_however_the_proxy_spelled_it(self):
        """x-real-ip from a trusted proxy arrives as the proxy wrote it."""
        sweep = self._sweep(
            "host.example.net", [], aaaa_records=["2404:6800:4004:80b::200e"]
        )
        html = self._self_page(
            local_client,
            sweep,
            headers={**BROWSER_UA, "x-real-ip": "2404:6800:4004:80B::200E"},
        )
        assert (
            '<span class="kv-value tone-success">host.example.net. → confirmed</span>'
            in html
        )
