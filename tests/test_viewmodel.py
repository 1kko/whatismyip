import datetime

from rdap import normalize_whois
from viewmodel import (
    build_view,
    country_flag,
    format_distance,
    ssl_rows,
    whois_display,
)

UTC = datetime.timezone.utc

IP_RESPONSE = {
    "address": "8.8.8.8",
    "location": {
        "ip": "8.8.8.8",
        "country_code": "US",
        "country_name": "United States",
        "city_name": "",
        "subdivision_name": "",
        "cidr": "8.8.8.0/23",
        "asn_name": "Google LLC",
        "asn_cidr": "8.8.8.0/24",
        "is_private": False,
        "reverse_dns": "dns.google.",
    },
    "domain": {"a": [{"ip": "8.8.8.8", "ttl": 300}], "mx": [], "ns": [], "txt": []},
    "whois": {"error": "WHOIS lookup failed"},
    "ssl": None,
    "headers": {"user-agent": "curl/8.0"},
    "distance_km": 9010.4,
}

DOMAIN_RESPONSE = {
    "address": "google.com",
    "location": {
        "country_code": "US",
        "country_name": "United States",
        "city_name": "Mountain View",
        "subdivision_name": "California",
        "cidr": "142.250.192.0/19",
        "asn_name": "Google LLC",
        "is_private": False,
    },
    "domain": {
        "a": [{"ip": "142.250.207.46", "ttl": 300}],
        "mx": [{"host": "smtp.google.com."}],
        "ns": [{"hostname": "ns1.google.com."}] * 4,
        "txt": ["v=spf1"] * 12,
    },
    "whois": {
        "source": "rdap",
        "name": "google.com",
        "registrar": "MarkMonitor Inc.",
        "registrant": "Google LLC",
        "status": ["client transfer prohibited"],
        "name_servers": ["ns1.google.com", "ns2.google.com"],
        "created": datetime.datetime(1997, 9, 15, 4, 0, tzinfo=datetime.timezone.utc),
        "updated": datetime.datetime(2024, 8, 2, 2, 17, tzinfo=datetime.timezone.utc),
        "expires": datetime.datetime(2028, 9, 14, 4, 0, tzinfo=datetime.timezone.utc),
        "dnssec": False,
    },
    "ssl": {
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Google Trust Services"),),
        ),
        "notAfter": "Sep 14 08:00:00 2026 GMT",
        "subjectAltName": (("DNS", "*.google.com"), ("DNS", "google.com")),
    },
    "headers": {},
    "distance_km": None,
}


class TestHero:
    def test_self_lookup_eyebrow_and_tags(self):
        view = build_view(IP_RESPONSE, is_self=True)
        assert view["eyebrow"] == "YOUR IP ADDRESS"
        assert view["target"] == "8.8.8.8"
        assert {"text": "IPv4", "tone": "default"} in view["tags"]

    def test_remote_lookup_eyebrow_and_distance(self):
        view = build_view(IP_RESPONSE, is_self=False)
        assert view["eyebrow"] == "LOOKUP"
        assert view["distance_text"] == "≈ 9,010 km from you"

    def test_no_distance_when_missing(self):
        assert build_view(DOMAIN_RESPONSE, is_self=False)["distance_text"] is None

    def test_flag_from_country_code(self):
        assert country_flag("KR") == "🇰🇷"
        assert country_flag("us") == "🇺🇸"
        assert country_flag("") == ""
        assert country_flag("--") == ""

    def test_domain_target_shows_resolved_ip_tag(self):
        view = build_view(DOMAIN_RESPONSE, is_self=False)
        assert view["target"] == "google.com"
        assert any(tag["text"] == "DOMAIN" for tag in view["tags"])
        assert any("142.250.207.46" in tag["text"] for tag in view["tags"])

    def test_city_line_falls_back_to_country_when_city_unknown(self):
        view = build_view(IP_RESPONSE, is_self=True)
        assert view["country_name"] == "United States"
        assert view["city_line"] == ""


class TestFacts:
    def test_ip_columns(self):
        titles = [
            column["title"] for column in build_view(IP_RESPONSE, is_self=True)["facts"]
        ]
        assert titles == ["NETWORK", "REVERSE DNS", "WHOIS"]

    def test_domain_columns(self):
        titles = [
            column["title"]
            for column in build_view(DOMAIN_RESPONSE, is_self=False)["facts"]
        ]
        assert titles == ["NETWORK", "DNS", "CERTIFICATE"]

    def test_failed_whois_is_a_warning_not_an_error_page(self):
        whois_column = build_view(IP_RESPONSE, is_self=True)["facts"][2]
        status = whois_column["rows"][0]
        assert status["value"] == "unavailable"
        assert status["tone"] == "warning"

    def test_certificate_column_reads_the_raw_getpeercert_dict(self):
        cert = build_view(DOMAIN_RESPONSE, is_self=False)["facts"][2]
        rows = {row["label"]: row for row in cert["rows"]}
        assert rows["Issuer"]["value"] == "Google Trust Services"
        assert rows["SAN"]["value"] == "2 names"
        assert rows["Expires"]["value"] == "2026-09-14"
        assert rows["Status"]["tone"] in ("success", "warning", "danger")

    def test_dns_column_counts_records(self):
        dns_column = build_view(DOMAIN_RESPONSE, is_self=False)["facts"][1]
        rows = {row["label"]: row["value"] for row in dns_column["rows"]}
        assert rows["A"] == "1 record"
        assert rows["NS"] == "4 records"
        assert rows["TXT"] == "12 records"

    def test_empty_dns_records_render_as_dash(self):
        response = dict(DOMAIN_RESPONSE, domain={})
        dns_column = build_view(response, is_self=False)["facts"][1]
        assert all(row["value"] == "—" for row in dns_column["rows"])


class TestAccordions:
    def test_accordions_in_order(self):
        ids = [
            item["id"] for item in build_view(IP_RESPONSE, is_self=True)["accordions"]
        ]
        assert ids == ["whois", "dns", "ssl", "geoip", "headers", "raw"]

    def test_hints_summarise_content(self):
        items = {
            i["id"]: i["hint"]
            for i in build_view(DOMAIN_RESPONSE, is_self=False)["accordions"]
        }
        assert "MarkMonitor" in items["whois"]
        assert items["dns"] == "A 1 · MX 1 · NS 4 · TXT 12"

    def test_list_valued_whois_dates_are_flattened(self):
        # python-whois hands back lists for some domains; normalize_whois folds
        # them so the hint never renders "[dat → [dat".
        raw = {
            "domain_name": "google.com",
            "registrar": ["MarkMonitor Inc.", "MarkMonitor"],
            "creation_date": [
                datetime.datetime(1997, 9, 15, 4, 0, tzinfo=UTC),
                datetime.datetime(1997, 9, 15, 7, 0, tzinfo=UTC),
            ],
            "expiration_date": [datetime.datetime(2028, 9, 14, 4, 0, tzinfo=UTC)],
        }
        response = dict(DOMAIN_RESPONSE, whois=normalize_whois(raw, "google.com"))
        hint = {
            i["id"]: i["hint"]
            for i in build_view(response, is_self=False)["accordions"]
        }["whois"]
        assert hint == "MarkMonitor Inc. · 1997 → 2028"

    def test_failed_whois_hint(self):
        items = {
            i["id"]: i["hint"]
            for i in build_view(IP_RESPONSE, is_self=True)["accordions"]
        }
        assert items["whois"] == "lookup failed"
        assert items["headers"] == "1 header"

    def test_ssl_hint_present_for_domain_and_absent_for_ip(self):
        dom = {
            i["id"]: i["hint"]
            for i in build_view(DOMAIN_RESPONSE, is_self=False)["accordions"]
        }
        assert "Google Trust Services" in dom["ssl"]
        ip = {
            i["id"]: i["hint"]
            for i in build_view(IP_RESPONSE, is_self=True)["accordions"]
        }
        assert ip["ssl"] == "no certificate"


FULL_SSL = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
    "notBefore": "Jun 01 00:00:00 2026 GMT",
    "notAfter": "Sep 14 08:00:00 2026 GMT",
    "serialNumber": "0ABCDEF",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    "protocol": "TLSv1.3",
    "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
}


class TestSslSection:
    def test_no_certificate_yields_empty_rows(self):
        assert build_view(IP_RESPONSE, is_self=True)["ssl_rows"] == []

    def test_certificate_rows_expose_ca_protocol_and_dates(self):
        rows = {
            r["label"]: r["value"]
            for r in build_view(dict(DOMAIN_RESPONSE, ssl=FULL_SSL), is_self=False)[
                "ssl_rows"
            ]
        }
        assert rows["Issuer (CA)"] == "Let's Encrypt"
        assert rows["Subject"] == "example.com"
        assert rows["Protocol"] == "TLSv1.3"
        assert "TLS_AES_256_GCM_SHA384" in rows["Cipher"]
        assert "256-bit" in rows["Cipher"]
        assert rows["Valid from"] == "2026-06-01"
        assert rows["Valid until"] == "2026-09-14"
        assert rows["SAN"] == "example.com, www.example.com"
        assert rows["Serial"] == "0ABCDEF"

    def test_missing_optional_fields_render_as_dash(self):
        # DOMAIN_RESPONSE's cert has no subject/protocol/cipher/serial.
        rows = {
            r["label"]: r["value"]
            for r in build_view(DOMAIN_RESPONSE, is_self=False)["ssl_rows"]
        }
        assert rows["Issuer (CA)"] == "Google Trust Services"
        assert rows["Protocol"] == "—"
        assert rows["Cipher"] == "—"
        assert rows["Subject"] == "—"


DV_CERT = {  # Let's Encrypt naver.com apex: CN only, no org, no www.naver.com
    "subject": ((("commonName", "naver.co.kr"),),),
    "issuer": ((("organizationName", "Let's Encrypt"),),),
    "notAfter": "Sep 14 08:00:00 2026 GMT",
    "subjectAltName": (("DNS", "naver.com"), ("DNS", "www.naver.co.kr")),
}
OV_CERT = {  # DigiCert *.naver.com wildcard with an organizationName
    "subject": (
        (("commonName", "*.naver.com"),),
        (("organizationName", "NAVER Corporation"),),
    ),
    "issuer": ((("organizationName", "DigiCert Inc"),),),
    "notAfter": "Sep 14 08:00:00 2026 GMT",
    "subjectAltName": (("DNS", "*.naver.com"), ("DNS", "*.blog.naver.com")),
}
EV_CERT = {  # businessCategory marks an EV cert
    "subject": (
        (("businessCategory", "Private Organization"),),
        (("organizationName", "Example Bank"),),
        (("commonName", "example-bank.com"),),
    ),
    "issuer": ((("organizationName", "DigiCert Inc"),),),
    "notAfter": "Sep 14 08:00:00 2026 GMT",
    "subjectAltName": (("DNS", "example-bank.com"),),
}


class TestSslHostMatchAndValidation:
    @staticmethod
    def _rows(ssl_data, address):
        return {r["label"]: r for r in ssl_rows(ssl_data, address)}

    def test_exact_san_entry_covers_the_host(self):
        row = self._rows(DV_CERT, "naver.com")["Host match"]
        assert row["value"] == "valid for naver.com"
        assert row["tone"] == "success"

    def test_host_absent_from_san_is_flagged(self):
        # The Let's Encrypt apex cert does not list www.naver.com.
        row = self._rows(DV_CERT, "www.naver.com")["Host match"]
        assert row["value"] == "not valid for www.naver.com"
        assert row["tone"] == "danger"

    def test_wildcard_covers_exactly_one_label(self):
        assert self._rows(OV_CERT, "www.naver.com")["Host match"]["tone"] == "success"
        # *.naver.com matches neither the bare apex nor a two-label host.
        assert self._rows(OV_CERT, "naver.com")["Host match"]["tone"] == "danger"
        assert self._rows(OV_CERT, "a.b.naver.com")["Host match"]["tone"] == "danger"

    def test_no_host_match_row_without_a_hostname(self):
        assert "Host match" not in self._rows(OV_CERT, "8.8.8.8")
        assert "Host match" not in self._rows(OV_CERT, None)

    def test_validation_level_is_read_from_the_subject(self):
        assert self._rows(DV_CERT, "naver.com")["Validation"]["value"] == (
            "DV (domain validated)"
        )
        assert (
            self._rows(OV_CERT, "www.naver.com")["Validation"]["value"]
            == "OV · NAVER Corporation"
        )
        assert (
            self._rows(EV_CERT, "example-bank.com")["Validation"]["value"]
            == "EV · Example Bank"
        )


class TestOsmLink:
    def test_city_precision_links_deep(self):
        response = dict(
            IP_RESPONSE,
            location=dict(
                IP_RESPONSE["location"], lat=37.5665, lon=126.978, precision="city"
            ),
        )
        assert (
            build_view(response, is_self=True)["map_link"]
            == "https://www.openstreetmap.org/#map=11/37.5665/126.978"
        )

    def test_country_precision_zooms_out(self):
        response = dict(
            IP_RESPONSE,
            location=dict(
                IP_RESPONSE["location"], lat=39.5, lon=-98.35, precision="country"
            ),
        )
        assert build_view(response, is_self=True)["map_link"].startswith(
            "https://www.openstreetmap.org/#map=5/"
        )

    def test_no_coords_no_link(self):
        # IP_RESPONSE's location has no lat/lon, so there is nothing to link to.
        assert build_view(IP_RESPONSE, is_self=True)["map_link"] is None


class TestMetaLine:
    def test_reports_elapsed_time_and_server_clock(self):
        response = dict(
            IP_RESPONSE,
            elapsed_ms=243,
            datetime=datetime.datetime(2026, 7, 14, 16, 40, 12, tzinfo=UTC),
        )
        assert (
            build_view(response, is_self=True)["meta_line"]
            == "resolved in 243 ms · 2026-07-14 16:40 UTC"
        )

    def test_falls_back_to_the_clock_when_timing_is_missing(self):
        response = dict(
            IP_RESPONSE,
            datetime=datetime.datetime(2026, 7, 14, 16, 40, 12, tzinfo=UTC),
        )
        assert build_view(response, is_self=True)["meta_line"] == "2026-07-14 16:40 UTC"

    def test_empty_when_there_is_nothing_to_report(self):
        assert build_view(IP_RESPONSE, is_self=True)["meta_line"] == ""


class TestFormatDistance:
    def test_thousands_separator_and_approx_sign(self):
        assert format_distance(9010.4) == "≈ 9,010 km from you"

    def test_none_stays_none(self):
        assert format_distance(None) is None


class TestWhoisDisplay:
    def test_whois_fallback_lists_and_datetimes_render_readably(self):
        # bahama.com shape from the port-43 fallback: lists (name servers, a
        # list-valued date) and datetime objects must survive normalize_whois +
        # whois_display without leaking Python reprs into the table.
        tz = UTC
        raw = {
            "domain_name": "BAHAMA.COM",
            "registrar": "NameSecure",
            "updated_date": [
                datetime.datetime(2022, 12, 27, 17, 1, 31, tzinfo=tz),
                datetime.datetime(2022, 12, 27, 17, 1, 31, tzinfo=tz),
            ],
            "creation_date": datetime.datetime(1995, 3, 23, 5, 0, tzinfo=tz),
            "name_servers": ["DNS1.NAMESECURE.COM", "DNS2.NAMESECURE.COM"],
            "emails": ["a@x.com", "b@y.com"],
        }
        out = whois_display(normalize_whois(raw, "bahama.com"))
        assert out["Source"] == "WHOIS"
        assert out["Name"] == "BAHAMA.COM"
        assert out["Registrar"] == "NameSecure"
        assert out["Updated"] == "2022-12-27 17:01 UTC"  # deduped, formatted
        assert out["Created"] == "1995-03-23 05:00 UTC"
        assert out["Name servers"] == "dns1.namesecure.com, dns2.namesecure.com"
        assert out["Abuse contact"] == "a@x.com"
        for value in out.values():
            assert "datetime.datetime" not in value and "[" not in value

    def test_rdap_record_renders_ordered_labelled_rows(self):
        record = {
            "source": "rdap",
            "name": "google.com",
            "registrar": "MarkMonitor Inc.",
            "status": ["client transfer prohibited"],
            "name_servers": ["ns1.google.com", "ns2.google.com"],
            "expires": datetime.datetime(2028, 9, 14, 4, 0, tzinfo=UTC),
            "dnssec": False,
        }
        out = whois_display(record)
        assert out["Source"] == "RDAP"
        assert out["Registrar"] == "MarkMonitor Inc."
        assert out["Name servers"] == "ns1.google.com, ns2.google.com"
        assert out["Expires"] == "2028-09-14 04:00 UTC"
        assert out["DNSSEC"] == "unsigned"

    def test_error_record_shows_a_single_error_row(self):
        assert whois_display({"error": "not registered"}) == {"Error": "not registered"}
        assert whois_display(None) == {}


class TestGeoIpSection:
    def test_rows_expose_coordinates_accuracy_and_timezone(self):
        response = dict(
            DOMAIN_RESPONSE,
            location={
                "country_code": "KR",
                "country_name": "South Korea",
                "city_name": "Seoul",
                "subdivision_name": "Seoul",
                "subdivision_code": "11",
                "lat": 37.5656,
                "lon": 126.978,
                "accuracy_km": 20,
                "time_zone": "Asia/Seoul",
                "asn_name": "SK Broadband",
                "cidr": "1.2.3.0/24",
            },
        )
        rows = {
            r["label"]: r["value"]
            for r in build_view(response, is_self=False)["geoip_rows"]
        }
        assert "South Korea" in rows["Country"] and "KR" in rows["Country"]
        assert rows["City"] == "Seoul"
        assert rows["Coordinates"] == "37.5656, 126.978"
        assert rows["Accuracy"] == "± 20 km"
        assert rows["Time zone"] == "Asia/Seoul"
        assert rows["ASN org"] == "SK Broadband"

    def test_missing_geo_is_dashes_not_errors(self):
        rows = {
            r["label"]: r["value"]
            for r in build_view(IP_RESPONSE, is_self=True)["geoip_rows"]
        }
        assert rows["Coordinates"] == "—"
        assert rows["Accuracy"] == "—"
