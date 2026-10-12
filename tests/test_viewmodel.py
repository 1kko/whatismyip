import datetime
import re

import pytest

import viewmodel
from rdap import _normalize_rdap_domain, _normalize_rdap_ip, normalize_whois
from viewmodel import (
    DASH,
    _age_days,
    _parse_dmarc,
    build_view,
    cert_age,
    country_flag,
    dmarc_policy,
    fcrdns_state,
    format_distance,
    registration_age,
    reputation_view,
    ssl_rows,
    whois_display,
    whois_fill,
)

UTC = datetime.timezone.utc

IP_RESPONSE = {
    "address": "8.8.8.8",
    "location": {
        "ip": "8.8.8.8",
        "country_code": "US",
        "country_name": "United States",
        "country_source": "located",
        "city_name": "",
        "subdivision_name": "",
        "cidr": "8.8.8.0/23",
        "asn_name": "Google LLC",
        "asn_cidr": "8.8.8.0/24",
        "is_private": False,
        "reverse_dns": "dns.google.",
        "precision": "city",
    },
    "domain": {"a": [{"ip": "8.8.8.8", "ttl": 300}], "mx": [], "ns": [], "txt": []},
    "whois": {"error": "WHOIS lookup failed"},
    "ssl": None,
    "headers": {"user-agent": "curl/8.0"},
    "distance_km": 9010.4,
    # The visitor's end of the arc, as main.build_map_payload writes it.
    "origin": {
        "ip": "118.235.14.201",
        "country_code": "KR",
        "country_name": "South Korea",
        "city_name": "Seoul",
        "lat": 37.5665,
        "lon": 126.978,
        "accuracy_km": 20,
        "precision": "city",
    },
}

DOMAIN_RESPONSE = {
    "address": "google.com",
    "location": {
        "country_code": "US",
        "country_name": "United States",
        "country_source": "located",
        "city_name": "Mountain View",
        "subdivision_name": "California",
        "cidr": "142.250.192.0/19",
        "asn_name": "Google LLC",
        "is_private": False,
        "precision": "city",
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


# GeoLite2's answer for 8.8.8.8: the US centroid with a 1000 km radius, no
# city, and a time zone that is the centroid's, not the address's.
COUNTRY_LEVEL_RESPONSE = {
    **IP_RESPONSE,
    "location": {
        **IP_RESPONSE["location"],
        "lat": 37.751,
        "lon": -97.822,
        "accuracy_km": 1000,
        "time_zone": "America/Chicago",
        "precision": "country",
    },
    "distance_km": 10462.3,
}

# GeoLite2's answer for 1.1.1.1: only the country the block is registered in
# and no coordinates at all; the coordinates here are the gazetteer's centroid
# the page draws (main._apply_resolved_target).
REGISTERED_ONLY_RESPONSE = {
    **IP_RESPONSE,
    "address": "1.1.1.1",
    "location": {
        **IP_RESPONSE["location"],
        "ip": "1.1.1.1",
        "country_code": "AU",
        "country_name": "Australia",
        "country_source": "registered",
        "lat": -33.4888,
        "lon": 144.9099,
        "precision": "country",
    },
    "distance_km": 8300.0,
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


class TestDnsCaption:
    """The DNS table's caption names the name the sweep was of and the zone its
    NS and fallback MX came from. Two new keys: `domain` itself never reaches
    the template (main.render_page passes `view` and `dns_rows`)."""

    def test_a_subdomain_names_itself_and_its_zone(self):
        response = {
            **DOMAIN_RESPONSE,
            "address": "www.google.com",
            "domain": {
                **DOMAIN_RESPONSE["domain"],
                "queried_name": "www.google.com",
                "zone": "google.com",
            },
        }
        view = build_view(response, is_self=False)
        assert view["dns_queried_name"] == "www.google.com"
        assert view["dns_zone"] == "google.com"

    def test_an_ip_names_the_ptr_name_the_sweep_was_of(self):
        # lookup._run_legs sweeps an IP's PTR name, and get_records reports
        # that name, trailing dot stripped, as queried_name.
        response = {
            **IP_RESPONSE,
            "domain": {
                **IP_RESPONSE["domain"],
                "queried_name": "dns.google",
                "zone": "dns.google",
            },
        }
        view = build_view(response, is_self=False)
        assert view["dns_queried_name"] == "dns.google"
        assert view["dns_zone"] == "dns.google"

    def test_a_response_without_the_names_falls_back_to_the_address(self):
        # An IP with no PTR gets domain={} from gather(), and older fixtures
        # carry neither key. Both name the address twice, which the template
        # reads as "no zone to mention".
        view = build_view(IP_RESPONSE, is_self=False)
        assert view["dns_queried_name"] == "8.8.8.8"
        assert view["dns_zone"] == "8.8.8.8"

        for domain in (None, {}):
            view = build_view({**IP_RESPONSE, "domain": domain}, is_self=False)
            assert (view["dns_queried_name"], view["dns_zone"]) == (
                "8.8.8.8",
                "8.8.8.8",
            )


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
        assert items["dns"] == "A 1 · AAAA 0 · MX 1 · NS 4 · TXT 12"

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
        assert whois_display({"error": "WHOIS lookup timed out"}) == {
            "Error": "WHOIS lookup timed out"
        }
        assert whois_display(None) == {}

    def test_not_registered_is_reported_as_an_answer_not_an_error(self):
        """The registry answered that the registrable domain has no record."""
        out = whois_display({"error": "not registered"})
        assert "Error" not in out
        assert out == {"Status": "no registration record for this name"}

    def test_a_record_of_the_registrable_domain_says_so_first(self):
        record = {
            "source": "rdap",
            "name": "example.com",
            "registrar": "Example Registrar",
            "status": ["client transfer prohibited"],
            "queried_name": "www.example.com",
            "registrable_domain": "example.com",
        }
        out = whois_display(record)
        assert list(out)[0] == "Registration of"
        assert out["Registration of"] == "example.com"
        assert out["Name"] == "example.com"
        assert out["Status"] == (
            "clientTransferProhibited — transfer lock set by the registrar "
            "(a common setting)"
        )

    def test_the_names_own_record_has_no_such_row(self):
        record = {
            "source": "rdap",
            "name": "example.com",
            "queried_name": "example.com",
            "registrable_domain": "example.com",
        }
        assert "Registration of" not in whois_display(record)
        assert "Registration of" not in whois_display(
            {"source": "rdap", "name": "GOGL"}
        )


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

    def test_a_name_reached_through_a_cname_chain_says_whose_location_it_is(self):
        response = dict(
            DOMAIN_RESPONSE,
            domain={
                **DOMAIN_RESPONSE["domain"],
                "queried_name": "www.example.com",
                "canonical_name": "edge.example.net",
                "cname_chain": [
                    {
                        "name": "www.example.com.",
                        "target": "alias.example.net.",
                        "ttl": 300,
                    },
                    {
                        "name": "alias.example.net.",
                        "target": "edge.example.net.",
                        "ttl": 60,
                    },
                ],
            },
        )
        rows = {
            r["label"]: r["value"]
            for r in build_view(response, is_self=False)["geoip_rows"]
        }
        assert rows["Resolves via"] == (
            "edge.example.net — the location and ASN above are its"
        )
        # Only that the names differ is known: no "CDN" verdict.
        assert "CDN" not in rows["Resolves via"]

    def test_a_name_that_is_its_own_canonical_name_gets_no_such_row(self):
        response = dict(
            DOMAIN_RESPONSE,
            domain={
                **DOMAIN_RESPONSE["domain"],
                "queried_name": "google.com",
                "canonical_name": "google.com",
                "cname_chain": [],
            },
        )
        labels = [r["label"] for r in build_view(response, is_self=False)["geoip_rows"]]
        assert "Resolves via" not in labels

    def test_an_ip_target_never_gets_the_row(self):
        """Review Focus 1. An IP's sweep is of its PTR name, whose own A
        record may sit behind a CNAME; the location on the card is the IP's,
        so that chain says nothing about it. The self page is an IP target."""
        response = dict(
            IP_RESPONSE,
            domain={
                **IP_RESPONSE["domain"],
                "queried_name": "dns.google",
                "canonical_name": "edge.example.net",
                "cname_chain": [
                    {"name": "dns.google.", "target": "edge.example.net.", "ttl": 300}
                ],
            },
        )
        for is_self in (True, False):
            labels = [
                r["label"] for r in build_view(response, is_self=is_self)["geoip_rows"]
            ]
            assert "Resolves via" not in labels, is_self

    def test_a_response_without_the_keys_renders_as_before(self):
        """A mocked sweep has no canonical_name: no row, no KeyError."""
        labels = [
            r["label"] for r in build_view(DOMAIN_RESPONSE, is_self=False)["geoip_rows"]
        ]
        assert "Resolves via" not in labels

    def test_a_sweep_that_did_not_answer_names_no_canonical_name(self):
        """Neither the A nor the AAAA query of the sweep answered (the public
        resolvers timed out), so canonical_name is null with queried_name set:
        the chain is unknown, not absent. The card must not print 'Resolves
        via None' for a name it never learned; the DNS table's A row already
        says the query failed. DOMAIN_RESPONSE has no queried_name at all, so
        the test above cannot tell this case from the no-chain one."""
        response = dict(
            DOMAIN_RESPONSE,
            domain={
                **DOMAIN_RESPONSE["domain"],
                "a": [],
                "queried_name": "www.example.com",
                "canonical_name": None,
                "cname_chain": [],
                "status": {"a": "timeout", "aaaa": "timeout"},
            },
        )
        rows = build_view(response, is_self=False)["geoip_rows"]
        assert "Resolves via" not in [r["label"] for r in rows]
        assert not any("None" in str(r["value"]) for r in rows)


class TestPrecisionWording:
    """What the hero and the GeoIP card say when the fix is not a city.

    8.8.8.8 drew a crisp pin in Kansas with "≈ 10,462 km from you", and 1.1.1.1
    an Australian flag over the outback, with the only honest line ("Accuracy
    ± 1000 km") inside an accordion. The words below replace the city line, so
    the first thing read under the country is how far to trust it. None of
    them is a verdict: "anycast" is a trait GeoLite2 does not carry."""

    def test_a_city_fix_shows_the_city_and_region(self):
        view = build_view(DOMAIN_RESPONSE, is_self=False)
        assert view["city_line"] == "Mountain View · California"

    def test_a_country_centroid_is_called_approximate(self):
        view = build_view(COUNTRY_LEVEL_RESPONSE, is_self=False)
        assert view["country_name"] == "United States"
        assert view["city_line"] == "approximate · country-level"

    def test_a_registered_only_country_says_so(self):
        view = build_view(REGISTERED_ONLY_RESPONSE, is_self=False)
        assert view["flag"] == "🇦🇺"
        assert view["city_line"] == "registered in Australia · location unknown"
        assert "anycast" not in view["city_line"]

    def test_no_country_means_no_line(self):
        """An address no database places: an empty country must not get
        "approximate · country-level" written under it."""
        response = dict(
            IP_RESPONSE,
            location={"ip": "8.8.8.8", "country_code": "--", "precision": None},
        )
        assert build_view(response, is_self=False)["city_line"] == ""

    def test_a_private_visitor_gets_no_approximate_line(self):
        """A dev server with no proxy in front: the self page's country reads
        "Private network", which is not a country-level fix."""
        response = dict(
            IP_RESPONSE,
            address="192.168.0.10",
            location={
                "ip": "192.168.0.10",
                "country_code": "--",
                "country_name": "Private network",
                "is_private": True,
                "precision": None,
            },
        )
        assert build_view(response, is_self=True)["city_line"] == ""

    def test_no_distance_to_a_country_centroid(self):
        assert (
            build_view(COUNTRY_LEVEL_RESPONSE, is_self=False)["distance_text"] is None
        )
        assert (
            build_view(REGISTERED_ONLY_RESPONSE, is_self=False)["distance_text"] is None
        )

    def test_no_distance_from_a_country_level_visitor(self):
        """The other end of the arc: a visitor GeoLite2 can only place in a
        country gets no "≈ N km from you" either, whatever the target."""
        response = dict(
            IP_RESPONSE, origin=dict(IP_RESPONSE["origin"], precision="country")
        )
        assert build_view(response, is_self=False)["distance_text"] is None

    def test_distance_between_two_city_fixes_is_unchanged(self):
        assert (
            build_view(IP_RESPONSE, is_self=False)["distance_text"]
            == "≈ 9,010 km from you"
        )

    def _rows(self, response):
        return {
            r["label"]: r["value"]
            for r in build_view(response, is_self=False)["geoip_rows"]
        }

    def test_the_accuracy_row_names_the_level(self):
        rows = self._rows(COUNTRY_LEVEL_RESPONSE)
        assert rows["Accuracy"] == "country-level (± 1000 km)"
        # The card is the raw GeoLite2 detail, and the JSON keeps these values
        # (the API contract), so the card prints them under the grade. Flip
        # the two lines below if the owner decides the Time zone row should
        # follow MCP and go blank at country level (backlog #2, 정할 것).
        assert rows["Coordinates"] == "37.751, -97.822"
        assert rows["Time zone"] == "America/Chicago"

    def test_the_accuracy_row_for_a_registered_only_country(self):
        rows = self._rows(REGISTERED_ONLY_RESPONSE)
        assert rows["Accuracy"] == "country-level · registered country only"
        assert "🇦🇺" in rows["Country"] and "AU" in rows["Country"]

    def test_a_gazetteer_centroid_has_no_radius_to_print(self):
        response = dict(
            IP_RESPONSE,
            location={
                **IP_RESPONSE["location"],
                "lat": 39.5,
                "lon": -98.35,
                "precision": "country",
            },
        )
        assert self._rows(response)["Accuracy"] == "country-level"

    def test_a_fallback_country_is_approximate_not_registered(self):
        """Before the first GeoLite2-City download, and on CI, the bundled
        geoip2fast snapshot answers with a country alone and no word on which
        key it came from (country_source None); the page draws the gazetteer's
        centroid. That is a country-level fix, not a registered-only one."""
        response = dict(
            IP_RESPONSE,
            location={
                **IP_RESPONSE["location"],
                "country_source": None,
                "lat": 39.5,
                "lon": -98.35,
                "precision": "country",
            },
        )
        assert build_view(response, is_self=False)["city_line"] == (
            "approximate · country-level"
        )
        assert self._rows(response)["Accuracy"] == "country-level"

    def test_a_city_fix_keeps_its_plain_radius(self):
        response = dict(
            IP_RESPONSE,
            location={
                **IP_RESPONSE["location"],
                "lat": 37.386,
                "lon": -122.084,
                "accuracy_km": 20,
            },
        )
        assert self._rows(response)["Accuracy"] == "± 20 km"


class TestSelfFlag:
    def test_self_lookup_is_flagged(self):
        view = build_view({"address": "1.2.3.4", "location": {}}, is_self=True)
        assert view["is_self"] is True

    def test_non_self_lookup_is_flagged(self):
        view = build_view({"address": "1.2.3.4", "location": {}}, is_self=False)
        assert view["is_self"] is False


def test_a_domain_lookup_offers_the_subdomains_accordion():
    view = build_view(
        {
            # "a" holds {"ip": ...} dicts, not bare strings -- see IP_RESPONSE /
            # DOMAIN_RESPONSE above; _tags() reads first_a["ip"].
            "address": "example.com",
            "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
            "location": {},
        },
        is_self=False,
    )
    ids = [item["id"] for item in view["accordions"]]
    assert "subdomains" in ids


def test_an_ip_lookup_does_not_offer_the_subdomains_accordion():
    """An IP address has no subdomains; offering the panel would invite a
    request that can only fail."""
    view = build_view(
        {"address": "8.8.8.8", "domain": {}, "location": {}}, is_self=False
    )
    ids = [item["id"] for item in view["accordions"]]
    assert "subdomains" not in ids


def test_the_kill_switch_removes_the_subdomains_accordion_for_a_domain():
    """Review M2. SUBDOMAIN_ENABLED=false must not leave the page still
    offering a panel whose only possible outcome is a 400 from the route --
    the flag gets flipped exactly when something is on fire."""
    view = build_view(
        {
            "address": "example.com",
            "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
            "location": {},
        },
        is_self=False,
        subdomains_enabled=False,
    )
    ids = [item["id"] for item in view["accordions"]]
    assert "subdomains" not in ids


def _subdomain_hint(subdomains=None):
    """The hint on the Subdomains accordion for a domain lookup."""
    response = {
        "address": "example.com",
        "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
        "location": {},
    }
    if subdomains is not None:
        response["subdomains"] = subdomains
    view = build_view(response, is_self=False)
    return next(i["hint"] for i in view["accordions"] if i["id"] == "subdomains")


def test_the_unopened_panel_invites_a_click_rather_than_naming_its_source():
    """Nothing is fetched until the accordion opens, so the hint says what
    opening it does. Where the data comes from is inside the panel."""
    assert _subdomain_hint() == "click to lookup"


def test_a_loaded_panel_reports_the_count():
    hint = _subdomain_hint(
        {"names": ["a.example.com"], "count": 29, "error": None, "stale": False}
    )
    assert hint == "29 subdomains found"


def test_a_single_result_is_not_pluralised():
    hint = _subdomain_hint(
        {"names": ["a.example.com"], "count": 1, "error": None, "stale": False}
    )
    assert hint == "1 subdomain found"


def test_a_failed_lookup_says_so_rather_than_inviting_another_click():
    hint = _subdomain_hint({"names": [], "count": 0, "error": "timed out"})
    assert hint == "lookup failed"


class TestWhoisNotRegistered:
    """An absent registration is an answer and differs from a timeout."""

    @staticmethod
    def _view(whois):
        return build_view(
            {
                "address": "docs.example.com",
                "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
                "location": {},
                "whois": whois,
            },
            is_self=False,
        )

    @staticmethod
    def _hint(view):
        return next(i["hint"] for i in view["accordions"] if i["id"] == "whois")

    @staticmethod
    def _status(whois):
        """The WHOIS facts column is only built for an IP target -- a domain
        gets DNS and certificate columns instead -- so this path is reached by
        an unallocated address, not by a subdomain."""
        view = build_view(
            {"address": "192.0.2.1", "domain": {}, "location": {}, "whois": whois},
            is_self=False,
        )
        col = next(c for c in view["facts"] if c["title"] == "WHOIS")
        return next(r for r in col["rows"] if r["label"] == "Status")

    def test_the_accordion_hint_distinguishes_the_two(self):
        assert self._hint(self._view({"error": "not registered"})) == "not registered"
        assert self._hint(self._view({"error": "WHOIS lookup timed out"})) == (
            "lookup failed"
        )
        assert self._hint(self._view(None)) == "lookup failed"

    def test_the_facts_column_has_three_states_not_two(self):
        not_reg = self._status({"error": "not registered"})
        assert not_reg["value"] == "not registered"
        assert not_reg["tone"] != "warning"  # nothing is wrong

        failed = self._status({"error": "WHOIS lookup timed out"})
        assert failed["value"] == "unavailable"
        assert failed["tone"] == "warning"

        ok = self._status({"registrar": "Example Registrar"})
        assert ok["value"] == "record found"  # the lookup's status, not the name's
        assert ok["tone"] == "success"


class TestWhoisOfTheRegistrableDomain:
    RECORD = {
        "source": "rdap",
        "name": "example.com",
        "registrar": "Example Registrar",
        "created": datetime.datetime(1995, 8, 14, 4, 0, tzinfo=UTC),
        "expires": datetime.datetime(2027, 8, 13, 4, 0, tzinfo=UTC),
    }

    @staticmethod
    def _hint(address, whois):
        view = build_view(
            {
                "address": address,
                "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
                "location": {},
                "whois": whois,
            },
            is_self=False,
        )
        return next(i["hint"] for i in view["accordions"] if i["id"] == "whois")

    def test_the_hint_leads_with_whose_registration_it_is(self):
        labelled = {
            **self.RECORD,
            "queried_name": "www.example.com",
            "registrable_domain": "example.com",
        }
        assert self._hint("www.example.com", labelled) == (
            "registration of example.com · Example Registrar · 1995 → 2027"
        )

    def test_the_names_own_record_reads_as_before(self):
        own = {
            **self.RECORD,
            "queried_name": "example.com",
            "registrable_domain": "example.com",
        }
        assert self._hint("example.com", own) == "Example Registrar · 1995 → 2027"
        assert self._hint("example.com", self.RECORD) == (
            "Example Registrar · 1995 → 2027"
        )

    def test_an_unregistered_registrable_domain_still_reads_not_registered(self):
        missing = {
            "error": "not registered",
            "queried_name": "www.nosuch-name.com",
            "registrable_domain": "nosuch-name.com",
        }
        assert self._hint("www.nosuch-name.com", missing) == "not registered"
        assert whois_display(missing) == {
            "Status": "no registration record for this name"
        }


THIN_RECORD = {"source": "whois", "name": "admin.ch", "thin": True}


class TestWhoisThinRecord:
    @staticmethod
    def _hint(whois):
        view = build_view(
            {
                "address": "admin.ch",
                "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
                "location": {},
                "whois": whois,
            },
            is_self=False,
        )
        return next(i["hint"] for i in view["accordions"] if i["id"] == "whois")

    @staticmethod
    def _status(whois):
        view = build_view(
            {"address": "192.0.2.1", "domain": {}, "location": {}, "whois": whois},
            is_self=False,
        )
        column = next(c for c in view["facts"] if c["title"] == "WHOIS")
        return next(row for row in column["rows"] if row["label"] == "Status")

    def test_the_hint_says_no_details_rather_than_registry_data(self):
        assert self._hint(THIN_RECORD) == "no details over WHOIS"
        assert self._hint({"source": "whois", "registrar": "cyon AG"}) == "cyon AG"
        parent = dict(
            THIN_RECORD, queried_name="www.admin.ch", registrable_domain="admin.ch"
        )
        assert self._hint(parent) == (
            "registration of admin.ch · no details over WHOIS"
        )

    def test_the_facts_column_has_a_fourth_state(self):
        thin = self._status(THIN_RECORD)
        assert (thin["value"], thin["tone"]) == ("no details", "muted")
        assert (
            self._status({"registrar": "Example Registrar"})["value"] == "record found"
        )
        assert self._status({"error": "not registered"})["value"] == "not registered"
        failed = self._status({"error": "WHOIS lookup timed out"})
        assert (failed["value"], failed["tone"]) == ("unavailable", "warning")

    def test_the_accordion_rows_are_the_two_facts_there_are(self):
        assert whois_display(THIN_RECORD) == {"Source": "WHOIS", "Name": "admin.ch"}

    def test_whois_fill_words_it_the_same(self):
        fill = whois_fill(THIN_RECORD)
        assert fill["hint"] == "no details over WHOIS"
        assert fill["column"][0] == {
            "label": "Status",
            "value": "no details",
            "tone": "muted",
        }


class TestStatusRow:
    """Two vocabularies reach the Status row -- RFC 8056's words from RDAP and
    ICANN's port-43 line from python-whois -- and neither says what a code
    means. Both render as the EPP code with its meaning."""

    PORT43 = "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
    GLOSSED = (
        "clientTransferProhibited — transfer lock set by the registrar "
        "(a common setting)"
    )

    def test_rdap_and_port_43_read_the_same(self):
        via_rdap = _normalize_rdap_domain(
            {"name": "x.com", "status": ["client transfer prohibited"]}, "x.com"
        )
        via_port43 = normalize_whois(
            {"domain_name": "x.com", "status": [self.PORT43]}, "x.com"
        )
        assert whois_display(via_rdap)["Status"] == self.GLOSSED
        assert whois_display(via_port43)["Status"] == self.GLOSSED

    def test_a_registry_specific_word_shows_as_itself(self):
        # DENIC answers "connect"; no table knows it, so it is not reworded.
        record = normalize_whois(
            {"domain_name": "heise.de", "status": "connect"}, "heise.de"
        )
        assert whois_display(record)["Status"] == "connect"

    def test_several_codes_are_separated_by_semicolons(self):
        record = {
            "registrar": "Example Registrar",
            "status": ["client hold", "server transfer prohibited"],
        }
        status = whois_display(record)["Status"]
        assert status.startswith("clientHold — ")
        assert "; serverTransferProhibited — transfer lock set by the registry" in (
            status
        )

    def test_an_ip_allocations_status_is_not_an_epp_code(self):
        # RIR RDAP says "active" of a network. Folded to EPP's "ok" and glossed
        # with domain semantics it would be wrong, so an IP record keeps its
        # words: the record has no registrar key, which is how it is told.
        record = _normalize_rdap_ip(
            {"name": "GOGL", "status": ["active"], "rir": "arin"}, "8.8.8.8"
        )
        assert whois_display(record)["Status"] == "active"

    def test_the_other_rows_are_untouched(self):
        record = _normalize_rdap_domain(
            {
                "name": "x.com",
                "status": ["client hold"],
                "nameservers": ["ns1.x.com", "ns2.x.com"],
            },
            "x.com",
        )
        out = whois_display(record)
        assert out["Name servers"] == "ns1.x.com, ns2.x.com"
        assert out["Source"] == "RDAP"


class TestStatusTag:
    """A hold or a pending delete is the one registry status a visitor needs
    to see before opening the WHOIS accordion: the name is out of the DNS or
    about to be dropped. The tag is the code, which the accordion glosses."""

    @staticmethod
    def _view(status, reputation=None):
        # ssl=None: the fixture certificate has expired since it was written,
        # and its "TLS expired" tag would be a second danger tag here.
        whois = dict(DOMAIN_RESPONSE["whois"], status=status)
        response = dict(DOMAIN_RESPONSE, whois=whois, ssl=None)
        if reputation is not None:
            response["reputation"] = reputation
        return build_view(response, is_self=False)

    def test_a_hold_earns_one_danger_tag_named_for_the_code(self):
        assert {"text": "clientHold", "tone": "danger"} in self._view(["client hold"])[
            "tags"
        ]

    def test_two_danger_codes_share_the_one_tag(self):
        tags = self._view(["clientHold", "pending delete", "ok"])["tags"]
        assert {"text": "clientHold · pendingDelete", "tone": "danger"} in tags
        assert sum(tag["tone"] == "danger" for tag in tags) == 1

    def test_a_lock_or_an_unknown_word_earns_no_tag(self):
        for status in (["client transfer prohibited"], ["connect"], [], None):
            tags = self._view(status)["tags"]
            assert all(tag["tone"] != "danger" for tag in tags), status

    def test_an_ip_target_never_gets_one(self):
        # The hero's IP branch returns before any registry status is read: an
        # allocation's own words, and even a record that would earn the tag on
        # a domain page, earn none here.
        for whois in (
            {"source": "rdap", "name": "GOGL", "rir": "arin", "status": ["active"]},
            {"source": "rdap", "registrar": "x", "status": ["server hold"]},
        ):
            view = build_view(dict(IP_RESPONSE, whois=whois), is_self=True)
            assert all(tag["tone"] != "danger" for tag in view["tags"]), whois

    def test_the_tag_is_not_a_reputation_signal(self):
        # reputation.grade() sums the weights of `signals`; a hold is not one,
        # so the card, its level and the list's own tag read the same with and
        # without it.
        tor = {
            "id": "tor_exit",
            "label": "Tor exit",
            "source": "Tor Project",
            "as_of": "2026-10-09T06:13:20Z",
        }
        reputation = {
            "level": "medium",
            "signals": [dict(tor, weight=50)],
            "checked": [tor],
            "unavailable": [],
            "attribution": [],
        }
        held = self._view(["server hold"], reputation)
        plain = self._view(["ok"], reputation)
        assert {"text": "serverHold", "tone": "danger"} in held["tags"]
        assert {"text": "Tor exit", "tone": "warning"} in plain["tags"]
        assert held["reputation"] == plain["reputation"]
        assert held["reputation"]["rows"][0]["value"] == "Medium"
        assert [t for t in held["tags"] if t["text"] != "serverHold"] == plain["tags"]

    def test_the_link_preview_does_not_change(self):
        # _summary() reads only the TLS tags off the hero.
        assert "serverHold" not in self._view(["server hold"])["description"]


class TestReputationLevelWording:
    """The Level row said "None" for reputation.LEVELS[0], which beside
    "Listed on 1 of 5 lists" (an informational datacenter listing) reads as
    "no level at all". The JSON keeps the word `none`; only the card changes."""

    TOR = {
        "id": "tor_exit",
        "label": "Tor exit",
        "source": "Tor Project",
        "as_of": "2026-10-09T06:13:20Z",
    }
    DATACENTER = {
        "id": "datacenter",
        "label": "Datacenter",
        "source": "X4BNet lists_vpn",
        "as_of": "2026-10-09T06:13:20Z",
    }

    def _card(self, level, signals=(), score=0):
        if level is None:
            score = None
        return reputation_view(
            {
                "level": level,
                "score": score,
                "signals": list(signals),
                "checked": [] if level is None else [self.TOR, self.DATACENTER],
                "unavailable": [],
                "attribution": [],
            }
        )

    def test_none_reads_as_no_signals(self):
        card = self._card("none", [dict(self.DATACENTER, weight=0)])
        assert card["rows"][0] == {
            "label": "Level",
            "value": "No signals",
            "tone": "default",
        }
        assert card["rows"][1] == {
            "label": "Score",
            "value": "0 of 100",
            "tone": "default",
        }
        assert card["summary"].startswith("Listed on 1 of the 2 lists checked")
        assert card["hint"] == "0 · none · Datacenter"

    def test_no_list_read_is_still_unknown(self):
        card = self._card(None)
        assert card["rows"][0]["value"] == "Unknown"
        assert card["rows"][0]["tone"] == "muted"
        assert card["rows"][1]["value"] == "Unknown"
        assert "0" not in card["rows"][1]["value"]

    def test_graded_levels_are_unchanged(self):
        card = self._card("medium", [dict(self.TOR, weight=50)], score=50)
        assert card["rows"][0]["value"] == "Medium"
        assert card["rows"][0]["tone"] == "warning"
        assert card["rows"][1]["value"] == "50 of 100"
        assert card["hint"] == "50 · medium · Tor exit"


# --- forward-confirmed reverse DNS ---------------------------------------------------


def _sweep(a=(), aaaa=(), a_status="ok", aaaa_status="ok"):
    """The sweep of a PTR name, in the shape DomainManager.get_records()
    returns: {"ip", "ttl"} dicts, and each type's dns_status() under "status"."""
    return {
        "queried_name": "dns.google",
        "a": [{"ip": ip, "ttl": 300} for ip in a],
        "aaaa": [{"ip": ip, "ttl": 300} for ip in aaaa],
        "ns": [],
        "status": {"a": a_status, "aaaa": aaaa_status},
    }


class TestFcrdnsState:
    """Whether an IP's PTR name resolves back to it, read off the PTR and the
    sweep of that name the lookup already made: no query of its own."""

    def test_a_match_is_confirmed(self):
        sweep = _sweep(a=["8.8.8.8"])
        assert fcrdns_state("dns.google.", sweep, "8.8.8.8") == "confirmed"

    def test_one_match_in_a_round_robin_is_enough(self):
        sweep = _sweep(a=["8.8.4.4", "8.8.8.8"])
        assert fcrdns_state("dns.google.", sweep, "8.8.8.8") == "confirmed"

    def test_addresses_that_are_all_elsewhere_are_unconfirmed(self):
        sweep = _sweep(a=["216.239.32.10", "216.239.34.10"])
        assert fcrdns_state("dns.google.", sweep, "8.8.8.8") == "unconfirmed"

    @pytest.mark.parametrize("status", ["noanswer", "nxdomain"])
    def test_a_ptr_name_with_no_address_is_unconfirmed(self, status):
        """noanswer and nxdomain are answers: the name has no address of that
        family, or does not exist, so it cannot point back."""
        sweep = _sweep(a_status=status)
        assert fcrdns_state("dns.google.", sweep, "8.8.8.8") == "unconfirmed"

    @pytest.mark.parametrize("status", ["timeout", "servfail", "error"])
    def test_a_failed_forward_query_is_unknown_never_unconfirmed(self, status):
        sweep = _sweep(a_status=status)
        assert fcrdns_state("dns.google.", sweep, "8.8.8.8") == "unknown"

    def test_no_ptr(self):
        assert fcrdns_state(None, {}, "8.8.8.8") == "no_ptr"
        assert fcrdns_state("", _sweep(a=["8.8.8.8"]), "8.8.8.8") == "no_ptr"

    def test_an_ipv6_address_is_compared_with_aaaa(self):
        v6 = "2001:4860:4860::8888"
        sweep = _sweep(a=["8.8.8.8"], aaaa=["2001:4860:4860::8844", v6])
        assert fcrdns_state("dns.google.", sweep, v6) == "confirmed"

    def test_an_ipv6_address_whose_ptr_name_has_only_a_is_unconfirmed(self):
        """One family is compared: an A record, even the same host's IPv4
        address, does not confirm the PTR of an IPv6 address."""
        sweep = _sweep(a=["8.8.8.8"], aaaa_status="noanswer")
        v6 = "2001:4860:4860::8888"
        assert fcrdns_state("dns.google.", sweep, v6) == "unconfirmed"

    def test_a_failed_aaaa_query_is_unknown_for_ipv6_whatever_a_says(self):
        sweep = _sweep(a=["8.8.8.8"], aaaa_status="timeout")
        v6 = "2001:4860:4860::8888"
        assert fcrdns_state("dns.google.", sweep, v6) == "unknown"

    @pytest.mark.parametrize(
        ("address", "records"),
        [
            # What a dual-stack socket reports for an IPv4 visitor.
            ("::ffff:8.8.8.8", {"a": ["8.8.8.8"]}),
            ("2001:4860:4860:0:0:0:0:8888", {"aaaa": ["2001:4860:4860::8888"]}),
            ("2404:6800:4004:80B::200E", {"aaaa": ["2404:6800:4004:80b::200e"]}),
        ],
    )
    def test_spellings_of_one_address_are_one_address(self, address, records):
        """The self page's address comes from the socket or a proxy header, not
        through gather(), which is what gives every other target one spelling."""
        assert fcrdns_state("dns.google.", _sweep(**records), address) == "confirmed"

    def test_there_is_nothing_to_judge_for_a_domain(self):
        """A domain's sweep is of the domain itself, not of a PTR name."""
        sweep = _sweep(a=["93.184.216.34"])
        assert fcrdns_state(None, sweep, "example.com") is None

    def test_there_is_nothing_to_judge_without_the_sweep(self):
        """?fields= on `/` asks for the visitor's PTR but sweeps nothing."""
        assert fcrdns_state("dns.google.", None, "8.8.8.8") is None
        assert fcrdns_state("dns.google.", {}, "8.8.8.8") is None


def _reverse_rows(response, is_self=False):
    column = build_view(response, is_self=is_self)["facts"][1]
    assert column["title"] == "REVERSE DNS"
    return {row["label"]: row for row in column["rows"]}


class TestReverseColumnVerdict:
    def test_a_ptr_that_points_back_says_confirmed(self):
        # IP_RESPONSE's PTR is dns.google., whose A records include 8.8.8.8.
        assert _reverse_rows(IP_RESPONSE)["PTR"] == {
            "label": "PTR",
            "value": "dns.google.",
            "suffix": " → confirmed",
            "tone": "success",
        }

    def test_a_ptr_that_points_elsewhere_says_it_does_not_point_back(self):
        response = {**IP_RESPONSE, "domain": _sweep(a=["216.239.32.10"])}
        assert _reverse_rows(response)["PTR"] == {
            "label": "PTR",
            "value": "dns.google.",
            "suffix": " → does not point back",
            "tone": "warning",
        }

    def test_the_wording_never_accuses(self):
        """CDNs and shared hosts fail this legitimately."""
        response = {**IP_RESPONSE, "domain": _sweep(a=["216.239.32.10"])}
        text = " ".join(
            f"{row['value']}{row.get('suffix', '')}".lower()
            for row in _reverse_rows(response).values()
        )
        for word in ("spoof", "forged", "fake", "invalid"):
            assert word not in text

    def test_a_failed_forward_query_leaves_the_name_as_it_was(self):
        """The A row already says the query failed; the PTR row claims nothing."""
        rows = _reverse_rows({**IP_RESPONSE, "domain": _sweep(a_status="timeout")})
        assert rows["PTR"] == {
            "label": "PTR",
            "value": "dns.google.",
            "tone": "default",
        }
        assert rows["A"] == {"label": "A", "value": "(timed out)", "tone": "warning"}

    def test_no_ptr_is_still_a_muted_dash(self):
        location = {**IP_RESPONSE["location"], "reverse_dns": None}
        response = {**IP_RESPONSE, "location": location, "domain": {}}
        assert _reverse_rows(response)["PTR"] == {
            "label": "PTR",
            "value": DASH,
            "tone": "muted",
        }

    def test_the_self_page_judges_the_visitors_own_address(self):
        """build_view gives the self page the same column; its address can be
        the ::ffff: form a dual-stack socket reports."""
        response = {**IP_RESPONSE, "address": "::ffff:8.8.8.8"}
        row = _reverse_rows(response, is_self=True)["PTR"]
        assert row["value"] == "dns.google."
        assert row["suffix"] == " → confirmed"


def _fact(view, title, label):
    column = next(c for c in view["facts"] if c["title"] == title)
    return next(r for r in column["rows"] if r["label"] == label)


class TestLookupLinks:
    """build_view() links nothing on its own. main passes its rule
    (lookup_href) as link_for; this module stays free of lookup, whose import
    builds the GeoIP, suffix-list and DNS managers."""

    @staticmethod
    def _link_for(value):
        return "/" + value.rstrip(".")

    def test_without_a_link_function_nothing_carries_an_href(self):
        """Not even href=None: every facts row and tag is the dict it always
        was, and tests across the suite compare those dicts whole."""
        for response in (IP_RESPONSE, DOMAIN_RESPONSE):
            view = build_view(response, is_self=False)
            rows = [row for column in view["facts"] for row in column["rows"]]
            assert not any("href" in row for row in rows)
            assert not any("href" in tag for tag in view["tags"])
            assert not any(ns["href"] for ns in view["whois_name_servers"])

    def test_the_ptr_row_takes_the_link(self):
        # No sweep of the PTR name (domain={}), so the row is the name alone.
        view = build_view(
            dict(IP_RESPONSE, domain={}), is_self=True, link_for=self._link_for
        )
        ptr = _fact(view, "REVERSE DNS", "PTR")
        assert (ptr["value"], ptr["href"]) == ("dns.google.", "/dns.google")
        assert "suffix" not in ptr

    def test_a_ptr_with_a_verdict_links_the_name_and_keeps_the_verdict_apart(self):
        """The href is the name's; the verdict stays its own `suffix`, which
        the template prints after the anchor as plain text."""
        view = build_view(IP_RESPONSE, is_self=True, link_for=self._link_for)
        assert _fact(view, "REVERSE DNS", "PTR") == {
            "label": "PTR",
            "value": "dns.google.",
            "suffix": " → confirmed",
            "tone": "success",
            "href": "/dns.google",
        }

    def test_the_rdns_row_takes_the_link(self):
        location = {**DOMAIN_RESPONSE["location"], "reverse_dns": "lhr25s34.1e100.net."}
        view = build_view(
            dict(DOMAIN_RESPONSE, location=location),
            is_self=False,
            link_for=self._link_for,
        )
        rdns = _fact(view, "NETWORK", "rDNS")
        assert rdns["value"] == "lhr25s34.1e100.net."
        assert rdns["href"] == "/lhr25s34.1e100.net"

    def test_a_missing_ptr_is_a_dash_with_no_link(self):
        location = {**IP_RESPONSE["location"], "reverse_dns": None}
        view = build_view(
            dict(IP_RESPONSE, location=location), is_self=True, link_for=self._link_for
        )
        ptr = _fact(view, "REVERSE DNS", "PTR")
        assert ptr["value"] == DASH
        assert "href" not in ptr

    def test_a_value_the_rule_refuses_carries_no_href(self):
        """link_for's None (a private address, a name with no public suffix)
        leaves the row as it was, not with href=None."""
        view = build_view(IP_RESPONSE, is_self=True, link_for=lambda value: None)
        assert "href" not in _fact(view, "REVERSE DNS", "PTR")

    def test_the_address_tag_links_to_the_address(self):
        view = build_view(DOMAIN_RESPONSE, is_self=False, link_for=self._link_for)
        tag = next(t for t in view["tags"] if t["text"].startswith("A → "))
        assert tag["href"] == "/142.250.207.46"
        assert all("href" not in t for t in view["tags"] if t is not tag)

    def test_name_servers_become_one_entry_each_in_the_row_s_order(self):
        view = build_view(DOMAIN_RESPONSE, is_self=False, link_for=self._link_for)
        assert view["whois_name_servers"] == [
            {"text": "ns1.google.com", "href": "/ns1.google.com"},
            {"text": "ns2.google.com", "href": "/ns2.google.com"},
        ]
        # The same names in the same order as the row's text, which the
        # template shows when there is nothing to link.
        assert whois_display(DOMAIN_RESPONSE["whois"])["Name servers"] == (
            "ns1.google.com, ns2.google.com"
        )

    def test_duplicate_and_empty_name_servers_collapse_as_the_row_text_does(self):
        whois = {
            **DOMAIN_RESPONSE["whois"],
            "name_servers": ["ns1.google.com", "ns1.google.com", "", None],
        }
        view = build_view(
            dict(DOMAIN_RESPONSE, whois=whois), is_self=False, link_for=self._link_for
        )
        assert [ns["text"] for ns in view["whois_name_servers"]] == ["ns1.google.com"]

    def test_a_record_with_no_name_servers_gives_an_empty_list(self):
        assert (
            build_view(IP_RESPONSE, is_self=True, link_for=self._link_for)[
                "whois_name_servers"
            ]
            == []
        )
        errored = dict(DOMAIN_RESPONSE, whois={"error": "WHOIS lookup failed"})
        assert (
            build_view(errored, is_self=False, link_for=self._link_for)[
                "whois_name_servers"
            ]
            == []
        )


# --- registration and certificate age (#23) ----------------------------------

# Ages are counted against this fixed clock where the function takes `now`.
# whois_display and build_view read the real clock, so their dates are built
# relative to it: N days before now floors to exactly N whole days.
NOW = datetime.datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def _days_ago(days: float) -> datetime.datetime:
    return datetime.datetime.now(UTC) - datetime.timedelta(days=days)


def _domain_record(**fields) -> dict:
    """A domain's canonical record. Both domain shapes always carry a
    `registrar` key, None included, and the WHOIS panel tells a domain's
    record from an address block's by it, for the Age row as for Status."""
    return {"source": "rdap", "registrar": "Example Registrar", **fields}


class TestAgeDays:
    """viewmodel._age_days: whole days in UTC, and None rather than an
    exception for anything it cannot read."""

    def test_an_aware_datetime(self):
        assert _age_days(datetime.datetime(2026, 9, 15, 12, 0, tzinfo=UTC), NOW) == 25

    def test_a_naive_datetime_is_read_as_utc(self):
        # python-whois hands back naive datetimes.
        assert _age_days(datetime.datetime(2026, 9, 15, 12, 0), NOW) == 25

    def test_another_timezone_is_converted(self):
        seoul = datetime.timezone(datetime.timedelta(hours=9))
        created = datetime.datetime(2026, 9, 15, 21, 0, tzinfo=seoul)
        assert _age_days(created, NOW) == 25

    def test_an_iso_string(self):
        # The odd WHOIS record hands back a string, which _year already allows.
        assert _age_days("2026-09-15T12:00:00Z", NOW) == 25
        assert _age_days("2026-09-15", NOW) == 25

    def test_anything_unreadable_has_no_age(self):
        for value in ("before Aug-1996", "", None, 12345):
            assert _age_days(value, NOW) is None

    def test_up_to_a_day_ahead_counts_as_today(self):
        """A registry's naive local time east of UTC lands a few hours ahead."""
        ahead = datetime.datetime(2026, 10, 10, 20, 0, tzinfo=UTC)
        assert _age_days(ahead, NOW) == 0

    def test_further_ahead_is_bad_data_not_a_negative_age(self):
        assert _age_days(datetime.datetime(2026, 10, 12, tzinfo=UTC), NOW) is None

    def test_the_default_clock_is_now(self):
        assert _age_days(_days_ago(6)) == 6


class TestRegistrationAndCertAge:
    def test_registration_age_counts_created_and_updated(self):
        record = {
            "source": "rdap",
            "created": datetime.datetime(2026, 9, 15, 12, 0, tzinfo=UTC),
            "updated": datetime.datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
        }
        assert registration_age(record, NOW) == (25, 2)

    def test_no_record_has_no_age(self):
        for record in (
            None,
            {},
            {"error": "WHOIS lookup timed out"},
            {"error": "not registered"},
        ):
            assert registration_age(record, NOW) == (None, None)

    def test_cert_age_reads_getpeercerts_not_before(self):
        assert cert_age({"notBefore": "Sep 30 12:00:00 2026 GMT"}, NOW) == 10
        # OpenSSL pads a one-digit day with a space.
        assert cert_age({"notBefore": "Oct  9 12:00:00 2026 GMT"}, NOW) == 1

    def test_cert_age_without_a_readable_date_is_none(self):
        for ssl_data in (
            None,
            {},
            {"notBefore": "garbage"},
            {"error": "port 443 unreachable", "reason": "timed out"},
        ):
            assert cert_age(ssl_data, NOW) is None

    def test_valid_from_still_reads_as_before(self):
        """The SSL panel's date now parses through the same helper as
        cert_age; a malformed value is still shown as it came."""
        rows = {r["label"]: r["value"] for r in ssl_rows(FULL_SSL, "example.com")}
        assert rows["Valid from"] == "2026-06-01"
        broken = dict(FULL_SSL, notBefore="garbage")
        rows = {r["label"]: r["value"] for r in ssl_rows(broken, "example.com")}
        assert rows["Valid from"] == "garbage"


class TestWhoisAgeRow:
    """The WHOIS panel's Age row: the arithmetic a reader would otherwise do
    on Created and Updated."""

    def test_age_follows_updated_with_the_update_beside_it(self):
        record = _domain_record(
            name="example.com",
            created=_days_ago(6),
            updated=_days_ago(2),
            expires=datetime.datetime(2027, 9, 14, 4, 0, tzinfo=UTC),
        )
        out = whois_display(record)
        assert out["Age"] == "6 days (updated 2 days ago)"
        labels = list(out)
        assert labels.index("Age") == labels.index("Updated") + 1
        assert labels.index("Age") < labels.index("Expires")

    def test_without_an_update_the_age_stands_alone(self):
        assert whois_display(_domain_record(created=_days_ago(6)))["Age"] == "6 days"

    def test_one_day_and_today_read_as_words(self):
        record = _domain_record(created=_days_ago(1), updated=_days_ago(0))
        assert whois_display(record)["Age"] == "1 day (updated today)"

    def test_an_old_name_counts_in_thousands(self):
        # google.com, created in 1997 and updated in 2024.
        age = whois_display(DOMAIN_RESPONSE["whois"])["Age"]
        assert re.fullmatch(r"\d{1,3}(,\d{3})+ days \(updated [\d,]+ days ago\)", age)

    def test_no_row_without_a_readable_created_date(self):
        """A date that cannot be read leaves the row out instead of raising;
        the Created row still shows what the registry sent."""
        out = whois_display(
            _domain_record(source="whois", name="example.uk", created="before Aug-1996")
        )
        assert "Age" not in out
        assert out["Created"] == "before Aug-1996"
        assert "Age" not in whois_display(_domain_record(updated=_days_ago(2)))

    def test_the_whois_fallbacks_list_dates_still_age(self):
        """python-whois's lists are folded to their first value upstream
        (rdap._first), so the row counts from one date. The record's
        registrar is None here: the key alone makes it a domain's."""
        raw = {
            "domain_name": "example.com",
            "creation_date": [_days_ago(6), _days_ago(5)],
            "updated_date": [_days_ago(2)],
        }
        out = whois_display(normalize_whois(raw, "example.com"))
        assert out["Age"] == "6 days (updated 2 days ago)"


_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _asn1(when: datetime.datetime) -> str:
    """A time in getpeercert()'s print form, 'Oct  9 12:00:00 2026 GMT'. Not
    strftime: its %b follows the process locale (managers._asn1_time)."""
    return f"{_MONTHS[when.month - 1]} {when.day:2d} {when:%H:%M:%S} {when.year} GMT"


def _registered(days_ago: float) -> dict:
    """DOMAIN_RESPONSE with its registration created `days_ago` days ago."""
    whois = dict(DOMAIN_RESPONSE["whois"], created=_days_ago(days_ago))
    return dict(DOMAIN_RESPONSE, whois=whois)


def _registered_tags(response: dict) -> list[str]:
    tags = build_view(response, is_self=False)["tags"]
    return [tag["text"] for tag in tags if tag["text"].startswith("REGISTERED")]


class TestYoungDomainTag:
    """The hero's amber tag for a domain registered days ago."""

    @pytest.fixture(autouse=True)
    def threshold(self, monkeypatch):
        # A developer's .env may set YOUNG_DOMAIN_DAYS; these boundaries are 30's.
        monkeypatch.setattr(viewmodel, "YOUNG_DOMAIN_DAYS", 30)

    def test_a_name_registered_25_days_ago_is_tagged_amber(self):
        view = build_view(_registered(25), is_self=False)
        assert {"text": "REGISTERED 25 DAYS AGO", "tone": "warning"} in view["tags"]

    def test_29_days_is_tagged_and_30_is_not(self):
        assert _registered_tags(_registered(29)) == ["REGISTERED 29 DAYS AGO"]
        assert _registered_tags(_registered(30)) == []

    def test_today_and_one_day_read_as_words(self):
        assert _registered_tags(_registered(2 / 24)) == ["REGISTERED TODAY"]
        assert _registered_tags(_registered(1 + 1 / 24)) == ["REGISTERED 1 DAY AGO"]

    def test_a_registry_clock_hours_ahead_is_today_and_days_ahead_is_no_tag(self):
        """python-whois hands back a registry's local time as a naive datetime,
        read as UTC: a name registered minutes ago in Seoul reads nine hours
        ahead. That is today, not a negative age; two days ahead is bad data,
        and no tag rather than an exception."""
        seoul = datetime.datetime.now(UTC) + datetime.timedelta(hours=9)
        whois = dict(DOMAIN_RESPONSE["whois"], created=seoul.replace(tzinfo=None))
        assert _registered_tags(dict(DOMAIN_RESPONSE, whois=whois)) == [
            "REGISTERED TODAY"
        ]
        assert _registered_tags(_registered(-2)) == []

    def test_an_old_name_is_not_tagged(self):
        # google.com, created in 1997.
        assert _registered_tags(DOMAIN_RESPONSE) == []

    def test_an_old_name_updated_yesterday_is_not_tagged(self):
        """A name caught at an expiry auction keeps its old created date. The
        WHOIS panel's Age row keeps the fresh update beside it; the tag goes by
        created alone."""
        whois = dict(DOMAIN_RESPONSE["whois"], updated=_days_ago(1))
        assert _registered_tags(dict(DOMAIN_RESPONSE, whois=whois)) == []
        assert whois_display(whois)["Age"].endswith(" (updated 1 day ago)")

    def test_zero_turns_the_tag_off(self, monkeypatch):
        monkeypatch.setattr(viewmodel, "YOUNG_DOMAIN_DAYS", 0)
        assert _registered_tags(_registered(2 / 24)) == []

    def test_an_unreadable_or_missing_date_is_no_tag(self):
        for created in ("before Aug-1996", None):
            whois = dict(DOMAIN_RESPONSE["whois"], created=created)
            assert _registered_tags(dict(DOMAIN_RESPONSE, whois=whois)) == []

    def test_no_registration_is_no_tag(self):
        for whois in (
            {"error": "WHOIS lookup timed out"},
            {"error": "not registered"},
            None,
        ):
            assert _registered_tags(dict(DOMAIN_RESPONSE, whois=whois)) == []

    def test_an_ip_lookup_is_never_tagged(self):
        whois = {"source": "rdap", "rir": "arin", "created": _days_ago(3)}
        assert _registered_tags(dict(IP_RESPONSE, whois=whois)) == []

    def test_a_young_certificate_changes_no_tag(self):
        """ACME renews every few weeks, so nearly every certificate is young:
        a tag for it would sit on nearly every page and say nothing."""
        issued = dict(FULL_SSL, notBefore=_asn1(_days_ago(1)))
        assert cert_age(issued) == 1
        young = build_view(dict(DOMAIN_RESPONSE, ssl=issued), is_self=False)
        old = build_view(dict(DOMAIN_RESPONSE, ssl=FULL_SSL), is_self=False)
        assert young["tags"] == old["tags"]

    def test_the_link_preview_does_not_mention_it(self):
        """_summary() reads only the TLS tags, so og:description is the same
        for a name registered yesterday as for one registered in 1997."""
        young = build_view(_registered(1), is_self=False)
        old = build_view(DOMAIN_RESPONSE, is_self=False)
        assert young["description"] == old["description"]
        assert "REGISTERED" not in young["description"]


class TestParseDmarc:
    """Read for display only, and leniently: what a domain publishes is shown
    as published, never graded."""

    def test_the_four_tags_are_read(self):
        assert _parse_dmarc(
            "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:d@example.com"
        ) == {
            "p": "quarantine",
            "sp": "reject",
            "pct": "50",
            "rua": "mailto:d@example.com",
        }

    def test_case_spaces_and_stray_semicolons_are_tolerated(self):
        assert _parse_dmarc(" V = DMARC1 ;;P = Reject ; SP=None;") == {
            "p": "reject",
            "sp": "none",
        }

    def test_a_record_joined_from_255_byte_strings_reads_whole(self):
        head = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@exam"
        assert _parse_dmarc(head + "ple.com")["rua"] == (
            "mailto:dmarc-reports@example.com"
        )

    def test_unknown_tags_and_junk_are_skipped(self):
        assert _parse_dmarc("v=DMARC1; p=none; adkim=s; foo=bar; junk; =x") == {
            "p": "none"
        }

    def test_a_policy_that_is_not_one_is_dropped(self):
        assert _parse_dmarc("v=DMARC1; p=rejected; sp=") == {}

    def test_the_first_of_a_repeated_tag_wins(self):
        assert _parse_dmarc("v=DMARC1; p=none; p=reject") == {"p": "none"}

    def test_text_that_is_not_dmarc_reads_as_nothing(self):
        assert _parse_dmarc("v=spf1 -all") == {}
        # DMARC1 must match exactly (RFC 7489 §6.3): receivers ignore this one.
        assert _parse_dmarc("v=dmarc1; p=reject") == {}
        assert _parse_dmarc("p=reject; v=DMARC1") == {}
        assert _parse_dmarc("") == {}


def _dmarc_domain(*texts, source="_dmarc.example.com", queried="example.com"):
    return {
        "queried_name": queried,
        "dmarc": [{"text": t, "ttl": 300, "queried_name": source} for t in texts],
        "status": {"dmarc": "ok"},
    }


class TestDmarcPolicy:
    def test_the_names_own_record_governs_by_its_p(self):
        domain = _dmarc_domain("v=DMARC1; p=reject; sp=none")
        assert dmarc_policy(domain) == {
            "tag": "p",
            "policy": "reject",
            "pct": None,
            "inherited_from": None,
        }

    def test_an_inherited_record_governs_a_subdomain_by_its_sp(self):
        """RFC 7489 §6.3: sp= is the policy for the domain's subdomains."""
        domain = _dmarc_domain("v=DMARC1; p=reject; sp=none", queried="www.example.com")
        assert dmarc_policy(domain) == {
            "tag": "sp",
            "policy": "none",
            "pct": None,
            "inherited_from": "example.com",
        }

    def test_an_inherited_record_without_sp_governs_by_its_p(self):
        domain = _dmarc_domain("v=DMARC1; p=quarantine", queried="www.example.com")
        assert dmarc_policy(domain)["tag"] == "p"
        assert dmarc_policy(domain)["policy"] == "quarantine"

    def test_pct_is_kept_only_when_it_narrows_the_policy(self):
        assert dmarc_policy(_dmarc_domain("v=DMARC1; p=reject; pct=25"))["pct"] == "25"
        assert dmarc_policy(_dmarc_domain("v=DMARC1; p=reject; pct=100"))["pct"] is None

    def test_a_record_with_no_policy_has_none(self):
        domain = _dmarc_domain("v=DMARC1; rua=mailto:d@example.com")
        assert dmarc_policy(domain)["policy"] is None

    def test_two_records_are_no_policy(self):
        """RFC 7489 §6.6.3 ends policy discovery when a name has two."""
        domain = _dmarc_domain("v=DMARC1; p=none", "v=DMARC1; p=reject")
        assert dmarc_policy(domain) is None

    def test_no_record_is_no_policy(self):
        assert dmarc_policy({"dmarc": [], "status": {"dmarc": "nxdomain"}}) is None
        assert dmarc_policy({}) is None
        assert dmarc_policy(None) is None


def _mail_fact(domain):
    column = build_view(dict(DOMAIN_RESPONSE, domain=domain), is_self=False)
    rows = {row["label"]: row for row in column["facts"][1]["rows"]}
    return rows["Mail"]["value"], rows["Mail"]["tone"]


SPF = [{"text": "v=spf1 -all", "ttl": 300}]


class TestMailRow:
    def test_spf_and_the_policy_on_one_line(self):
        domain = {**_dmarc_domain("v=DMARC1; p=reject"), "spf": SPF}
        assert _mail_fact(domain) == ("SPF yes · DMARC p=reject", "default")

    def test_p_none_is_an_answer_not_a_warning(self):
        """p=none asks receivers for reports only: monitoring, not a fault."""
        domain = {**_dmarc_domain("v=DMARC1; p=none"), "spf": SPF}
        assert _mail_fact(domain) == ("SPF yes · DMARC p=none", "default")

    def test_an_inherited_policy_names_the_domain_it_came_from(self):
        domain = _dmarc_domain(
            "v=DMARC1; p=reject; sp=quarantine; pct=50", queried="www.example.com"
        )
        assert _mail_fact(domain) == (
            "SPF — · DMARC sp=quarantine pct=50 (example.com)",
            "default",
        )

    def test_no_record_is_a_dash(self):
        domain = {"spf": SPF, "dmarc": [], "status": {"dmarc": "nxdomain"}}
        assert _mail_fact(domain) == ("SPF yes · DMARC —", "default")

    def test_neither_is_a_single_dash(self):
        domain = {"spf": [], "dmarc": [], "status": {"spf": "noanswer"}}
        assert _mail_fact(domain) == ("—", "default")

    def test_a_failed_query_says_so_and_warns(self):
        domain = {"spf": SPF, "dmarc": [], "status": {"dmarc": "timeout"}}
        assert _mail_fact(domain) == ("SPF yes · DMARC (timed out)", "warning")
        domain = {"spf": [], "dmarc": [], "status": {"spf": "servfail"}}
        assert _mail_fact(domain) == ("SPF (server failure) · DMARC —", "warning")

    def test_two_records_are_counted_not_read(self):
        domain = _dmarc_domain("v=DMARC1; p=none", "v=DMARC1; p=reject")
        assert _mail_fact(domain) == ("SPF — · DMARC 2 records", "default")

    def test_a_record_without_a_policy_says_so(self):
        domain = _dmarc_domain("v=DMARC1; rua=mailto:d@example.com")
        assert _mail_fact(domain) == ("SPF — · DMARC no p= tag", "default")
