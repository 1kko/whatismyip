import datetime
import re

import pytest

import overview
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
    reverse_ip_view,
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


def _hints(view):
    """Each section's hint, by section id (the contents list and the heading
    both print it)."""
    return {section["id"]: section["hint"] for section in view["sections"]}


class TestCardsOfTheFixtures:
    """What the facts columns used to say, now on the status cards
    (overview.py) and in the Certificate section's rows."""

    def test_failed_whois_is_a_failure_not_an_error_page(self):
        card = overview.registration_card(IP_RESPONSE["whois"], is_ip=True)
        assert (card["value"], card["sub"], card["state"]) == (
            "?",
            "lookup failed",
            "unknown",
        )

    def test_the_certificate_reads_the_raw_getpeercert_dict(self):
        card = overview.certificate_card(DOMAIN_RESPONSE["ssl"])
        assert card["sub"] == "Google Trust Services"
        assert card["state"] in ("pass", "warn", "danger")
        rows = {
            row["label"]: row["value"]
            for row in build_view(DOMAIN_RESPONSE, is_self=False)["ssl_rows"]
        }
        assert rows["Issuer (CA)"] == "Google Trust Services"
        assert rows["Valid until"].startswith("2026-09-14")
        assert len(rows["SAN"].split(", ")) == 2

    def test_the_dns_card_counts_records(self):
        card = overview.dns_card(DOMAIN_RESPONSE["domain"])
        assert card["value"] == "18 records"
        assert card["sub"] == "A 1 · AAAA 0 · MX 1 · NS 4 · TXT 12"


class TestSectionHints:
    def test_hints_summarise_content(self):
        hints = _hints(build_view(DOMAIN_RESPONSE, is_self=False))
        assert "MarkMonitor" in hints["whois"]
        assert hints["dns"] == "A 1 · AAAA 0 · MX 1 · NS 4 · TXT 12"

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
        hint = _hints(build_view(response, is_self=False))["whois"]
        assert hint == "MarkMonitor Inc. · 1997 → 2028"

    def test_failed_whois_hint(self):
        assert _hints(build_view(IP_RESPONSE, is_self=True))["whois"] == (
            "lookup failed"
        )

    def test_ssl_hint_present_for_domain_and_no_section_for_ip(self):
        dom = _hints(build_view(DOMAIN_RESPONSE, is_self=False))
        assert "Google Trust Services" in dom["ssl"]
        assert "ssl" not in _hints(build_view(IP_RESPONSE, is_self=True))


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


def test_a_domain_lookup_offers_the_subdomains_section():
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
    ids = [item["id"] for item in view["sections"]]
    assert "subdomains" in ids


def test_an_ip_lookup_does_not_offer_the_subdomains_section():
    """An IP address has no subdomains; offering the panel would invite a
    request that can only fail."""
    view = build_view(
        {"address": "8.8.8.8", "domain": {}, "location": {}}, is_self=False
    )
    ids = [item["id"] for item in view["sections"]]
    assert "subdomains" not in ids


def test_the_kill_switch_removes_the_subdomains_section_for_a_domain():
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
    ids = [item["id"] for item in view["sections"]]
    assert "subdomains" not in ids


def _subdomain_hint(subdomains=None):
    """The hint on the Subdomains section for a domain lookup."""
    response = {
        "address": "example.com",
        "domain": {"a": [{"ip": "1.2.3.4", "ttl": 300}]},
        "location": {},
    }
    if subdomains is not None:
        response["subdomains"] = subdomains
    view = build_view(response, is_self=False)
    return next(i["hint"] for i in view["sections"] if i["id"] == "subdomains")


def test_the_unasked_panel_says_on_request_rather_than_naming_its_source():
    """Nothing is fetched until "Look up subdomains" is pressed, so the hint
    says the section is on request. Where the data comes from is inside it."""
    assert _subdomain_hint() == "on request"


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


def test_subdomain_hint_counts_both_sources():
    hint = _subdomain_hint(
        {
            "names": ["a.example.com", "b.example.com"],
            "count": 2,
            "openintel": {"names": ["b.example.com", "c.example.com"], "count": 2},
        }
    )
    assert hint == "3 subdomains found"


def test_subdomain_hint_crtsh_failed_lists_found():
    hint = _subdomain_hint(
        {
            "names": [],
            "count": 0,
            "error": "timed out",
            "openintel": {"names": ["a.example.com", "b.example.com"], "count": 2},
        }
    )
    assert hint == "2 subdomains found"


def test_subdomain_hint_both_failed():
    for lists in (None, {"names": None, "count": None}, {"names": [], "count": 0}):
        data = {"names": [], "count": 0, "error": "timed out"}
        if lists is not None:
            data["openintel"] = lists
        assert _subdomain_hint(data) == "lookup failed"


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
        return next(i["hint"] for i in view["sections"] if i["id"] == "whois")

    @staticmethod
    def _card(whois):
        """The Registration card of an address (an unallocated one, not a
        subdomain), as overview.py words it."""
        return overview.registration_card(whois, is_ip=True)

    def test_the_section_hint_distinguishes_the_two(self):
        assert self._hint(self._view({"error": "not registered"})) == "not registered"
        assert self._hint(self._view({"error": "WHOIS lookup timed out"})) == (
            "lookup failed"
        )
        assert self._hint(self._view(None)) == "lookup failed"

    def test_the_card_has_three_states_not_two(self):
        not_reg = self._card({"error": "not registered"})
        assert (not_reg["value"], not_reg["sub"]) == ("no record", "not registered")
        assert not_reg["state"] == "info"  # nothing is wrong

        failed = self._card({"error": "WHOIS lookup timed out"})
        assert (failed["value"], failed["state"]) == ("?", "unknown")

        ok = self._card({"registrar": "Example Registrar"})
        assert ok["value"] == "record found"  # the lookup's status, not the name's
        assert ok["state"] == "info"


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
        return next(i["hint"] for i in view["sections"] if i["id"] == "whois")

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
        return next(i["hint"] for i in view["sections"] if i["id"] == "whois")

    @staticmethod
    def _card(whois):
        return overview.registration_card(whois, is_ip=True)

    def test_the_hint_says_no_details_rather_than_registry_data(self):
        assert self._hint(THIN_RECORD) == "no details over WHOIS"
        assert self._hint({"source": "whois", "registrar": "cyon AG"}) == "cyon AG"
        parent = dict(
            THIN_RECORD, queried_name="www.admin.ch", registrable_domain="admin.ch"
        )
        assert self._hint(parent) == (
            "registration of admin.ch · no details over WHOIS"
        )

    def test_the_card_has_a_fourth_state(self):
        thin = self._card(THIN_RECORD)
        assert (thin["value"], thin["state"]) == ("no details", "info")
        assert self._card({"registrar": "Example Registrar"})["value"] == "record found"
        assert self._card({"error": "not registered"})["value"] == "no record"
        failed = self._card({"error": "WHOIS lookup timed out"})
        assert (failed["value"], failed["state"]) == ("?", "unknown")

    def test_the_section_rows_are_the_two_facts_there_are(self):
        assert whois_display(THIN_RECORD) == {"Source": "WHOIS", "Name": "admin.ch"}

    def test_whois_fill_words_it_the_same(self):
        fill = whois_fill(THIN_RECORD)
        assert fill["hint"] == "no details over WHOIS"
        assert fill["rows"] == [
            {"label": label, "value": value}
            for label, value in whois_display(THIN_RECORD).items()
        ]


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
    to see before reading the Registration section: the name is out of the DNS or
    about to be dropped. The tag is the code, which the section glosses."""

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


def _ptr(response, is_self=False):
    """The PTR row an IP's Domains section draws (the ptr block)."""
    return build_view(response, is_self=is_self)["ptr_row"]


class TestPtrRowVerdict:
    def test_a_ptr_that_points_back_says_confirmed(self):
        # IP_RESPONSE's PTR is dns.google., whose A records include 8.8.8.8.
        assert _ptr(IP_RESPONSE) == {
            "label": "PTR",
            "value": "dns.google.",
            "suffix": " → confirmed",
            "tone": "success",
        }

    def test_a_ptr_that_points_elsewhere_says_it_does_not_point_back(self):
        response = {**IP_RESPONSE, "domain": _sweep(a=["216.239.32.10"])}
        assert _ptr(response) == {
            "label": "PTR",
            "value": "dns.google.",
            "suffix": " → does not point back",
            "tone": "warning",
        }

    def test_the_wording_never_accuses(self):
        """CDNs and shared hosts fail this legitimately."""
        response = {**IP_RESPONSE, "domain": _sweep(a=["216.239.32.10"])}
        row = _ptr(response)
        text = f"{row['value']}{row.get('suffix', '')}".lower()
        for word in ("spoof", "forged", "fake", "invalid"):
            assert word not in text

    def test_a_failed_forward_query_leaves_the_name_as_it_was(self):
        """The PTR name's DNS table already says the A query failed (its A
        row reads dns_failure_text); the PTR row claims nothing."""
        domain = _sweep(a_status="timeout")
        assert _ptr({**IP_RESPONSE, "domain": domain}) == {
            "label": "PTR",
            "value": "dns.google.",
            "tone": "default",
        }
        assert viewmodel.dns_failure_text(domain, "a") == "(timed out)"

    def test_no_ptr_is_still_a_muted_dash(self):
        location = {**IP_RESPONSE["location"], "reverse_dns": None}
        response = {**IP_RESPONSE, "location": location, "domain": {}}
        assert _ptr(response) == {
            "label": "PTR",
            "value": DASH,
            "tone": "muted",
        }

    def test_the_self_page_judges_the_visitors_own_address(self):
        """build_view gives the self page the same row; its address can be
        the ::ffff: form a dual-stack socket reports."""
        response = {**IP_RESPONSE, "address": "::ffff:8.8.8.8"}
        row = _ptr(response, is_self=True)
        assert row["value"] == "dns.google."
        assert row["suffix"] == " → confirmed"


class TestLookupLinks:
    """build_view() links nothing on its own. main passes its rule
    (lookup_href) as link_for; this module stays free of lookup, whose import
    builds the GeoIP, suffix-list and DNS managers."""

    @staticmethod
    def _link_for(value):
        return "/" + value.rstrip(".")

    def test_without_a_link_function_nothing_carries_an_href(self):
        """Not even href=None: every row the blocks draw and every tag is the
        dict it always was, and tests across the suite compare those dicts
        whole."""
        for response in (IP_RESPONSE, DOMAIN_RESPONSE):
            view = build_view(response, is_self=False)
            rows = [
                row
                for row in (
                    view["rdns_row"],
                    view["ptr_row"],
                    *(view["org_rows"] or []),
                )
                if row
            ]
            assert rows
            assert not any("href" in row for row in rows)
            assert not any("href" in tag for tag in view["tags"])
            assert not any(ns["href"] for ns in view["whois_name_servers"])

    def test_the_ptr_row_takes_the_link(self):
        # No sweep of the PTR name (domain={}), so the row is the name alone.
        view = build_view(
            dict(IP_RESPONSE, domain={}), is_self=True, link_for=self._link_for
        )
        ptr = view["ptr_row"]
        assert (ptr["value"], ptr["href"]) == ("dns.google.", "/dns.google")
        assert "suffix" not in ptr

    def test_a_ptr_with_a_verdict_links_the_name_and_keeps_the_verdict_apart(self):
        """The href is the name's; the verdict stays its own `suffix`, which
        the template prints after the anchor as plain text."""
        view = build_view(IP_RESPONSE, is_self=True, link_for=self._link_for)
        assert view["ptr_row"] == {
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
        rdns = view["rdns_row"]
        assert rdns["value"] == "lhr25s34.1e100.net."
        assert rdns["href"] == "/lhr25s34.1e100.net"

    def test_a_missing_ptr_is_a_dash_with_no_link(self):
        location = {**IP_RESPONSE["location"], "reverse_dns": None}
        view = build_view(
            dict(IP_RESPONSE, location=location), is_self=True, link_for=self._link_for
        )
        ptr = view["ptr_row"]
        assert ptr["value"] == DASH
        assert "href" not in ptr

    def test_a_value_the_rule_refuses_carries_no_href(self):
        """link_for's None (a private address, a name with no public suffix)
        leaves the row as it was, not with href=None."""
        view = build_view(IP_RESPONSE, is_self=True, link_for=lambda value: None)
        assert "href" not in view["ptr_row"]

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


class TestDnsSecurityView:
    DATA = {
        "spf": {"state": "pass", "summary": "SPF: -all", "findings": []},
        "dmarc": {
            "state": "warn",
            "summary": "DMARC: p=none",
            "findings": [{"severity": "warn", "text": "p=none asks for reports only"}],
        },
        "dkim": {
            "state": "unknown",
            "summary": "DKIM: not found at the common selectors",
            "findings": [],
        },
        "caa": {"state": "fail", "summary": "x", "findings": []},
    }

    def test_none_is_none(self):
        assert viewmodel.dns_security_view(None) is None

    def test_rows_labels_tones(self):
        """Each row in its state's tone, warnings and failures first."""
        view = viewmodel.dns_security_view(self.DATA)
        assert [(r["label"], r["tone"]) for r in view["rows"]] == [
            ("DMARC", "warning"),
            ("CAA", "danger"),
            ("SPF", "success"),
            ("DKIM", "muted"),
        ]
        assert view["rows"][0]["findings"] == [
            {"text": "p=none asks for reports only", "tone": "warning"}
        ]

    def test_hint_counts_in_order(self):
        assert (
            viewmodel.dns_security_view(self.DATA)["hint"]
            == "1 pass · 1 warn · 1 fail · 1 unknown"
        )

    def test_security_rows_warnings_first(self):
        """nasa.gov: DKIM and CAA warn, SPF, DMARC and DNSSEC pass, and the
        three opt-ins are not published. The warnings come first, the passes
        after them, each in the check order, and the unpublished opt-ins fold
        into one row. The hint still counts every check."""
        data = {
            "spf": {"state": "pass", "summary": "SPF: -all", "findings": []},
            "dmarc": {"state": "pass", "summary": "DMARC: p=reject", "findings": []},
            "dkim": {"state": "warn", "summary": "DKIM: 1024-bit", "findings": []},
            "caa": {"state": "warn", "summary": "CAA: none", "findings": []},
            "dnssec": {"state": "pass", "summary": "DNSSEC: signed", "findings": []},
            "mta_sts": {"state": "info", "summary": "MTA-STS: not published"},
            "tls_rpt": {"state": "info", "summary": "TLS-RPT: not published"},
            "bimi": {"state": "info", "summary": "BIMI: not published"},
        }
        view = viewmodel.dns_security_view(data)
        assert [r["label"] for r in view["rows"]] == [
            "DKIM",
            "CAA",
            "SPF",
            "DMARC",
            "DNSSEC",
        ]
        assert view["folded"] == {
            "label": "Not published",
            "state": "info",
            "tone": "muted",
            "value": "MTA-STS · TLS-RPT · BIMI",
        }
        assert view["hint"] == "3 pass · 2 warn · 3 info"

    def test_fail_and_warn_share_the_first_group_in_check_order(self):
        """Warnings and failures together, in the check order, as the review
        chips list them; an unknown after the passes; an info row that is not
        an unpublished opt-in stays a row of its own, after the unknowns."""
        data = {
            **self.DATA,
            "mta_sts": {"state": "info", "summary": "MTA-STS: not published"},
            "spf": {"state": "info", "summary": "SPF: none for this name"},
            "dnssec": {"state": "pass", "summary": "DNSSEC: signed", "findings": []},
        }
        view = viewmodel.dns_security_view(data)
        assert [(r["label"], r["state"]) for r in view["rows"]] == [
            ("DMARC", "warn"),
            ("CAA", "fail"),
            ("DNSSEC", "pass"),
            ("DKIM", "unknown"),
            ("SPF", "info"),
        ]
        assert view["folded"]["value"] == "MTA-STS"

    def test_not_published_matches_dnssecurity(self):
        """viewmodel._NOT_PUBLISHED mirrors dnssecurity's summary for an
        opt-in record that is not there: graded by dnssecurity.evaluate, the
        three fold into the one row."""
        import dnssecurity

        absent = {"records": [], "status": "noanswer"}
        graded = dnssecurity.evaluate(
            None, {check: absent for check in ("mta_sts", "tls_rpt", "bimi")}
        )
        view = viewmodel.dns_security_view(graded)
        assert view["folded"]["value"] == "MTA-STS · TLS-RPT · BIMI"
        assert all(
            not row["summary"].endswith(viewmodel._NOT_PUBLISHED)
            for row in view["rows"]
        )

    def test_nothing_unpublished_folds_nothing(self):
        assert viewmodel.dns_security_view(self.DATA)["folded"] is None

    def test_section_follows_dns(self):
        response = {"address": "example.com", "dns_security": self.DATA}
        ids = list(_hints(viewmodel.build_view(response, is_self=False)))
        assert ids[ids.index("dns") + 1] == "security"

    def test_no_section_without_data(self):
        for response in ({"address": "1.1.1.1"}, {"address": "example.com"}):
            ids = list(_hints(viewmodel.build_view(response, is_self=False)))
            assert "security" not in ids


# ---------------------------------------------------------------------------
# The "Domains on this address" panel's view.
# ---------------------------------------------------------------------------

_LICENCE = {
    "coverage": "Covers only names on the Tranco list.",
    "license": "CC BY-NC-SA 4.0",
    "license_url": "https://creativecommons.org/licenses/by-nc-sa/4.0/",
    "terms_url": "https://ip.example/static/licenses/openintel-terms.html",
    "attribution": "Made possible by OpenINTEL.",
}
ANSWER_4_NAMES = {
    "total": 4,
    "names": ["example.com", "example.net", "example.org", "<b>x</b>.example"],
    "truncated": False,
    "block": {"prefix": "93.184.215.0/24", "addresses": 4, "names": 7},
    "as_of": "2026-10-20",
    "sources": [{"id": "tranco", "label": "Tranco", "date": "2026-10-20"}],
    "unavailable": [],
    **_LICENCE,
}
ANSWER_ZERO = {
    **ANSWER_4_NAMES,
    "total": 0,
    "names": [],
    "block": {"prefix": "175.214.27.0/24", "addresses": 0, "names": 0},
}
ANSWER_UNKNOWN = {
    **ANSWER_4_NAMES,
    "total": None,
    "names": None,
    "truncated": None,
    "block": None,
    "as_of": None,
    "sources": [],
    "unavailable": [
        {"source": "tranco", "label": "Tranco", "reason": "not downloaded yet"}
    ],
}


def test_reverse_ip_view_none_is_none():
    assert reverse_ip_view(None) is None


def test_reverse_ip_view_names_link_and_count():
    view = reverse_ip_view(ANSWER_4_NAMES, link_for=lambda v: f"/{v}")
    assert view["hint"] == "4 names"
    assert view["names"][0] == {"text": "example.com", "href": "/example.com"}
    assert view["more"] == 0
    assert view["state_line"] is None
    assert view["block_line"] == "93.184.215.0/24: 4 addresses carry 7 listed names"
    assert (
        view["coverage"] == "Covers only names on the Tranco list. Measured 2026-10-20."
    )
    assert view["attribution"] == "Made possible by OpenINTEL."
    assert view["license"] == "CC BY-NC-SA 4.0"
    assert view["license_url"] == _LICENCE["license_url"]
    assert view["terms_path"] == "/static/licenses/openintel-terms.html"


def test_reverse_ip_view_without_link_for_links_nothing():
    view = reverse_ip_view(ANSWER_4_NAMES)
    assert view["names"][0] == {"text": "example.com", "href": None}


def test_reverse_ip_view_none_listed():
    view = reverse_ip_view(ANSWER_ZERO)
    assert view["hint"] == "none in top lists"
    assert view["names"] == []
    assert view["state_line"] == (
        "No name on these lists resolved to this address on "
        "2026-10-20. Names outside them are not covered."
    )
    assert view["block_line"] == "175.214.27.0/24: no address carries a listed name"


def test_reverse_ip_view_unknown_keeps_the_licence_lines():
    view = reverse_ip_view(ANSWER_UNKNOWN)
    assert view["hint"] == "unknown" and view["block_line"] is None
    assert view["names"] == [] and view["more"] == 0
    assert view["state_line"] == "Unknown: Tranco: not downloaded yet"
    # the reasons are the state line; there is nothing else not checked
    assert view["not_checked"] is None
    assert view["coverage"] == _LICENCE["coverage"]
    assert view["attribution"] == _LICENCE["attribution"]


def _unavailable(*pairs):
    return [
        {"source": label.lower(), "label": label, "reason": reason}
        for label, reason in pairs
    ]


def test_reverse_ip_view_unknown_says_a_shared_reason_once():
    view = reverse_ip_view(
        {
            **ANSWER_UNKNOWN,
            "unavailable": _unavailable(
                ("Tranco", "not downloaded yet"),
                ("Cisco Umbrella", "not downloaded yet"),
                ("Majestic Million", "no copy"),
                ("Cloudflare Radar", "not downloaded yet"),
            ),
        }
    )
    assert view["state_line"] == (
        "Unknown: Tranco, Cisco Umbrella, Cloudflare Radar: not downloaded yet;"
        " Majestic Million: no copy"
    )


def test_reverse_ip_view_complete_has_no_not_checked_line():
    assert reverse_ip_view(ANSWER_4_NAMES)["not_checked"] is None
    assert reverse_ip_view(ANSWER_ZERO)["not_checked"] is None


def test_reverse_ip_view_partial_zero_says_how_many_lists():
    view = reverse_ip_view(
        {
            **ANSWER_ZERO,
            "unavailable": _unavailable(
                ("Cisco Umbrella", "not in the database"),
                ("Majestic Million", "last measured 2026-10-15, older than 96 hours"),
            ),
        }
    )
    assert view["hint"] == "none in 1 of 3 lists"
    assert view["not_checked"] == (
        "Not checked: Cisco Umbrella (not in the database);"
        " Majestic Million (last measured 2026-10-15, older than 96 hours)"
    )


def test_reverse_ip_view_partial_names_keep_their_hint():
    view = reverse_ip_view(
        {
            **ANSWER_4_NAMES,
            "unavailable": _unavailable(
                ("Cisco Umbrella", "not downloaded yet"),
                ("Cloudflare Radar", "not downloaded yet"),
            ),
        }
    )
    assert view["hint"] == "4 names"
    assert view["not_checked"] == (
        "Not checked: Cisco Umbrella, Cloudflare Radar (not downloaded yet)"
    )


def test_one_address_one_name_is_singular():
    answer = {
        **ANSWER_4_NAMES,
        "total": 1,
        "names": ["example.com"],
        "block": {"prefix": "93.184.215.0/24", "addresses": 1, "names": 1},
    }
    view = reverse_ip_view(answer)
    assert view["hint"] == "1 name"
    assert view["block_line"] == "93.184.215.0/24: 1 address carries 1 listed name"


def test_truncated_says_how_many_more():
    answer = {
        **ANSWER_4_NAMES,
        "total": 4821,
        "names": [f"n{i}.example" for i in range(100)],
        "truncated": True,
    }
    view = reverse_ip_view(answer)
    assert view["hint"] == "4,821 names"
    assert view["more"] == 4721
    assert reverse_ip_view({**answer, "total": 250})["more"] == 150
