"""The WHOIS facts column on an IP lookup shows the registration record only.

It used to read a key the canonical record never has ('updated_date'), so every
IP lookup rendered 'Updated —', and it filled Netblock and Country from GeoIP,
so a column titled WHOIS was mostly showing geolocation data. Pure and
deterministic: no network.
"""

import datetime

import rdap
from viewmodel import DASH, build_view, geoip_rows, whois_display

UTC = datetime.timezone.utc

# A whoisit.ip() result for 8.8.8.8, trimmed to what the normaliser reads.
WHOISIT_IP = {
    "name": "GOGL",
    "handle": "NET-8-8-8-0-2",
    "parent_handle": "NET-8-0-0-0-0",
    "assignment_type": "direct allocation",
    "network": "8.8.8.0/24",
    "country": "",
    "rir": "arin",
    "registration_date": datetime.datetime(2023, 12, 28, 17, 24, tzinfo=UTC),
    "last_changed_date": datetime.datetime(2024, 3, 5, 9, 41, tzinfo=UTC),
    "entities": {
        "registrant": [{"name": "Google LLC"}],
        "abuse": [{"name": "Abuse", "email": "network-abuse@google.com"}],
    },
}

# GeoIP deliberately disagrees with the registry on every overlapping field, so
# a value that leaks from the wrong source is visible in the assertion.
LOCATION = {
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States",
    "cidr": "8.8.8.0/23",
    "asn_cidr": "8.8.8.0/22",
    "asn_name": "Google LLC",
    "is_private": False,
}


def _response(whois):
    return {
        "address": "8.8.8.8",
        "location": dict(LOCATION),
        "domain": {"a": [{"ip": "8.8.8.8", "ttl": 300}]},
        "whois": whois,
    }


def _column(whois):
    view = build_view(_response(whois), is_self=False)
    column = next(c for c in view["facts"] if c["title"] == "WHOIS")
    return {row["label"]: row for row in column["rows"]}


class TestRdapIpNormaliser:
    def test_keeps_assignment_type_and_parent_handle(self):
        out = rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8")
        assert out["assignment_type"] == "direct allocation"
        assert out["parent_handle"] == "NET-8-0-0-0-0"

    def test_empty_strings_collapse_to_none(self):
        # whoisit's clean() turns a missing field into "", not None.
        raw = dict(WHOISIT_IP, assignment_type="", parent_handle="")
        out = rdap._normalize_rdap_ip(raw, "8.8.8.8")
        assert out["assignment_type"] is None
        assert out["parent_handle"] is None

    def test_both_are_canonical_fields(self):
        assert "assignment_type" in rdap.CANONICAL_FIELDS
        assert "parent_handle" in rdap.CANONICAL_FIELDS


class TestIpWhoisColumn:
    def test_updated_is_filled_from_a_normalised_record(self):
        rows = _column(rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8"))
        assert rows["Updated"]["value"] != DASH
        assert "2024-03-05" in rows["Updated"]["value"]
        assert rows["Updated"]["tone"] == "default"

    def test_rows_come_from_the_registration_record_not_geoip(self):
        rows = _column(rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8"))
        assert rows["Network"]["value"] == "8.8.8.0/24"  # GeoIP says /23
        assert rows["RIR"]["value"] == "ARIN"
        assert rows["Abuse"]["value"] == "network-abuse@google.com"
        values = {row["value"] for row in rows.values()}
        assert LOCATION["cidr"] not in values
        assert LOCATION["country_code"] not in values
        # The GeoIP-sourced rows are gone from this column altogether.
        assert "Netblock" not in rows
        assert "Country" not in rows

    def test_failed_lookup_does_not_fall_back_to_geoip(self):
        rows = _column({"error": "WHOIS lookup timed out"})
        assert rows["Status"]["value"] == "unavailable"
        for label in ("Network", "RIR", "Abuse", "Updated"):
            assert rows[label]["value"] == DASH
            assert rows[label]["tone"] == "muted"

    def test_geoip_values_are_still_on_the_page(self):
        # What left the WHOIS column must still be shown where it belongs.
        view = build_view(_response({"error": "x"}), is_self=False)
        network = next(c for c in view["facts"] if c["title"] == "NETWORK")
        assert {"label": "CIDR", "value": "8.8.8.0/23", "tone": "default"} in (
            network["rows"]
        )
        geo = {row["label"]: row["value"] for row in geoip_rows(LOCATION)}
        assert geo["Network"] == "8.8.8.0/23"
        assert "(US)" in geo["Country"]


class TestWhoisAccordion:
    def test_ip_record_shows_assignment_and_parent(self):
        out = whois_display(rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8"))
        assert out["Assignment"] == "direct allocation"
        assert out["Parent handle"] == "NET-8-0-0-0-0"
        assert out["Updated"] == "2024-03-05 09:41 UTC"
        assert out["RIR"] == "ARIN"

    def test_domain_record_is_unaffected(self):
        record = {
            "source": "rdap",
            "name": "google.com",
            "registrar": "MarkMonitor Inc.",
            "updated": datetime.datetime(2024, 8, 2, 2, 17, tzinfo=UTC),
        }
        assert whois_display(record) == {
            "Source": "RDAP",
            "Name": "google.com",
            "Registrar": "MarkMonitor Inc.",
            "Updated": "2024-08-02 02:17 UTC",
        }

    def test_domain_lookup_still_has_no_whois_facts_column(self):
        view = build_view(
            {
                "address": "google.com",
                "location": dict(LOCATION),
                "domain": {"a": [{"ip": "142.250.207.46", "ttl": 300}]},
                "whois": {"source": "rdap", "name": "google.com"},
            },
            is_self=False,
        )
        assert [c["title"] for c in view["facts"]] == [
            "NETWORK",
            "DNS",
            "CERTIFICATE",
        ]
