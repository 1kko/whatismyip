"""An IP lookup's registration shows the registration record only.

The WHOIS facts column it once had used to read a key the canonical record
never has ('updated_date'), so every IP lookup rendered 'Updated —', and it
filled Netblock and Country from GeoIP, so a column titled WHOIS was mostly
showing geolocation data. The Registration card (overview.registration_card)
and section that replace it read the record alone. Pure and deterministic: no
network.
"""

import datetime

import overview
import rdap
from viewmodel import build_view, geoip_rows, whois_display, whois_fill

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


def _card(whois):
    """The IP page's Registration card, as overview.build words it."""
    cards = overview.build(_response(whois))["cards"]
    return next(card for card in cards if card["id"] == "whois")


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


class TestIpRegistrationCard:
    def test_updated_is_filled_from_a_normalised_record(self):
        card = _card(rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8"))
        assert "2024-03-05" in card["sub"]

    def test_it_comes_from_the_registration_record_not_geoip(self):
        record = rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8")
        card = _card(record)
        assert card["value"] == "8.8.8.0/24"  # GeoIP says /23
        assert card["sub"] == "ARIN · 2024-03-05"
        assert card["state"] == "info"
        shown = {card["value"], card["sub"], *whois_display(record).values()}
        assert LOCATION["cidr"] not in shown
        assert LOCATION["country_code"] not in shown
        assert whois_display(record)["Abuse contact"] == "network-abuse@google.com"
        # GeoIP-sourced rows are no part of the registration.
        assert "Netblock" not in whois_display(record)
        assert "Country" not in whois_display(record)

    def test_failed_lookup_does_not_fall_back_to_geoip(self):
        card = _card({"error": "WHOIS lookup timed out"})
        assert (card["value"], card["sub"], card["state"]) == (
            "?",
            "lookup failed",
            "unknown",
        )

    def test_geoip_values_are_still_on_the_page(self):
        # What is not the registration's is still shown where it belongs: the
        # Organization section's network rows, and the GeoIP rows.
        view = build_view(_response({"error": "x"}), is_self=False)
        assert {"label": "CIDR", "value": "8.8.8.0/23", "tone": "default"} in (
            view["org_rows"]
        )
        geo = {row["label"]: row["value"] for row in geoip_rows(LOCATION)}
        assert geo["Network"] == "8.8.8.0/23"
        assert "(US)" in geo["Country"]


class TestRegistrationRows:
    def test_ip_record_shows_assignment_and_parent(self):
        out = whois_display(rdap._normalize_rdap_ip(WHOISIT_IP, "8.8.8.8"))
        assert out["Assignment"] == "direct allocation"
        assert out["Parent handle"] == "NET-8-0-0-0-0"
        assert out["Updated"] == "2024-03-05 09:41 UTC"
        assert out["RIR"] == "ARIN"

    def test_an_address_block_gets_no_age_row(self):
        """The Age row is a domain's, so an IP lookup and the self page read
        as they did. A domain's record is told by its registrar key, as for
        the Status row: _normalize_rdap_ip sets none, whatever its `rir`
        (empty when whoisit could not name the registry)."""
        young = dict(
            WHOISIT_IP,
            registration_date=datetime.datetime.now(UTC) - datetime.timedelta(days=3),
        )
        for rir in ("arin", ""):
            record = rdap._normalize_rdap_ip(dict(young, rir=rir), "8.8.8.8")
            assert "registrar" not in record
            assert "Age" not in whois_display(record)
            assert "Age" not in [row["label"] for row in whois_fill(record)["rows"]]

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
