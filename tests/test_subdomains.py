"""Normalization and source-adapter tests.

The fixture below mirrors the *shapes* seen in live crt.sh output — wildcards,
the apex, unrelated SANs sharing a certificate, underscore labels, and
rfc822Name email entries. The email addresses are synthetic on purpose:
committing a real one would be the same privacy failure the code prevents.
"""

import json
from unittest.mock import patch

import pytest

import subdomains

CRTSH_ROWS = [
    {"name_value": "*.example.com\nexample.com", "common_name": "example.com"},
    {"name_value": "api.example.com", "common_name": "api.example.com"},
    {"name_value": "API.Example.COM.", "common_name": "api.example.com"},
    {"name_value": "_dmarc.example.com", "common_name": "_dmarc.example.com"},
    {"name_value": "deep.nested.example.com", "common_name": None},
    {"name_value": "someone@example.com", "common_name": "someone@example.com"},
    {"name_value": "first.last@mail.example.com", "common_name": None},
    {"name_value": "unrelated.example.org", "common_name": "unrelated.example.org"},
    {"name_value": "notexample.com", "common_name": "notexample.com"},
]


def _names():
    return subdomains.extract_names(CRTSH_ROWS)


def test_email_addresses_are_discarded():
    """The load-bearing privacy rule. crt.sh's name_value carries rfc822Name
    entries from S/MIME certificates; 551 appear for nasa.gov alone."""
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert not any("@" in n for n in names)
    # must not survive by stripping the local part
    assert "mail.example.com" not in names


def test_wildcards_fold_onto_the_apex_and_the_apex_is_dropped():
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "example.com" not in names
    assert not any(n.startswith("*") for n in names)


def test_unrelated_sans_on_a_shared_certificate_are_dropped():
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "unrelated.example.org" not in names


def test_a_suffix_match_is_not_a_substring_match():
    """ "notexample.com" ends with "example.com" but is a different domain."""
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "notexample.com" not in names


def test_underscore_labels_survive():
    """_dmarc and _acme-challenge are legitimate DNS labels."""
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "_dmarc.example.com" in names


def test_names_are_lowercased_deduplicated_and_sorted():
    names, total = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert names == sorted(set(names))
    assert names.count("api.example.com") == 1
    assert total == len(names)


def test_capping_reports_the_true_total():
    names, total = subdomains.normalize_names(_names(), "example.com", cap=2)
    assert len(names) == 2
    assert total > 2


def test_an_internationalised_domain_survives_normalization():
    """Review Focus 5. Punycode is plain ASCII and must not be filtered out."""
    rows = [{"name_value": "www.xn--3e0b707e.kr", "common_name": None}]
    names, _ = subdomains.normalize_names(
        subdomains.extract_names(rows), "xn--3e0b707e.kr", cap=100
    )
    assert names == ["www.xn--3e0b707e.kr"]


def test_extract_names_tolerates_a_non_list_payload():
    """Review Focus 1. crt.sh answers {"error": ...} under load; iterating that
    dict yields strings, and .get on a string raises AttributeError."""
    assert subdomains.extract_names({"error": "rate limited"}) == []
    assert subdomains.extract_names(None) == []
    assert subdomains.extract_names("garbage") == []


def test_extract_names_skips_malformed_rows():
    assert subdomains.extract_names([{"no_name_value": 1}, None, "x"]) == []


class TestFetchFromSource:
    @pytest.mark.asyncio
    async def test_a_successful_fetch_returns_normalized_names(self):
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS):
            names, total = await subdomains.fetch_from_source("example.com")
        assert "api.example.com" in names
        assert total == len(names)

    @pytest.mark.asyncio
    async def test_a_timeout_raises_rather_than_returning_empty(self):
        with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
            with pytest.raises(subdomains.SubdomainError):
                await subdomains.fetch_from_source("example.com")

    @pytest.mark.asyncio
    async def test_malformed_json_raises_rather_than_returning_empty(self):
        with patch.object(
            subdomains, "_fetch_sync", side_effect=json.JSONDecodeError("x", "y", 0)
        ):
            with pytest.raises(subdomains.SubdomainError):
                await subdomains.fetch_from_source("example.com")

    @pytest.mark.asyncio
    async def test_an_error_object_payload_yields_no_names_without_raising(self):
        """Review Focus 1. A 200 carrying {"error": ...} is a successful HTTP
        exchange with nothing in it — not an exception, and not a crash."""
        with patch.object(
            subdomains, "_fetch_sync", return_value={"error": "rate limited"}
        ):
            names, total = await subdomains.fetch_from_source("example.com")
        assert names == []
        assert total == 0
