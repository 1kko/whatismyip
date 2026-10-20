"""An AS number is a lookup target: `AS4766`, in any case, as a path segment.

Nothing here touches the network; an AS target never reaches the pipeline.
"""

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
from lookup import (
    InvalidTargetError,
    classify_target,
    gather,
    normalize_lookup_target,
    parse_asn,
    special_asn,
)

client = TestClient(main.app)


@pytest.mark.parametrize("raw", ["AS4766", "as4766", "AS04766", "AS4766."])
def test_spellings_classify_as_asn_4766(raw):
    target = normalize_lookup_target(raw)
    assert classify_target(target) == "asn" and parse_asn(target) == 4766


def test_a_pasted_url_is_cut_to_its_host_not_its_path():
    # normalize_lookup_target keeps the host, so a URL whose path is an AS
    # number is a lookup of the host.
    assert normalize_lookup_target("https://example.com/AS4766") == "example.com"
    assert normalize_lookup_target("https://AS4766/") == "as4766"


def test_a_bare_as_is_the_country_suffix_not_an_asn():
    # ".as" is American Samoa's TLD, so "as" is a domain, as before.
    assert parse_asn("as") is None and classify_target("as") != "asn"


@pytest.mark.parametrize(
    "raw", ["4766", "AS-4766", "AS 4766", "AS4294967296", "AS99999999999"]
)
def test_non_asns_are_invalid(raw):
    assert classify_target(normalize_lookup_target(raw)) == "invalid"


@pytest.mark.parametrize("raw", ["AS0", "AS4294967295"])
def test_the_ends_of_the_range_are_asn_targets(raw):
    assert classify_target(raw.lower()) == "asn"


@pytest.mark.parametrize(
    "asn,code",
    [
        (0, "reserved_asn"),
        (23456, "as_trans"),
        (64496, "documentation_asn"),
        (65551, "documentation_asn"),
        (64512, "private_asn"),
        (4200000000, "private_asn"),
        (65535, "reserved_asn"),
        (100000, "reserved_asn"),
        (4294967295, "reserved_asn"),
    ],
)
def test_special_asns(asn, code):
    assert special_asn(asn)["code"] == code


def test_assignable_asns_are_not_special():
    assert special_asn(4766) is None and special_asn(131072) is None


def test_a_special_asn_names_its_range_and_purpose():
    assert special_asn(64999) == {
        "code": "private_asn",
        "label": "Private use",
        "first": 64512,
        "last": 65534,
        "defined_in": "RFC 6996",
        "purpose": (
            "For a network's own internal BGP, as 10.0.0.0/8 is for addresses. "
            "Many networks use the same number at once, so it names no one on "
            "the public internet."
        ),
    }
    assert special_asn(23456)["first"] == special_asn(23456)["last"] == 23456


def test_each_range_reports_its_own_bounds():
    assert (special_asn(65540)["first"], special_asn(65540)["last"]) == (65536, 65551)
    assert (special_asn(64500)["first"], special_asn(64500)["last"]) == (64496, 64511)
    assert (special_asn(4200000001)["first"], special_asn(4200000001)["last"]) == (
        4200000000,
        4294967294,
    )
    assert (special_asn(65535)["defined_in"], special_asn(65535)["first"]) == (
        "RFC 7300",
        65535,
    )
    assert special_asn(70000)["defined_in"] == "IANA"
    assert (special_asn(70000)["first"], special_asn(70000)["last"]) == (65552, 131071)
    assert special_asn(0)["defined_in"] == "RFC 7607"
    assert special_asn(0)["purpose"].startswith('Means "no AS".')


def test_gather_refuses_an_as_target():
    with pytest.raises(InvalidTargetError) as raised:
        asyncio.run(gather("AS4766"))
    assert raised.value.code == "asn_target"
    assert raised.value.message == (
        "an AS number: look it up as /AS<n> or with the as_info tool"
    )


def test_an_as_path_is_never_banned(monkeypatch):
    # No detector rule matches "/AS4766" today; the exemption keeps it that way
    # if one is added, and a bare AS path is not a domain or an IPv4 address.
    for path in ("/AS4766", "/as4766", "/AS0", "/AS4766:443"):
        assert main._suspicious_path_is_ordinary(path)
    assert not main._suspicious_path_is_ordinary("/AS4294967296")
    monkeypatch.setattr(main.rate_limiter, "requests_per_second", 1000)
    for _ in range(30):
        assert client.get("/AS4766").status_code != 403
    assert client.get("/").status_code != 403


APP_JS = Path("static/js/app.js")
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_search_box_accepts_as_numbers():
    import re

    source = APP_JS.read_text(encoding="utf-8")
    parts = []
    for name in [
        "IPV4",
        "DOMAIN",
        "PROBE_SUFFIX",
        "PROBE_PATH",
        "ipv6Host",
        "isLookupTarget",
    ]:
        match = re.search(
            rf"^(?:const {name} = .*?;|function {name}\(.*?^\}})$", source, re.M | re.S
        )
        parts.append(match.group(0))
    values = [
        "AS4766",
        "as4766",
        "AS04766",
        "AS0",
        "AS4766.",
        "4766",
        "AS",
        "AS-4766",
        "AS12345678901",
    ]
    script = (
        "\n".join(parts)
        + f"\nconsole.log(JSON.stringify({json.dumps(values)}.map(isLookupTarget)));"
    )
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    assert json.loads(out.stdout) == [
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
    ]
