"""An AS number is a lookup target: `AS4766`, in any case, as a path segment.

Nothing here touches the network; an AS target never reaches the pipeline.
GET /AS<n> answers from the local AS database (main._as_lookup): JSON, the
text block, or the AS page (templates/as.html).
"""

import asyncio
import html as htmllib
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import asinfo
import concurrency
import lookup
import main
from asinfo import ANSWER_KEYS
from asinfo_fixtures import build_manager
from lookup import (
    InvalidTargetError,
    classify_target,
    gather,
    normalize_lookup_target,
    parse_asn,
    special_asn,
)
from test_as_surfaces import asn_drop_lists

client = TestClient(main.app)

CURL = {"user-agent": "curl/8.7.1"}
BROWSER = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
PRIVATE_USE = special_asn(64512)
AS_LOOKUPS_OFF = "AS lookups are turned off on this server"
AS_FIELDS_UNSUPPORTED = (
    "fields are not available for an AS lookup: ask for the whole answer as "
    "JSON or with ?format=text"
)
AS_SUBDOMAINS_UNSUPPORTED = "subdomains apply to a domain name, not an AS number"
# GET /AS4766?format=text over the fixture data (tests/asinfo_fixtures.py).
AS4766_BLOCK = (
    "asn: 4766\n"
    "name: KIXS-AS-KR-KR - Korea Telecom\n"
    "country: KR\n"
    "rir: apnic\n"
    "assigned: 1996-04-22\n"
    "org: Korea Telecom\n"
    "prefixes_v4: 2\n"
    "prefixes_v6: 1\n"
    "rpki_valid: 2\n"
    "rpki_invalid: 0\n"
    "rpki_not_found: 1\n"
    "upstreams: 174 701\n"
    "downstreams: 3\n"
    "peers: 1\n"
    # The suite runs with the reputation lists off: ASN-DROP was not read.
    "asn_drop: ?\n"
)


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


# --- GET /AS<n> ------------------------------------------------------------------


def _never(*args, **kwargs):
    raise AssertionError("a special-purpose ASN read the AS database")


def _rows(html):
    """Each records-table row whose label is plain text, as label -> the text
    of its cell, tags stripped and entities decoded."""
    return {
        htmllib.unescape(label): htmllib.unescape(re.sub(r"<[^>]+>", "", value))
        for label, value in re.findall(
            r"<tr><td>([^<]*)</td><td[^>]*>(.*?)</td></tr>", html, re.S
        )
    }


def _head(html):
    return html.split("</head>")[0]


def _hero(html):
    return html.split('<div class="hero')[1].split("</section>")[0]


def _page_data(html):
    return json.loads(
        re.search(
            r'<script type="application/json" id="page-data" nonce="[^"]*">(.*?)'
            r"</script>",
            html,
            re.S,
        ).group(1)
    )


def _without_timing(data):
    return {key: value for key, value in data.items() if key != "elapsed_ms"}


def _assert_lookup_headers(response):
    # Like every answer of the lookup routes, errors included: the URL answers
    # by negotiation, and no cache keeps it.
    assert response.headers["cache-control"] == "no-store"
    vary = response.headers["vary"]
    assert "Accept" in vary and "User-Agent" in vary


def test_as_json(asinfo_enabled):
    response = client.get("/AS4766", params={"format": "json"})
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == "AS4766" and data["asn"] == 4766
    assert data["prefix_list"]["count"] >= 2
    # as_info_for_asn's card, whole and with its full lists and neighbour
    # sizes (detail), between the
    # address and the time the read took.
    assert list(data) == ["address", *ANSWER_KEYS, "special", "elapsed_ms"]
    assert _without_timing(data) == {
        "address": "AS4766",
        **lookup.as_info_for_asn(4766, full=True, detail=True),
    }
    assert isinstance(data["elapsed_ms"], int)
    assert [entry["prefix"] for entry in data["prefix_list"]["list"]] == [
        "211.252.0.0/15",
        "211.252.112.0/24",
        "2001:2d8::/32",
    ]
    assert [entry["asn"] for entry in data["upstreams"]] == [174, 701]
    assert data["downstreams"]["count"] == 3
    # An AS has no route of its own: that is an address's.
    assert data["route"] is None and data["special"] is None
    _assert_lookup_headers(response)
    # curl negotiates JSON, as on every lookup.
    assert _without_timing(client.get("/AS4766", headers=CURL).json()) == (
        _without_timing(data)
    )


@pytest.mark.parametrize("path", ["/as4766", "/AS04766", "/AS4766.", "/AS4766:443"])
def test_every_spelling_answers_as_as4766(asinfo_enabled, path):
    data = client.get(path, headers=CURL).json()
    assert data["address"] == "AS4766" and data["asn"] == 4766


def test_as_text_block(asinfo_enabled):
    response = client.get("/AS4766", params={"format": "text"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "asn: 4766\n" in response.text
    assert "upstreams: 174 701\n" in response.text
    assert response.text == AS4766_BLOCK
    _assert_lookup_headers(response)
    accept = client.get("/AS4766", headers={**CURL, "accept": "text/plain"})
    assert accept.text == AS4766_BLOCK


def test_a_dataset_that_cannot_be_read_is_unknown_not_none(monkeypatch, tmp_path):
    # CAIDA's relationships file is dated past its 75 days: the neighbours are
    # unknown ("?"), which "-" (none) would misstate.
    manager = build_manager(tmp_path, meta={"caida_rel": {"source_date": "2026-07-01"}})
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    text = client.get("/AS4766", params={"format": "text"}).text
    lines = dict(line.split(": ", 1) for line in text.splitlines())
    assert lines["upstreams"] == lines["downstreams"] == lines["peers"] == "?"
    assert lines["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert lines["prefixes_v4"] == "2"

    (entry,) = [
        e for e in manager.for_asn(4766)["unavailable"] if e["dataset"] == "caida_rel"
    ]
    page = client.get("/AS4766", headers=BROWSER).text
    unknown = f"Unknown: {entry['reason']}"
    # The graph's upstreams, the Neighbours tile and the table: each says why.
    assert unknown in _section(page, "as-graph")
    assert unknown in _section(page, "as-neighbours")
    tiles = _section(page, "as-tiles").split('<div class="as-tile">')[1:]
    (neighbours_tile,) = [tile for tile in tiles if ">Neighbours<" in tile]
    assert ">Unknown<" in neighbours_tile and unknown in neighbours_tile
    # No zero stands in for the unknown counts, and no chip offers them.
    assert 'data-relation="' not in _section(page, "as-neighbours")


def test_a_fresh_volume_answers_unknown_never_an_error(monkeypatch, tmp_path):
    # AS lookups on, before the first download: every section is unknown, with
    # its reason, and nothing raises.
    manager = asinfo.AsInfoManager(directory=str(tmp_path), enabled=True)
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    data = client.get("/AS4766", headers=CURL).json()
    assert data["address"] == "AS4766" and data["name"] is None
    assert {entry["reason"] for entry in data["unavailable"]} == {"not downloaded yet"}
    text = client.get("/AS4766?format=text").text
    assert text.startswith("asn: 4766\nname: ?\n")
    assert text.count(": ?\n") == len(text.splitlines()) - 1
    page = client.get("/AS4766", headers=BROWSER)
    assert page.status_code == 200
    rows = _rows(_section(page.text, "as-details"))
    assert rows["Registry"] == "Unknown: not downloaded yet"
    for section in ("as-graph", "as-neighbours", "as-prefixes"):
        assert "Unknown: not downloaded yet" in _section(page.text, section), section
    labels = re.findall(
        r'<div class="as-tile__value tone-muted">([^<]*)</div>', page.text
    )
    assert labels == ["Unknown"] * 4
    # Nothing places the AS: no prefixes to sample, no country to pin.
    assert 'id="as-map"' not in page.text


# Where AS4766's IPv4 space geolocates, in place of a GeoLite2-City read: the
# suite's GeoIP database is whatever data/ holds, so a page test that draws the
# map says what the map is of.
SEOUL_FOOTPRINT = {
    "cities": [
        {"name": "Seoul", "country": "KR", "lat": 37.57, "lon": 126.98, "share": 1.0}
    ],
    "country_level_share": 0.0,
    "unplaced_share": 0.0,
    "sampled_share": 1.0,
    "samples": 1,
}
COUNTRY_LEVEL_ONLY = {
    "cities": [],
    "country_level_share": 1.0,
    "unplaced_share": 0.0,
    "sampled_share": 1.0,
    "samples": 2,
}


def _section(html, section_id):
    """One <section> of the AS page, from its id to its end."""
    return html.split(f'id="{section_id}"')[1].split("</section>")[0]


def test_as_html_page_names_the_as_and_links_neighbours(asinfo_enabled, monkeypatch):
    monkeypatch.setattr(main, "as_footprint", lambda prefixes: SEOUL_FOOTPRINT)
    response = client.get("/AS4766", headers=BROWSER)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    _assert_lookup_headers(response)
    html = response.text
    head = _head(html)

    # The link preview names the AS; the canonical page is /AS4766.
    title = "AS4766 · KIXS-AS-KR-KR - Korea Telecom — WhatIsMyIP"
    assert f"<title>{title}</title>" in head
    assert f'<meta property="og:title" content="{title}">' in head
    assert '<link rel="canonical" href="http://testserver/AS4766">' in head
    assert '<meta property="og:url" content="http://testserver/AS4766">' in head
    (description,) = re.findall(r'<meta name="description" content="([^"]*)">', head)
    assert description == (
        "AS4766 · KIXS-AS-KR-KR - Korea Telecom · KR · 3 prefixes · RPKI 67% valid"
    )
    assert re.findall(r'<meta property="og:description" content="([^"]*)">', head) == [
        description
    ]

    # The hero: the number, its holder and its tags.
    hero = _hero(html)
    assert '<h1 class="ip mono">AS4766</h1>' in hero
    assert "KIXS-AS-KR-KR - Korea Telecom" in hero
    assert '<span class="tag tone-default">ASN</span>' in hero
    assert '<span class="tag tone-default">APNIC</span>' in hero
    assert "NOT ANNOUNCED" not in hero

    # Every neighbour and sibling links to its own page, as every lookup link
    # does; the page's own number does not link to itself.
    for asn in (174, 701, 17858, 38661, 45400, 9318, 9760):
        assert f'<a class="lookup-link" href="/AS{asn}" rel="nofollow">AS{asn}</a>' in (
            html
        )
    assert 'href="/AS4766"' not in html

    # Summary first: the sentence and the four tiles.
    assert 'id="as-summary"' in html
    assert "A network in South Korea, registered with APNIC in 1996." in html
    assert re.findall(r'<div class="as-tile__label">([^<]*)</div>', html) == [
        "IPv4 space",
        "Prefixes",
        "RPKI signed",
        "Neighbours",
    ]
    # The upstream graph and the map (footprint monkeypatched above).
    graph = _section(html, "as-graph")
    assert '<a class="lookup-link" href="/AS174" rel="nofollow">AS174</a>' in graph
    assert 'referrerpolicy="strict-origin" loading="lazy"' in graph
    assert "© OpenStreetMap contributors · GeoLite2 by MaxMind" in graph
    # One neighbours table, 10 rows at most, every relation.
    neighbours = _section(html, "as-neighbours")
    assert neighbours.count('class="lookup-link"') == 6
    assert re.findall(r'data-relation="([a-z]+)"', neighbours) == [
        "all",
        "upstream",
        "downstream",
        "peer",
    ]
    # Details keep the card rows and the credits, CAIDA's linked.
    details = _section(html, "as-details")
    rows = _rows(details)
    assert rows["Registry"] == "APNIC · KR · assigned 1996-04-22"
    assert rows["Organization"] == "Korea Telecom · 1 sibling AS: AS9760"
    assert rows["ASN-DROP"] == "Unknown"

    # The datasets' credits, after the details rows; CAIDA's citations link to
    # their dataset pages, and the JSON keeps the plain lines.
    data = client.get("/AS4766", headers=CURL).json()
    credits = re.findall(
        r'<p class="api-note tone-muted">(.*?)</p>', details.split("</table>")[1]
    )
    caida = "https://www.caida.org/catalog/datasets/"
    assert data["attribution"] == [
        "Source: RIPE NCC",
        "RPKI data validated by rpki-client.org",
        "The CAIDA UCSD AS Relationships Dataset, 2026-10-01",
        "The CAIDA UCSD AS Organizations Dataset, 2026-10-01",
    ]
    assert credits == [
        "Source: RIPE NCC",
        "RPKI data validated by rpki-client.org",
        f'<a href="{caida}as-relationships/" rel="noopener noreferrer">'
        "The CAIDA UCSD AS Relationships Dataset, 2026-10-01</a>",
        f'<a href="{caida}as-organizations/" rel="noopener noreferrer">'
        "The CAIDA UCSD AS Organizations Dataset, 2026-10-01</a>",
    ]

    # The page's own map, server-drawn, and none of an address's or a domain's
    # panels: the lookup page's map band and map.js are not on it.
    for absent in (
        'id="page-map"',
        'id="mobile-map"',
        'id="map-data"',
        "map.js",
        'id="acc-dns"',
        'id="acc-ssl"',
        'id="acc-whois"',
        'id="acc-geoip"',
        'id="acc-headers"',
        'id="acc-subdomains"',
        'id="acc-fingerprint"',
    ):
        assert absent not in html, absent
    panels = re.findall(r'<details class="accordion" id="acc-([a-z]+)"', html)
    assert panels == ["raw"]

    # Raw JSON as on a lookup page: the curl line and the JSON answer.
    raw = html.split('id="acc-raw"')[1]
    assert "curl http://testserver/AS4766" in raw
    assert 'id="raw-json"' in raw
    assert _without_timing(_page_data(html)) == _without_timing(data)

    # Every loaded row travels in the page for as.js, beside the JSON answer
    # rather than in it.
    payload = json.loads(
        re.search(r'id="as-lists" nonce="[^"]*">(.*?)</script>', html, re.S).group(1)
    )
    assert payload["own"] == 4766 and len(payload["neighbours"]["rows"]) == 6


def test_long_lists_say_how_many_are_loaded(asinfo_enabled, monkeypatch):
    # The page's lists stop at ASINFO_PAGE_LIMIT per relation and per family,
    # and say so with the true count beside them.
    monkeypatch.setattr(asinfo, "ASINFO_PAGE_LIMIT", 1)
    html = client.get("/AS4766", headers=BROWSER).text
    neighbours = _section(html, "as-neighbours")
    assert "Largest 1 of 3 downstreams loaded." in neighbours
    assert "Largest 1 of 2 upstreams loaded." in neighbours
    assert "peers loaded" not in neighbours
    # The chips and the button count every neighbour, not just the loaded ones.
    assert "Show all 6 neighbours" in neighbours
    prefixes = _section(html, "as-prefixes")
    assert "Largest 1 of 2 IPv4 prefixes loaded." in prefixes
    assert "Show all 2 prefixes" in prefixes
    # The graph draws the one loaded upstream and counts the other.
    graph = _section(html, "as-graph")
    assert graph.count('class="lookup-link"') == 1
    assert re.search(
        r'<a class="as-graph__more" href="#as-neighbours" data-relation="upstream">'
        r"\+1 more</a>",
        graph,
    )


def test_no_city_placement_falls_back_to_the_country_pin(asinfo_enabled, monkeypatch):
    monkeypatch.setattr(main, "as_footprint", lambda prefixes: COUNTRY_LEVEL_ONLY)
    html = client.get("/AS4766", headers=BROWSER).text
    assert "the pin marks South Korea, at country level." in html
    # One dot, at the centroid of the AS's registered country.
    figure = html.split('id="as-map"')[1].split("</figure>")[0]
    assert figure.count("<circle") == 1


def test_no_country_and_no_placement_draws_no_map(monkeypatch, tmp_path):
    # AS4766's name line without ", KR": no country to fall back to.
    manager = build_manager(
        tmp_path, texts={"asnames": "4766 KIXS-AS-KR-KR - Korea Telecom\n"}
    )
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    monkeypatch.setattr(main, "as_footprint", lambda prefixes: COUNTRY_LEVEL_ONLY)
    html = client.get("/AS4766", headers=BROWSER).text
    assert 'id="as-map"' not in html and 'id="as-graph"' in html
    # The graph ends on the plain node instead.
    assert '<div class="as-graph__node' in _section(html, "as-graph")


def test_the_map_samples_only_the_ipv4_prefixes(asinfo_enabled, monkeypatch):
    asked = []

    def footprint(prefixes):
        asked.append(list(prefixes))
        return SEOUL_FOOTPRINT

    monkeypatch.setattr(main, "as_footprint", footprint)
    client.get("/AS4766", headers=BROWSER)
    assert asked == [["211.252.0.0/15", "211.252.112.0/24"]]
    # JSON and text draw no map, so they sample nothing.
    client.get("/AS4766", headers=CURL)
    client.get("/AS4766?format=text")
    assert len(asked) == 1


def test_markup_in_a_name_stays_text_everywhere_on_the_as_page(monkeypatch, tmp_path):
    # A neighbour (AS174, an upstream: graph row, table row, payload) named
    # with markup.
    names = (
        "174 <img src=x onerror=alert(1)> - Evil, US\n"
        "4766 KIXS-AS-KR-KR - Korea Telecom, KR\n"
    )
    manager = build_manager(tmp_path, texts={"asnames": names})
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    html = client.get("/AS4766", headers=BROWSER).text
    assert "<img src=x" not in html.split('id="page-data"')[0]
    assert "&lt;img src=x onerror=alert(1)&gt;" in _section(html, "as-graph")
    lists = html.split('id="as-lists"')[1].split("</script>")[0]
    assert "<" not in lists.split(">", 1)[1]


def test_an_as_on_asn_drop_says_so(asinfo_enabled, monkeypatch, tmp_path):
    lists = asn_drop_lists(tmp_path / "reputation", 4766)
    monkeypatch.setattr(lookup, "reputation_manager", lists)
    monkeypatch.setattr(main, "reputation_manager", lists)
    assert client.get("/AS4766", headers=CURL).json()["asn_drop"] is True
    assert "asn_drop: true\n" in client.get("/AS4766?format=text").text
    assert "asn_drop: false\n" in client.get("/AS9318?format=text").text
    html = client.get("/AS4766", headers=BROWSER).text
    assert '<span class="tag tone-danger">ASN-DROP</span>' in _hero(html)
    assert _rows(html)["ASN-DROP"] == "Listed on Spamhaus ASN-DROP"
    assert "ASN-DROP" not in _hero(client.get("/AS9318", headers=BROWSER).text)


def test_a_special_asn_answers_its_purpose_as_json(asinfo_enabled, monkeypatch):
    # No dataset is read for it: a private ASN leaked into RIS would draw a
    # card that looks like someone's network.
    monkeypatch.setattr(asinfo_enabled, "for_asn", _never)
    monkeypatch.setattr(asinfo_enabled, "for_address", _never)
    response = client.get("/AS64512", headers=CURL)
    assert response.status_code == 200
    data = response.json()
    assert data["special"]["code"] == "private_asn"
    assert data["special"] == PRIVATE_USE
    assert list(data) == ["address", *ANSWER_KEYS, "special", "elapsed_ms"]
    assert _without_timing(data) == {
        "address": "AS64512",
        **lookup.as_info_for_asn(64512),
    }
    assert data["asn"] == 64512 and data["unavailable"] == []
    assert all(
        data[key] is None for key in ANSWER_KEYS if key not in ("asn", "unavailable")
    )
    for path, code in (("/AS0", "reserved_asn"), ("/AS4294967295", "reserved_asn")):
        assert client.get(path, headers=CURL).json()["special"]["code"] == code


def test_a_special_asn_text_block(asinfo_enabled, monkeypatch):
    monkeypatch.setattr(asinfo_enabled, "for_asn", _never)
    response = client.get("/AS64512", params={"format": "text"})
    assert response.status_code == 200
    assert "range: AS64512-AS65534\n" in response.text
    assert "defined_in: RFC 6996\n" in response.text
    assert response.text == (
        "asn: 64512\n"
        "special: private_asn\n"
        "range: AS64512-AS65534\n"
        "defined_in: RFC 6996\n"
        f"purpose: {PRIVATE_USE['purpose']}\n"
    )
    # A one-number row is named once.
    assert "range: AS23456\n" in client.get("/AS23456?format=text").text
    assert "range: AS4294967295\n" in client.get("/AS4294967295?format=text").text


def test_a_special_asn_page_shows_use_range_and_purpose(asinfo_enabled, monkeypatch):
    monkeypatch.setattr(asinfo_enabled, "for_asn", _never)
    response = client.get("/AS64512", headers=BROWSER)
    assert response.status_code == 200
    html = response.text
    assert "<title>AS64512 · Private use — WhatIsMyIP</title>" in _head(html)
    assert '<link rel="canonical" href="http://testserver/AS64512">' in _head(html)
    hero = _hero(html)
    assert '<h1 class="ip mono">AS64512</h1>' in hero
    # One neutral tag, the label.
    assert re.findall(r'<span class="tag tone-([a-z]+)">([^<]*)</span>', hero) == [
        ("default", "Private use")
    ]
    assert _rows(html) == {
        "Use": "Private use",
        "Range": "AS64512 – AS65534",
        "Defined in": "RFC 6996",
        "Purpose": PRIVATE_USE["purpose"],
    }
    # No data: no lists, no prefixes and no credits, and none of the summary
    # page drawn for an assignable number.
    panels = re.findall(r'<details class="accordion" id="acc-([a-z]+)"', html)
    assert panels == ["as", "raw"]
    for absent in ('id="as-summary"', 'id="as-tiles"', 'id="as-lists"', "as.js"):
        assert absent not in html, absent
    assert 'class="api-note tone-muted">Source' not in html
    assert 'title="AS64512 · private use">AS64512 · private use</span>' in html
    assert 'href="/AS64512"' not in html
    assert _without_timing(_page_data(html))["special"] == PRIVATE_USE

    rows = _rows(client.get("/AS23456", headers=BROWSER).text)
    assert rows["Range"] == "AS23456"
    assert rows["Use"] == "AS_TRANS"


def test_head_special_asn_is_200(monkeypatch):
    lookups = MagicMock(side_effect=AssertionError("HEAD looked the AS up"))
    monkeypatch.setattr(lookup, "as_info_for_asn", lookups)
    monkeypatch.setattr(main, "as_info_for_asn", lookups)
    response = client.head("/AS64512", headers=BROWSER)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.content == b""
    assert (
        client.head("/AS64512", headers=CURL)
        .headers["content-type"]
        .startswith("application/json")
    )


def test_head_as_page(monkeypatch):
    lookups = MagicMock(side_effect=AssertionError("HEAD looked the AS up"))
    monkeypatch.setattr(lookup, "as_info_for_asn", lookups)
    monkeypatch.setattr(main, "as_info_for_asn", lookups)
    for headers, params, media_type in (
        (BROWSER, {}, "text/html"),
        (CURL, {}, "application/json"),
        (CURL, {"format": "text"}, "text/plain"),
    ):
        response = client.head("/AS4766", headers=headers, params=params)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(media_type)
        _assert_lookup_headers(response)
    lookups.assert_not_called()


@pytest.mark.parametrize("path", ["/AS4766", "/AS64512", "/AS0"])
def test_as_lookups_off_is_a_400(path):
    # The suite runs with ASINFO_ENABLED=false: every AS number is refused,
    # the special-purpose ones too.
    assert lookup.asinfo_manager.enabled is False
    response = client.get(path, headers=CURL)
    assert response.status_code == 400
    assert response.json() == {
        "detail": AS_LOOKUPS_OFF,
        "error": AS_LOOKUPS_OFF,
        "code": "asinfo_disabled",
    }
    _assert_lookup_headers(response)

    text = client.get(path, params={"format": "text"})
    assert text.status_code == 400
    assert text.text == f"error: {AS_LOOKUPS_OFF}\n"

    page = client.get(path, headers=BROWSER)
    assert page.status_code == 400
    assert page.headers["content-type"].startswith("text/html")
    assert "<title>AS lookups are off — WhatIsMyIP</title>" in page.text
    assert "ERROR 400" in page.text
    _assert_lookup_headers(page)


def test_an_unknown_asn_is_a_200_saying_so(asinfo_enabled):
    response = client.get("/AS9999", headers=CURL)
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == "AS9999"
    # Every dataset was read and none knows it: not in the data, not unknown.
    assert data["unavailable"] == []
    assert data["name"] is None and data["registry"] is None and data["org"] is None
    assert data["announced"] is False
    assert data["prefix_list"] == {"count": 0, "list": []}

    lines = dict(
        line.split(": ", 1)
        for line in client.get("/AS9999?format=text").text.splitlines()
    )
    assert lines["name"] == lines["rir"] == lines["org"] == lines["upstreams"] == "-"
    assert lines["prefixes_v4"] == lines["downstreams"] == "0"

    html = client.get("/AS9999", headers=BROWSER).text
    assert "<title>AS9999 — WhatIsMyIP</title>" in html
    hero = _hero(html)
    assert '<span class="tag tone-default">NOT ANNOUNCED</span>' in hero
    rows = _rows(_section(html, "as-details"))
    assert rows["Registry"] == "Not in NRO delegated statistics"
    assert rows["Organization"] == "Not in CAIDA AS organizations"
    # Known to have none: a finding, said as one, never "Unknown".
    assert "No announced prefixes" in _section(html, "as-prefixes")
    assert "No upstreams in CAIDA&#39;s data" in _section(html, "as-graph")
    assert "No neighbours in CAIDA&#39;s data" in _section(html, "as-neighbours")
    assert "Unknown" not in _section(html, "as-prefixes")


def test_as_lookup_takes_no_gate_slot(asinfo_enabled, monkeypatch):
    def no_slot():
        raise AssertionError("an AS lookup took a lookup_gate slot")

    monkeypatch.setattr(concurrency.lookup_gate, "slot", no_slot)
    pipeline = AsyncMock(side_effect=AssertionError("an AS lookup reached gather()"))
    monkeypatch.setattr(main, "gather", pipeline)
    for path in ("/AS4766", "/AS64512"):
        for headers, params in ((CURL, {}), (BROWSER, {}), (CURL, {"format": "text"})):
            response = client.get(path, headers=headers, params=params)
            assert response.status_code == 200, (path, headers, params)
    pipeline.assert_not_called()


@pytest.mark.parametrize(
    "query,body",
    [
        (
            "fields=asn_number",
            {"error": AS_FIELDS_UNSUPPORTED, "code": "invalid_field"},
        ),
        ("subdomains=include", {"detail": AS_SUBDOMAINS_UNSUPPORTED}),
        ("subdomains=only", {"detail": AS_SUBDOMAINS_UNSUPPORTED}),
    ],
)
def test_fields_and_subdomains_do_not_apply_to_an_as(asinfo_enabled, query, body):
    # The field table is an address's and a domain's, and an AS has no
    # subdomains: refused rather than answered as though understood.
    response = client.get(f"/AS4766?{query}", headers=CURL)
    assert response.status_code == 400
    assert response.json() == body
    _assert_lookup_headers(response)
    text = client.get(f"/AS4766?{query}&format=text")
    assert text.status_code == 400
    message = body.get("error") or body.get("detail")
    assert text.text == f"error: {message}\n"
    # Not even for a special-purpose number.
    assert client.get(f"/AS64512?{query}", headers=CURL).status_code == 400


def test_as_lookup_is_logged(caplog, asinfo_enabled):
    caplog.set_level(logging.INFO)
    client.get("/as04766", headers=CURL)
    # The service logs through the root logger; the test client's own request
    # lines carry the URL as sent.
    lines = [r.getMessage() for r in caplog.records if r.name == "root"]
    assert any(line.endswith(" lookup=AS4766") for line in lines), lines
    assert not any("as04766" in line for line in lines)


def test_the_as_page_head_is_every_page_s(asinfo_enabled):
    """as.html carries what browser.html, error.html and privacy.html do: the
    versioned stylesheet, the manifest, the theme metas and the icons."""
    response = client.get("/AS4766", headers=BROWSER)
    assert response.status_code == 200
    html = response.text
    head = _head(html)
    assert '<h1 class="ip mono">AS4766</h1>' in html
    assert re.findall(r'<link rel="stylesheet" href="([^"]+)"', head) == [
        f"/static/css/whatismyip.css?v={main.APP_VERSION}"
    ]
    assert '<link rel="manifest" href="/static/site.webmanifest">' in head
    assert '<meta name="theme-color" content="#0B0D12">' in head
    assert '<meta name="color-scheme" content="dark">' in head
    assert '<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">' in head
    assert 'id="lookup-form"' in html and 'class="footer inset"' in html
    assert '<script src="/static/js/app.js" nonce="' in html
    assert "onclick=" not in html


def test_dataset_text_is_escaped_on_the_as_page(monkeypatch, tmp_path):
    # An AS name is third-party text: markup in it is shown, never run.
    names = "4766 <script>alert(1)</script> & Co, KR\n174 COGENT-174 - Cogent, US\n"
    manager = build_manager(tmp_path, texts={"asnames": names})
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    html = client.get("/AS4766", headers=BROWSER).text
    assert "<script>alert(1)</script>" not in html.split('id="page-data"')[0]
    assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; Co" in _hero(html)
    # The Raw JSON copy is JSON with no "<" in it, so nothing in a name can end
    # the script element or open a comment inside it, and it parses back whole.
    embedded = html.split('id="page-data"')[1].split(">", 1)[1].split("</script>")[0]
    assert "<" not in embedded and "\\u003cscript\\u003e" in embedded
    assert _page_data(html)["name"] == "<script>alert(1)</script> & Co"


def test_as_json_neighbours_carry_their_own_size(asinfo_enabled):
    data = client.get("/AS4766", headers=CURL).json()
    assert data["upstreams"][0]["customers"] == 1
    assert data["upstreams"][0]["country"] == "US"
    assert "v4_addresses" in data["downstreams"]["list"][0]
    assert data["org"]["siblings"] == [9760]
    assert client.get("/AS4766?format=text").text == AS4766_BLOCK  # text unchanged
