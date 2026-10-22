"""asinfo.py's dataset table, source parsers, database build, reads and
refresh. No network: downloads go to a fake fetch, or to a server on
loopback."""

import bz2
import dataclasses
import datetime
import gzip
import http.server
import json
import logging
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import asinfo
from asinfo import (
    DATABASE_NAME,
    DATASET_IDS,
    SCHEMA_VERSION,
    AsInfoManager,
    build_database,
    default_datasets,
    newest_file,
    open_text,
    parse_as_org,
    parse_as_rel,
    parse_asnames,
    parse_nro,
    parse_ris,
    parse_vrps,
    rov_state,
)
from asinfo_fixtures import (
    ASNAMES,
    CAIDA_DATE,
    CAIDA_ORG,
    CAIDA_ORG_NAME,
    CAIDA_REL,
    CAIDA_REL_NAME,
    DAY,
    HOUR,
    KT_ORG_ID,
    NOW,
    RIS_V4,
    Clock,
    build_live,
    build_manager,
    fake_fetch,
    fixture_meta,
    good_ris_v4_bytes,
    iso,
    rebuild,
    refresh_datasets,
    refreshed_manager,
    write_sources,
)
from config import REPUTATION_USER_AGENT


@pytest.fixture(autouse=True)
def _caida_on(monkeypatch):
    """The tests here take CAIDA's datasets as fetched, the default; a
    developer's .env must not turn them off underneath. A test about turning
    them off sets the flag itself."""
    monkeypatch.setattr(asinfo, "ASINFO_CAIDA_ENABLED", True)


def test_asnames_splits_the_country_off_the_last_comma():
    rows = list(
        parse_asnames(
            [
                "4766 KIXS-AS-KR-KR - Korea Telecom, KR",
                "13335 CLOUDFLARENET - Cloudflare, Inc., US",
            ]
        )
    )
    assert rows == [
        (4766, "KIXS-AS-KR-KR - Korea Telecom", "KR"),
        (13335, "CLOUDFLARENET - Cloudflare, Inc.", "US"),
    ]


def test_asnames_without_a_country_keeps_the_whole_name_and_skips_junk():
    rows = list(parse_asnames(["65000 Some Holder", "not-a-number x, KR", "", "7"]))
    assert rows == [(65000, "Some Holder", None)]


def test_nro_keeps_assigned_asn_rows_and_expands_nothing():
    lines = [
        "2|nro|20261019|773470|19821213|20261019|+0000",
        "nro|*|asn|*|117501|summary",
        "apnic|KR|asn|4766|1|19960422|assigned|A9149F3E|e-stats",
        "ripencc|NL|asn|1101|10|19930901|assigned|x|e-stats",
        "arin||asn|7|1||available||e-stats",
    ]
    assert list(parse_nro(lines)) == [
        (4766, 1, "apnic", "KR", "1996-04-22", "assigned"),
        (1101, 10, "ripencc", "NL", "1993-09-01", "assigned"),
    ]


def test_nro_skips_other_types_and_malformed_rows():
    lines = [
        "apnic|KR|ipv4|1.0.0.0|256|20100101|allocated|x|e-stats",
        "apnic|KR|asn|abc|1|19960422|assigned|x|e-stats",
        "apnic|KR|asn|99",
        "lacnic|BR|asn|28000|2|00000000|allocated|x|e-stats",
    ]
    assert list(parse_nro(lines)) == [(28000, 2, "lacnic", "BR", None, "allocated")]


def test_nro_country_is_upper_case_or_none():
    lines = [
        "apnic|kr|asn|4766|1|19960422|assigned|x|e-stats",
        "arin||asn|701|1|19900801|assigned|x|e-stats",
        "ripencc|NLD|asn|1101|1|19930901|assigned|x|e-stats",
    ]
    assert list(parse_nro(lines)) == [
        (4766, 1, "apnic", "KR", "1996-04-22", "assigned"),
        (701, 1, "arin", None, "1990-08-01", "assigned"),
        (1101, 1, "ripencc", None, "1993-09-01", "assigned"),
    ]


def test_ris_drops_comments_sets_thin_rows_and_default_routes():
    lines = [
        "% comment",
        "",
        "174\t0.0.0.0/0\t40",
        "{38266}\t1.39.84.0/22\t65",
        "4766\t14.34.86.32/27\t8",
        "4766\t211.252.112.0/24\t326",
        "6939\t2001:db8::/12\t50",
    ]
    assert list(parse_ris(lines, min_peers=10)) == [(4766, "211.252.112.0/24", 326)]


def test_ris_keeps_ipv6_and_skips_malformed_rows():
    lines = [
        "4766\t2001:2d8::/32\t120",
        "4766\tnot-a-prefix\t120",
        "4766\t10.0.0.1/24\t120",
        "4766\t211.252.0.0/15",
        "4766\t211.252.0.0/15\tmany",
    ]
    assert list(parse_ris(lines, min_peers=10)) == [(4766, "2001:2d8::/32", 120)]


def test_vrps_read_the_as_prefix_off_the_csv():
    lines = [
        "ASN,IP Prefix,Max Length,Trust Anchor,Expires",
        "AS13335,1.0.0.0/24,24,apnic,1792937860",
        "AS0,10.0.0.0/8,32,ripe,1",
    ]
    assert list(parse_vrps(lines)) == [(13335, "1.0.0.0/24", 24), (0, "10.0.0.0/8", 32)]


def test_vrps_skip_malformed_rows():
    lines = ["ASX,1.0.0.0/24,24", "AS1,bogus,24", "AS1,1.0.0.0/24,x", "AS1,1.0.0.0/24"]
    assert list(parse_vrps(lines)) == []


def test_vrps_skip_a_max_length_outside_the_prefix_and_its_family():
    lines = [
        "AS1,1.0.0.0/24,23,apnic,1",
        "AS1,1.0.0.0/24,33,apnic,1",
        "AS1,2001:db8::/32,31,ripe,1",
        "AS1,2001:db8::/32,129,ripe,1",
        "AS1,1.0.0.0/24,24,apnic,1",
        "AS1,1.0.0.0/24,32,apnic,1",
        "AS1,2001:db8::/32,128,ripe,1",
    ]
    assert list(parse_vrps(lines)) == [
        (1, "1.0.0.0/24", 24),
        (1, "1.0.0.0/24", 32),
        (1, "2001:db8::/32", 128),
    ]


def test_as_rel_reads_provider_and_peer_rows():
    lines = [
        "# comment",
        "174|4766|-1|bgp",
        "4766|9318|0|bgp",
        "1|2|1|bgp",
        "x|2|-1|bgp",
        "5|6",
    ]
    assert list(parse_as_rel(lines)) == [(174, 4766, -1), (4766, 9318, 0)]


def test_as_org_tags_asn_and_organization_records():
    lines = [
        "# comment",
        '{"type":"ASN","asn":"4766","name":"KIXS","organizationId":"@aut-1-APNIC"}',
        '{"type":"Organization","organizationId":"@aut-1-APNIC",'
        '"name":"Korea Telecom","country":"KR"}',
        '{"type":"Organization","organizationId":"@aut-2-X","name":"No Country"}',
        '{"type":"ASN","asn":"oops","organizationId":"@aut-1-APNIC"}',
        "{broken json",
        "[1, 2]",
    ]
    assert list(parse_as_org(lines)) == [
        ("asn", 4766, "@aut-1-APNIC"),
        ("org", "@aut-1-APNIC", "Korea Telecom", "KR"),
        ("org", "@aut-2-X", "No Country", None),
    ]


def test_newest_file_picks_the_latest_matching_href():
    html = (
        '<a href="20260901.as-rel2.txt.bz2">x</a>'
        '<a href="20261001.as-rel2.txt.bz2">y</a>'
        '<a href="20261101.as-rel2.txt.bz2.sig">z</a>'
    )
    assert newest_file(html, r"\d{8}\.as-rel2\.txt\.bz2") == "20261001.as-rel2.txt.bz2"
    assert newest_file("<a href='x'>", r"\d{8}\.as-rel2\.txt\.bz2") is None


def test_open_text_sniffs_gzip_bz2_and_plain(tmp_path):
    plain = tmp_path / "plain"
    plain.write_text("a\nb\r\n")
    zipped = tmp_path / "named-nothing-like-gz"
    zipped.write_bytes(gzip.compress(b"one\ntwo\n"))
    bzipped = tmp_path / "named-nothing-like-bz2"
    bzipped.write_bytes(bz2.compress(b"three\n"))
    assert list(open_text(str(plain))) == ["a", "b"]
    assert list(open_text(str(zipped))) == ["one", "two"]
    assert list(open_text(str(bzipped))) == ["three"]


def test_open_text_is_lazy(tmp_path):
    path = tmp_path / "f"
    path.write_text("a\nb\n")
    lines = open_text(str(path))
    assert iter(lines) is lines
    assert next(lines) == "a"


def test_default_datasets_table():
    datasets = default_datasets()
    assert [d.id for d in datasets] == [
        "asnames",
        "nro",
        "ris_v4",
        "ris_v6",
        "rpki",
        "caida_rel",
        "caida_org",
    ]
    assert [d.min_rows for d in datasets] == [
        50_000,
        50_000,
        500_000,
        100_000,
        300_000,
        300_000,
        50_000,
    ]
    by_id = {d.id: d for d in datasets}
    assert {d.interval_hours for d in datasets} == {24}
    assert by_id["ris_v4"].max_age_hours == 72
    assert by_id["caida_rel"].max_age_hours == 75 * 24
    assert by_id["caida_org"].max_age_hours == 200 * 24
    assert by_id["nro"].max_bytes > 57 * 1024 * 1024
    # Room for the CSV unzipped (about 50 MB), from a server that ignores
    # Accept-Encoding.
    assert by_id["rpki"].max_bytes == 128 * 1024 * 1024
    assert by_id["caida_rel"].pattern and by_id["caida_org"].pattern
    assert all(d.pattern is None for d in datasets[:5])
    assert by_id["nro"].credit == "Source: RIPE NCC"
    assert by_id["rpki"].credit == "RPKI data validated by rpki-client.org"
    assert "{date}" in by_id["caida_rel"].credit
    # CAIDA's citations link to their dataset pages; the others link nowhere.
    assert by_id["caida_rel"].credit_url == (
        "https://www.caida.org/catalog/datasets/as-relationships/"
    )
    assert by_id["caida_org"].credit_url == (
        "https://www.caida.org/catalog/datasets/as-organizations/"
    )
    assert all(d.credit_url is None for d in datasets[:5])


def test_default_datasets_are_every_dataset_the_build_reads():
    assert {d.id for d in default_datasets()} == set(DATASET_IDS)


def test_default_datasets_drops_caida_when_disabled(monkeypatch):
    monkeypatch.setattr(asinfo, "ASINFO_CAIDA_ENABLED", False)
    assert [d.id for d in asinfo.default_datasets()] == [
        "asnames",
        "nro",
        "ris_v4",
        "ris_v6",
        "rpki",
    ]


def test_fixture_sources_parse_through_the_real_parsers(tmp_path):
    paths = write_sources(tmp_path)
    assert paths["caida_rel"].endswith(CAIDA_REL_NAME)
    assert paths["caida_org"].endswith(CAIDA_ORG_NAME)

    names = {a: (n, c) for a, n, c in parse_asnames(open_text(paths["asnames"]))}
    assert names[4766] == ("KIXS-AS-KR-KR - Korea Telecom", "KR")
    assert (4766, 1, "apnic", "KR", "1996-04-22", "assigned") in set(
        parse_nro(open_text(paths["nro"]))
    )
    v4 = list(parse_ris(open_text(paths["ris_v4"]), min_peers=10))
    assert (4766, "211.252.112.0/24", 326) in v4
    assert (4766, "211.252.0.0/15", 330) in v4
    assert (13335, "1.1.1.0/24", 340) in v4
    assert len(list(parse_ris(open_text(paths["ris_v6"]), min_peers=10))) == 2
    assert (13335, "1.1.1.0/24", 24) in set(parse_vrps(open_text(paths["rpki"])))
    rels = set(parse_as_rel(open_text(paths["caida_rel"])))
    assert {(174, 4766, -1), (701, 4766, -1), (4766, 9318, 0)} <= rels
    assert len([r for r in rels if r[0] == 4766 and r[2] == -1]) == 3
    org = list(parse_as_org(open_text(paths["caida_org"])))
    members = {r[1] for r in org if r[0] == "asn" and r[2] == KT_ORG_ID}
    assert members == {4766, 9760}


# The database build.

VRP_HEADER = "ASN,IP Prefix,Max Length,Trust Anchor,Expires\n"


def _build(tmp_path, sources=None, meta=None, min_peers=10):
    if sources is None:
        (tmp_path / "src").mkdir()
        sources = write_sources(tmp_path / "src")
    out = tmp_path / "asinfo.sqlite3"
    rows = build_database(sources, str(out), min_peers, meta or {})
    db = sqlite3.connect(out)
    db.row_factory = sqlite3.Row
    return db, rows


def _write(path, text):
    path.write_text(text)
    return str(path)


def _stats(db, asn):
    row = db.execute("SELECT * FROM asn_stats WHERE asn = ?", (asn,)).fetchone()
    return dict(row) if row else None


def _states(db, prefix):
    return [
        tuple(r)
        for r in db.execute(
            "SELECT origin, ris_peers, rpki_state, rpki_reason FROM route"
            " WHERE prefix = ? ORDER BY origin",
            (prefix,),
        )
    ]


def test_rov_states():
    assert rov_state(4766, 24, []) == ("not-found", None)
    assert rov_state(13335, 24, [(13335, 24)]) == ("valid", None)
    assert rov_state(13335, 25, [(13335, 24)]) == ("invalid", "length")
    assert rov_state(64500, 24, [(13335, 24)]) == ("invalid", "origin")
    assert rov_state(13335, 24, [(64500, 24), (13335, 24)]) == ("valid", None)
    assert rov_state(0, 24, [(0, 32)]) == ("invalid", "origin")  # AS0 never validates


def test_rov_state_reads_length_when_any_vrp_names_the_origin():
    assert rov_state(13335, 24, [(64500, 24), (13335, 22)]) == ("invalid", "length")
    assert rov_state(13335, 24, [(13335, 22), (13335, 24)]) == ("valid", None)
    assert rov_state(13335, 24, iter([(13335, 24)])) == ("valid", None)


def test_build_records_rpki_per_origin_of_a_multi_origin_prefix(tmp_path):
    sources = {
        "ris_v4": _write(
            tmp_path / "ris4", "64500\t192.0.2.0/24\t300\n64501\t192.0.2.0/24\t40\n"
        ),
        "rpki": _write(
            tmp_path / "vrps", VRP_HEADER + "AS64500,192.0.2.0/24,24,ripe,1\n"
        ),
    }
    db, rows = _build(tmp_path, sources)
    assert _states(db, "192.0.2.0/24") == [
        (64500, 300, "valid", None),
        (64501, 40, "invalid", "origin"),
    ]
    assert rows == {"ris_v4": 2, "rpki": 1}


def test_build_rpki_sweep_covers_nested_routes_only(tmp_path):
    ris_v4 = (
        "64500\t10.0.0.0/16\t100\n"  # the VRP's own prefix
        "64500\t10.0.1.0/24\t100\n"  # inside it, longer than its max length
        "64502\t10.0.2.0/24\t100\n"  # inside it, another origin
        "64500\t10.1.0.0/24\t100\n"  # past the VRP's end
        "64503\t10.2.0.0/16\t100\n"  # holds a more specific VRP, which covers less
        "64503\t10.2.0.0/24\t100\n"
        "64505\t10.3.0.0/24\t100\n"  # under an AS0 VRP
        "64506\t223.255.0.0/24\t100\n"
    )
    ris_v6 = (
        "64500\t2001:db8:1::/48\t100\n"
        "64504\t2001:db9::/32\t100\n"  # after the last IPv4 VRP: none covers it
    )
    vrps = VRP_HEADER + (
        "AS64500,10.0.0.0/16,16,ripe,1\n"
        "AS64503,10.2.0.0/24,24,ripe,1\n"
        "AS0,10.3.0.0/16,24,ripe,1\n"
        "AS64506,223.0.0.0/8,24,apnic,1\n"
        "AS64500,2001:db8::/32,48,ripe,1\n"
    )
    sources = {
        "ris_v4": _write(tmp_path / "ris4", ris_v4),
        "ris_v6": _write(tmp_path / "ris6", ris_v6),
        "rpki": _write(tmp_path / "vrps", vrps),
    }
    db, _ = _build(tmp_path, sources)
    got = {
        r["prefix"]: (r["rpki_state"], r["rpki_reason"])
        for r in db.execute("SELECT prefix, rpki_state, rpki_reason FROM route")
    }
    assert got == {
        "10.0.0.0/16": ("valid", None),
        "10.0.1.0/24": ("invalid", "length"),
        "10.0.2.0/24": ("invalid", "origin"),
        "10.1.0.0/24": ("not-found", None),
        "10.2.0.0/16": ("not-found", None),
        "10.2.0.0/24": ("valid", None),
        "10.3.0.0/24": ("invalid", "origin"),
        "223.255.0.0/24": ("valid", None),
        "2001:db8:1::/48": ("valid", None),
        "2001:db9::/32": ("not-found", None),
    }
    assert not db.execute(
        "SELECT name FROM sqlite_master WHERE name LIKE '%vrp%'"
    ).fetchall()


def test_build_rpki_sweep_keeps_an_outer_vrp_after_an_inner_one_ends(tmp_path):
    ris_v4 = (
        "64501\t10.1.1.0/24\t100\n"  # inside the inner VRP, its own origin
        "64501\t10.1.1.0/25\t100\n"  # the inner VRP's origin, too long for it
        "64502\t10.1.2.0/24\t100\n"  # inside both, named by neither
        "64500\t10.1.3.0/24\t100\n"  # inside the inner VRP, valid by the outer
        "64500\t10.2.0.0/24\t100\n"  # past the inner VRP, inside the outer
        "64501\t10.2.1.0/24\t100\n"  # the inner VRP's origin, but past it
        "64500\t10.255.255.255/32\t100\n"  # the outer VRP's last address
        "64500\t11.0.0.0/24\t100\n"  # past both
    )
    vrps = VRP_HEADER + (
        "AS64500,10.0.0.0/8,32,ripe,1\nAS64501,10.1.0.0/16,24,ripe,1\n"
    )
    sources = {
        "ris_v4": _write(tmp_path / "ris4", ris_v4),
        "rpki": _write(tmp_path / "vrps", vrps),
    }
    db, _ = _build(tmp_path, sources)
    got = {
        r["prefix"]: (r["rpki_state"], r["rpki_reason"])
        for r in db.execute("SELECT prefix, rpki_state, rpki_reason FROM route")
    }
    assert got == {
        "10.1.1.0/24": ("valid", None),
        "10.1.1.0/25": ("invalid", "length"),
        "10.1.2.0/24": ("invalid", "origin"),
        "10.1.3.0/24": ("valid", None),
        "10.2.0.0/24": ("valid", None),
        "10.2.1.0/24": ("invalid", "origin"),
        "10.255.255.255/32": ("valid", None),
        "11.0.0.0/24": ("not-found", None),
    }


def test_build_stores_route_bounds_as_fixed_width_big_endian_blobs(tmp_path):
    db, _ = _build(tmp_path)
    rows = db.execute(
        'SELECT family, plen, start, "end", prefix FROM route WHERE origin = 4766'
        " ORDER BY family, start, plen"
    ).fetchall()
    assert [tuple(r) for r in rows] == [
        (4, 15, bytes([211, 252, 0, 0]), bytes([211, 253, 255, 255]), "211.252.0.0/15"),
        (
            4,
            24,
            bytes([211, 252, 112, 0]),
            bytes([211, 252, 112, 255]),
            "211.252.112.0/24",
        ),
        (
            6,
            32,
            bytes.fromhex("200102d8" + "00" * 12),
            bytes.fromhex("200102d8" + "ff" * 12),
            "2001:2d8::/32",
        ),
    ]


def test_build_keeps_one_route_per_prefix_and_origin(tmp_path):
    ris = "64500\t192.0.2.0/24\t30\n64500\t192.0.2.0/24\t50\n64500\t192.0.2.0/24\t40\n"
    db, _ = _build(tmp_path, {"ris_v4": _write(tmp_path / "ris4", ris)})
    assert _states(db, "192.0.2.0/24") == [(64500, 50, None, None)]


def test_build_drops_routes_seen_by_too_few_peers(tmp_path):
    (tmp_path / "src").mkdir()
    sources = write_sources(tmp_path / "src")
    for min_peers, expected in ((10, 3), (5, 4)):
        out = tmp_path / f"min{min_peers}.sqlite3"
        rows = build_database({"ris_v4": sources["ris_v4"]}, str(out), min_peers, {})
        assert rows == {"ris_v4": expected}
        db = sqlite3.connect(out)
        assert db.execute("SELECT count(*) FROM route").fetchone()[0] == expected
        db.close()


def test_build_counts_prefixes_and_address_space_once_for_nested_prefixes(tmp_path):
    db, _ = _build(tmp_path)
    assert _stats(db, 4766) == {
        "asn": 4766,
        "v4_prefixes": 2,  # 211.252.0.0/15 and 211.252.112.0/24; the /27 is thin
        "v6_prefixes": 1,
        "v4_addresses": 131072,  # the /24 sits in the /15
        "v6_48s": 65536,
        "rpki_valid": 2,
        "rpki_invalid": 0,
        "rpki_not_found": 1,
        "providers": 2,
        "customers": 3,
        "peers": 1,
    }
    assert _stats(db, 13335)["rpki_valid"] == 1
    assert _stats(db, 13335)["v4_addresses"] == 256


def test_build_counts_disjoint_space_and_v6_in_distinct_48s(tmp_path):
    ris_v4 = (
        "64500\t198.18.0.0/15\t100\n"
        "64500\t198.18.1.0/24\t100\n"
        "64500\t198.51.100.0/24\t100\n"
        "64501\t198.18.0.0/15\t100\n"
    )
    ris_v6 = (
        "64500\t2001:db8::/32\t100\n"
        "64500\t2001:db8:5::/48\t100\n"  # nested
        "64500\t2001:db9:0:100::/56\t100\n"
        "64500\t2001:db9:0:200::/56\t100\n"  # the same /48 as the one before
        "64500\t2001:dba::/48\t100\n"
    )
    sources = {
        "ris_v4": _write(tmp_path / "ris4", ris_v4),
        "ris_v6": _write(tmp_path / "ris6", ris_v6),
    }
    db, _ = _build(tmp_path, sources)
    mine = _stats(db, 64500)
    assert (mine["v4_prefixes"], mine["v4_addresses"]) == (3, 131072 + 256)
    assert (mine["v6_prefixes"], mine["v6_48s"]) == (5, 65536 + 1 + 1)
    other = _stats(db, 64501)
    assert (other["v4_prefixes"], other["v4_addresses"]) == (1, 131072)
    assert other["v6_prefixes"] == other["v6_48s"] == 0
    # No rpki in this build: no route has a state, so no state is counted.
    assert mine["rpki_valid"] == mine["rpki_invalid"] == mine["rpki_not_found"] == 0


def test_build_relationship_and_sibling_rows(tmp_path):
    db, rows = _build(tmp_path)

    def column(sql, *args):
        return {r[0] for r in db.execute(sql, args)}

    assert column("SELECT a FROM rel WHERE b = ? AND kind = -1", 4766) == {174, 701}
    assert column("SELECT b FROM rel WHERE a = ? AND kind = -1", 4766) == {
        17858,
        38661,
        45400,
    }
    assert column(
        "SELECT b FROM rel WHERE a = ? AND kind = 0"
        " UNION SELECT a FROM rel WHERE b = ? AND kind = 0",
        4766,
        4766,
    ) == {9318}
    counts = {
        asn: (s["providers"], s["customers"], s["peers"])
        for asn in (174, 701, 4766, 9318, 45400)
        if (s := _stats(db, asn))
    }
    assert counts == {
        174: (0, 1, 0),
        701: (0, 1, 0),
        4766: (2, 3, 1),
        9318: (0, 0, 1),
        45400: (1, 0, 0),
    }
    # An AS only in the relationships still gets its route counts, as zeros.
    assert _stats(db, 45400)["v4_prefixes"] == 0

    org_id = db.execute("SELECT org_id FROM asn_org WHERE asn = 4766").fetchone()[0]
    assert org_id == KT_ORG_ID
    assert column("SELECT asn FROM asn_org WHERE org_id = ?", org_id) == {4766, 9760}
    org = db.execute("SELECT name, country FROM org WHERE id = ?", (org_id,)).fetchone()
    assert tuple(org) == ("Korea Telecom", "KR")
    assert column("SELECT org_id FROM asn_org WHERE asn = 9318") == {"@aut-9318-APNIC"}
    assert (rows["caida_rel"], rows["caida_org"]) == (6, 5)


def test_build_names_and_registry_ranges(tmp_path):
    db, rows = _build(tmp_path)
    name = db.execute("SELECT name, country FROM asn WHERE asn = 4766").fetchone()
    assert tuple(name) == ("KIXS-AS-KR-KR - Korea Telecom", "KR")

    def registry(asn):
        row = db.execute(
            "SELECT rir, country, assigned, status FROM registry"
            " WHERE first <= ? ORDER BY first DESC LIMIT 1",
            (asn,),
        ).fetchone()
        last = db.execute(
            "SELECT last FROM registry WHERE first <= ? ORDER BY first DESC LIMIT 1",
            (asn,),
        ).fetchone()
        return tuple(row) if row and last[0] >= asn else None

    assert registry(4766) == ("apnic", "KR", "1996-04-22", "assigned")
    assert (
        registry(1101) == registry(1110) == ("ripencc", "NL", "1993-09-01", "assigned")
    )
    assert registry(1111) is None
    assert registry(7) is None  # "available" in the NRO file
    assert (rows["asnames"], rows["nro"]) == (8, 4)


def test_build_returns_and_records_rows_and_dates_per_dataset(tmp_path):
    meta = {
        "ris_v4": {
            "fetched_at": "2026-10-20T08:20:00+00:00",
            "source_date": "2026-10-20",
        },
        "caida_rel": {
            "fetched_at": "2026-10-19T00:00:00+00:00",
            "source_date": "2026-10-01",
        },
    }
    db, rows = _build(tmp_path, meta=meta)
    assert rows == {
        "asnames": 8,
        "nro": 4,
        "ris_v4": 3,
        "ris_v6": 2,
        "rpki": 2,
        "caida_rel": 6,
        "caida_org": 5,
    }
    recorded = {
        r["dataset"]: (r["built"], r["rows"], r["fetched_at"], r["source_date"])
        for r in db.execute("SELECT * FROM meta")
    }
    assert recorded == {
        "asnames": (1, 8, None, None),
        "nro": (1, 4, None, None),
        "ris_v4": (1, 3, "2026-10-20T08:20:00+00:00", "2026-10-20"),
        "ris_v6": (1, 2, None, None),
        "rpki": (1, 2, None, None),
        "caida_rel": (1, 6, "2026-10-19T00:00:00+00:00", "2026-10-01"),
        "caida_org": (1, 5, None, None),
    }
    assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_build_without_a_dataset_leaves_its_tables_empty_and_says_so_in_meta(tmp_path):
    (tmp_path / "src").mkdir()
    sources = write_sources(tmp_path / "src")
    del sources["rpki"], sources["caida_rel"], sources["nro"]
    meta = {"rpki": {"fetched_at": "2026-10-18T00:00:00+00:00", "source_date": None}}
    db, rows = _build(tmp_path, sources, meta)
    assert set(rows) == {"asnames", "ris_v4", "ris_v6", "caida_org"}
    recorded = {
        r["dataset"]: (r["built"], r["rows"], r["fetched_at"])
        for r in db.execute("SELECT * FROM meta")
    }
    assert recorded["rpki"] == (0, 0, "2026-10-18T00:00:00+00:00")
    assert recorded["caida_rel"] == (0, 0, None)
    assert recorded["nro"] == (0, 0, None)
    assert recorded["ris_v4"] == (1, 3, None)
    assert db.execute("SELECT count(*) FROM rel").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM registry").fetchone()[0] == 0
    # Without VRPs a route's state is unknown, not "not-found".
    states = db.execute("SELECT DISTINCT rpki_state, rpki_reason FROM route")
    assert [tuple(r) for r in states] == [(None, None)]
    stats = _stats(db, 4766)
    assert stats["v4_prefixes"] == 2
    assert stats["rpki_valid"] == stats["rpki_not_found"] == stats["providers"] == 0


def test_build_records_the_prefix_lengths_each_family_has(tmp_path):
    db, _ = _build(tmp_path)
    stored = [tuple(r) for r in db.execute("SELECT family, plen FROM route_plen")]
    found = db.execute("SELECT DISTINCT family, plen FROM route ORDER BY 1, 2")
    assert stored == [tuple(r) for r in found]
    assert {family for family, _ in stored} == {4, 6}


def test_build_from_nothing_is_an_empty_database(tmp_path):
    db, rows = _build(tmp_path, {})
    assert rows == {}
    assert db.execute("SELECT count(*) FROM meta WHERE built = 0").fetchone()[0] == 7
    for table in (
        "asn",
        "registry",
        "org",
        "asn_org",
        "route",
        "route_plen",
        "rel",
        "asn_stats",
    ):
        assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0  # noqa: S608


def test_build_refuses_an_unknown_dataset(tmp_path):
    with pytest.raises(ValueError, match="spamhaus"):
        build_database({"spamhaus": "x"}, str(tmp_path / "out"), 10, {})


def test_build_raises_on_a_truncated_source_and_records_no_meta(tmp_path):
    (tmp_path / "src").mkdir()
    sources = write_sources(tmp_path / "src")
    path = sources["ris_v4"]
    with open(path, "rb") as handle:
        whole = handle.read()
    with open(path, "wb") as handle:
        handle.write(whole[:-12])
    out = tmp_path / "asinfo.sqlite3"
    with pytest.raises(EOFError):
        build_database(sources, str(out), 10, {})
    try:
        recorded = sqlite3.connect(out).execute("SELECT count(*) FROM meta").fetchone()
    except sqlite3.DatabaseError:
        return  # no schema written, or not a database: nothing looks complete
    assert recorded == (0,)


def test_build_replaces_a_leftover_file(tmp_path):
    out = tmp_path / "asinfo.sqlite3"
    out.write_bytes(b"left over from a build that died")
    db, rows = _build(tmp_path)
    assert rows["ris_v4"] == 3
    assert db.execute("SELECT count(*) FROM route").fetchone()[0] == 5


def test_built_database_answers_the_reads_from_indexes(tmp_path):
    db, _ = _build(tmp_path)
    reads = [
        ("SELECT plen FROM route_plen WHERE family = ? ORDER BY plen DESC", (4,)),
        (
            "SELECT prefix FROM route WHERE family = 4 AND plen = 24 AND start = ?",
            (bytes([211, 252, 112, 0]),),
        ),
        (
            "SELECT prefix FROM route WHERE origin = ?"
            " ORDER BY family, start LIMIT 100",
            (4766,),
        ),
        ("SELECT b FROM rel WHERE a = ? AND kind = -1", (4766,)),
        ("SELECT a FROM rel WHERE b = ? AND kind = -1", (4766,)),
        ("SELECT asn FROM asn_org WHERE org_id = ?", (KT_ORG_ID,)),
        ("SELECT * FROM asn_stats WHERE asn = ?", (4766,)),
    ]
    for sql, args in reads:
        plan = " ".join(r[3] for r in db.execute("EXPLAIN QUERY PLAN " + sql, args))
        assert plan.startswith("SEARCH"), (sql, plan)
        assert "TEMP B-TREE" not in plan, (sql, plan)


# Reads.

RIPE_CREDIT = "Source: RIPE NCC"
RPKI_CREDIT = "RPKI data validated by rpki-client.org"
CAIDA_REL_CREDIT = "The CAIDA UCSD AS Relationships Dataset, 2026-10-01"
CAIDA_ORG_CREDIT = "The CAIDA UCSD AS Organizations Dataset, 2026-10-01"
EVERY_CREDIT = [RIPE_CREDIT, RPKI_CREDIT, CAIDA_REL_CREDIT, CAIDA_ORG_CREDIT]
AS_SECTIONS = (
    "name",
    "country",
    "registry",
    "org",
    "prefixes",
    "rpki",
    "upstreams",
    "downstreams",
    "peers",
)
CAIDA_EPOCH = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc).timestamp()


def _unavailable(info):
    return {u["dataset"]: u["reason"] for u in info["unavailable"]}


def _asns(entries):
    return [entry["asn"] for entry in entries]


def _seen_by(manager):
    """How many RIS peers see the route covering 211.252.112.1."""
    return manager.for_address("211.252.112.1")["route"]["origins"][0]["ris_peers"]


def test_for_address_finds_the_longest_covering_route(tmp_path):
    info = build_manager(tmp_path).for_address("211.252.112.1")
    # The /24 sits in 211.252.0.0/15, whose VRP lets AS4766 announce up to /24.
    assert info["route"] == {
        "prefix": "211.252.112.0/24",
        "origins": [
            {"asn": 4766, "ris_peers": 326, "rpki": {"state": "valid", "reason": None}}
        ],
    }
    assert info["asn"] == 4766 and info["source"] == "route"
    assert [u["asn"] for u in info["upstreams"]] == [174, 701]
    assert info["registry"] == {
        "rir": "apnic",
        "country": "KR",
        "assigned": "1996-04-22",
        "status": "assigned",
    }


def test_for_address_answers_every_section_of_the_routes_origin(tmp_path):
    info = build_manager(tmp_path).for_address("211.252.112.1")
    dates = {
        dataset_id: fields["source_date"]
        for dataset_id, fields in fixture_meta().items()
    }
    assert info == {
        "asn": 4766,
        "name": "KIXS-AS-KR-KR - Korea Telecom",
        "country": "KR",
        "registry": {
            "rir": "apnic",
            "country": "KR",
            "assigned": "1996-04-22",
            "status": "assigned",
        },
        "org": {
            "id": KT_ORG_ID,
            "name": "Korea Telecom",
            "country": "KR",
            "siblings": [9760],
            "sibling_count": 1,
        },
        "prefixes": {"v4": 2, "v6": 1, "v4_addresses": 131072, "v6_48s": 65536},
        "rpki": {"valid": 2, "invalid": 0, "not_found": 1},
        "upstreams": [
            {"asn": 174, "name": "COGENT-174 - Cogent Communications"},
            {"asn": 701, "name": "UUNET - Verizon Business"},
        ],
        "downstreams": {
            "count": 3,
            "list": [
                {"asn": 17858, "name": "POWERVIS-AS-KR - LG POWERCOMM"},
                {"asn": 38661, "name": "KRNIC-AS-KR - Example Customer One"},
                {"asn": 45400, "name": "KT-CUSTOMER-AS - Example Customer Two"},
            ],
        },
        "peers": {
            "count": 1,
            "list": [{"asn": 9318, "name": "SKB-AS-KR - SK Broadband Co Ltd"}],
        },
        "asn_drop": None,
        "route": {
            "prefix": "211.252.112.0/24",
            "origins": [
                {
                    "asn": 4766,
                    "ris_peers": 326,
                    "rpki": {"state": "valid", "reason": None},
                }
            ],
        },
        "announced": True,
        "source": "route",
        "datasets": dates,
        "unavailable": [],
        "attribution": EVERY_CREDIT,
        "prefix_list": None,
    }
    assert list(info) == list(asinfo.ANSWER_KEYS)


def test_for_address_falls_back_to_a_shorter_route_and_reads_ipv6(tmp_path):
    manager = build_manager(tmp_path)
    assert manager.for_address("211.253.0.1")["route"]["prefix"] == "211.252.0.0/15"
    info = manager.for_address("2606:4700::1111")
    assert info["route"] == {
        "prefix": "2606:4700::/32",
        "origins": [
            {
                "asn": 13335,
                "ris_peers": 150,
                "rpki": {"state": "not-found", "reason": None},
            }
        ],
    }
    assert (info["asn"], info["name"], info["country"]) == (
        13335,
        "CLOUDFLARENET - Cloudflare, Inc.",
        "US",
    )


def test_an_ipv4_mapped_address_is_matched_as_ipv4(tmp_path):
    info = build_manager(tmp_path).for_address("::ffff:211.252.112.1")
    assert info["route"]["prefix"] == "211.252.112.0/24"


def test_a_multi_origin_route_describes_the_origin_most_peers_see(tmp_path):
    texts = {"ris_v4": RIS_V4 + "9318\t211.252.112.0/24\t40\n"}
    info = build_manager(tmp_path, texts=texts).for_address("211.252.112.1")
    assert info["route"]["origins"] == [
        {"asn": 4766, "ris_peers": 326, "rpki": {"state": "valid", "reason": None}},
        {
            "asn": 9318,
            "ris_peers": 40,
            "rpki": {"state": "invalid", "reason": "origin"},
        },
    ]
    assert (info["asn"], info["source"]) == (4766, "route")


def test_an_unannounced_address_falls_back_to_geolite2s_asn(tmp_path):
    manager = build_manager(tmp_path)
    info = manager.for_address("192.0.2.1", fallback_asn=13335)
    assert info["route"] is None and info["announced"] is False
    assert (info["asn"], info["source"]) == (13335, "geolite2")
    assert info["name"] == "CLOUDFLARENET - Cloudflare, Inc."
    assert info["prefixes"] == {"v4": 1, "v6": 1, "v4_addresses": 256, "v6_48s": 65536}
    assert info["unavailable"] == []
    # A route outranks GeoLite2's number.
    assert manager.for_address("1.1.1.1", fallback_asn=4766)["asn"] == 13335


def test_an_unannounced_address_with_no_asn_describes_no_as(tmp_path):
    info = build_manager(tmp_path).for_address("192.0.2.1")
    assert (info["asn"], info["source"], info["announced"]) == (None, None, False)
    assert all(info[key] is None for key in AS_SECTIONS)
    assert info["unavailable"] == []
    # Only the routes were read, so only their source is dated and credited.
    assert list(info["datasets"]) == ["ris_v4"]
    assert info["attribution"] == [RIPE_CREDIT]


def test_an_assignable_asn_with_no_rows_reads_as_empty_not_unavailable(tmp_path):
    info = build_manager(tmp_path).for_asn(200500)
    assert (info["asn"], info["source"], info["announced"]) == (200500, "asn", False)
    assert info["name"] is info["country"] is info["registry"] is info["org"] is None
    assert info["prefixes"] == {"v4": 0, "v6": 0, "v4_addresses": 0, "v6_48s": 0}
    assert info["rpki"] == {"valid": 0, "invalid": 0, "not_found": 0}
    assert info["upstreams"] == []
    assert info["downstreams"] == info["peers"] == {"count": 0, "list": []}
    assert info["unavailable"] == []
    assert info["attribution"] == EVERY_CREDIT


def test_credit_links_give_each_caida_citation_its_dataset_page(tmp_path):
    manager = build_manager(tmp_path)
    info = manager.for_asn(4766)
    assert manager.credit_links(info["datasets"]) == {
        CAIDA_REL_CREDIT: "https://www.caida.org/catalog/datasets/as-relationships/",
        CAIDA_ORG_CREDIT: "https://www.caida.org/catalog/datasets/as-organizations/",
    }
    # Only the credits the answer carries.
    assert set(manager.credit_links(info["datasets"])) <= set(info["attribution"])
    stale = build_manager(tmp_path / "stale", now=CAIDA_EPOCH + 76 * DAY)
    assert list(stale.credit_links(stale.for_asn(4766)["datasets"])) == [
        CAIDA_ORG_CREDIT
    ]
    assert manager.credit_links({}) == {}


def test_a_dataset_left_out_of_the_build_is_unavailable(tmp_path):
    info = build_manager(tmp_path, drop=("nro", "caida_org")).for_asn(4766)
    assert info["registry"] is None and info["org"] is None
    assert _unavailable(info) == {
        "nro": "not downloaded yet",
        "caida_org": "not downloaded yet",
    }
    assert {u["label"] for u in info["unavailable"]} == {
        "NRO delegated statistics",
        "CAIDA AS organizations",
    }
    assert info["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert "nro" not in info["datasets"] and "caida_org" not in info["datasets"]
    assert info["attribution"] == [RIPE_CREDIT, RPKI_CREDIT, CAIDA_REL_CREDIT]


def test_a_stale_dataset_is_unavailable_never_empty(tmp_path):
    now = CAIDA_EPOCH + 76 * DAY  # relationships allow 75 days, organizations 200
    info = build_manager(tmp_path, now=now).for_address("211.252.112.1")
    assert info["upstreams"] is None
    assert info["downstreams"] is None and info["peers"] is None
    assert _unavailable(info) == {"caida_rel": "76 days old, past its limit of 75 days"}
    assert info["org"]["name"] == "Korea Telecom"
    assert "caida_rel" not in info["datasets"]
    assert CAIDA_REL_CREDIT not in info["attribution"]
    assert CAIDA_ORG_CREDIT in info["attribution"]

    fresh = AsInfoManager(
        directory=str(tmp_path), enabled=True, clock=lambda: CAIDA_EPOCH + 74 * DAY
    )
    assert _asns(fresh.for_address("211.252.112.1")["upstreams"]) == [174, 701]


def test_age_is_the_sources_own_date_else_when_it_was_fetched(tmp_path):
    meta = {
        # Fetched long ago, but the source dates itself an hour back.
        "ris_v4": {"fetched_at": iso(NOW - 100 * HOUR), "source_date": iso(NOW - HOUR)},
        # No date of its own: its fetch time is its age.
        "asnames": {"fetched_at": iso(NOW - 80 * HOUR), "source_date": None},
    }
    info = build_manager(tmp_path, meta=meta).for_address("211.252.112.1")
    assert info["route"]["prefix"] == "211.252.112.0/24"
    assert _unavailable(info) == {"asnames": "80 hours old, past its limit of 72 hours"}
    assert info["name"] is None and info["country"] is None
    # Neighbours are CAIDA's; only their names are lost.
    assert info["upstreams"] == [{"asn": 174, "name": None}, {"asn": 701, "name": None}]
    assert "asnames" not in info["datasets"]


@pytest.mark.parametrize(
    "hours, reason",
    [
        (72.4, "73 hours old, past its limit of 72 hours"),
        (95.5, "96 hours old, past its limit of 72 hours"),
        (96.5, "5 days old, past its limit of 72 hours"),
    ],
)
def test_a_stale_age_is_rounded_up_past_its_limit(tmp_path, hours, reason):
    # Rounded to the nearest, 72.4 hours would read "72 hours old, past its
    # limit of 72 hours".
    old = iso(NOW - hours * HOUR)
    manager = build_manager(tmp_path, meta={"rpki": {"source_date": old}})
    assert _unavailable(manager.for_asn(4766)) == {"rpki": reason}


@pytest.mark.parametrize("how", ["left out", "stale"])
def test_without_current_vrps_rpki_is_unavailable_never_not_found(tmp_path, how):
    if how == "left out":
        manager = build_manager(tmp_path, drop=("rpki",))
        reason = "not downloaded yet"
    else:
        old = iso(NOW - 100 * HOUR)
        meta = {"rpki": {"fetched_at": old, "source_date": old}}
        manager = build_manager(tmp_path, meta=meta)
        reason = "5 days old, past its limit of 72 hours"  # 4 days and 4 hours
    info = manager.for_address("2606:4700::1")
    assert info["route"]["origins"] == [{"asn": 13335, "ris_peers": 150, "rpki": None}]
    assert info["rpki"] is None
    assert _unavailable(info) == {"rpki": reason}
    assert RPKI_CREDIT not in info["attribution"]
    full = manager.for_asn(4766, full=True)
    assert [p["rpki"] for p in full["prefix_list"]["list"]] == [None, None, None]
    assert full["prefixes"]["v4"] == 2


def test_caida_turned_off_reads_none_of_its_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(asinfo, "ASINFO_CAIDA_ENABLED", False)
    # The file still holds CAIDA's rows.
    manager = build_manager(tmp_path, datasets=asinfo.default_datasets())
    info = manager.for_asn(4766)
    assert info["org"] is None and info["upstreams"] is None
    assert info["downstreams"] is None and info["peers"] is None
    assert _unavailable(info) == {"caida_rel": "turned off", "caida_org": "turned off"}
    assert [u["label"] for u in info["unavailable"]] == [
        "CAIDA AS relationships",
        "CAIDA AS organizations",
    ]
    assert info["attribution"] == [RIPE_CREDIT, RPKI_CREDIT]
    assert set(manager.status()["datasets"]) == {
        "asnames",
        "nro",
        "ris_v4",
        "ris_v6",
        "rpki",
    }
    assert manager.stale_datasets() == []


def test_no_database_yet_is_every_section_unavailable(tmp_path):
    manager = AsInfoManager(directory=str(tmp_path), enabled=True)
    info = manager.for_address("211.252.112.1")
    assert info["route"] is None and info["upstreams"] is None
    assert info["registry"] is None
    assert {u["dataset"] for u in info["unavailable"]} == {
        d.id for d in default_datasets()
    }
    assert all(info[key] is None for key in AS_SECTIONS)
    assert (info["asn"], info["source"], info["announced"]) == (None, None, None)
    assert set(_unavailable(info).values()) == {"not downloaded yet"}
    assert info["datasets"] == {} and info["attribution"] == []

    geolite2 = manager.for_address("211.252.112.1", fallback_asn=4766)
    assert (geolite2["asn"], geolite2["source"]) == (4766, "geolite2")
    assert all(geolite2[key] is None for key in AS_SECTIONS)
    by_asn = manager.for_asn(4766, full=True)
    assert all(by_asn[key] is None for key in (*AS_SECTIONS, "prefix_list"))
    assert len(by_asn["unavailable"]) == len(DATASET_IDS)

    assert manager.build_attempted is False
    status = manager.status()
    assert (status["enabled"], status["database"]) == (True, False)
    assert all(d["stale"] and d["rows"] == 0 for d in status["datasets"].values())
    # A missing database is /healthz's asinfo_unavailable, not a stale dataset.
    assert manager.stale_datasets() == []


def test_a_missing_directory_is_no_database(tmp_path):
    manager = AsInfoManager(directory=str(tmp_path / "not-there"), enabled=True)
    assert manager.for_asn(4766)["registry"] is None
    assert manager.status()["database"] is False


def test_a_database_from_another_release_is_not_read(tmp_path):
    build_live(tmp_path)
    db = sqlite3.connect(tmp_path / asinfo.DATABASE_NAME)
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    db.close()
    manager = AsInfoManager(directory=str(tmp_path), enabled=True, clock=lambda: NOW)
    info = manager.for_address("211.252.112.1")
    assert info["route"] is None
    assert set(_unavailable(info).values()) == {"the database is from another release"}
    assert manager.status()["database"] is False


def test_a_rebuild_swapped_in_is_read_without_error(tmp_path):
    manager = build_manager(tmp_path)
    assert _seen_by(manager) == 326
    rebuild(tmp_path, ris_v4_peers=400)
    assert _seen_by(manager) == 400


def test_a_rebuild_is_seen_by_a_thread_that_read_the_old_file(tmp_path):
    manager = build_manager(tmp_path)

    with ThreadPoolExecutor(max_workers=1) as one_thread:
        assert one_thread.submit(_seen_by, manager).result() == 326
        rebuild(tmp_path, ris_v4_peers=400)
        assert _seen_by(manager) == 400  # this thread opens the new file first
        assert one_thread.submit(_seen_by, manager).result() == 400


def test_reads_racing_rebuilds_never_raise(tmp_path):
    manager = build_manager(tmp_path)
    built = {326}
    stop = threading.Event()

    def read_until_stopped():
        seen = set()
        while not stop.is_set():
            seen.add(_seen_by(manager))
        return seen

    with ThreadPoolExecutor(max_workers=4) as pool:
        readers = [pool.submit(read_until_stopped) for _ in range(4)]
        for peers in range(400, 410):
            rebuild(tmp_path, ris_v4_peers=peers)
            built.add(peers)
        stop.set()
        seen = set().union(*(reader.result() for reader in readers))
    assert seen <= built
    assert _seen_by(manager) == 409


def test_a_database_removed_under_a_reader_is_no_database(tmp_path):
    manager = build_manager(tmp_path)
    assert manager.for_asn(4766)["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    os.remove(tmp_path / asinfo.DATABASE_NAME)
    info = manager.for_asn(4766)
    assert info["name"] is None
    assert set(_unavailable(info).values()) == {"not downloaded yet"}


def test_a_read_that_fails_once_is_read_again_from_a_fresh_open(
    tmp_path, monkeypatch, caplog
):
    # macOS's own SQLite fails the next read of a file swapped out from under
    # an open connection (SQLITE_IOERR_VNODE), though the file then at the
    # path is a complete build.
    manager = build_manager(tmp_path)
    expected = manager.for_address("211.252.112.1")
    real = asinfo._Reader._execute
    failed = []

    def fail_once(reader, sql, args):
        if not failed:
            failed.append(sql)
            raise sqlite3.OperationalError("disk I/O error")
        return real(reader, sql, args)

    monkeypatch.setattr(asinfo._Reader, "_execute", fail_once)
    with caplog.at_level(logging.WARNING):
        assert manager.for_address("211.252.112.1") == expected
    assert len(failed) == 1
    # Answered in full, but the failure is still logged.
    [record] = [r for r in caplog.records if "AS database" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert "disk I/O error" in record.getMessage()


def test_a_programming_error_is_raised_not_read_as_an_unreadable_file(
    tmp_path, monkeypatch
):
    # A bug in a query is not a file that failed to read.
    manager = build_manager(tmp_path)

    def misuse(reader, sql, args):
        raise sqlite3.ProgrammingError("Incorrect number of bindings supplied")

    monkeypatch.setattr(asinfo._Reader, "_execute", misuse)
    with pytest.raises(sqlite3.ProgrammingError):
        manager.for_address("211.252.112.1")


def test_a_rebuild_with_a_new_prefix_length_finds_the_longer_route(tmp_path):
    manager = build_manager(tmp_path)
    assert manager.for_address("211.252.112.1")["route"]["prefix"] == (
        "211.252.112.0/24"
    )
    rebuild(tmp_path, texts={"ris_v4": RIS_V4 + "4766\t211.252.112.0/28\t50\n"})
    route = manager.for_address("211.252.112.1")["route"]
    assert (route["prefix"], route["origins"][0]["ris_peers"]) == (
        "211.252.112.0/28",
        50,
    )


def test_a_read_takes_the_prefix_lengths_from_the_build(tmp_path, monkeypatch):
    # Finding them in the routes scans the whole table (about 160 ms on the
    # real data), on the event loop, on the first read of every new file.
    manager = build_manager(tmp_path)
    statements = []
    connect = sqlite3.connect

    def traced(*args, **kwargs):
        con = connect(*args, **kwargs)
        con.set_trace_callback(statements.append)
        return con

    monkeypatch.setattr(asinfo.sqlite3, "connect", traced)
    assert manager.for_address("211.252.112.1")["route"]["prefix"] == (
        "211.252.112.0/24"
    )
    assert any("route_plen" in sql for sql in statements)
    assert not any("DISTINCT" in sql.upper() for sql in statements)


def test_a_file_swapped_in_as_a_reader_opens_is_read_with_its_own_lengths(
    tmp_path, monkeypatch
):
    manager = build_manager(tmp_path)
    # Reading caches this file's prefix lengths, which have no /28.
    assert manager.for_address("211.252.112.1")["route"]["prefix"] == (
        "211.252.112.0/24"
    )
    manager._release()
    # The next build, which adds a /28, lands between the reader's stat of the
    # path and its connect.
    following = tmp_path / "following"
    build_live(following, texts={"ris_v4": RIS_V4 + "4766\t211.252.112.0/28\t50\n"})
    connect = sqlite3.connect

    def connect_after_a_swap(*args, **kwargs):
        if (following / DATABASE_NAME).exists():
            os.replace(following / DATABASE_NAME, tmp_path / DATABASE_NAME)
        return connect(*args, **kwargs)

    monkeypatch.setattr(asinfo.sqlite3, "connect", connect_after_a_swap)
    assert manager.for_address("211.252.112.1")["route"]["prefix"] == (
        "211.252.112.0/28"
    )


def test_a_database_that_keeps_failing_is_unavailable_never_raised(
    tmp_path, monkeypatch, caplog
):
    manager = build_manager(tmp_path)

    def fail(reader, sql, args):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(asinfo._Reader, "_execute", fail)
    info = manager.for_address("211.252.112.1", fallback_asn=4766)
    assert info["route"] is None and info["announced"] is None
    assert all(info[key] is None for key in AS_SECTIONS)
    assert (info["asn"], info["source"]) == (4766, "geolite2")
    assert set(_unavailable(info).values()) == {"the database could not be read"}
    assert "Cannot read the AS database" in caplog.text
    caplog.clear()
    manager.for_asn(4766)
    assert "Cannot read the AS database" not in caplog.text  # once per file


def test_a_file_that_is_not_a_database_is_unreadable_never_raised(tmp_path):
    (tmp_path / asinfo.DATABASE_NAME).write_bytes(b"not a database. " * 512)
    manager = AsInfoManager(directory=str(tmp_path), enabled=True)
    info = manager.for_asn(4766)
    assert info["registry"] is None
    assert set(_unavailable(info).values()) == {"the database could not be read"}
    assert manager.status()["database"] is False
    assert manager.stale_datasets() == []


def test_for_asn_full_caps_lists_and_reports_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(asinfo, "ASINFO_LIST_LIMIT", 2)
    caida_rel = (
        "174|4766|-1|bgp\n701|4766|-1|bgp\n1299|4766|-1|bgp\n"
        "4766|17858|-1|bgp\n4766|38661|-1|bgp\n4766|45400|-1|bgp\n"
        # Customers of their own: 45400 has two, 38661 one, 17858 none.
        "45400|200001|-1|bgp\n45400|200002|-1|bgp\n38661|200003|-1|bgp\n"
        # Peers, listed either way round: 9318 has a customer, 3356 none.
        "4766|9318|0|bgp\n3356|4766|0|bgp\n9318|200004|-1|bgp\n"
    )
    info = build_manager(tmp_path, texts={"caida_rel": caida_rel}).for_asn(
        4766, full=True
    )
    assert _asns(info["upstreams"]) == [174, 701, 1299]  # never capped
    assert info["downstreams"]["count"] == 3
    assert _asns(info["downstreams"]["list"]) == [45400, 38661]
    assert info["peers"]["count"] == 2
    assert _asns(info["peers"]["list"]) == [9318, 3356]
    assert info["prefix_list"] == {
        "count": 3,
        "list": [
            {
                "prefix": "211.252.0.0/15",
                "ris_peers": 330,
                "rpki": {"state": "valid", "reason": None},
            },
            {
                "prefix": "211.252.112.0/24",
                "ris_peers": 326,
                "rpki": {"state": "valid", "reason": None},
            },
        ],
    }
    assert (info["source"], info["route"], info["announced"]) == ("asn", None, True)


def test_org_siblings_are_capped_and_counted_in_full(tmp_path, monkeypatch):
    monkeypatch.setattr(asinfo, "ASINFO_LIST_LIMIT", 2)
    more = [
        {"type": "ASN", "asn": str(asn), "name": "KT", "organizationId": KT_ORG_ID}
        for asn in (23577, 3559, 5051)
    ]
    caida_org = "".join(json.dumps(r) + "\n" for r in [*CAIDA_ORG, *more])
    info = build_manager(tmp_path, texts={"caida_org": caida_org}).for_asn(4766)
    # The lowest numbers, the AS itself left out; the count is all of them.
    assert info["org"]["siblings"] == [3559, 5051]
    assert info["org"]["sibling_count"] == 4  # 3559, 5051, 9760, 23577


def test_for_asn_without_full_lists_no_prefixes(tmp_path):
    info = build_manager(tmp_path).for_asn(4766)
    assert info["prefix_list"] is None
    assert info["prefixes"]["v4"] == 2
    assert list(info) == list(asinfo.ANSWER_KEYS)


def test_reads_refuse_what_is_not_an_address_or_an_as_number(tmp_path):
    manager = build_manager(tmp_path)
    assert manager.for_address("not-an-address") is None
    assert manager.for_asn(-1) is None
    assert manager.for_asn(2**32) is None


def test_disabled_manager_answers_none(tmp_path):
    build_live(tmp_path)
    manager = AsInfoManager(directory=str(tmp_path), enabled=False, clock=lambda: NOW)
    assert manager.enabled is False
    assert manager.for_address("211.252.112.1") is None
    assert manager.for_address("211.252.112.1", fallback_asn=4766) is None
    assert manager.for_asn(4766) is None
    assert manager.for_asn(4766, full=True) is None
    assert manager.status() == {"enabled": False}
    assert manager.stale_datasets() == []


def test_status_reports_each_dataset(tmp_path):
    status = build_manager(tmp_path).status()
    assert (status["enabled"], status["database"]) == (True, True)
    assert list(status["datasets"]) == list(DATASET_IDS)
    meta = fixture_meta()
    assert status["datasets"]["ris_v4"] == {
        "label": "RIPE RIS routes (IPv4)",
        "fetched_at": meta["ris_v4"]["fetched_at"],
        "source_date": meta["ris_v4"]["source_date"],
        "age_hours": 2.0,
        "rows": 3,
        "stale": False,
    }
    assert status["datasets"]["caida_rel"] == {
        "label": "CAIDA AS relationships",
        "fetched_at": meta["caida_rel"]["fetched_at"],
        "source_date": "2026-10-01",
        "age_hours": 19.5 * 24,
        "rows": 6,
        "stale": False,
    }


def test_status_and_stale_datasets_name_what_lookups_cannot_read(tmp_path):
    now = CAIDA_EPOCH + 76 * DAY
    manager = build_manager(tmp_path, now=now, drop=("nro",))
    status = manager.status()["datasets"]
    assert [i for i, d in status.items() if d["stale"]] == ["nro", "caida_rel"]
    assert status["caida_rel"]["age_hours"] == 76 * 24
    assert status["nro"]["rows"] == 0
    assert manager.stale_datasets() == [
        "the NRO delegated statistics dataset is unavailable to lookups: "
        "not downloaded yet",
        "the CAIDA AS relationships dataset is unavailable to lookups: "
        "76 days old, past its limit of 75 days",
    ]
    assert build_manager(tmp_path / "fresh").stale_datasets() == []


def test_hosts_names_each_dataset_server_once():
    assert AsInfoManager(enabled=False).hosts() == [
        "ftp.ripe.net",
        "www.ris.ripe.net",
        "console.rpki-client.org",
        "publicdata.caida.org",
    ]


# Download and refresh.

URLS = {d.id: d.url for d in default_datasets(caida=True)}
# Each copy is named after the last segment of the URL it came from.
COPIES = {
    "asnames": "asn.txt",
    "nro": "nro-delegated-stats",
    "ris_v4": "riswhoisdump.IPv4.gz",
    "ris_v6": "riswhoisdump.IPv6.gz",
    "rpki": "rpki.csv",
    "caida_rel": CAIDA_REL_NAME,
    "caida_org": CAIDA_ORG_NAME,
}
# A request's stamp: CAIDA's is its listing's, written before the listing is.
STAMPS = [
    "as-organizations.requested",
    "asn.txt.requested",
    "nro-delegated-stats.requested",
    "riswhoisdump.IPv4.gz.requested",
    "riswhoisdump.IPv6.gz.requested",
    "rpki.csv.requested",
    "serial-2.requested",
]
KT_RENAMED = ASNAMES.replace("Korea Telecom", "KT Corporation").encode()


def _manager(directory, clock, fetch, enabled=True):
    return AsInfoManager(
        directory=str(directory),
        datasets=refresh_datasets(),
        enabled=enabled,
        fetch=fetch,
        clock=clock,
    )


def _requested(fetch):
    return [url for url, _ in fetch.calls]


def _database_file(directory):
    """The live database's identity: a rebuild swaps in another file."""
    stat = (directory / DATABASE_NAME).stat()
    return stat.st_ino, stat.st_mtime_ns


def test_refresh_downloads_every_missing_dataset_and_builds(tmp_path):
    fetch = fake_fetch(
        last_modified={
            "asnames": "Mon, 19 Oct 2026 22:15:00 GMT",
            # The dump's own line and the file name outrank the header.
            "ris_v4": "Tue, 20 Oct 2026 09:28:09 GMT",
            "caida_rel": "Fri, 02 Oct 2026 03:00:00 GMT",
        }
    )
    manager = _manager(tmp_path, Clock(), fetch)
    assert manager.build_attempted is False
    assert manager.refresh() is True
    assert manager.build_attempted is True

    assert fetch.calls == [
        (URLS["asnames"], False),
        (URLS["nro"], False),
        (URLS["ris_v4"], False),
        (URLS["ris_v6"], False),
        (URLS["rpki"], True),  # Accept-Encoding: gzip
        (URLS["caida_rel"], False),  # the listing, then its newest file
        (URLS["caida_rel"] + CAIDA_REL_NAME, False),
        (URLS["caida_org"], False),
        (URLS["caida_org"] + CAIDA_ORG_NAME, False),
    ]
    names = set(os.listdir(tmp_path))
    assert {*COPIES.values(), DATABASE_NAME, *STAMPS} <= names
    assert not [name for name in names if name.endswith(".tmp")]
    # rpki.csv is kept as it came, gzipped; reading sniffs that.
    assert (tmp_path / "rpki.csv").read_bytes()[:2] == b"\x1f\x8b"

    info = manager.for_address("211.252.112.1")
    assert info["route"]["prefix"] == "211.252.112.0/24"
    assert info["route"]["origins"][0]["rpki"] == {"state": "valid", "reason": None}
    assert info["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert _asns(info["upstreams"]) == [174, 701]
    assert info["org"]["name"] == "Korea Telecom"
    assert info["unavailable"] == []

    fetched = iso(NOW)
    generated = "2026-10-19T08:00:00+00:00"
    status = manager.status()["datasets"]
    assert {
        dataset_id: (d["fetched_at"], d["source_date"], d["rows"], d["stale"])
        for dataset_id, d in status.items()
    } == {
        "asnames": (fetched, "2026-10-19T22:15:00+00:00", 8, False),  # Last-Modified
        "nro": (fetched, fetched, 4, False),  # nothing better than the fetch
        "ris_v4": (fetched, generated, 3, False),  # the dump's "generated at"
        "ris_v6": (fetched, generated, 2, False),
        "rpki": (fetched, fetched, 2, False),
        "caida_rel": (fetched, CAIDA_DATE, 6, False),  # the file name's date
        "caida_org": (fetched, CAIDA_DATE, 5, False),
    }


def test_each_request_is_recorded_before_it_is_sent(tmp_path):
    clock = Clock()
    serve = fake_fetch()
    stamped = []

    def fetch(url, dest_path, max_bytes, accept_gzip=False):
        stamped.append({n for n in os.listdir(tmp_path) if n.endswith(".requested")})
        return serve(url, dest_path, max_bytes, accept_gzip)

    _manager(tmp_path, clock, fetch).refresh()
    assert stamped[0] == {"asn.txt.requested"}
    # The listing's stamp covers the file it names.
    assert "serial-2.requested" in stamped[6]
    stamps = {name: os.path.getmtime(tmp_path / name) for name in STAMPS}
    assert set(stamps.values()) == {NOW}


def test_refresh_skips_a_fresh_copy_and_waits_after_a_failed_request(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(asinfo, "ASINFO_RETRY_SECONDS", 3600)
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    built = _database_file(tmp_path)

    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=23)
    assert manager.refresh() is True
    assert fetch.calls == []  # every copy was checked under a day ago

    # A day on, each dataset is checked again, and the AS names fail.
    manager._fetch = fetch = fake_fetch(asnames=OSError("connection reset"))
    clock.advance(hours=2)
    assert manager.refresh() is False
    assert _requested(fetch)[:3] == [URLS["asnames"], URLS["nro"], URLS["ris_v4"]]
    # The rest came back unchanged, so nothing was built.
    assert _database_file(tmp_path) == built
    assert manager.for_asn(4766)["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert manager.for_asn(4766)["unavailable"] == []

    # For an hour after the failed request, the AS names wait, also across a
    # restart; the others are fresh.
    clock.advance(seconds=3599)
    restarted = _manager(tmp_path, clock, fake_fetch())
    assert restarted.refresh() is False
    assert restarted._fetch.calls == []

    # Then they are asked for again, and new rows build a new database.
    restarted._fetch = fetch = fake_fetch(asnames=KT_RENAMED)
    clock.advance(seconds=1)
    assert restarted.refresh() is True
    assert _requested(fetch) == [URLS["asnames"]]
    assert _database_file(tmp_path) != built
    assert restarted.for_asn(4766)["name"] == "KIXS-AS-KR-KR - KT Corporation"
    assert restarted.status()["datasets"]["asnames"]["fetched_at"] == iso(clock())


def test_a_daily_dataset_is_due_up_to_half_a_check_interval_early(
    tmp_path, monkeypatch
):
    # The job runs every ASINFO_CHECK_INTERVAL_SECONDS. Due only a full day
    # after its check, a copy checked a moment into one run waits for the
    # run after that one's day is up, and the daily datasets drift into runs
    # of their own, each with a rebuild.
    monkeypatch.setattr(asinfo, "ASINFO_CHECK_INTERVAL_SECONDS", 3600)
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=23)
    assert manager.refresh() is True
    assert fetch.calls == []  # checked 23 hours ago: not due
    clock.advance(seconds=40 * 60)
    assert manager.refresh() is True
    # Checked 23 hours 40 minutes ago: every dataset is due in this one run.
    assert _requested(fetch) == [
        URLS["asnames"],
        URLS["nro"],
        URLS["ris_v4"],
        URLS["ris_v6"],
        URLS["rpki"],
        URLS["caida_rel"],
        URLS["caida_org"],
    ]


def test_caida_is_downloaded_again_only_when_a_newer_file_is_listed(tmp_path):
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    built = _database_file(tmp_path)

    # A day on, the listings name the same files: neither is downloaded again.
    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=25)
    assert manager.refresh() is True
    caida = [url for url in _requested(fetch) if "caida" in url]
    assert caida == [URLS["caida_rel"], URLS["caida_org"]]
    assert _database_file(tmp_path) == built

    # That check counts: the listings are not read again for another day.
    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=23)
    assert manager.refresh() is True
    assert fetch.calls == []

    # Then a newer month is listed: it is downloaded, replaces the old file,
    # and is built in under its own date.
    newer = "20261101.as-rel2.txt.bz2"
    caida_rel = bz2.compress((CAIDA_REL + "1299|4766|-1|bgp\n").encode())
    manager._fetch = fetch = fake_fetch(
        listed={"caida_rel": newer}, caida_rel=caida_rel
    )
    clock.advance(hours=2)
    assert manager.refresh() is True
    caida = [url for url in _requested(fetch) if "caida" in url]
    assert caida == [URLS["caida_rel"], URLS["caida_rel"] + newer, URLS["caida_org"]]
    assert (tmp_path / newer).exists()
    assert not (tmp_path / CAIDA_REL_NAME).exists()
    info = manager.for_asn(4766)
    assert _asns(info["upstreams"]) == [174, 701, 1299]
    assert "The CAIDA UCSD AS Relationships Dataset, 2026-11-01" in info["attribution"]
    assert manager.status()["datasets"]["caida_rel"]["source_date"] == "2026-11-01"


def test_a_caida_listing_without_its_file_keeps_the_copy(tmp_path):
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    manager._fetch = fetch = fake_fetch(listed={"caida_rel": None})
    clock.advance(hours=25)
    assert manager.refresh() is False
    assert URLS["caida_rel"] in _requested(fetch)
    assert (tmp_path / CAIDA_REL_NAME).exists()
    assert _asns(manager.for_asn(4766)["upstreams"]) == [174, 701]


@pytest.mark.parametrize("download", ["truncated", "reformatted", "thin"])
def test_a_truncated_or_thin_download_keeps_the_old_copy(tmp_path, download):
    # Review Focus 4.
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)  # one good refresh
    copy = tmp_path / "riswhoisdump.IPv4.gz"
    db = tmp_path / "asinfo.sqlite3"
    before = (copy.read_bytes(), db.stat().st_mtime_ns)
    if download == "truncated":
        bad = good_ris_v4_bytes()[:200]  # gzip cut short
        assert len(bad) < len(good_ris_v4_bytes())
    elif download == "reformatted":
        bad = gzip.compress(RIS_V4.replace("\t", ",").encode())  # no row parses
    else:
        bad = gzip.compress(RIS_V4.replace("\t340\n", "\t3\n").encode())  # 2 of 3
    manager._fetch = fake_fetch(ris_v4=bad)
    clock.advance(hours=25)
    assert manager.refresh() is False
    assert (copy.read_bytes(), db.stat().st_mtime_ns) == before
    info = manager.for_address("211.252.112.1")
    assert info["route"] is not None
    # The previous copy is still the one read.
    assert info["unavailable"] == []
    assert not (tmp_path / "riswhoisdump.IPv4.gz.tmp").exists()


def test_a_download_past_its_cap_keeps_the_old_copy(tmp_path):
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    before = (tmp_path / "asn.txt").read_bytes()
    datasets = [dataclasses.replace(d, max_bytes=len(before)) for d in manager.datasets]
    manager.datasets = tuple(datasets)
    manager._fetch = fake_fetch(asnames=before + b"65000 ONE-MORE, NL\n")
    clock.advance(hours=25)
    assert manager.refresh() is False
    assert (tmp_path / "asn.txt").read_bytes() == before


def test_a_failed_build_keeps_the_old_database(tmp_path, monkeypatch, caplog):
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    built = _database_file(tmp_path)
    build = asinfo.build_database

    def fail(sources, out_path, min_peers, meta):
        with open(out_path, "wb") as handle:
            handle.write(b"half a database")
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(asinfo, "build_database", fail)
    manager._fetch = fake_fetch(asnames=KT_RENAMED)
    clock.advance(hours=25)
    assert manager.refresh() is False
    assert _database_file(tmp_path) == built
    assert not (tmp_path / "asinfo.sqlite3.tmp").exists()
    assert "database or disk is full" in caplog.text
    assert manager.for_asn(4766)["name"] == "KIXS-AS-KR-KR - Korea Telecom"

    # The new copy stays, and the next refresh builds it in, downloading
    # nothing.
    monkeypatch.setattr(asinfo, "build_database", build)
    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=1)
    assert manager.refresh() is True
    assert fetch.calls == []
    assert manager.for_asn(4766)["name"] == "KIXS-AS-KR-KR - KT Corporation"


def test_a_database_from_another_release_is_rebuilt_from_the_copies(tmp_path):
    clock = Clock()
    manager = refreshed_manager(tmp_path, clock)
    db = sqlite3.connect(tmp_path / DATABASE_NAME)
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    db.close()
    assert manager.for_address("211.252.112.1")["route"] is None
    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=1)
    assert manager.refresh() is True
    assert fetch.calls == []
    assert manager.for_address("211.252.112.1")["route"]["prefix"] == (
        "211.252.112.0/24"
    )


def test_a_first_refresh_builds_what_it_could_download(tmp_path, monkeypatch):
    monkeypatch.setattr(asinfo, "ASINFO_RETRY_SECONDS", 3600)
    clock = Clock()
    manager = _manager(tmp_path, clock, fake_fetch(ris_v6=OSError("timed out")))
    assert manager.refresh() is False
    assert manager.for_address("1.1.1.1")["route"]["prefix"] == "1.1.1.0/24"
    info = manager.for_address("2606:4700::1")
    assert info["route"] is None and info["announced"] is None
    assert _unavailable(info) == {"ris_v6": "not downloaded yet"}

    # An hour on, the missing dataset is asked for again and built in.
    manager._fetch = fetch = fake_fetch()
    clock.advance(hours=1)
    assert manager.refresh() is True
    assert _requested(fetch) == [URLS["ris_v6"]]
    info = manager.for_address("2606:4700::1")
    assert info["route"]["prefix"] == "2606:4700::/32"
    assert info["unavailable"] == []


def test_a_first_refresh_that_downloads_nothing_leaves_no_database(tmp_path):
    down = {dataset_id: OSError("unreachable") for dataset_id in DATASET_IDS}
    listed = {"caida_rel": OSError("unreachable"), "caida_org": OSError("x")}
    manager = _manager(tmp_path, Clock(), fake_fetch(listed=listed, **down))
    assert manager.refresh() is False
    assert manager.build_attempted is True
    assert not (tmp_path / DATABASE_NAME).exists()
    reasons = _unavailable(manager.for_address("1.1.1.1"))
    assert set(reasons.values()) == {"the database has not been built"}
    assert manager.status()["database"] is False


def test_disabled_refresh_does_nothing(tmp_path):
    directory = tmp_path / "asinfo"
    fetch = fake_fetch()
    manager = _manager(directory, Clock(), fetch, enabled=False)
    assert manager.refresh() is True
    assert fetch.calls == []
    assert not directory.exists()
    assert manager.build_attempted is False


def test_the_default_fetch_is_the_real_download():
    assert AsInfoManager(enabled=False)._fetch is asinfo._download


class _Source(http.server.BaseHTTPRequestHandler):
    """A dataset's server on loopback, answering every GET with `reply`."""

    seen: list[dict] = []
    reply = (200, {}, b"")

    def do_GET(self):  # noqa: N802 - the stdlib's name
        type(self).seen.append(dict(self.headers.items()))
        status, headers, body = type(self).reply
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def source():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Source)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Source.seen = []
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/rpki.csv"
    finally:
        server.shutdown()
        server.server_close()


def test_download_streams_the_body_to_its_file(tmp_path, source):
    body = os.urandom(3 * 1024 * 1024 + 5)  # several chunks
    last_modified = "Tue, 20 Oct 2026 09:28:09 GMT"
    _Source.reply = (200, {"Last-Modified": last_modified}, body)
    dest = tmp_path / "copy.tmp"
    answer = asinfo._download(source, str(dest), len(body))
    assert answer == {"last_modified": last_modified}
    assert dest.read_bytes() == body
    [sent] = _Source.seen
    assert sent["User-Agent"] == REPUTATION_USER_AGENT
    assert sent.get("Accept-Encoding") != "gzip"


def test_download_asks_for_gzip_only_when_told(tmp_path, source):
    _Source.reply = (200, {}, gzip.compress(b"ASN,IP Prefix\n"))
    answer = asinfo._download(source, str(tmp_path / "rpki"), 100, accept_gzip=True)
    assert answer == {"last_modified": None}
    [sent] = _Source.seen
    assert sent["Accept-Encoding"] == "gzip"


@pytest.mark.parametrize("stated", [True, False])
def test_download_refuses_a_body_past_its_cap(tmp_path, source, stated):
    # With a Content-Length it is refused unread; without one, once the
    # body runs past the cap.
    headers = {"Content-Length": "101"} if stated else {}
    _Source.reply = (200, headers, b"y" * 101)
    with pytest.raises(ValueError, match="100"):
        asinfo._download(source, str(tmp_path / "copy.tmp"), 100)


def test_download_refuses_a_body_short_of_its_length(tmp_path, source):
    # Stated 1000 bytes, closed after 400: http.client's read() answers an
    # early b"" there, not an error.
    _Source.reply = (200, {"Content-Length": "1000"}, b"z" * 400)
    with pytest.raises(ValueError, match="400 of its 1000"):
        asinfo._download(source, str(tmp_path / "copy.tmp"), 2000)


def test_a_plain_text_download_cut_short_keeps_the_old_copy(tmp_path, source):
    # Review Focus 4 through the real download. asn.txt is plain text, so
    # the part that arrived parses, and in real data half the file clears
    # min_rows (50,000 of about 123,000 rows).
    url = source.rsplit("/", 1)[0] + "/asn.txt"
    [asnames] = [
        dataclasses.replace(d, url=url, min_rows=1)
        for d in refresh_datasets()
        if d.id == "asnames"
    ]
    clock = Clock()
    manager = AsInfoManager(
        directory=str(tmp_path),
        datasets=[asnames],
        enabled=True,
        fetch=asinfo._download,
        clock=clock,
    )
    whole = ASNAMES.encode()
    _Source.reply = (200, {"Content-Length": str(len(whole))}, whole)
    assert manager.refresh() is True

    half = whole[: len(whole) // 2]
    _Source.reply = (200, {"Content-Length": str(len(whole))}, half)
    clock.advance(hours=25)
    assert manager.refresh() is False
    assert (tmp_path / "asn.txt").read_bytes() == whole
    assert not (tmp_path / "asn.txt.tmp").exists()
    # A row from the half that never came is still read.
    assert manager.for_asn(13335)["name"] == "CLOUDFLARENET - Cloudflare, Inc."


def test_download_raises_on_an_error_status(tmp_path, source):
    _Source.reply = (404, {}, b"not here")
    with pytest.raises(OSError):
        asinfo._download(source, str(tmp_path / "copy.tmp"), 100)


def test_schema_3_stores_each_family_s_median_ris_peers(tmp_path):
    manager = build_manager(tmp_path)
    assert asinfo.SCHEMA_VERSION == 3
    page = manager.page_data(4766)
    # v4 routes after the filters: 326, 330, 340 -> lower median 330;
    # v6: 120, 150 -> 120.
    assert page["medians"] == {"v4": 330, "v6": 120}


def test_page_data_lists_every_relation_with_each_neighbour_s_own_size(tmp_path):
    page = build_manager(tmp_path).page_data(4766)
    assert page["upstreams"]["count"] == 2
    assert page["upstreams"]["list"][0] == {
        "asn": 174,
        "name": "COGENT-174 - Cogent Communications",
        "country": "US",
        "customers": 1,
        "v4_addresses": 0,
        "v4_prefixes": 0,
        "v6_prefixes": 0,
    }
    assert [n["asn"] for n in page["downstreams"]["list"]] == [17858, 38661, 45400]
    assert [n["asn"] for n in page["peers"]["list"]] == [9318]
    assert page["prefixes"]["v4"] == {
        "count": 2,
        "list": [
            {
                "prefix": "211.252.0.0/15",
                "plen": 15,
                "ris_peers": 330,
                "rpki": {"state": "valid", "reason": None},
            },
            {
                "prefix": "211.252.112.0/24",
                "plen": 24,
                "ris_peers": 326,
                "rpki": {"state": "valid", "reason": None},
            },
        ],
    }
    assert page["prefixes"]["v6"]["count"] == 1


def test_page_data_stops_each_list_at_the_page_limit(tmp_path, monkeypatch):
    manager = build_manager(tmp_path)
    monkeypatch.setattr(asinfo, "ASINFO_PAGE_LIMIT", 1)
    page = manager.page_data(4766)
    assert page["upstreams"]["count"] == 2 and len(page["upstreams"]["list"]) == 1
    assert page["downstreams"]["count"] == 3 and len(page["downstreams"]["list"]) == 1
    assert [p["prefix"] for p in page["prefixes"]["v4"]["list"]] == ["211.252.0.0/15"]


def test_page_data_sections_are_none_when_their_dataset_is_unavailable(tmp_path):
    page = build_manager(tmp_path, drop=("caida_rel", "ris_v6")).page_data(4766)
    assert page["upstreams"] is None and page["downstreams"] is None
    assert page["peers"] is None
    assert page["prefixes"] is None and page["medians"] is None


def test_detail_adds_sizes_only_when_asked(tmp_path):
    manager = build_manager(tmp_path)
    detailed = manager.for_asn(4766, full=True, detail=True)
    assert set(detailed["upstreams"][0]) == {
        "asn",
        "name",
        "country",
        "customers",
        "v4_addresses",
        "v4_prefixes",
        "v6_prefixes",
    }
    assert set(detailed["downstreams"]["list"][0]) == set(detailed["upstreams"][0])
    assert detailed["org"]["siblings"] == [9760]
    for answer in (
        manager.for_asn(4766, full=True),
        manager.for_address("211.252.112.5"),
    ):
        assert set(answer["upstreams"][0]) == {"asn", "name"}
