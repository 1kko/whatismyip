"""asinfo.py's dataset table, source parsers, database build and reads. No
network."""

import bz2
import datetime
import gzip
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import asinfo
from asinfo import (
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
    CAIDA_ORG_NAME,
    CAIDA_REL_NAME,
    DAY,
    HOUR,
    KT_ORG_ID,
    NOW,
    RIS_V4,
    build_live,
    build_manager,
    fixture_meta,
    iso,
    rebuild,
    write_sources,
)


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
    assert by_id["caida_rel"].pattern and by_id["caida_org"].pattern
    assert all(d.pattern is None for d in datasets[:5])
    assert by_id["nro"].credit == "Source: RIPE NCC"
    assert by_id["rpki"].credit == "RPKI data validated by rpki-client.org"
    assert "{date}" in by_id["caida_rel"].credit


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


def test_build_from_nothing_is_an_empty_database(tmp_path):
    db, rows = _build(tmp_path, {})
    assert rows == {}
    assert db.execute("SELECT count(*) FROM meta WHERE built = 0").fetchone()[0] == 7
    for table in ("asn", "registry", "org", "asn_org", "route", "rel", "asn_stats"):
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


@pytest.mark.parametrize("how", ["left out", "stale"])
def test_without_current_vrps_rpki_is_unavailable_never_not_found(tmp_path, how):
    if how == "left out":
        manager = build_manager(tmp_path, drop=("rpki",))
        reason = "not downloaded yet"
    else:
        old = iso(NOW - 100 * HOUR)
        meta = {"rpki": {"fetched_at": old, "source_date": old}}
        manager = build_manager(tmp_path, meta=meta)
        reason = "4 days old, past its limit of 72 hours"
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
    manager = build_manager(tmp_path)  # the file still holds CAIDA's rows
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


def test_a_read_that_fails_once_is_read_again_from_a_fresh_open(tmp_path, monkeypatch):
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
    assert manager.for_address("211.252.112.1") == expected
    assert len(failed) == 1


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
