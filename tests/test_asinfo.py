"""asinfo.py's dataset table and source parsers. No network, no database."""

import bz2
import gzip

from asinfo import (
    default_datasets,
    newest_file,
    open_text,
    parse_as_org,
    parse_as_rel,
    parse_asnames,
    parse_nro,
    parse_ris,
    parse_vrps,
)
from asinfo_fixtures import CAIDA_ORG_NAME, CAIDA_REL_NAME, write_sources


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


def test_default_datasets_drops_caida_when_disabled(monkeypatch):
    import asinfo

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
    members = {r[1] for r in org if r[0] == "asn" and r[2] == "@aut-45400-APNIC"}
    assert members == {4766, 9760}
