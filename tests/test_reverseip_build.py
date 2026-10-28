import ipaddress
import os
import sqlite3

import pytest

import reverseip
import reverseip_build
from reverseip_build import NO_RANK, build_database, read_pairs
from reverseip_fixtures import DAY, NOW, ROWS, Row, write_parquet

TRANCO = reverseip.parse_sources("tranco")
BOTH = reverseip.parse_sources("tranco,umbrella")


def _build(tmp_path, copies, sources):
    build_database(str(tmp_path), copies, sources, now=NOW)
    return sqlite3.connect(str(tmp_path / reverseip.DATABASE_NAME))


def _built(tmp_path, rows=ROWS):
    write_parquet(tmp_path / "tranco-0.parquet", rows)
    copies = {"tranco": {"date": DAY, "files": ["tranco-0.parquet"]}}
    return _build(tmp_path, copies, TRANCO)


def names_on(con, ip):
    return [
        n
        for (n,) in con.execute(
            "SELECT n.name FROM addr a JOIN names n ON n.id = a.name_id WHERE a.ip = ?",
            (ipaddress.ip_address(ip).packed,),
        )
    ]


def test_answers_only_ordered_by_rank(tmp_path):
    con = _built(tmp_path)
    assert names_on(con, "93.184.215.14") == [
        "example.com",
        "shop.example.org",
        "upper.example.net",
        "norank.example.com",
    ]


def test_www_is_folded_only_where_the_apex_is(tmp_path):
    con = _built(tmp_path)
    assert names_on(con, "93.184.215.99") == ["www.example.com"]


def test_a_mapped_address_is_stored_as_ipv4(tmp_path):
    assert names_on(_built(tmp_path), "93.184.215.15") == ["mapped.example.org"]


def test_authority_private_and_junk_rows_are_dropped(tmp_path):
    con = _built(tmp_path)
    names = {n for (n,) in con.execute("SELECT name FROM names")}
    assert not names & {"glue.example.com", "private.example.com"}
    assert not any("032" in n for n in names)


def test_ip_count_and_block(tmp_path):
    con = _built(tmp_path)
    packed = ipaddress.ip_address("93.184.215.14").packed
    assert con.execute(
        "SELECT names FROM ip_count WHERE ip = ?", (packed,)
    ).fetchone() == (4,)
    # .14, .15, .16, .99 carry names; distinct names across them:
    # example.com, shop.example.org, upper.example.net, norank.example.com,
    # mapped.example.org, a.b.example.com, www.example.com
    assert con.execute(
        "SELECT addresses, names FROM block WHERE prefix = ?", (packed[:3],)
    ).fetchone() == (4, 7)
    v6 = ipaddress.ip_address("2606:2800:21f:cb07:6820:80da:af6b:8b2c").packed
    assert con.execute(
        "SELECT addresses, names FROM block WHERE prefix = ?", (v6[:6],)
    ).fetchone() == (1, 1)


def test_sub_holds_reversed_names_of_three_labels_or_more(tmp_path):
    con = _built(tmp_path)
    subs = {r[::-1] for (r,) in con.execute("SELECT rname FROM sub")}
    assert {
        "shop.example.org",
        "upper.example.net",
        "a.b.example.com",
        "mapped.example.org",
        "norank.example.com",
    } <= subs
    assert "www.example.com" not in subs  # its apex is listed
    assert "example.com" not in subs  # two labels


def _two_sources(tmp_path, umbrella_rows):
    write_parquet(tmp_path / "tranco-0.parquet", ROWS)
    write_parquet(tmp_path / "umbrella-0.parquet", umbrella_rows)
    copies = {
        "tranco": {"date": DAY, "files": ["tranco-0.parquet"]},
        "umbrella": {"date": DAY, "files": ["umbrella-0.parquet"]},
    }
    return _build(tmp_path, copies, BOTH)


def test_best_rank_and_source_bits_across_sources(tmp_path):
    umbrella = [Row("example.com.", "A", "A", "ans", "93.184.215.14", None, "2")]
    con = _two_sources(tmp_path, umbrella)
    assert con.execute(
        "SELECT rank, sources FROM names WHERE name = 'example.com'"
    ).fetchone() == (2, 0b11)
    # the address row carries the final best rank, and the name only once
    assert con.execute(
        "SELECT a.rank FROM addr a JOIN names n ON n.id = a.name_id"
        " WHERE n.name = 'example.com'"
    ).fetchall() == [(2,)]
    # a name on one source only keeps that source's bit
    assert con.execute(
        "SELECT sources FROM names WHERE name = 'shop.example.org'"
    ).fetchone() == (0b01,)


def test_a_copy_that_does_not_parse_is_left_out_and_recorded(tmp_path, caplog):
    (tmp_path / "umbrella-0.parquet").write_bytes(b"not parquet")
    write_parquet(tmp_path / "tranco-0.parquet", ROWS)
    copies = {
        "tranco": {"date": DAY, "files": ["tranco-0.parquet"]},
        "umbrella": {"date": DAY, "files": ["umbrella-0.parquet"]},
    }
    con = _build(tmp_path, copies, BOTH)
    meta = {
        r[0]: r[1:]
        for r in con.execute("SELECT id, date, pairs, error FROM source_meta")
    }
    assert meta["umbrella"][1] == 0 and meta["umbrella"][2]
    assert meta["umbrella"][0] == DAY  # a copy exists, so its date is recorded
    assert meta["tranco"][1] > 0 and meta["tranco"][2] is None
    assert "umbrella-0.parquet" in caplog.text


def test_a_copy_that_fails_midway_leaves_none_of_its_names(tmp_path):
    write_parquet(tmp_path / "umbrella-0.parquet", ROWS)
    (tmp_path / "umbrella-1.parquet").write_bytes(b"not parquet")
    copies = {
        "umbrella": {
            "date": DAY,
            "files": ["umbrella-0.parquet", "umbrella-1.parquet"],
        }
    }
    con = _build(tmp_path, copies, reverseip.parse_sources("umbrella"))
    assert con.execute("SELECT count(*) FROM names").fetchone() == (0,)
    assert con.execute("SELECT count(*) FROM addr").fetchone() == (0,)


def test_a_copy_past_the_maximum_age_is_left_out(tmp_path):
    write_parquet(tmp_path / "tranco-0.parquet", ROWS)
    copies = {"tranco": {"date": "2026-10-10", "files": ["tranco-0.parquet"]}}
    con = _build(tmp_path, copies, TRANCO)
    assert con.execute("SELECT date, pairs, error FROM source_meta").fetchall() == [
        ("2026-10-10", 0, "older than 96 hours")
    ]
    assert con.execute("SELECT count(*) FROM names").fetchone() == (0,)


def test_a_source_without_a_copy_has_no_date(tmp_path):
    con = _build(tmp_path, {}, TRANCO)
    date, pairs, error = con.execute(
        "SELECT date, pairs, error FROM source_meta"
    ).fetchone()
    assert date is None and pairs == 0 and error


def test_the_file_is_versioned_and_swapped_in_whole(tmp_path):
    con = _built(tmp_path)
    assert con.execute("PRAGMA user_version").fetchone() == (reverseip.SCHEMA_VERSION,)
    assert sorted(os.listdir(tmp_path)) == ["reverseip.sqlite3", "tranco-0.parquet"]
    assert not con.execute(
        "SELECT 1 FROM sqlite_master WHERE name IN ('pair', 'names_name')"
    ).fetchall()


def test_a_failed_build_keeps_the_previous_file(tmp_path, monkeypatch):
    _built(tmp_path).close()
    before = (tmp_path / "reverseip.sqlite3").read_bytes()

    def boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(reverseip_build, "_finish", boom)
    with pytest.raises(RuntimeError):
        _built(tmp_path)
    assert (tmp_path / "reverseip.sqlite3").read_bytes() == before
    assert sorted(os.listdir(tmp_path)) == ["reverseip.sqlite3", "tranco-0.parquet"]


def test_read_pairs_reads_only_the_wanted_columns(tmp_path):
    path = tmp_path / "wide.parquet"
    write_parquet(path, ROWS, pad_columns=3)
    seen = []
    import pyarrow.parquet as pq

    real = pq.ParquetFile.iter_batches

    def spy(self, *args, **kwargs):
        seen.append(kwargs.get("columns"))
        return real(self, *args, **kwargs)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(pq.ParquetFile, "iter_batches", spy)
    try:
        pairs = list(read_pairs(str(path)))
    finally:
        monkeypatch.undo()
    assert seen == [list(reverseip_build.WANTED_COLUMNS)]
    assert ("example.com", ipaddress.ip_address("93.184.215.14").packed, 5) in pairs
    assert (
        "norank.example.com",
        ipaddress.ip_address("93.184.215.14").packed,
        NO_RANK,
    ) in pairs


def test_a_sqlite_failure_is_the_builds_own_and_keeps_the_previous_file(
    tmp_path, monkeypatch
):
    _built(tmp_path).close()
    before = (tmp_path / "reverseip.sqlite3").read_bytes()

    def full_disk(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(reverseip_build, "_insert_file", full_disk)
    with pytest.raises(sqlite3.OperationalError):
        _built(tmp_path)
    assert (tmp_path / "reverseip.sqlite3").read_bytes() == before
    assert sorted(os.listdir(tmp_path)) == ["reverseip.sqlite3", "tranco-0.parquet"]
