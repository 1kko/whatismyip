import email.message
import io
import ipaddress
import os
import sqlite3
import urllib.error
import urllib.response
from datetime import date

import pyarrow.parquet as pq
import pytest

import config
import reverseip
import reverseip_build
from reverseip_build import (
    NO_RANK,
    WANTED_COLUMNS,
    FetchError,
    Response,
    build_database,
    fetch_columns,
    newest_partition,
    read_pairs,
    urllib_transport,
)
from reverseip_fixtures import DAY, NOW, ROWS, FakeBucket, Row, write_parquet

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


BASE = "https://openintel.test/openintel-public/"


def src(source_id):
    (source,) = reverseip.parse_sources(source_id)
    return source


def key(source_id, day, part=0):
    year, month, dd = day.split("-")
    return (
        f"fdns/basis=toplist/{src(source_id).path}/year={year}/month={month}"
        f"/day={dd}/part-{part:05d}-x.c000.gz.parquet"
    )


def test_the_newest_day_of_this_month():
    bucket = FakeBucket()
    bucket.add(key("tranco", "2026-10-19"), b"x" * 10)
    bucket.add(key("tranco", "2026-10-20"), b"y" * 20)
    part = newest_partition(BASE, src("tranco"), date(2026, 10, 21), bucket)
    assert part.date == "2026-10-20" and part.keys == (
        (key("tranco", "2026-10-20"), 20),
    )


def test_the_first_of_the_month_reads_the_previous_month():
    bucket = FakeBucket()
    bucket.add(key("tranco", "2026-09-30"), b"x" * 10)
    part = newest_partition(BASE, src("tranco"), date(2026, 10, 1), bucket)
    assert part.date == "2026-09-30"
    assert [url.rsplit("/year=", 1)[1] for url, _ in bucket.requests] == [
        "2026/month=10/",
        "2026/month=09/",
    ]


def test_a_month_with_a_day_does_not_read_the_previous_one():
    bucket = FakeBucket()
    bucket.add(key("tranco", "2026-09-30"), b"x" * 10)
    bucket.add(key("tranco", "2026-10-01"), b"y" * 10)
    part = newest_partition(BASE, src("tranco"), date(2026, 10, 1), bucket)
    assert part.date == "2026-10-01" and len(bucket.requests) == 1


def test_no_partition_in_either_month_is_none():
    # January falls back to the December before it
    bucket = FakeBucket()
    bucket.add(key("tranco", "2025-11-30"), b"x" * 10)
    assert newest_partition(BASE, src("tranco"), date(2026, 1, 5), bucket) is None
    assert [url.rsplit("/year=", 1)[1] for url, _ in bucket.requests] == [
        "2026/month=01/",
        "2025/month=12/",
    ]


def test_every_part_of_the_newest_day_is_listed():
    bucket = FakeBucket()
    bucket.add(key("tranco", "2026-10-19"), b"o" * 5)
    # Spark names its parts both ways: `-c000` and `.c000`
    second = key("tranco", "2026-10-20", part=1).replace(".c000", "-c000")
    bucket.add(second, b"b" * 30)
    bucket.add(key("tranco", "2026-10-20"), b"a" * 20)
    bucket.add(key("tranco", "2026-10-20").replace(".parquet", ".crc"), b"c")
    part = newest_partition(BASE, src("tranco"), date(2026, 10, 21), bucket)
    assert part.date == "2026-10-20"
    assert part.keys == ((key("tranco", "2026-10-20"), 20), (second, 30))


def test_crux_countries_list_under_country_code():
    bucket = FakeBucket()
    bucket.add(key("crux:kr", "2026-10-20"), b"k" * 8)
    bucket.add(key("crux:global", "2026-10-21"), b"g" * 8)
    part = newest_partition(BASE, src("crux:kr"), date(2026, 10, 21), bucket)
    assert part.keys == ((key("crux:kr", "2026-10-20"), 8),)
    (url, _), *_ = bucket.requests
    assert url.startswith(BASE + "?list-type=2&prefix=fdns/basis=toplist/")
    assert "source=crux/country-code=kr/year=2026/month=10/" in url


def test_a_truncated_listing_is_followed():
    bucket = FakeBucket(page_size=1)
    for day in ("2026-10-18", "2026-10-19", "2026-10-20"):
        bucket.add(key("tranco", day), b"x" * 10)
    part = newest_partition(BASE, src("tranco"), date(2026, 10, 21), bucket)
    assert part.date == "2026-10-20"
    urls = [url for url, _ in bucket.requests]
    assert len(urls) == 3
    assert "continuation-token" not in urls[0]
    assert all("&continuation-token=" in url for url in urls[1:])


def test_a_listing_that_is_not_200_raises():
    def unavailable(url, headers):
        return Response(503, {}, b"<Error><Code>SlowDown</Code></Error>")

    with pytest.raises(FetchError, match="503"):
        newest_partition(BASE, src("tranco"), date(2026, 10, 21), unavailable)


def _wide(tmp_path, rows=ROWS, pad_columns=0):
    """A source file in the bucket as `k`: its bytes and the bucket."""
    write_parquet(tmp_path / "src.parquet", rows, pad_columns=pad_columns)
    data = (tmp_path / "src.parquet").read_bytes()
    bucket = FakeBucket()
    bucket.add("k", data)
    return data, bucket


def _requested(bucket):
    return [
        tuple(map(int, r.removeprefix("bytes=").split("-"))) for _, r in bucket.requests
    ]


def _chunks(path, names):
    """The byte span of every column chunk whose column is in `names`."""
    group = pq.ParquetFile(path).metadata.row_group(0)
    spans = []
    for i in range(group.num_columns):
        chunk = group.column(i)
        if chunk.path_in_schema in names:
            first = chunk.dictionary_page_offset or chunk.data_page_offset
            spans.append((first, first + chunk.total_compressed_size - 1))
    return spans


def test_only_the_wanted_column_chunks_are_fetched(tmp_path):
    # Forty copies of ROWS put the pad columns' bytes well past the 64 KiB tail.
    data, bucket = _wide(tmp_path, ROWS * 40, pad_columns=20)
    fetched = fetch_columns(
        BASE + "k", len(data), str(tmp_path / "copy.parquet"), bucket
    )
    assert fetched < len(data) / 2
    assert sorted(read_pairs(str(tmp_path / "copy.parquet"))) == sorted(
        read_pairs(str(tmp_path / "src.parquet"))
    )
    # past the footer's tail, no byte of another column is asked for
    names = pq.ParquetFile(tmp_path / "src.parquet").schema_arrow.names
    unwanted = _chunks(tmp_path / "src.parquet", set(names) - set(WANTED_COLUMNS))
    tail, *chunks = _requested(bucket)
    assert tail == (len(data) - 65536, len(data) - 1)
    assert chunks and not any(
        first <= hi and lo <= last for first, last in chunks for lo, hi in unwanted
    )
    # adjacent chunks are asked for as one range
    assert all(nxt[0] > prev[1] + 1 for prev, nxt in zip(chunks, chunks[1:]))
    assert fetched == sum(last - first + 1 for first, last in [tail, *chunks])
    assert os.path.getsize(tmp_path / "copy.parquet") == len(data)


def test_a_file_inside_the_tail_is_one_request(tmp_path):
    data, bucket = _wide(tmp_path)
    copy = tmp_path / "copy.parquet"
    assert fetch_columns(BASE + "k", len(data), str(copy), bucket) == len(data)
    assert _requested(bucket) == [(0, len(data) - 1)]
    assert copy.read_bytes() == data


def test_a_footer_longer_than_the_tail_is_fetched_whole(tmp_path):
    data, bucket = _wide(tmp_path, pad_columns=20)
    footer = len(data) - 8 - int.from_bytes(data[-8:-4], "little")
    copy = tmp_path / "copy.parquet"
    fetch_columns(BASE + "k", len(data), str(copy), bucket, tail=256)
    assert _requested(bucket)[:2] == [
        (len(data) - 256, len(data) - 1),
        (footer, len(data) - 257),
    ]
    assert sorted(read_pairs(str(copy))) == sorted(
        read_pairs(str(tmp_path / "src.parquet"))
    )


def _refused(tmp_path, transport, size, match, **kwargs):
    with pytest.raises(FetchError, match=match):
        fetch_columns(
            BASE + "k", size, str(tmp_path / "copy.parquet"), transport, **kwargs
        )


def test_a_200_is_refused(tmp_path):
    data, bucket = _wide(tmp_path)
    bucket.fail["k"] = Response(200, {"content-length": str(len(data))}, data)
    _refused(tmp_path, bucket, len(data), "HTTP 200")
    assert sorted(os.listdir(tmp_path)) == ["src.parquet"]


def test_a_wrong_content_range_is_refused(tmp_path):
    # the object changed size since it was listed
    data, bucket = _wide(tmp_path)
    bucket.fail["k"] = Response(
        206, {"content-range": f"bytes 0-{len(data) - 1}/{len(data) + 1}"}, data
    )
    _refused(tmp_path, bucket, len(data), "content-range")
    assert sorted(os.listdir(tmp_path)) == ["src.parquet"]


def test_a_short_body_is_refused(tmp_path):
    data, bucket = _wide(tmp_path)
    bucket.fail["k"] = Response(
        206, {"content-range": f"bytes 0-{len(data) - 1}/{len(data)}"}, data[:-1]
    )
    _refused(tmp_path, bucket, len(data), "a body of")
    assert sorted(os.listdir(tmp_path)) == ["src.parquet"]


def test_a_failure_after_the_footer_keeps_the_previous_copy(tmp_path):
    data, bucket = _wide(tmp_path, pad_columns=20)
    (tmp_path / "copy.parquet").write_bytes(b"yesterday's copy")

    def short_chunks(url, headers):
        response = bucket(url, headers)
        if len(bucket.requests) > 2:  # past the two footer requests
            return response._replace(body=response.body[:-1])
        return response

    _refused(tmp_path, short_chunks, len(data), "a body of", tail=256)
    assert len(bucket.requests) == 3
    assert (tmp_path / "copy.parquet").read_bytes() == b"yesterday's copy"
    assert sorted(os.listdir(tmp_path)) == ["copy.parquet", "src.parquet"]


def test_a_missing_column_is_refused(tmp_path):
    write_parquet(tmp_path / "full.parquet", ROWS)
    table = pq.read_table(tmp_path / "full.parquet").drop_columns(["rank"])
    pq.write_table(table, tmp_path / "src.parquet")
    data = (tmp_path / "src.parquet").read_bytes()
    bucket = FakeBucket()
    bucket.add("k", data)
    _refused(tmp_path, bucket, len(data), "rank")
    assert sorted(os.listdir(tmp_path)) == ["full.parquet", "src.parquet"]


def test_a_file_that_is_not_parquet_is_refused(tmp_path):
    bucket = FakeBucket()
    bucket.add("k", b"<html>not here</html>")
    _refused(tmp_path, bucket, 21, "Parquet")
    assert os.listdir(tmp_path) == []


def _headers(**fields):
    message = email.message.Message()
    for name, value in fields.items():
        message[name.replace("_", "-")] = value
    return message


def test_urllib_transport_sends_the_user_agent_and_not_the_hint(monkeypatch):
    seen = {}

    def urlopen(request, timeout):
        seen.update(headers=dict(request.header_items()), timeout=timeout)
        headers = _headers(Content_Length="3", Content_Range="bytes 0-2/10")
        return urllib.response.addinfourl(
            io.BytesIO(b"abc"), headers, request.full_url, code=206
        )

    monkeypatch.setattr(reverseip_build.urllib.request, "urlopen", urlopen)
    response = urllib_transport(BASE + "k", {"range": "bytes=0-2", "x-max-bytes": "3"})
    assert response == Response(
        206, {"content-length": "3", "content-range": "bytes 0-2/10"}, b"abc"
    )
    assert seen == {
        "headers": {"Range": "bytes=0-2", "User-agent": config.REPUTATION_USER_AGENT},
        "timeout": 60,
    }


def test_urllib_transport_returns_an_error_status(monkeypatch):
    def urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            416,
            "Range Not Satisfiable",
            _headers(Content_Length="5"),
            io.BytesIO(b"nope!"),
        )

    monkeypatch.setattr(reverseip_build.urllib.request, "urlopen", urlopen)
    assert urllib_transport(BASE + "k", {"x-max-bytes": "100"}) == Response(
        416, {"content-length": "5"}, b"nope!"
    )


@pytest.mark.parametrize(
    ("stated", "body", "match"),
    [
        ("100", b"x" * 100, "100 bytes"),  # refused before a byte is read
        (None, b"x" * 11, "more than 10"),
        ("10", b"x" * 5, "after 5 of its 10"),  # the connection dropped
    ],
    ids=["stated", "unstated", "dropped"],
)
def test_urllib_transport_holds_the_body_to_the_hint(monkeypatch, stated, body, match):
    def urlopen(request, timeout):
        headers = _headers(Content_Length=stated) if stated else _headers()
        return urllib.response.addinfourl(
            io.BytesIO(body), headers, request.full_url, code=200
        )

    monkeypatch.setattr(reverseip_build.urllib.request, "urlopen", urlopen)
    with pytest.raises(FetchError, match=match):
        urllib_transport(BASE + "k", {"x-max-bytes": "10"})
