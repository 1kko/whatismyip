"""Reverse IP, the child process's work: list OpenINTEL's bucket, range-read
the columns the build needs, and build one SQLite file from those copies. The
child is the only place pyarrow is imported.

Imports `config`, `reverseip`, pyarrow and the standard library. Nothing in
the web process imports it."""

import datetime
import html
import http.client
import ipaddress
import logging
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from calendar import timegm
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import NamedTuple

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

import config
import reverseip

logger = logging.getLogger(__name__)

WANTED_COLUMNS = (
    "query_name",
    "response_type",
    "section",
    "ip4_address",
    "ip6_address",
    "rank",
)
# A name on a list that gives no position sorts after every ranked one.
NO_RANK = 2**31 - 1
BATCH_ROWS = 65536

_NAME = re.compile(r"[a-z0-9._-]{1,253}")
_SCRATCH_NAME = "reverseip.build.sqlite3"

_SCHEMA = """
CREATE TABLE names(id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                   rank INTEGER NOT NULL, sources INTEGER NOT NULL);
CREATE UNIQUE INDEX names_name ON names(name);
CREATE TABLE pair(ip BLOB NOT NULL, name_id INTEGER NOT NULL,
                  PRIMARY KEY (ip, name_id)) WITHOUT ROWID;
CREATE TABLE addr(ip BLOB, rank INTEGER, name_id INTEGER,
                  PRIMARY KEY (ip, rank, name_id)) WITHOUT ROWID;
CREATE TABLE ip_count(ip BLOB PRIMARY KEY, names INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE block(prefix BLOB PRIMARY KEY, addresses INTEGER NOT NULL,
                   names INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE sub(rname TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE source_meta(id TEXT PRIMARY KEY, date TEXT,
                         pairs INTEGER NOT NULL, error TEXT);
"""


def _packed(text: str | None) -> bytes | None:
    """The address as bytes (an IPv4-mapped one as IPv4), or None unless it is
    a global unicast address."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast:
        return None
    return address.packed


def _rank(text: str | None) -> int:
    if text and text.isascii() and text.isdigit():
        return min(int(text), NO_RANK)
    return NO_RANK


def read_pairs(path: str) -> Iterator[tuple[str, bytes, int]]:
    """`(name, packed address, rank)` for each answer row of a Parquet file.

    Only WANTED_COLUMNS are read: a local copy holds real bytes for no others.
    Batches are filtered in Arrow before any row becomes a Python object."""
    reader = pq.ParquetFile(path)
    for batch in reader.iter_batches(
        batch_size=BATCH_ROWS, columns=list(WANTED_COLUMNS)
    ):
        is_a = pc.and_(
            pc.equal(batch["response_type"], "A"), pc.is_valid(batch["ip4_address"])
        )
        is_aaaa = pc.and_(
            pc.equal(batch["response_type"], "AAAA"),
            pc.is_valid(batch["ip6_address"]),
        )
        keep = pc.and_(pc.equal(batch["section"], "ans"), pc.or_(is_a, is_aaaa))
        kept = batch.filter(pc.fill_null(keep, False))
        for name, kind, ip4, ip6, rank in zip(
            kept["query_name"].to_pylist(),
            kept["response_type"].to_pylist(),
            kept["ip4_address"].to_pylist(),
            kept["ip6_address"].to_pylist(),
            kept["rank"].to_pylist(),
        ):
            if not name:
                continue
            name = name.lower().removesuffix(".")
            if "." not in name or not _NAME.fullmatch(name):
                continue
            packed = _packed(ip4 if kind == "A" else ip6)
            if packed is not None:
                yield name, packed, _rank(rank)


def _insert_file(con: sqlite3.Connection, path: str, bit: int) -> int:
    """Stream one copy into `names` and `pair`; returns the pairs read."""
    count = 0
    batch: list[tuple[str, bytes, int]] = []

    def flush() -> None:
        best: dict[str, int] = {}
        for name, _, rank in batch:
            if rank < best.get(name, NO_RANK + 1):
                best[name] = rank
        con.executemany(
            "INSERT INTO names(name, rank, sources) VALUES (?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET rank = min(rank, excluded.rank),"
            " sources = sources | excluded.sources",
            [(name, rank, bit) for name, rank in best.items()],
        )
        con.executemany(
            "INSERT OR IGNORE INTO pair(ip, name_id)"
            " SELECT ?, id FROM names WHERE name = ?",
            [(ip, name) for name, ip, _ in batch],
        )
        batch.clear()

    for item in read_pairs(path):
        batch.append(item)
        count += 1
        if len(batch) >= BATCH_ROWS:
            flush()
    if batch:
        flush()
    return count


def _age_error(date: str, now: float) -> str | None:
    """The reason a copy is too old to build from, counted from the start of
    its UTC day: the one rule the read side applies too."""
    try:
        year, month, day = (int(part) for part in date.split("-"))
        started = timegm((year, month, day, 0, 0, 0))
    except (ValueError, OverflowError):
        return f"unreadable date {date!r}"
    if now - started > config.REVERSEIP_MAX_AGE_HOURS * 3600:
        return f"older than {config.REVERSEIP_MAX_AGE_HOURS:g} hours"
    return None


def _add_source(
    con: sqlite3.Connection,
    directory: str,
    source: reverseip.Source,
    bit: int,
    copy: dict | None,
    now: float,
) -> None:
    date = copy.get("date") if copy else None
    error = None
    pairs = 0
    if copy is None:
        error = "no copy"
    else:
        error = _age_error(str(date), now)
    if error is None:
        current = ""
        con.execute("SAVEPOINT source")
        try:
            for name in copy.get("files", []):
                current = name
                pairs += _insert_file(con, os.path.join(directory, name), bit)
        except (pa.ArrowException, OSError) as exc:
            # Only a copy that will not read; a SQLite error is the build's own
            # and propagates, so the previous database stays in place.
            logger.warning(
                "reverse IP: %s copy left out, %s: %s", source.id, current, exc
            )
            con.execute("ROLLBACK TO source")
            pairs = 0
            error = f"could not read {current}: {exc}"
        con.execute("RELEASE source")
    con.execute(
        "INSERT INTO source_meta(id, date, pairs, error) VALUES (?, ?, ?, ?)",
        (source.id, date, pairs, error),
    )


def _fill(con: sqlite3.Connection) -> None:
    """Everything derived from `names` and `pair`, once every source is in."""
    # www.<x> is left off an address that <x> is also on.
    con.execute(
        "INSERT INTO addr(ip, rank, name_id)"
        " SELECT p.ip, n.rank, p.name_id FROM pair p JOIN names n ON n.id = p.name_id"
        " WHERE NOT (substr(n.name, 1, 4) = 'www.' AND EXISTS ("
        "   SELECT 1 FROM names a JOIN pair q ON q.name_id = a.id"
        "   WHERE a.name = substr(n.name, 5) AND q.ip = p.ip))"
    )
    con.execute(
        "INSERT INTO ip_count(ip, names) SELECT ip, count(*) FROM addr GROUP BY ip"
    )
    con.execute(
        "INSERT INTO block(prefix, addresses, names)"
        " SELECT prefix, count(DISTINCT ip), count(DISTINCT name_id) FROM ("
        "   SELECT CASE WHEN length(ip) = 4 THEN substr(ip, 1, 3)"
        "          ELSE substr(ip, 1, 6) END AS prefix, ip, name_id FROM addr)"
        " GROUP BY prefix"
    )
    con.create_function("rev", 1, lambda s: s[::-1], deterministic=True)
    con.execute(
        "INSERT INTO sub(rname) SELECT rev(name) FROM names"
        " WHERE length(name) - length(replace(name, '.', '')) >= 2"
        " AND NOT (substr(name, 1, 4) = 'www.'"
        "   AND substr(name, 5) IN (SELECT name FROM names))"
    )


def _finish(scratch: str, tmp: str, final: str) -> None:
    """Write the scratch file out whole and swap it in."""
    con = sqlite3.connect(scratch, isolation_level=None)
    try:
        con.execute("DROP TABLE pair")
        con.execute("DROP INDEX names_name")
        con.execute("VACUUM INTO ?", (tmp,))
    finally:
        con.close()
    os.replace(tmp, final)


def build_database(
    directory: str,
    copies: dict[str, dict],
    sources: Sequence[reverseip.Source],
    now: float | None = None,
) -> None:
    """Build `reverseip.sqlite3` in `directory` from the copies it lists.

    A source whose copy is missing, too old or unreadable is recorded in
    `source_meta` and left out; the others still build. A failure of the build
    itself raises and leaves the previous database in place."""
    now = time.time() if now is None else now
    scratch = os.path.join(directory, _SCRATCH_NAME)
    final = os.path.join(directory, reverseip.DATABASE_NAME)
    tmp = final + ".tmp"
    for stale in (scratch, tmp):
        if os.path.exists(stale):
            os.remove(stale)
    try:
        con = sqlite3.connect(scratch, isolation_level=None)
        try:
            con.execute("PRAGMA journal_mode = OFF")
            con.execute("PRAGMA synchronous = OFF")
            con.executescript(_SCHEMA)
            con.execute("BEGIN")
            for position, source in enumerate(sources):
                _add_source(
                    con,
                    directory,
                    source,
                    1 << position,
                    copies.get(source.id),
                    now,
                )
            _fill(con)
            con.execute(f"PRAGMA user_version = {int(reverseip.SCHEMA_VERSION)}")
            con.execute("COMMIT")
        finally:
            con.close()
        _finish(scratch, tmp, final)
    finally:
        for leftover in (scratch, tmp):
            if os.path.exists(leftover):
                os.remove(leftover)


class Response(NamedTuple):
    status: int
    # Header names are lower-case.
    headers: dict[str, str]
    body: bytes


# (url, headers) -> Response. `x-max-bytes` in the headers is a hint to the
# transport, the most body it may read; it is never sent.
Transport = Callable[[str, dict[str, str]], Response]


class FetchError(Exception):
    """A listing or a range the bucket did not answer as asked."""


_TIMEOUT_SECONDS = 60
_CHUNK = 1 << 20
# One ListObjectsV2 page is at most 1,000 keys, a few hundred KB.
_LISTING_MAX_BYTES = 8 << 20


def _read(response, limit: int, url: str) -> bytes:
    """The body, refused past `limit` (unread when the response says up front
    that it is longer) and when it ends short of its Content-Length:
    http.client's read(amt) answers a dropped connection with an early b"",
    not an error."""
    status = response.status
    stated = response.headers.get("Content-Length", "")
    if stated.isdigit() and int(stated) > limit:
        raise FetchError(f"HTTP {status}: {url} is {stated} bytes, more than {limit}")
    chunks: list[bytes] = []
    size = 0
    while chunk := response.read(min(_CHUNK, limit + 1 - size)):
        size += len(chunk)
        if size > limit:
            raise FetchError(f"HTTP {status}: {url} sent more than {limit} bytes")
        chunks.append(chunk)
    if stated.isdigit() and size != int(stated):
        raise FetchError(
            f"HTTP {status}: {url} ended after {size} of its {stated} bytes"
        )
    return b"".join(chunks)


def urllib_transport(url: str, headers: dict[str, str]) -> Response:
    """GET `url` with `headers` and REPUTATION_USER_AGENT, reading at most the
    `x-max-bytes` hint. An HTTP error status is a Response, not an exception.
    The URL is the operator's REVERSEIP_BASE_URL, or a key its listing gave
    that matched a partition's pattern, never user input."""
    limit = int(headers["x-max-bytes"])
    sent = {name: value for name, value in headers.items() if name != "x-max-bytes"}
    sent["User-Agent"] = config.REPUTATION_USER_AGENT
    request = urllib.request.Request(url, headers=sent)  # noqa: S310
    try:
        try:
            response = urllib.request.urlopen(  # noqa: S310
                request, timeout=_TIMEOUT_SECONDS
            )
        except urllib.error.HTTPError as error:
            response = error
        with response:
            received = {name.lower(): value for name, value in response.headers.items()}
            return Response(response.status, received, _read(response, limit, url))
    except http.client.HTTPException as exc:
        raise FetchError(f"{url}: {exc!r}") from exc


@dataclass(frozen=True)
class Partition:
    date: str
    # (object key, size) of every part-*.parquet of that day, sorted by key.
    keys: tuple[tuple[str, int], ...]


_CONTENTS = re.compile(r"<Contents>(.*?)</Contents>", re.S)
_KEY = re.compile(r"<Key>(.*?)</Key>", re.S)
_SIZE = re.compile(r"<Size>(\d+)</Size>")
_TRUNCATED = re.compile(r"<IsTruncated>(true|false)</IsTruncated>")
_NEXT = re.compile(r"<NextContinuationToken>(.*?)</NextContinuationToken>", re.S)


def _month_days(
    base_url: str, prefix: str, transport: Transport
) -> dict[str, list[tuple[str, int]]]:
    """The part files listed under one month's prefix, by zero-padded day.
    Follows continuation tokens while the listing is truncated."""
    day_part = re.compile(re.escape(prefix) + r"day=(\d{2})/part-[^/]+\.parquet")
    days: dict[str, list[tuple[str, int]]] = {}
    token = None
    while True:
        url = f"{base_url}?list-type=2&prefix={prefix}"
        if token is not None:
            url += "&continuation-token=" + urllib.parse.quote(token, safe="")
        response = transport(url, {"x-max-bytes": str(_LISTING_MAX_BYTES)})
        if response.status != 200:
            raise FetchError(f"listing {prefix}: HTTP {response.status}")
        text = response.body.decode("utf-8", "replace")
        truncated = _TRUNCATED.search(text)
        if truncated is None:
            raise FetchError(f"listing {prefix}: not a ListObjectsV2 answer")
        for block in _CONTENTS.findall(text):
            found = _KEY.search(block)
            key = html.unescape(found[1]) if found else ""
            match = day_part.fullmatch(key)
            if match is None:
                continue
            size = _SIZE.search(block)
            if size is None:
                raise FetchError(f"listing {prefix}: no size for {key}")
            days.setdefault(match[1], []).append((key, int(size[1])))
        if truncated[1] == "false":
            return days
        following = _NEXT.search(text)
        if following is None:
            raise FetchError(f"listing {prefix}: truncated without a token")
        token = html.unescape(following[1])


def newest_partition(
    base_url: str,
    source: reverseip.Source,
    today: datetime.date,
    transport: Transport,
) -> Partition | None:
    """The newest day of `source` in today's month, or in the month before
    when today's holds none yet; None when neither does. A listing that is not
    200 raises FetchError."""
    year, month = today.year, today.month
    for _ in range(2):
        prefix = f"fdns/basis=toplist/{source.path}/year={year}/month={month:02d}/"
        days = _month_days(base_url, prefix, transport)
        if days:
            day = max(days)
            return Partition(f"{year}-{month:02d}-{day}", tuple(sorted(days[day])))
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    return None


_MAGIC = b"PAR1"


def _fetch_range(
    url: str, first: int, last: int, size: int, transport: Transport
) -> bytes:
    """Bytes `first`..`last` of the object, refused unless the answer is
    exactly those: a 206 with their Content-Range and length."""
    length = last - first + 1
    response = transport(
        url, {"range": f"bytes={first}-{last}", "x-max-bytes": str(length)}
    )
    if response.status != 206:
        raise FetchError(f"{url}: HTTP {response.status} for bytes {first}-{last}")
    stated = response.headers.get("content-range")
    if stated != f"bytes {first}-{last}/{size}":
        raise FetchError(
            f"{url}: content-range {stated!r} for bytes {first}-{last}/{size}"
        )
    if len(response.body) != length:
        raise FetchError(
            f"{url}: a body of {len(response.body)} bytes for bytes {first}-{last}"
        )
    return response.body


def _chunk_ranges(
    url: str, path: str, columns: Sequence[str], footer: int
) -> list[tuple[int, int]]:
    """The byte range of each wanted column chunk in every row group, read
    from the footer already written at its offset in `path`."""
    try:
        metadata = pq.ParquetFile(path).metadata
    except pa.ArrowException as exc:
        raise FetchError(f"{url}: unreadable footer: {exc}") from exc
    present = {metadata.schema.column(i).path for i in range(metadata.num_columns)}
    missing = [name for name in columns if name not in present]
    if missing:
        raise FetchError(f"{url}: no column {', '.join(missing)}")
    ranges = []
    for group in range(metadata.num_row_groups):
        row_group = metadata.row_group(group)
        for i in range(row_group.num_columns):
            chunk = row_group.column(i)
            if chunk.path_in_schema not in columns:
                continue
            # A chunk starts at its dictionary page when it has one. Some
            # writers leave the offset 0 or None without one, so trust it only
            # when set and ahead of the first data page.
            first = chunk.data_page_offset
            dictionary = chunk.dictionary_page_offset
            if chunk.has_dictionary_page and dictionary and dictionary < first:
                first = dictionary
            last = first + chunk.total_compressed_size - 1
            if first < len(_MAGIC) or last >= footer:
                raise FetchError(
                    f"{url}: column {chunk.path_in_schema} lies outside the data"
                )
            ranges.append((first, last))
    return ranges


def _merged(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The ranges with adjacent and overlapping ones joined, in order."""
    merged: list[tuple[int, int]] = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def fetch_columns(
    url: str,
    size: int,
    dest: str,
    transport: Transport,
    columns: Sequence[str] = WANTED_COLUMNS,
    tail: int = 65536,
) -> int:
    """Copy the Parquet object at `url` (`size` bytes, from its listing) to
    `dest` as a sparse file of the same size that holds only the footer and
    the `columns`' chunks; the rest reads as zeros. Returns the bytes fetched.

    The last `tail` bytes come first, and the rest of the footer when it is
    longer. Any answer that is not exactly the range asked for, or a wanted
    column missing from the schema, raises FetchError. The copy is written to
    `dest`.tmp and swapped in only whole, so `dest` is absent or as it was."""
    if size < 2 * len(_MAGIC) + 4:
        raise FetchError(f"{url}: {size} bytes is too small for Parquet")
    tmp = dest + ".tmp"
    fetched = 0
    try:
        with open(tmp, "wb") as handle:
            handle.truncate(size)

            def put(first: int, last: int) -> bytes:
                nonlocal fetched
                body = _fetch_range(url, first, last, size, transport)
                handle.seek(first)
                handle.write(body)
                fetched += len(body)
                return body

            # From `covered` to the end of the file is already in place.
            covered = max(0, size - tail)
            end = put(covered, size - 1)[-8:]
            if end[4:] != _MAGIC:
                raise FetchError(f"{url} does not end like a Parquet file")
            footer = size - 8 - int.from_bytes(end[:4], "little")
            if footer < len(_MAGIC):
                raise FetchError(f"{url}: a footer longer than the file")
            if footer < covered:
                put(footer, covered - 1)
                covered = footer
            handle.flush()
            for first, last in _merged(_chunk_ranges(url, tmp, columns, footer)):
                if first < covered:
                    put(first, min(last, covered - 1))
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return fetched
