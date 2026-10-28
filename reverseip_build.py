"""Reverse IP, the build step: OpenINTEL's Parquet copies in, one SQLite file
out. Runs in the child process, which is the only place pyarrow is imported.

Imports `config`, `reverseip`, pyarrow and the standard library. Nothing in
the web process imports it."""

import ipaddress
import logging
import os
import re
import sqlite3
import time
from calendar import timegm
from collections.abc import Iterator, Sequence

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
