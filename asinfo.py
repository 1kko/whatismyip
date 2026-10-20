"""AS information: the route an address sits in and the AS that originates it.

Seven public datasets, downloaded by the scheduler into ASINFO_DIR and built
into one SQLite file: RIPE NCC's AS names, the NRO's delegated statistics, RIPE
RIS's whois dumps (IPv4 and IPv6), rpki-client's VRPs, and CAIDA's AS
relationships and AS organizations. A lookup reads that file, so it sends
nothing anywhere and opens no new SSRF surface.

Rules the parsers keep:
- They stream: a generator over lines, never a whole file in memory (the NRO
  file is 57 MB).
- A malformed line is skipped, never raised. What rejects a broken download is
  the dataset's `min_rows`, not a parser.
- They have no side effects and read no network.

CAIDA's two datasets are credited by file date, so their `credit` carries a
`{date}` placeholder that the caller fills with the file's own YYYY-MM-DD, and
each credit links to its dataset's page (`credit_url`), as CAIDA's terms ask.

`build_database` turns the local copies into the SQLite file, streaming each
source into batched inserts. Each route's RPKI state (RFC 6811) and each AS's
prefix, address space, RPKI and neighbour counts are worked out at build time,
so a lookup only reads them, and the VRPs are not kept.

`AsInfoManager` reads that file for lookups. A dataset the file lacks, or holds
past its `max_age_hours`, is unavailable: every section that reads it is None
and `unavailable` says why, so "not known" never reads as "none".

`AsInfoManager.refresh()`, run by the scheduler, keeps a copy of each source
beside the database and rebuilds the database when a copy changes. A download
replaces its copy only once its parser finds `min_rows` rows in it, and a
build replaces the database only once complete, so a broken source or a
failed build leaves lookups reading what they read before.

Imports config and the standard library only: lookup.py builds the singleton.
"""

import bz2
import contextlib
import datetime
import email.utils
import filecmp
import gzip
import ipaddress
import itertools
import json
import logging
import math
import operator
import os
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from config import (
    ASINFO_ASNAMES_URL,
    ASINFO_CAIDA_ENABLED,
    ASINFO_CAIDA_ORG_MAX_AGE_DAYS,
    ASINFO_CAIDA_ORG_URL,
    ASINFO_CAIDA_REL_MAX_AGE_DAYS,
    ASINFO_CAIDA_REL_URL,
    ASINFO_CHECK_INTERVAL_SECONDS,
    ASINFO_DIR,
    ASINFO_ENABLED,
    ASINFO_LIST_LIMIT,
    ASINFO_MAX_AGE_HOURS,
    ASINFO_MIN_RIS_PEERS,
    ASINFO_NRO_URL,
    ASINFO_RETRY_SECONDS,
    ASINFO_RIS_V4_URL,
    ASINFO_RIS_V6_URL,
    ASINFO_RPKI_URL,
    REPUTATION_USER_AGENT,
)

_RIPE_CREDIT = "Source: RIPE NCC"
_MB = 1024 * 1024


@dataclass(frozen=True)
class Dataset:
    """One source. `pattern` set means `url` is a directory listing and the
    file is the newest href matching it. `max_bytes` refuses a download bigger
    than that unread; `min_rows` is what the build must find to accept it.
    `credit_url` is the page a credit links to, where there is one."""

    id: str
    label: str
    url: str
    pattern: str | None
    interval_hours: float
    max_age_hours: float
    min_rows: int
    max_bytes: int
    credit: str
    credit_url: str | None = None


def default_datasets(caida: bool | None = None) -> tuple[Dataset, ...]:
    """The datasets this deployment fetches: CAIDA's two only under
    ASINFO_CAIDA_ENABLED, unless `caida` says otherwise."""
    if caida is None:
        caida = ASINFO_CAIDA_ENABLED
    daily = ASINFO_MAX_AGE_HOURS
    datasets = [
        Dataset(
            "asnames",
            "RIPE NCC AS names",
            ASINFO_ASNAMES_URL,
            None,
            24,
            daily,
            50_000,
            32 * _MB,
            _RIPE_CREDIT,
        ),
        Dataset(
            "nro",
            "NRO delegated statistics",
            ASINFO_NRO_URL,
            None,
            24,
            daily,
            50_000,
            192 * _MB,
            _RIPE_CREDIT,
        ),
        Dataset(
            "ris_v4",
            "RIPE RIS routes (IPv4)",
            ASINFO_RIS_V4_URL,
            None,
            24,
            daily,
            500_000,
            64 * _MB,
            _RIPE_CREDIT,
        ),
        Dataset(
            "ris_v6",
            "RIPE RIS routes (IPv6)",
            ASINFO_RIS_V6_URL,
            None,
            24,
            daily,
            100_000,
            32 * _MB,
            _RIPE_CREDIT,
        ),
        Dataset(
            "rpki",
            "rpki-client VRPs",
            ASINFO_RPKI_URL,
            None,
            24,
            daily,
            300_000,
            # Asked for gzipped (5 MB), but about 50 MB from a server that
            # ignores Accept-Encoding.
            128 * _MB,
            "RPKI data validated by rpki-client.org",
        ),
    ]
    if caida:
        datasets += [
            Dataset(
                "caida_rel",
                "CAIDA AS relationships",
                ASINFO_CAIDA_REL_URL,
                r"\d{8}\.as-rel2\.txt\.bz2",
                24,
                ASINFO_CAIDA_REL_MAX_AGE_DAYS * 24,
                300_000,
                32 * _MB,
                "The CAIDA UCSD AS Relationships Dataset, {date}",
                "https://www.caida.org/catalog/datasets/as-relationships/",
            ),
            Dataset(
                "caida_org",
                "CAIDA AS organizations",
                ASINFO_CAIDA_ORG_URL,
                r"\d{8}\.as-org2info\.jsonl\.gz",
                24,
                ASINFO_CAIDA_ORG_MAX_AGE_DAYS * 24,
                50_000,
                64 * _MB,
                "The CAIDA UCSD AS Organizations Dataset, {date}",
                "https://www.caida.org/catalog/datasets/as-organizations/",
            ),
        ]
    return tuple(datasets)


def open_text(path: str) -> Iterator[str]:
    """Lines of a local copy, gunzipped or bunzipped when its first bytes say so."""
    with open(path, "rb") as probe:
        magic = probe.read(3)
    if magic[:2] == b"\x1f\x8b":
        opener = gzip.open
    elif magic == b"BZh":
        opener = bz2.open
    else:
        opener = open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def _asn(text: str) -> int | None:
    text = text.strip()
    if text.isascii() and text.isdigit():
        value = int(text)
        if value <= 0xFFFFFFFF:
            return value
    return None


def _country(text: str) -> str | None:
    text = text.strip()
    return text.upper() if len(text) == 2 and text.isalpha() else None


def parse_asnames(lines: Iterable[str]) -> Iterator[tuple[int, str, str | None]]:
    """`<asn> <name>, <CC>`: the country is whatever follows the last comma."""
    for line in lines:
        head, _, rest = line.strip().partition(" ")
        asn = _asn(head)
        rest = rest.strip()
        if asn is None or not rest:
            continue
        name, comma, tail = rest.rpartition(",")
        country = _country(tail) if comma else None
        if country is None:
            yield asn, rest, None
        elif name.strip():
            yield asn, name.strip(), country


def _iso_date(text: str) -> str | None:
    if len(text) == 8 and text.isascii() and text.isdigit() and text != "00000000":
        return f"{text[:4]}-{text[4:6]}-{text[6:]}"
    return None


def parse_nro(
    lines: Iterable[str],
) -> Iterator[tuple[int, int, str, str | None, str | None, str]]:
    """The `asn` rows with status assigned or allocated. `value` is a count, so
    a row can cover a range; it is not expanded here."""
    for line in lines:
        fields = line.split("|")
        if len(fields) < 7 or fields[2] != "asn":
            continue
        if fields[6] not in ("assigned", "allocated"):
            continue
        first = _asn(fields[3])
        count = _asn(fields[4])
        if first is None or not count:
            continue
        yield (
            first,
            count,
            fields[0],
            _country(fields[1]),
            _iso_date(fields[5]),
            fields[6],
        )


def _prefix_ok(prefix: str) -> bool:
    """A well-formed network that is not a default or near-default route."""
    try:
        network = ipaddress.ip_network(prefix, strict=True)
    except ValueError:
        return False
    return network.prefixlen >= (8 if network.version == 4 else 16)


def parse_ris(lines: Iterable[str], min_peers: int) -> Iterator[tuple[int, str, int]]:
    """`<origin>\\t<prefix>\\t<peers>`. Dropped: comments, an AS_SET origin,
    a prefix shorter than /8 (v4) or /16 (v6), and rows seen by too few peers."""
    for line in lines:
        if not line or line.startswith("%"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        origin = _asn(fields[0])
        peers = _asn(fields[2])
        if origin is None or peers is None or peers < min_peers:
            continue
        if not _prefix_ok(fields[1]):
            continue
        yield origin, fields[1], peers


def parse_vrps(lines: Iterable[str]) -> Iterator[tuple[int, str, int]]:
    """rpki-client's CSV: `ASN,IP Prefix,Max Length,...`, ASN as `AS13335`.
    A max length shorter than the prefix or longer than its family allows is
    skipped: it would validate the wrong routes."""
    for line in lines:
        fields = line.split(",")
        if len(fields) < 3 or not fields[0].upper().startswith("AS"):
            continue
        asn = _asn(fields[0][2:])
        max_length = _asn(fields[2])
        if asn is None or max_length is None:
            continue
        try:
            network = ipaddress.ip_network(fields[1], strict=True)
        except ValueError:
            continue
        if network.prefixlen <= max_length <= network.max_prefixlen:
            yield asn, fields[1], max_length


def parse_as_rel(lines: Iterable[str]) -> Iterator[tuple[int, int, int]]:
    """`<a>|<b>|<rel>|<source>`: -1 means a provides b, 0 means peers."""
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) < 3 or fields[2] not in ("-1", "0"):
            continue
        a, b = _asn(fields[0]), _asn(fields[1])
        if a is not None and b is not None:
            yield a, b, int(fields[2])


def parse_as_org(lines: Iterable[str]) -> Iterator[tuple]:
    """CAIDA's JSON lines: `("asn", asn, org_id)` or `("org", org_id, name,
    country)`."""
    for line in lines:
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        org_id = record.get("organizationId")
        if not isinstance(org_id, str) or not org_id:
            continue
        kind = record.get("type")
        if kind == "ASN":
            asn = _asn(str(record.get("asn", "")))
            if asn is not None:
                yield "asn", asn, org_id
        elif kind == "Organization":
            name = record.get("name")
            country = record.get("country")
            yield (
                "org",
                org_id,
                name if isinstance(name, str) else "",
                _country(country) if isinstance(country, str) else None,
            )


def newest_file(listing_html: str, pattern: str) -> str | None:
    """The greatest href in a directory listing that fully matches `pattern`.
    The names lead with a date, so the greatest sorts as the newest."""
    names = re.findall(r'href="([^"]+)"', listing_html)
    matching = [n for n in names if re.fullmatch(pattern, n)]
    return max(matching) if matching else None


def rov_state(
    origin: int, prefix_len: int, covering: Iterable[tuple[int, int]]
) -> tuple[str, str | None]:
    """RFC 6811 route origin validation of one route. `covering` is
    `(vrp_asn, max_length)` for each VRP whose prefix covers the route's.
    Invalid says why: `length` when a VRP names the origin but allows only
    shorter prefixes, `origin` when none names it. A VRP for AS0 matches no
    route: it says the space should not be routed at all."""
    covered = named = False
    for asn, max_length in covering:
        covered = True
        if asn == origin and asn != 0:
            if prefix_len <= max_length:
                return "valid", None
            named = True
    if not covered:
        return "not-found", None
    return "invalid", "length" if named else "origin"


# Bumped when the tables change, so a reader can tell a file built by an older
# release (stored as PRAGMA user_version), and refresh() rebuilds it from the
# copies. 2 added route_plen.
SCHEMA_VERSION = 2

# Every dataset the build reads, in build order. `meta` has a row for each,
# built or not, so a reader can tell "not in this build" from "no row for
# this ASN".
DATASET_IDS = ("asnames", "nro", "ris_v4", "ris_v6", "rpki", "caida_rel", "caida_org")

# route.start and route.end are the first and last address as fixed-width
# big-endian bytes, 4 for IPv4 and 16 for IPv6 (`ipaddress`'s `packed`): wider
# than SQLite's integers, and within a family they sort as the addresses do.
# route's primary key orders it by address, so the build appends its rows in
# key order and needs no second index for a longest-prefix match: that asks
# (family, plen, start) for each length, longest first, and an equality on
# all three uses the key whatever its column order. route_plen lists the
# lengths each family has, written at build: finding them in route scans the
# whole table, too slow for the first read of a file. rpki_state is valid,
# invalid or not-found, NULL when the build had no VRPs; rpki_reason is origin
# or length beside invalid.
# registry holds the NRO's ranges as they are, first..last inclusive: the one
# covering an ASN is the row with the greatest first <= it, if its last >= it.
# rel is CAIDA's: kind -1 means a provides transit to b, 0 that they peer.
_SCHEMA = """
CREATE TABLE meta (
    dataset TEXT PRIMARY KEY,
    built INTEGER NOT NULL,
    rows INTEGER NOT NULL,
    fetched_at,
    source_date
);
CREATE TABLE asn (asn INTEGER PRIMARY KEY, name TEXT NOT NULL, country TEXT);
CREATE TABLE registry (
    first INTEGER PRIMARY KEY,
    last INTEGER NOT NULL,
    rir TEXT NOT NULL,
    country TEXT,
    assigned TEXT,
    status TEXT NOT NULL
);
CREATE TABLE org (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, country TEXT
) WITHOUT ROWID;
CREATE TABLE asn_org (asn INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE route (
    family INTEGER NOT NULL,
    plen INTEGER NOT NULL,
    start BLOB NOT NULL,
    "end" BLOB NOT NULL,
    prefix TEXT NOT NULL,
    origin INTEGER NOT NULL,
    ris_peers INTEGER NOT NULL,
    rpki_state TEXT,
    rpki_reason TEXT,
    PRIMARY KEY (family, start, plen, origin)
) WITHOUT ROWID;
CREATE TABLE route_plen (
    family INTEGER NOT NULL, plen INTEGER NOT NULL, PRIMARY KEY (family, plen)
) WITHOUT ROWID;
CREATE TABLE rel (
    a INTEGER NOT NULL, b INTEGER NOT NULL, kind INTEGER NOT NULL,
    PRIMARY KEY (a, b)
) WITHOUT ROWID;
CREATE TABLE asn_stats (
    asn INTEGER PRIMARY KEY,
    v4_prefixes INTEGER NOT NULL DEFAULT 0,
    v6_prefixes INTEGER NOT NULL DEFAULT 0,
    v4_addresses INTEGER NOT NULL DEFAULT 0,
    v6_48s INTEGER NOT NULL DEFAULT 0,
    rpki_valid INTEGER NOT NULL DEFAULT 0,
    rpki_invalid INTEGER NOT NULL DEFAULT 0,
    rpki_not_found INTEGER NOT NULL DEFAULT 0,
    providers INTEGER NOT NULL DEFAULT 0,
    customers INTEGER NOT NULL DEFAULT 0,
    peers INTEGER NOT NULL DEFAULT 0
);
CREATE TEMP TABLE staged_route (
    family INTEGER, plen INTEGER, start BLOB, "end" BLOB, prefix TEXT,
    origin INTEGER, ris_peers INTEGER
);
CREATE TEMP TABLE vrp (
    family INTEGER, plen INTEGER, start BLOB, "end" BLOB,
    asn INTEGER, max_length INTEGER
);
"""

# Built after the bulk inserts, which are faster without them.
_LATE_INDEXES = (
    "CREATE INDEX route_origin ON route (origin, family, start, plen)",
    "CREATE INDEX rel_b ON rel (b, a)",
    "CREATE INDEX asn_org_org ON asn_org (org_id)",
)

# VRPs and staged routes in one stream, ordered by family, then first address,
# then length; a VRP comes before a route on the same prefix. Columns: family,
# start, plen, is_route, end, asn or origin, max_length or ris_peers, prefix.
_SWEEP = """
SELECT family, start, plen, 0, "end", asn, max_length, NULL FROM temp.vrp
UNION ALL
SELECT family, start, plen, 1, "end", origin, ris_peers, prefix FROM temp.staged_route
ORDER BY 1, 2, 3, 4, 6
"""

# A (prefix, origin) listed twice keeps the row seen by more peers.
_ROUTE_INSERT = """
INSERT INTO route VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (family, start, plen, origin)
DO UPDATE SET ris_peers = max(ris_peers, excluded.ris_peers)
"""

_NEIGHBOUR_COUNTS = (
    """INSERT INTO asn_stats (asn, providers)
    SELECT b, count(*) FROM rel WHERE kind = -1 GROUP BY b
    ON CONFLICT (asn) DO UPDATE SET providers = excluded.providers""",
    """INSERT INTO asn_stats (asn, customers)
    SELECT a, count(*) FROM rel WHERE kind = -1 GROUP BY a
    ON CONFLICT (asn) DO UPDATE SET customers = excluded.customers""",
    """INSERT INTO asn_stats (asn, peers)
    SELECT asn, count(*) FROM (
        SELECT a AS asn FROM rel WHERE kind = 0
        UNION ALL SELECT b FROM rel WHERE kind = 0
    ) WHERE true GROUP BY asn
    ON CONFLICT (asn) DO UPDATE SET peers = excluded.peers""",
)

_BATCH = 10_000
# The page cache of each schema during the build; the sorter's in-memory runs
# are as big. More only costs memory: on the real data 4 MiB built as fast as
# 16 MiB, at a fifth of the peak.
_CACHE_KIB = 4 * 1024


def _insert(con: sqlite3.Connection, sql: str, rows: Iterable[tuple]) -> int:
    """`executemany` in batches of `_BATCH`; the number of rows sent."""
    rows = iter(rows)
    count = 0
    while batch := list(itertools.islice(rows, _BATCH)):
        con.executemany(sql, batch)
        count += len(batch)
    return count


def _bounds(prefix: str) -> tuple[int, int, bytes, bytes, str]:
    """(family, length, first, last, text) of a prefix a parser accepted."""
    network = ipaddress.ip_network(prefix)
    return (
        network.version,
        network.prefixlen,
        network.network_address.packed,
        network.broadcast_address.packed,
        str(network),
    )


def _validated_routes(con: sqlite3.Connection, checked: bool) -> Iterator[tuple]:
    """The staged routes as `route` rows, in its key order, each with its RPKI
    state (None for all when not `checked`: there were no VRPs). One sorted
    sweep: prefixes are laminar (two are nested or disjoint), so the VRPs
    covering the current position form a stack, outermost first, and one that
    ends before the next row starts covers nothing after it."""
    stack: list[tuple[int, bytes, int, int]] = []
    cursor = con.execute(_SWEEP)
    try:
        for family, start, plen, is_route, end, asn, number, prefix in cursor:
            while stack and (stack[-1][0] != family or stack[-1][1] < start):
                stack.pop()
            if not is_route:
                stack.append((family, end, asn, number))
                continue
            state, reason = (
                rov_state(asn, plen, [(v[2], v[3]) for v in stack])
                if checked
                else (None, None)
            )
            yield family, plen, start, end, prefix, asn, number, state, reason
    finally:
        cursor.close()


def _route_stats(con: sqlite3.Connection) -> Iterator[tuple[int, ...]]:
    """One asn_stats row per origin: prefix counts, address space and RPKI
    counts. Space counts each address once: an AS's prefixes come ordered by
    first address, longest last, so one nested in a prefix already counted
    starts before that one's end, and is skipped. IPv6 counts the /48s its
    prefixes touch, a /56 as the /48 it sits in."""
    cursor = con.execute(
        "SELECT origin, family, start, plen, rpki_state FROM route"
        " ORDER BY origin, family, start, plen"
    )
    try:
        for origin, routes in itertools.groupby(cursor, key=operator.itemgetter(0)):
            prefixes = {4: 0, 6: 0}
            states = {"valid": 0, "invalid": 0, "not-found": 0}
            last_end = {4: -1, 6: -1}
            addresses = v6_48s = 0
            last_48 = -1
            for _, family, start, plen, state in routes:
                prefixes[family] += 1
                if state in states:
                    states[state] += 1
                first = int.from_bytes(start, "big")
                if first <= last_end[family]:
                    continue
                last = first + (1 << ((32 if family == 4 else 128) - plen)) - 1
                last_end[family] = last
                if family == 4:
                    addresses += last - first + 1
                else:
                    low, high = max(first >> 80, last_48 + 1), last >> 80
                    v6_48s += max(0, high - low + 1)
                    last_48 = max(last_48, high)
            yield (
                origin,
                prefixes[4],
                prefixes[6],
                addresses,
                v6_48s,
                states["valid"],
                states["invalid"],
                states["not-found"],
            )
    finally:
        cursor.close()


def _load(
    con: sqlite3.Connection, sources: dict[str, str], min_peers: int
) -> dict[str, int]:
    rows: dict[str, int] = {}

    def lines(dataset_id: str) -> Iterator[str]:
        return open_text(sources[dataset_id])

    if "asnames" in sources:
        rows["asnames"] = _insert(
            con,
            "INSERT OR REPLACE INTO asn VALUES (?, ?, ?)",
            parse_asnames(lines("asnames")),
        )
    if "nro" in sources:
        rows["nro"] = _insert(
            con,
            "INSERT OR REPLACE INTO registry VALUES (?, ?, ?, ?, ?, ?)",
            (
                (first, first + count - 1, rir, country, assigned, status)
                for first, count, rir, country, assigned, status in parse_nro(
                    lines("nro")
                )
            ),
        )
    for dataset_id in ("ris_v4", "ris_v6"):
        if dataset_id in sources:
            rows[dataset_id] = _insert(
                con,
                "INSERT INTO temp.staged_route VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    (*_bounds(prefix), origin, peers)
                    for origin, prefix, peers in parse_ris(lines(dataset_id), min_peers)
                ),
            )
    if "rpki" in sources:
        rows["rpki"] = _insert(
            con,
            "INSERT INTO temp.vrp VALUES (?, ?, ?, ?, ?, ?)",
            (
                (*_bounds(prefix)[:4], asn, max_length)
                for asn, prefix, max_length in parse_vrps(lines("rpki"))
            ),
        )
    _insert(con, _ROUTE_INSERT, _validated_routes(con, "rpki" in sources))
    con.execute("DROP TABLE temp.staged_route")
    con.execute("DROP TABLE temp.vrp")
    if "caida_rel" in sources:
        rows["caida_rel"] = _insert(
            con,
            "INSERT OR IGNORE INTO rel VALUES (?, ?, ?)",
            parse_as_rel(lines("caida_rel")),
        )
    if "caida_org" in sources:
        # Read twice, once per table: the file is small, and it keeps both
        # inserts a plain stream.
        asns = _insert(
            con,
            "INSERT OR REPLACE INTO asn_org VALUES (?, ?)",
            (r[1:] for r in parse_as_org(lines("caida_org")) if r[0] == "asn"),
        )
        orgs = _insert(
            con,
            "INSERT OR REPLACE INTO org VALUES (?, ?, ?)",
            (r[1:] for r in parse_as_org(lines("caida_org")) if r[0] == "org"),
        )
        rows["caida_org"] = asns + orgs
    return rows


def build_database(
    sources: dict[str, str], out_path: str, min_peers: int, meta: dict[str, dict]
) -> dict[str, int]:
    """Build the database at `out_path` from the local copies in `sources`
    (dataset id -> path); a dataset missing from it builds no rows. `meta[id]`
    gives each dataset's `fetched_at` and `source_date` for the `meta` table.
    Returns the rows read from each source.

    Writes `out_path` in place, with no journal: the caller builds into a
    temporary name and swaps it in. A build that raises leaves a file whose
    `meta` table is empty (written last) or that does not open at all."""
    unknown = sorted(set(sources) - set(DATASET_IDS))
    if unknown:
        raise ValueError(f"unknown datasets: {', '.join(unknown)}")
    with contextlib.suppress(FileNotFoundError):
        os.remove(out_path)
    con = sqlite3.connect(out_path, isolation_level=None)
    try:
        con.execute("PRAGMA journal_mode = OFF")
        con.execute("PRAGMA synchronous = OFF")
        # The staged rows and the sort behind the RPKI sweep go to temp files
        # rather than grow the process.
        con.execute("PRAGMA temp_store = FILE")
        con.executescript(_SCHEMA)
        # Dirty pages are written out once the cache holds this much. Set for
        # both schemas: some builds (macOS's) wait for 80 MB each by default.
        for schema in ("main", "temp"):
            con.execute(f"PRAGMA {schema}.cache_size = -{_CACHE_KIB}")
            con.execute(f"PRAGMA {schema}.cache_spill = -{_CACHE_KIB}")
        con.execute("BEGIN")
        rows = _load(con, sources, min_peers)
        con.execute("INSERT INTO route_plen SELECT DISTINCT family, plen FROM route")
        for sql in _LATE_INDEXES:
            con.execute(sql)
        _insert(
            con,
            "INSERT INTO asn_stats (asn, v4_prefixes, v6_prefixes, v4_addresses,"
            " v6_48s, rpki_valid, rpki_invalid, rpki_not_found)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            _route_stats(con),
        )
        for sql in _NEIGHBOUR_COUNTS:
            con.execute(sql)
        con.execute("ANALYZE")
        con.executemany(
            "INSERT INTO meta VALUES (?, ?, ?, ?, ?)",
            (
                (
                    dataset_id,
                    int(dataset_id in rows),
                    rows.get(dataset_id, 0),
                    meta.get(dataset_id, {}).get("fetched_at"),
                    meta.get(dataset_id, {}).get("source_date"),
                )
                for dataset_id in DATASET_IDS
            ),
        )
        con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        con.execute("COMMIT")
    finally:
        con.close()
    return rows


# Downloads. A dataset's copy is named after the last segment of its URL, or
# for CAIDA of the file its listing names, and kept beside the database.

DOWNLOAD_TIMEOUT_SECONDS = 30
_CHUNK = 1024 * 1024
# A directory listing is a page of links.
_LISTING_MAX_BYTES = 4 * _MB
# Each dataset's copy: its file, when it was downloaded, the source's own date
# (both stored in the database's meta), and when it was last checked against
# its server.
_COPIES_NAME = "copies.json"
_RECORD_KEYS = ("file", "fetched_at", "source_date", "checked_at")

# What a download must parse to, through the parser the build reads it with.
_PARSERS: dict[str, Callable[[Iterable[str]], Iterator]] = {
    "asnames": parse_asnames,
    "nro": parse_nro,
    "ris_v4": lambda lines: parse_ris(lines, ASINFO_MIN_RIS_PEERS),
    "ris_v6": lambda lines: parse_ris(lines, ASINFO_MIN_RIS_PEERS),
    "rpki": parse_vrps,
    "caida_rel": parse_as_rel,
    "caida_org": parse_as_org,
}

# The RIS dumps' header says "% This file was generated at Tue Oct 20 09:12:30
# UTC 2026." (`date` in the C locale, so English names).
_GENERATED_AT = re.compile(
    r"generated at \w{3} (\w{3}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) UTC (\d{4})"
)
_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _download(
    url: str, dest_path: str, max_bytes: int, accept_gzip: bool = False
) -> dict:
    """GET `url` into `dest_path`, streamed in chunks; {"last_modified": the
    response's Last-Modified header, or None}. Raises past `max_bytes`, unread
    when the response says up front that it is longer, and when the body ends
    short of its Content-Length: http.client's read(amt) answers a dropped
    connection with an early b"", not an error, and a plain-text source cut
    short can still pass its `min_rows`. Sends
    REPUTATION_USER_AGENT and, with `accept_gzip`, Accept-Encoding: gzip; a
    gzipped body is kept as it came, and open_text reads it. The URL is
    operator config, or a file name a listing gave that matched its
    dataset's pattern, never user input."""
    headers = {"User-Agent": REPUTATION_USER_AGENT}
    if accept_gzip:
        headers["Accept-Encoding"] = "gzip"
    request = urllib.request.Request(url, headers=headers)  # noqa: S310
    with urllib.request.urlopen(  # noqa: S310
        request, timeout=DOWNLOAD_TIMEOUT_SECONDS
    ) as response:
        stated = response.headers.get("Content-Length", "")
        if stated.isdigit() and int(stated) > max_bytes:
            raise ValueError(f"{url} is {stated} bytes, more than {max_bytes}")
        size = 0
        with open(dest_path, "wb") as handle:
            while chunk := response.read(_CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"{url} is larger than {max_bytes} bytes")
                handle.write(chunk)
        if stated.isdigit() and size != int(stated):
            raise ValueError(f"{url} ended after {size} of its {stated} bytes")
        return {"last_modified": response.headers.get("Last-Modified")}


def _request_name(dataset: Dataset) -> str:
    """The last segment of the dataset's URL: its copy's name, or for CAIDA
    its listing's (`serial-2`). Its `.requested` stamp is named after it."""
    path = urllib.parse.urlparse(dataset.url).path
    return path.rstrip("/").rsplit("/", 1)[-1] or dataset.id


def _iso(epoch: float) -> str:
    when = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return when.isoformat(timespec="seconds")


def _http_date(value: str | None) -> str | None:
    """A Last-Modified header as an ISO 8601 UTC time; None if none parses."""
    if not value:
        return None
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when.astimezone(datetime.timezone.utc).isoformat(timespec="seconds")


def _generated_at(path: str) -> str | None:
    """When a RIS dump says it was generated, read off its comment header, as
    an ISO 8601 UTC time; None when it does not say."""
    with contextlib.closing(open_text(path)) as lines:
        for line in lines:
            if line and not line.startswith("%"):
                return None
            match = _GENERATED_AT.search(line)
            if match is None:
                continue
            month, day, clock, year = match.groups()
            if month not in _MONTHS:
                return None
            month_number = _MONTHS.index(month) + 1
            text = f"{year}-{month_number:02d}-{int(day):02d}T{clock}+00:00"
            try:
                return datetime.datetime.fromisoformat(text).isoformat()
            except ValueError:
                return None
    return None


def _count_rows(dataset_id: str, path: str) -> int:
    """The rows the build would read from `path`: its parser's, after the
    parser's filters (RIS rows seen by too few peers are not counted). A file
    that ends early raises, a gzip or bzip2 cut short included."""
    with contextlib.closing(open_text(path)) as lines:
        return sum(1 for _ in _PARSERS[dataset_id](lines))


def _mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def _is_record(record) -> bool:
    """Whether a copies.json entry is whole: four strings, a bare file name,
    a check time that reads as one."""
    if not isinstance(record, dict):
        return False
    if not all(isinstance(record.get(key), str) for key in _RECORD_KEYS):
        return False
    name = record["file"]
    if name in ("", ".", "..") or os.path.basename(name) != name:
        return False
    return _epoch(record["checked_at"]) is not None


# The live database in the manager's directory. A refresh builds it as
# DATABASE_NAME + ".tmp" and swaps it in with os.replace.
DATABASE_NAME = "asinfo.sqlite3"

# An answer's keys, in order. A section is None when a dataset it reads is
# unavailable, and `unavailable` then names that dataset; an available dataset
# with nothing to say gives None for a record (name, country, registry, org),
# 0 for a count and [] for a list. When there is no AS to describe (`asn` is
# None), every AS section is None.
ANSWER_KEYS = (
    "asn",
    "name",
    "country",
    "registry",
    "org",
    "prefixes",
    "rpki",
    "upstreams",
    "downstreams",
    "peers",
    "asn_drop",
    "route",
    "announced",
    "source",
    "datasets",
    "unavailable",
    "attribution",
    "prefix_list",
)
_AS_SECTIONS = ANSWER_KEYS[1:10]

_NOT_DOWNLOADED = "not downloaded yet"
_UNREADABLE = "the database could not be read"

# A route of length plen covers an address when its start is the address with
# every bit past plen cleared. Several rows are several origins of one prefix.
_ROUTE = """
SELECT prefix, origin, ris_peers, rpki_state, rpki_reason FROM route
WHERE family = ? AND plen = ? AND start = ?
ORDER BY ris_peers DESC, origin
"""
# The range covering an ASN is the one with the greatest first <= it, if its
# last reaches it. `first <= ? AND last >= ?` would scan every lower range
# for an ASN in none.
_REGISTRY = """
SELECT last, rir, country, assigned, status FROM registry
WHERE first <= ? ORDER BY first DESC LIMIT 1
"""
_STATS = """
SELECT v4_prefixes, v6_prefixes, v4_addresses, v6_48s, rpki_valid,
    rpki_invalid, rpki_not_found, customers, peers
FROM asn_stats WHERE asn = ?
"""
_STATS_COLUMNS = (
    "v4_prefixes",
    "v6_prefixes",
    "v4_addresses",
    "v6_48s",
    "rpki_valid",
    "rpki_invalid",
    "rpki_not_found",
    "customers",
    "peers",
)
# Neighbours come largest first, by each one's own customer count.
_UPSTREAMS = """
SELECT r.a FROM rel AS r LEFT JOIN asn_stats AS s ON s.asn = r.a
WHERE r.b = ? AND r.kind = -1
ORDER BY coalesce(s.customers, 0) DESC, r.a
"""
_DOWNSTREAMS = """
SELECT r.b FROM rel AS r LEFT JOIN asn_stats AS s ON s.asn = r.b
WHERE r.a = ? AND r.kind = -1
ORDER BY coalesce(s.customers, 0) DESC, r.b LIMIT ?
"""
_PEERS = """
SELECT n.asn FROM (
    SELECT b AS asn FROM rel WHERE a = ? AND kind = 0
    UNION SELECT a FROM rel WHERE b = ? AND kind = 0
) AS n LEFT JOIN asn_stats AS s ON s.asn = n.asn
ORDER BY coalesce(s.customers, 0) DESC, n.asn LIMIT ?
"""
_PREFIXES = """
SELECT prefix, ris_peers, rpki_state, rpki_reason FROM route
WHERE origin = ? ORDER BY family, start, plen LIMIT ?
"""


def _is_asn(value) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 0xFFFFFFFF
    )


def _epoch(value) -> float | None:
    """A date as the meta table holds it, in epoch seconds: an ISO 8601 date
    or date and time (UTC unless it names a zone), or a number of seconds."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str):
        return None
    try:
        when = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when.timestamp()


def _day(value) -> str:
    """The UTC day of a date `_epoch` reads, as YYYY-MM-DD."""
    when = datetime.datetime.fromtimestamp(_epoch(value), tz=datetime.timezone.utc)
    return when.strftime("%Y-%m-%d")


# Hours below four days, so a daily dataset just past its 72 hours does not
# read "3 days old, past its limit of 3 days"; rounded up, so an age past its
# limit never reads as the limit itself.
def _age_text(hours: float) -> str:
    if hours < 96:
        return f"{math.ceil(hours)} hours"
    return f"{math.ceil(hours / 24)} days"


def _sqlite_error(exc: Exception) -> str:
    name = getattr(exc, "sqlite_errorname", None)
    return f"{name}: {exc}" if name else str(exc)


def _date(row: tuple) -> object:
    """A meta row's date: the source's own (source_date), else when it was
    fetched. Rows are (built, rows, fetched_at, source_date)."""
    return row[3] if row[3] is not None else row[2]


def _judge(
    dataset: Dataset, row: tuple | None, now: float
) -> tuple[float | None, str | None]:
    """(age in hours, why lookups may not read the dataset), the reason None
    when they may. `row` is its meta row, None when the database has none."""
    if row is None or not row[0]:
        return None, _NOT_DOWNLOADED
    epoch = _epoch(_date(row))
    if epoch is None:
        return None, "no date recorded"
    age = max(now - epoch, 0.0) / 3600
    if age > dataset.max_age_hours:
        limit = _age_text(dataset.max_age_hours)
        return age, f"{_age_text(age)} old, past its limit of {limit}"
    return age, None


def _rpki(state: str | None, reason: str | None) -> dict | None:
    return None if state is None else {"state": state, "reason": reason}


@dataclass(frozen=True)
class _Copy:
    """The database as one thread has it open: the connection, its meta rows
    by dataset, and the prefix lengths each family has, longest first."""

    con: sqlite3.Connection
    meta: dict[str, tuple]
    plens: dict[int, tuple[int, ...]]


class _Reader:
    """The reads behind one answer. `dates` has the date of each dataset
    lookups may read; can() says whether a section's datasets are all among
    them, and notes them as used, for the answer's datasets and attribution."""

    def __init__(self, copy: _Copy | None, dates: dict[str, object]):
        self.copy = copy
        self.dates = dates
        self.used: set[str] = set()
        self._stats: dict[int, dict[str, int]] = {}

    def can(self, *dataset_ids: str) -> bool:
        if all(dataset_id in self.dates for dataset_id in dataset_ids):
            self.used.update(dataset_ids)
            return True
        return False

    def _execute(self, sql: str, args: tuple) -> sqlite3.Cursor:
        return self.copy.con.execute(sql, args)

    def stats(self, asn: int) -> dict[str, int]:
        """The AS's counts; zeros for an AS that has no row."""
        if asn not in self._stats:
            row = self._execute(_STATS, (asn,)).fetchone()
            values = row or (0,) * len(_STATS_COLUMNS)
            self._stats[asn] = dict(zip(_STATS_COLUMNS, values, strict=True))
        return self._stats[asn]

    def route(self, address) -> tuple[dict | None, bool | None]:
        """The longest announced prefix covering `address`, and whether one
        does: (None, None) when its family's routes are unavailable."""
        if not self.can(f"ris_v{address.version}"):
            return None, None
        value, bits = int(address), address.max_prefixlen
        for plen in self.copy.plens[address.version]:
            host_bits = bits - plen
            start = (value >> host_bits << host_bits).to_bytes(bits // 8, "big")
            rows = self._execute(_ROUTE, (address.version, plen, start)).fetchall()
            if rows:
                break
        else:
            return None, False
        checked = self.can("rpki")
        origins = [
            {
                "asn": origin,
                "ris_peers": peers,
                "rpki": _rpki(state, reason) if checked else None,
            }
            for _, origin, peers, state, reason in rows
        ]
        return {"prefix": rows[0][0], "origins": origins}, True

    def describe(self, asn: int | None) -> dict:
        """`asn` through `asn_drop` (which lookup.py fills) for the AS."""
        answer = {"asn": asn, **dict.fromkeys(_AS_SECTIONS), "asn_drop": None}
        if asn is None:
            return answer
        if self.can("asnames"):
            row = self._execute("SELECT name, country FROM asn WHERE asn = ?", (asn,))
            answer["name"], answer["country"] = row.fetchone() or (None, None)
        if self.can("nro"):
            row = self._execute(_REGISTRY, (asn,)).fetchone()
            if row is not None and row[0] >= asn:
                keys = ("rir", "country", "assigned", "status")
                answer["registry"] = dict(zip(keys, row[1:], strict=True))
        if self.can("caida_org"):
            answer["org"] = self._org(asn)
        if self.can("ris_v4", "ris_v6"):
            stats = self.stats(asn)
            answer["prefixes"] = {
                "v4": stats["v4_prefixes"],
                "v6": stats["v6_prefixes"],
                "v4_addresses": stats["v4_addresses"],
                "v6_48s": stats["v6_48s"],
            }
        if self.can("ris_v4", "ris_v6", "rpki"):
            stats = self.stats(asn)
            answer["rpki"] = {
                "valid": stats["rpki_valid"],
                "invalid": stats["rpki_invalid"],
                "not_found": stats["rpki_not_found"],
            }
        if self.can("caida_rel"):
            stats, limit = self.stats(asn), ASINFO_LIST_LIMIT
            answer["upstreams"] = self._neighbours(_UPSTREAMS, (asn,))
            answer["downstreams"] = {
                "count": stats["customers"],
                "list": self._neighbours(_DOWNSTREAMS, (asn, limit)),
            }
            answer["peers"] = {
                "count": stats["peers"],
                "list": self._neighbours(_PEERS, (asn, asn, limit)),
            }
        return answer

    def _org(self, asn: int) -> dict | None:
        """The AS's organization and its other ASes: the lowest numbers, up
        to ASINFO_LIST_LIMIT (one organization has over 1,000), and their
        count."""
        row = self._execute("SELECT org_id FROM asn_org WHERE asn = ?", (asn,))
        org_id = (row.fetchone() or (None,))[0]
        if org_id is None:
            return None
        org = self._execute("SELECT name, country FROM org WHERE id = ?", (org_id,))
        name, country = org.fetchone() or (None, None)
        siblings = self._execute(
            "SELECT asn FROM asn_org WHERE org_id = ? AND asn != ? ORDER BY asn"
            " LIMIT ?",
            (org_id, asn, ASINFO_LIST_LIMIT),
        )
        count = self._execute(
            "SELECT count(*) FROM asn_org WHERE org_id = ? AND asn != ?",
            (org_id, asn),
        )
        return {
            "id": org_id,
            "name": name or None,
            "country": country,
            "siblings": [sibling for (sibling,) in siblings],
            "sibling_count": count.fetchone()[0],
        }

    def _neighbours(self, sql: str, args: tuple) -> list[dict]:
        """`{asn, name}` for each ASN the query lists; the names are None when
        the AS names are unavailable."""
        asns = [asn for (asn,) in self._execute(sql, args)]
        names: dict[int, str] = {}
        if asns and self.can("asnames"):
            marks = ", ".join("?" * len(asns))
            names = dict(
                self._execute(
                    f"SELECT asn, name FROM asn WHERE asn IN ({marks})",  # noqa: S608 - placeholders only
                    tuple(asns),
                )
            )
        return [{"asn": asn, "name": names.get(asn)} for asn in asns]

    def originates(self, asn: int) -> bool | None:
        if not self.can("ris_v4", "ris_v6"):
            return None
        stats = self.stats(asn)
        return stats["v4_prefixes"] + stats["v6_prefixes"] > 0

    def prefix_list(self, asn: int) -> dict | None:
        """The prefixes the AS originates, by address, capped at
        ASINFO_LIST_LIMIT, with the full count."""
        if not self.can("ris_v4", "ris_v6"):
            return None
        checked = self.can("rpki")
        stats = self.stats(asn)
        rows = self._execute(_PREFIXES, (asn, ASINFO_LIST_LIMIT))
        return {
            "count": stats["v4_prefixes"] + stats["v6_prefixes"],
            "list": [
                {
                    "prefix": prefix,
                    "ris_peers": peers,
                    "rpki": _rpki(state, reason) if checked else None,
                }
                for prefix, peers, state, reason in rows
            ],
        }


class AsInfoManager:
    """The AS database in ASINFO_DIR, read for lookups.

    Each thread reads through a read-only connection of its own, reopened
    when the file has changed: a rebuild is written beside the file and
    swapped in with os.replace. A connection still open on the old file goes
    on reading it until that thread's next read sees the swap, except on
    macOS, whose own SQLite fails a read of a file swapped out from under it
    (SQLITE_IOERR_VNODE); a read that fails therefore opens the file afresh,
    a complete build, and reads once more. The old file's disk space comes
    back once every thread that had it open has read again (or ended).

    A dataset the database lacks, or holds past its `max_age_hours` (counted
    from the source's own date, else from when it was fetched), is
    unavailable. So is one this deployment does not fetch (CAIDA's, under
    ASINFO_CAIDA_ENABLED=false), however the file was built.

    refresh() downloads the datasets and builds the database; see there.

    Disabled (ASINFO_ENABLED=false), it opens nothing, downloads nothing, and
    the reads answer None, which leaves AS information out of every response.
    """

    def __init__(
        self,
        directory: str = ASINFO_DIR,
        datasets: Iterable[Dataset] | None = None,
        enabled: bool = ASINFO_ENABLED,
        fetch: Callable[..., dict] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.directory = directory
        self.path = os.path.join(directory, DATABASE_NAME)
        self.datasets = default_datasets() if datasets is None else tuple(datasets)
        self.enabled = enabled
        # fetch(url, dest_path, max_bytes, accept_gzip=False), as _download.
        self._fetch = fetch or _download
        self._clock = clock
        # Whether a refresh has run since start, which is what tries to build
        # the database. Before one, a missing database is a fresh volume, not
        # a fault.
        self.build_attempted = False
        # Every dataset's label, fetched here or not, for `unavailable`.
        self._labels = {
            d.id: d.label for d in (*default_datasets(caida=True), *self.datasets)
        }
        self._local = threading.local()
        # The last file that failed to read, logged once rather than per lookup.
        # A file is named by its device, inode, mtime and size: a swap changes
        # them.
        self._unreadable: tuple | None = None

    def _file_key(self) -> tuple | None:
        try:
            stat = os.stat(self.path)
        except OSError:
            return None
        return stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size

    def _database(self) -> tuple[_Copy | None, str | None]:
        """This thread's open copy of the database, opened again when the file
        has changed since; or None and why there is none. Raises
        sqlite3.Error when the file does not read."""
        key = self._file_key()
        if key is None:
            self._release()
            if self.build_attempted:
                return None, "the database has not been built"
            return None, _NOT_DOWNLOADED
        held = getattr(self._local, "held", None)
        if held is None or held[0] != key:
            self._release()
            held = (key, *self._open())
            self._local.held = held
        return held[1], held[2]

    def _uri(self) -> str:
        return f"file:{urllib.parse.quote(os.path.abspath(self.path))}?mode=ro"

    def _open(self) -> tuple[_Copy | None, str | None]:
        con = sqlite3.connect(self._uri(), uri=True)
        try:
            version = con.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                logging.warning(
                    "Not reading the AS database %s: schema %s, expected %s",
                    self.path,
                    version,
                    SCHEMA_VERSION,
                )
                con.close()
                return None, "the database is from another release"
            meta = {
                row[0]: row[1:]
                for row in con.execute(
                    "SELECT dataset, built, rows, fetched_at, source_date FROM meta"
                )
            }
            # Read through `con`, so they are the lengths of the file it has
            # open, even when a swap came between the stat and the connect.
            plens = {
                family: tuple(
                    plen
                    for (plen,) in con.execute(
                        "SELECT plen FROM route_plen WHERE family = ?"
                        " ORDER BY plen DESC",
                        (family,),
                    )
                )
                for family in (4, 6)
            }
        except sqlite3.Error:
            con.close()
            raise
        return _Copy(con, meta, plens), None

    def _release(self) -> None:
        """Close this thread's connection, which holds its file open (on disk,
        even after a swap unlinked it) until then."""
        held = getattr(self._local, "held", None)
        self._local.held = None
        if held is not None and held[1] is not None:
            held[1].con.close()

    def _availability(
        self, copy: _Copy | None, problem: str | None
    ) -> tuple[dict[str, object], dict[str, str]]:
        """(dates, reasons): the date, as stored, of each dataset lookups may
        read, and why each other one may not be read."""
        now = self._clock()
        fetched = {dataset.id: dataset for dataset in self.datasets}
        dates: dict[str, object] = {}
        reasons: dict[str, str] = {}
        for dataset_id in self._labels:
            dataset = fetched.get(dataset_id)
            if dataset is None:
                reasons[dataset_id] = "turned off"
                continue
            if copy is None:
                reasons[dataset_id] = problem
                continue
            row = copy.meta.get(dataset_id)
            _, reason = _judge(dataset, row, now)
            if reason is None:
                dates[dataset_id] = _date(row)
            else:
                reasons[dataset_id] = reason
        return dates, reasons

    def _with_database[T](self, use: Callable[[_Copy | None, str | None], T]) -> T:
        """`use(copy, problem)`, on this thread's copy of the database. When it
        fails to read, the file is opened afresh and `use` runs once more (a
        swap fails a read on macOS), and the failure is logged as a warning;
        a second failure is logged as an error, once per file, and `use` gets
        no database. A file that does not read never raises, but a
        ProgrammingError, a fault in a query rather than in the file, does."""
        error = None
        for _ in range(2):
            try:
                answer = use(*self._database())
            except sqlite3.DatabaseError as exc:
                if isinstance(exc, sqlite3.ProgrammingError):
                    raise
                error = exc
                self._release()
                continue
            if error is not None:
                logging.warning(
                    "Read the AS database %s again after an error (%s)",
                    self.path,
                    _sqlite_error(error),
                )
            return answer
        key = self._file_key()
        if key != self._unreadable:
            self._unreadable = key
            logging.error(
                "Cannot read the AS database %s (%s)",
                self.path,
                _sqlite_error(error),
                exc_info=error,
            )
        return use(None, _UNREADABLE)

    def _answer(self, read: Callable[[_Reader], dict]) -> dict:
        """Run `read` on this thread's copy, and add which datasets it used,
        which were unavailable, and the credits the used ones ask for."""
        return self._with_database(lambda copy, problem: self._run(read, copy, problem))

    def _run(
        self, read: Callable[[_Reader], dict], copy: _Copy | None, problem: str | None
    ) -> dict:
        dates, reasons = self._availability(copy, problem)
        reader = _Reader(copy, dates)
        answer = read(reader)
        answer["datasets"] = {i: dates[i] for i in self._labels if i in reader.used}
        answer["unavailable"] = [
            {"dataset": i, "label": self._labels[i], "reason": reason}
            for i, reason in reasons.items()
        ]
        answer["attribution"] = self.attribution(answer["datasets"])
        return {key: answer[key] for key in ANSWER_KEYS}

    def _credits(self, datasets: dict[str, object]) -> dict[str, str | None]:
        """Each credit an answer's `datasets` ({id: date}) ask for, once, in
        dataset order, with the page it links to (None for most)."""
        credits: dict[str, str | None] = {}
        for dataset in self.datasets:
            if dataset.id in datasets:
                credit = dataset.credit.format(date=_day(datasets[dataset.id]))
                credits.setdefault(credit, dataset.credit_url)
        return credits

    def attribution(self, datasets: dict[str, object]) -> list[str]:
        """The credits an answer's `datasets` ({id: date}) ask for, each once,
        in dataset order: its `attribution`. lookup.py asks again for the
        datasets an answer still shows once it has dropped some sections."""
        return list(self._credits(datasets))

    def credit_links(self, datasets: dict[str, object]) -> dict[str, str]:
        """Each line of attribution(datasets) that links to its dataset's page
        (CAIDA's two), and that page: for the pages, which draw the lines as
        links. The JSON's `attribution` stays plain text."""
        return {text: url for text, url in self._credits(datasets).items() if url}

    def for_address(self, ip: str, fallback_asn: int | None = None) -> dict | None:
        """The announced route covering `ip`, and the AS it describes: the
        route's origin seen by the most RIS peers (`source: "route"`), else
        `fallback_asn`, GeoLite2's number (`"geolite2"`), else none (`asn`
        and `source` None). `announced` says whether a route covers `ip`, None
        when its family's routes are unavailable. An IPv4-mapped IPv6 address
        is read as the IPv4 address it carries.

        Read from the database only. None when disabled, or when `ip` is not
        an address."""
        if not self.enabled:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if not _is_asn(fallback_asn):
            fallback_asn = None

        def read(reader: _Reader) -> dict:
            route, announced = reader.route(address)
            if route is not None:
                asn, source = route["origins"][0]["asn"], "route"
            elif fallback_asn is not None:
                asn, source = fallback_asn, "geolite2"
            else:
                asn, source = None, None
            return {
                **reader.describe(asn),
                "route": route,
                "announced": announced,
                "source": source,
                "prefix_list": None,
            }

        return self._answer(read)

    def for_asn(self, asn: int, full: bool = False) -> dict | None:
        """The AS on its own (`source: "asn"`, no `route`). `announced` says
        whether it originates any route; `full` adds `prefix_list`. None when
        disabled, or when `asn` is not a 32-bit AS number."""
        if not self.enabled or not _is_asn(asn):
            return None

        def read(reader: _Reader) -> dict:
            return {
                **reader.describe(asn),
                "route": None,
                "announced": reader.originates(asn),
                "source": "asn",
                "prefix_list": reader.prefix_list(asn) if full else None,
            }

        return self._answer(read)

    def status(self) -> dict:
        """Per dataset fetched here: its dates as stored, age, rows, and
        whether lookups cannot read it (`stale`: not in the database, or past
        its age), for /healthz."""
        if not self.enabled:
            return {"enabled": False}
        return self._with_database(lambda copy, _: self._status(copy))

    def _status(self, copy: _Copy | None) -> dict:
        now = self._clock()
        datasets = {}
        for dataset in self.datasets:
            row = copy.meta.get(dataset.id) if copy is not None else None
            age, reason = _judge(dataset, row, now)
            datasets[dataset.id] = {
                "label": dataset.label,
                "fetched_at": row[2] if row else None,
                "source_date": row[3] if row else None,
                "age_hours": None if age is None else round(age, 1),
                "rows": row[1] if row else 0,
                "stale": reason is not None,
            }
        return {"enabled": True, "database": copy is not None, "datasets": datasets}

    def stale_datasets(self) -> list[str]:
        """One message per dataset fetched here that lookups cannot read, for
        /healthz. Empty when there is no database at all: that is the
        database's absence to report, not each dataset's."""
        if not self.enabled:
            return []
        copy, _ = self._with_database(lambda copy, problem: (copy, problem))
        if copy is None:
            return []
        now = self._clock()
        messages = []
        for dataset in self.datasets:
            _, reason = _judge(dataset, copy.meta.get(dataset.id), now)
            if reason is not None:
                messages.append(
                    f"the {dataset.label} dataset is unavailable to lookups: {reason}"
                )
        return messages

    def hosts(self) -> list[str]:
        """The servers the datasets come from, for /privacy."""
        hosts = []
        for dataset in self.datasets:
            host = urllib.parse.urlparse(dataset.url).hostname or dataset.url
            if host not in hosts:
                hosts.append(host)
        return hosts

    def refresh(self) -> bool:
        """Bring each dataset's copy up to date, and build the database from
        the copies when one changed; whether every dataset is current
        afterwards. Run by the scheduler, one run at a time, never by a
        request: it downloads tens of MB, parses each download, and a build
        takes about half a minute of CPU.

        A dataset is due when it has no copy, or its copy was last checked
        `interval_hours` ago, less half of ASINFO_CHECK_INTERVAL_SECONDS: the
        job runs on that interval, and without the slack a copy checked a
        moment into one run would wait an extra run, so the daily datasets
        would drift into runs (and rebuilds) of their own. A due dataset still
        waits while its last request is under ASINFO_RETRY_SECONDS old. That
        time is the mtime of `<file>.requested`, written before the request is
        sent, so the wait holds across a restart and a failed request counts
        as much as one that worked.

        Checking a dataset downloads its file to `<file>.tmp`. For CAIDA it
        first reads the listing (under the listing's stamp), and downloads
        the newest file there only when that is not the copy's. A download
        that is the copy byte for byte only marks the copy checked. Any other
        must give its parser `min_rows` rows before it replaces the copy, so
        a truncated, thin or reformatted file leaves the copy as it was.

        The database is built from the copies when it is missing or from
        another release, or when a copy is newer than what it was built from
        (replaced in this run, or in one whose build failed). The build goes
        to asinfo.sqlite3.tmp and replaces the database only once complete;
        a build that fails is logged and leaves the old file.
        """
        if not self.enabled:
            return True
        try:
            copies = self._read_copies()
            current = True
            for dataset in self.datasets:
                current = self._refresh_dataset(dataset, copies) and current
            return self._build_if_behind(copies) and current
        finally:
            self.build_attempted = True

    def _copies_path(self) -> str:
        return os.path.join(self.directory, _COPIES_NAME)

    def _read_copies(self) -> dict[str, dict]:
        """Each dataset's copy, from copies.json: {file, fetched_at,
        source_date, checked_at}. One whose file is gone is left out, which
        makes its dataset due."""
        try:
            with open(self._copies_path(), encoding="utf-8") as handle:
                records = json.load(handle)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            logging.exception("Ignoring the unreadable %s", self._copies_path())
            return {}
        if not isinstance(records, dict):
            return {}
        return {
            dataset_id: record
            for dataset_id, record in records.items()
            if _is_record(record)
            and os.path.isfile(os.path.join(self.directory, record["file"]))
        }

    def _write_copies(self, copies: dict[str, dict]) -> None:
        path = self._copies_path()
        with open(path + ".tmp", "w", encoding="utf-8") as handle:
            json.dump(copies, handle, indent=1, sort_keys=True)
        os.replace(path + ".tmp", path)

    def _refresh_dataset(self, dataset: Dataset, copies: dict[str, dict]) -> bool:
        """Check one dataset if it is due (see refresh()), updating its entry
        in `copies` and copies.json; whether its copy is current."""
        now = self._clock()
        record = copies.get(dataset.id)
        if record is not None:
            checked = _epoch(record["checked_at"])
            due = dataset.interval_hours * 3600 - ASINFO_CHECK_INTERVAL_SECONDS / 2
            if now - checked < due:
                return True
        stamp = os.path.join(self.directory, _request_name(dataset) + ".requested")
        last = _mtime(stamp)
        if last is not None and now - last < ASINFO_RETRY_SECONDS:
            return False
        try:
            os.makedirs(self.directory, exist_ok=True)
            with open(stamp, "w", encoding="utf-8") as handle:
                handle.write(dataset.url + "\n")
            os.utime(stamp, (now, now))
        except OSError:
            # Unrecorded, nothing would stop the next run, or the next
            # restart, from asking again at once, so nothing is asked.
            logging.exception(
                "Cannot record a request for %s; not downloading it", dataset.id
            )
            return False
        tmp = None
        try:
            name, url = self._source_file(dataset)
            path = os.path.join(self.directory, name)
            same_file = record is not None and record["file"] == name
            if same_file and dataset.pattern:
                # The listing names no newer file.
                record["checked_at"] = _iso(now)
            else:
                tmp = path + ".tmp"
                answer = self._fetch(
                    url, tmp, dataset.max_bytes, accept_gzip=dataset.id == "rpki"
                )
                if same_file and filecmp.cmp(tmp, path, shallow=False):
                    record["checked_at"] = _iso(now)
                else:
                    copies[dataset.id] = self._accept(dataset, name, tmp, answer, now)
                    tmp = None
            self._write_copies(copies)
            return True
        except Exception:
            logging.exception(
                "Error updating the AS dataset %s from %s", dataset.id, dataset.url
            )
            return False
        finally:
            if tmp is not None:
                with contextlib.suppress(OSError):
                    os.remove(tmp)

    def _source_file(self, dataset: Dataset) -> tuple[str, str]:
        """(copy name, URL) of the dataset's file: its URL's, or for CAIDA the
        newest file its listing names that fully matches its pattern."""
        if dataset.pattern is None:
            return _request_name(dataset), dataset.url
        listing = os.path.join(self.directory, _request_name(dataset) + ".tmp")
        try:
            self._fetch(dataset.url, listing, _LISTING_MAX_BYTES, accept_gzip=False)
            with open(listing, encoding="utf-8", errors="replace") as handle:
                name = newest_file(handle.read(), dataset.pattern)
        finally:
            with contextlib.suppress(OSError):
                os.remove(listing)
        if name is None:
            raise ValueError(f"{dataset.url} lists no file like {dataset.pattern}")
        return name, urllib.parse.urljoin(dataset.url, name)

    def _accept(
        self, dataset: Dataset, name: str, tmp: str, answer: dict, now: float
    ) -> dict:
        """Swap a download in as the dataset's copy, once its parser finds
        `min_rows` rows in it, and return the copy's record. Raises when the
        download falls short."""
        rows = _count_rows(dataset.id, tmp)
        if rows < dataset.min_rows:
            raise ValueError(
                f"{name} has {rows} rows, fewer than the {dataset.min_rows} expected"
            )
        # The source's own date: the dump's, the file name's, the server's.
        source_date = (
            (_generated_at(tmp) if dataset.id in ("ris_v4", "ris_v6") else None)
            or (_iso_date(name[:8]) if dataset.pattern else None)
            or _http_date(answer.get("last_modified"))
            or _iso(now)
        )
        os.replace(tmp, os.path.join(self.directory, name))
        if dataset.pattern:
            # A newer month's file replaces the older one's.
            for other in os.listdir(self.directory):
                if other != name and re.fullmatch(dataset.pattern, other):
                    with contextlib.suppress(OSError):
                        os.remove(os.path.join(self.directory, other))
        logging.info("AS dataset %s updated: %s, %d rows", dataset.id, name, rows)
        return {
            "file": name,
            "fetched_at": _iso(now),
            "source_date": source_date,
            "checked_at": _iso(now),
        }

    def _built(self) -> dict[str, tuple] | None:
        """(fetched_at, source_date) of each dataset in the live database, as
        its meta table has them; None when there is no database this release
        reads."""
        try:
            con = sqlite3.connect(self._uri(), uri=True)
        except sqlite3.Error:
            return None
        try:
            if con.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                return None
            rows = con.execute(
                "SELECT dataset, fetched_at, source_date FROM meta WHERE built = 1"
            )
            return {row[0]: tuple(row[1:]) for row in rows}
        except sqlite3.Error:
            return None
        finally:
            con.close()

    def _build_if_behind(self, copies: dict[str, dict]) -> bool:
        """Build the database from the copies of the datasets fetched here,
        unless it was built from exactly these; whether it is current."""
        records = {d.id: copies[d.id] for d in self.datasets if d.id in copies}
        built = self._built()
        if not records:
            return built is not None
        if built is not None and all(
            built.get(dataset_id) == (record["fetched_at"], record["source_date"])
            for dataset_id, record in records.items()
        ):
            return True
        sources = {
            dataset_id: os.path.join(self.directory, record["file"])
            for dataset_id, record in records.items()
        }
        meta = {
            dataset_id: {
                "fetched_at": record["fetched_at"],
                "source_date": record["source_date"],
            }
            for dataset_id, record in records.items()
        }
        tmp = self.path + ".tmp"
        try:
            rows = build_database(sources, tmp, ASINFO_MIN_RIS_PEERS, meta)
            os.replace(tmp, self.path)
        except Exception:
            logging.exception("Cannot build the AS database; keeping %s", self.path)
            with contextlib.suppress(OSError):
                os.remove(tmp)
            return False
        # This thread's own connection, if it read, would hold the old file.
        self._release()
        logging.info("AS database built: %s", rows)
        return True
