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
`{date}` placeholder that the caller fills with the file's own YYYY-MM-DD.

`build_database` turns the local copies into the SQLite file, streaming each
source into batched inserts. Each route's RPKI state (RFC 6811) and each AS's
prefix, address space, RPKI and neighbour counts are worked out at build time,
so a lookup only reads them, and the VRPs are not kept.

Imports config and the standard library only: lookup.py builds the singleton.
"""

import bz2
import contextlib
import gzip
import ipaddress
import itertools
import json
import operator
import os
import re
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from config import (
    ASINFO_ASNAMES_URL,
    ASINFO_CAIDA_ENABLED,
    ASINFO_CAIDA_ORG_MAX_AGE_DAYS,
    ASINFO_CAIDA_ORG_URL,
    ASINFO_CAIDA_REL_MAX_AGE_DAYS,
    ASINFO_CAIDA_REL_URL,
    ASINFO_MAX_AGE_HOURS,
    ASINFO_NRO_URL,
    ASINFO_RIS_V4_URL,
    ASINFO_RIS_V6_URL,
    ASINFO_RPKI_URL,
)

_RIPE_CREDIT = "Source: RIPE NCC"
_MB = 1024 * 1024


@dataclass(frozen=True)
class Dataset:
    """One source. `pattern` set means `url` is a directory listing and the
    file is the newest href matching it. `max_bytes` refuses a download bigger
    than that unread; `min_rows` is what the build must find to accept it."""

    id: str
    label: str
    url: str
    pattern: str | None
    interval_hours: float
    max_age_hours: float
    min_rows: int
    max_bytes: int
    credit: str


def default_datasets() -> tuple[Dataset, ...]:
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
            64 * _MB,
            "RPKI data validated by rpki-client.org",
        ),
    ]
    if ASINFO_CAIDA_ENABLED:
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
# release (stored as PRAGMA user_version).
SCHEMA_VERSION = 1

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
# all three uses the key whatever its column order. rpki_state is valid,
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
