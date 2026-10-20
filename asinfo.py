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

Imports config and the standard library only: lookup.py builds the singleton.
"""

import bz2
import gzip
import ipaddress
import json
import re
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
) -> Iterator[tuple[int, int, str, str, str | None, str]]:
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
        yield first, count, fields[0], fields[1], _iso_date(fields[5]), fields[6]


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
    """rpki-client's CSV: `ASN,IP Prefix,Max Length,...`, ASN as `AS13335`."""
    for line in lines:
        fields = line.split(",")
        if len(fields) < 3 or not fields[0].upper().startswith("AS"):
            continue
        asn = _asn(fields[0][2:])
        max_length = _asn(fields[2])
        if asn is None or max_length is None:
            continue
        try:
            ipaddress.ip_network(fields[1], strict=True)
        except ValueError:
            continue
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
