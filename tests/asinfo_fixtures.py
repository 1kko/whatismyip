"""Small source files in the real formats, for the asinfo tests.

`write_sources` writes one file per dataset id, named as the last path segment
of the dataset's URL (CAIDA's carry a date), gzipped or bzipped where the
source is. They describe a handful of ASes the tests share: AS4766 (KT), its
providers 174 and 701, its peer 9318, three customers, and AS13335.

`build_manager` builds them into a directory's database the way a refresh
does (into a .tmp file, then os.replace) and returns a manager over it whose
clock reads `now`; `rebuild` builds again over the live file.

`refreshed_manager` gets there through `refresh()` instead, downloading the
same sources from `fake_fetch`, a fetch that serves them by URL, on a `Clock`
the test moves by hand.
"""

import bz2
import dataclasses
import datetime
import gzip
import json
import os

from asinfo import (
    DATABASE_NAME,
    DATASET_IDS,
    AsInfoManager,
    build_database,
    default_datasets,
)

CAIDA_REL_NAME = "20261001.as-rel2.txt.bz2"
CAIDA_ORG_NAME = "20261001.as-org2info.jsonl.gz"
# The CAIDA files' own date, from their names.
CAIDA_DATE = "2026-10-01"
# The tests' present: nineteen and a half days after the CAIDA files.
NOW = datetime.datetime(2026, 10, 20, 12, tzinfo=datetime.timezone.utc).timestamp()
HOUR = 3600
DAY = 24 * HOUR
# CAIDA names an organization after one of its ASes; AS4766 is in this one.
KT_ORG_ID = "@aut-4766-APNIC"

ASNAMES = """\
174 COGENT-174 - Cogent Communications, US
701 UUNET - Verizon Business, US
4766 KIXS-AS-KR-KR - Korea Telecom, KR
9318 SKB-AS-KR - SK Broadband Co Ltd, KR
13335 CLOUDFLARENET - Cloudflare, Inc., US
17858 POWERVIS-AS-KR - LG POWERCOMM, KR
38661 KRNIC-AS-KR - Example Customer One, KR
45400 KT-CUSTOMER-AS - Example Customer Two, KR
"""

NRO = """\
2|nro|20261019|773470|19821213|20261019|+0000
nro|*|asn|*|117501|summary
apnic|KR|asn|4766|1|19960422|assigned|A9149F3E|e-stats
apnic|KR|asn|9318|1|20000101|assigned|B0000001|e-stats
arin|US|asn|701|1|19900801|assigned|C0000001|e-stats
ripencc|NL|asn|1101|10|19930901|assigned|x|e-stats
arin||asn|7|1||available||e-stats
"""

# The dumps open with RIPE's header, whose "generated at" line is their date.
RIS_V4 = """\
%
% This file was generated at Mon Oct 19 08:00:00 UTC 2026.
% A more recent copy may be available
% from http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz
%
% Full dump of combined RIS IPv4 routing tables
% Format:  <origin> <tab> <prefix> <tab> <seen by #rispeers>
%

4766\t211.252.112.0/24\t326
4766\t211.252.0.0/15\t330
13335\t1.1.1.0/24\t340
174\t0.0.0.0/0\t40
4766\t14.34.86.32/27\t8
"""

RIS_V6 = """\
%
% This file was generated at Mon Oct 19 08:00:00 UTC 2026.
%
4766\t2001:2d8::/32\t120
13335\t2606:4700::/32\t150
"""

RPKI = """\
ASN,IP Prefix,Max Length,Trust Anchor,Expires
AS13335,1.1.1.0/24,24,apnic,1792937860
AS4766,211.252.0.0/15,24,apnic,1792937860
"""

CAIDA_REL = """\
# inferred AS relationships, serial-2
174|4766|-1|bgp
701|4766|-1|bgp
4766|17858|-1|bgp
4766|38661|-1|bgp
4766|45400|-1|bgp
4766|9318|0|bgp
"""

CAIDA_ORG = [
    {
        "type": "ASN",
        "asn": "4766",
        "name": "KIXS-AS-KR",
        "organizationId": KT_ORG_ID,
        "source": "APNIC",
    },
    {
        "type": "ASN",
        "asn": "9318",
        "name": "SKB-AS-KR",
        "organizationId": "@aut-9318-APNIC",
        "source": "APNIC",
    },
    {
        "type": "ASN",
        "asn": "9760",
        "name": "KT-SIBLING",
        "organizationId": KT_ORG_ID,
        "source": "APNIC",
    },
    {
        "type": "Organization",
        "organizationId": KT_ORG_ID,
        "name": "Korea Telecom",
        "country": "KR",
        "source": "APNIC",
    },
    {
        "type": "Organization",
        "organizationId": "@aut-9318-APNIC",
        "name": "SK Broadband Co Ltd",
        "country": "KR",
        "source": "APNIC",
    },
]


def _gzip(path: str, text: str) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(text)


def write_sources(directory) -> dict[str, str]:
    """Write one file per dataset id into `directory`; return id -> path."""
    directory = str(directory)
    paths = {
        "asnames": os.path.join(directory, "asn.txt"),
        "nro": os.path.join(directory, "nro-delegated-stats"),
        "ris_v4": os.path.join(directory, "riswhoisdump.IPv4.gz"),
        "ris_v6": os.path.join(directory, "riswhoisdump.IPv6.gz"),
        "rpki": os.path.join(directory, "rpki.csv"),
        "caida_rel": os.path.join(directory, CAIDA_REL_NAME),
        "caida_org": os.path.join(directory, CAIDA_ORG_NAME),
    }
    for key in ("asnames", "nro", "rpki"):
        with open(paths[key], "w", encoding="utf-8") as handle:
            handle.write({"asnames": ASNAMES, "nro": NRO, "rpki": RPKI}[key])
    _gzip(paths["ris_v4"], RIS_V4)
    _gzip(paths["ris_v6"], RIS_V6)
    with bz2.open(paths["caida_rel"], "wt", encoding="utf-8") as handle:
        handle.write(CAIDA_REL)
    _gzip(paths["caida_org"], "".join(json.dumps(r) + "\n" for r in CAIDA_ORG))
    return paths


def iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()


def fixture_meta(now: float = NOW, overrides: dict | None = None) -> dict[str, dict]:
    """build_database's `meta` as a refresh at `now` records it: every dataset
    fetched an hour ago; the daily ones dated two hours ago by their source,
    CAIDA's by their file names. `overrides` replaces fields per dataset."""
    meta = {
        dataset_id: {
            "fetched_at": iso(now - HOUR),
            "source_date": (
                CAIDA_DATE if dataset_id.startswith("caida_") else iso(now - 2 * HOUR)
            ),
        }
        for dataset_id in DATASET_IDS
    }
    for dataset_id, fields in (overrides or {}).items():
        meta[dataset_id] = {**meta[dataset_id], **fields}
    return meta


def build_live(
    directory, now: float = NOW, meta=None, texts=None, drop=(), min_peers: int = 10
) -> None:
    """Build the fixture sources into `directory`'s database: to a .tmp file,
    then os.replace over the live one. `texts` replaces a dataset's source
    with plain text, `drop` leaves datasets out, `meta` overrides fields of
    `fixture_meta(now)`."""
    directory = str(directory)
    source_dir = os.path.join(directory, "src")
    os.makedirs(source_dir, exist_ok=True)
    sources = write_sources(source_dir)
    for dataset_id, text in (texts or {}).items():
        sources[dataset_id] = os.path.join(source_dir, f"{dataset_id}.txt")
        with open(sources[dataset_id], "w", encoding="utf-8") as handle:
            handle.write(text)
    for dataset_id in drop:
        del sources[dataset_id]
    live = os.path.join(directory, DATABASE_NAME)
    build_database(sources, live + ".tmp", min_peers, fixture_meta(now, meta))
    os.replace(live + ".tmp", live)


def build_manager(directory, now: float = NOW, clock=None, datasets=None, **build):
    """A manager over a freshly built `directory`, its clock at `now`. It
    fetches every dataset, CAIDA's included, whatever ASINFO_CAIDA_ENABLED
    a developer's .env sets, unless `datasets` says otherwise."""
    build_live(directory, now=now, **build)
    return AsInfoManager(
        directory=str(directory),
        datasets=default_datasets(caida=True) if datasets is None else datasets,
        enabled=True,
        clock=clock or (lambda: now),
    )


def rebuild(directory, ris_v4_peers: int | None = None, **build) -> None:
    """Build again over the live file; `ris_v4_peers` changes how many RIS peers
    see 211.252.112.0/24."""
    texts = dict(build.pop("texts", None) or {})
    if ris_v4_peers is not None:
        texts["ris_v4"] = RIS_V4.replace(
            "211.252.112.0/24\t326", f"211.252.112.0/24\t{ris_v4_peers}"
        )
    build_live(directory, texts=texts, **build)


# Refresh: the sources as the servers send them, through a fake fetch.

# The rows each source holds after its parser's filters.
FIXTURE_ROWS = {
    "asnames": 8,
    "nro": 4,
    "ris_v4": 3,
    "ris_v6": 2,
    "rpki": 2,
    "caida_rel": 6,
    "caida_org": 5,
}

# What each CAIDA listing names besides the dataset's newest file: its older
# months, and files that are not the dataset (another format, a README).
_OLDER = {
    "caida_rel": ("20260801.as-rel2.txt.bz2", "20260901.as-rel2.txt.bz2"),
    "caida_org": ("20260701.as-org2info.jsonl.gz",),
}
_NOT_THE_DATASET = {
    "caida_rel": ("20261001.ppdc-ases.txt.bz2", "README.txt"),
    "caida_org": ("20261001.as-org2info.txt.gz", "README.txt"),
}


def _gz(text: str) -> bytes:
    # A fixed mtime: the same text gzips to the same bytes, as a server's
    # unchanged file downloads to the same bytes.
    return gzip.compress(text.encode(), mtime=0)


def good_ris_v4_bytes() -> bytes:
    """The IPv4 dump as RIPE serves it, gzipped."""
    return _gz(RIS_V4)


def good_sources() -> dict[str, bytes]:
    """Each dataset's file as its server sends it (rpki before gzip)."""
    return {
        "asnames": ASNAMES.encode(),
        "nro": NRO.encode(),
        "ris_v4": good_ris_v4_bytes(),
        "ris_v6": _gz(RIS_V6),
        "rpki": RPKI.encode(),
        "caida_rel": bz2.compress(CAIDA_REL.encode()),
        "caida_org": _gz("".join(json.dumps(r) + "\n" for r in CAIDA_ORG)),
    }


def listing(dataset_id: str, newest: str | None) -> bytes:
    """A CAIDA directory listing whose newest file for the dataset is
    `newest`, after older ones; None lists no file of the dataset at all."""
    names = list(_NOT_THE_DATASET[dataset_id])
    if newest:
        names += [*_OLDER[dataset_id], newest]
    rows = "".join(f'<tr><td><a href="{n}">{n}</a></td></tr>\n' for n in names)
    return (
        '<html><body><table>\n<tr><th><a href="?C=N;O=D">Name</a></th></tr>\n'
        f'<tr><td><a href="/datasets/">Parent Directory</a></td></tr>\n{rows}'
        "</table></body></html>\n"
    ).encode()


def refresh_datasets():
    """Every dataset, CAIDA's included, each wanting exactly the rows its
    fixture source has: one row fewer is a thin download."""
    return tuple(
        dataclasses.replace(d, min_rows=FIXTURE_ROWS[d.id])
        for d in default_datasets(caida=True)
    )


class Clock:
    """The time as a test sets it: NOW until advanced."""

    def __init__(self, now: float = NOW):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, hours: float = 0, seconds: float = 0) -> None:
        self.now += hours * HOUR + seconds


def fake_fetch(listed=None, last_modified=None, **served):
    """A fetch serving the fixture sources by URL, as `_download` does: it
    writes the body to `dest_path` and answers {"last_modified"}.

    `served[id]` replaces a dataset's body: bytes, or an exception to raise.
    A CAIDA URL is a listing whose newest file is `listed[id]` (the fixture's
    name unless given; None lists none; an exception fails the listing), and
    a file under it is served that dataset's body. rpki comes gzipped when
    asked for gzip, as console.rpki-client.org sends it. `last_modified[id]`
    is the Last-Modified header. `fetch.calls` has (url, accept_gzip) per
    request, in order."""
    datasets = default_datasets(caida=True)
    bodies = {**good_sources(), **served}
    newest = {"caida_rel": CAIDA_REL_NAME, "caida_org": CAIDA_ORG_NAME}
    newest.update(listed or {})
    calls = []

    def fetch(url, dest_path, max_bytes, accept_gzip=False):
        calls.append((url, accept_gzip))
        for dataset in datasets:
            listed_file = dataset.pattern and url.startswith(dataset.url)
            if url == dataset.url and dataset.pattern:
                body = newest[dataset.id]
                if not isinstance(body, BaseException):
                    body = listing(dataset.id, body)
            elif url == dataset.url or listed_file:
                body = bodies[dataset.id]
                if dataset.id == "rpki" and accept_gzip:
                    body = gzip.compress(body, mtime=0)
            else:
                continue
            if isinstance(body, BaseException):
                raise body
            if len(body) > max_bytes:
                raise ValueError(f"{url} is larger than {max_bytes} bytes")
            with open(dest_path, "wb") as handle:
                handle.write(body)
            return {"last_modified": (last_modified or {}).get(dataset.id)}
        raise OSError(f"no fixture at {url}")

    fetch.calls = calls
    return fetch


def refreshed_manager(directory, clock=None, fetch=None, datasets=None):
    """A manager over `directory` after one refresh through `fetch` (the
    fixture sources unless given) that brought every dataset in."""
    manager = AsInfoManager(
        directory=str(directory),
        datasets=refresh_datasets() if datasets is None else datasets,
        enabled=True,
        fetch=fetch or fake_fetch(),
        clock=clock or Clock(),
    )
    assert manager.refresh() is True
    return manager
