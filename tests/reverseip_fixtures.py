"""Synthetic OpenINTEL Parquet files and an in-memory bucket for the reverse
IP tests: plain helpers and constants, no pytest fixtures."""

import calendar
import hashlib
import re
import urllib.parse
from typing import NamedTuple
from xml.sax.saxutils import escape

import pyarrow as pa
import pyarrow.parquet as pq

from reverseip_build import Response

DAY = "2026-10-20"
# 2026-10-21T12:00:00Z, a day and a half after DAY's partition began.
NOW = float(calendar.timegm((2026, 10, 21, 12, 0, 0)))


class Row(NamedTuple):
    query_name: str
    query_type: str
    response_type: str
    section: str
    ip4_address: str | None
    ip6_address: str | None
    rank: str | None


def _a(name, ip, rank, section="ans"):
    return Row(name, "A", "A", section, ip, None, rank)


ROWS: list[Row] = [
    _a("example.com.", "93.184.215.14", "5"),
    _a("www.example.com.", "93.184.215.14", "5"),
    _a("www.example.com.", "93.184.215.99", "5"),
    Row("shop.example.org.", "A", "CNAME", "ans", None, None, "9"),
    _a("shop.example.org.", "93.184.215.14", "9"),
    _a("Upper.Example.NET.", "93.184.215.14", "12"),
    Row(
        "example.net.",
        "AAAA",
        "AAAA",
        "ans",
        None,
        "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        "7",
    ),
    Row(
        "mapped.example.org.",
        "AAAA",
        "AAAA",
        "ans",
        None,
        "::ffff:93.184.215.15",
        "20",
    ),
    _a("glue.example.com.", "93.184.215.50", "1", section="auth"),
    _a("private.example.com.", "10.0.0.1", "1"),
    _a("\\032alt.aspmx.example.com.", "93.184.215.14", "3"),
    _a("norank.example.com.", "93.184.215.14", None),
    _a("a.b.example.com.", "93.184.215.16", "40"),
]


def write_parquet(path, rows, pad_columns: int = 0) -> None:
    """The six columns the build reads plus the ones it must not, in one row
    group, gzip-compressed. `pad_columns` adds string columns of its own, a
    distinct digest a row, so their chunks do not compress away."""
    columns = {
        "query_name": [r.query_name for r in rows],
        "query_type": [r.query_type for r in rows],
        "response_type": [r.response_type for r in rows],
        "section": [r.section for r in rows],
        "ip4_address": [r.ip4_address for r in rows],
        "ip6_address": [r.ip6_address for r in rows],
        "rank": [r.rank for r in rows],
        "cname_name": [None] * len(rows),
    }
    arrays = {k: pa.array(v, type=pa.string()) for k, v in columns.items()}
    arrays["rtt"] = pa.array([0.5] * len(rows), type=pa.float64())
    for i in range(pad_columns):
        arrays[f"pad{i}"] = pa.array(
            [hashlib.sha256(f"{i}:{n}".encode()).hexdigest() for n in range(len(rows))],
            type=pa.string(),
        )
    pq.write_table(
        pa.table(arrays),
        str(path),
        compression="gzip",
        row_group_size=max(len(rows), 1),
    )


_RANGE = re.compile(r"bytes=(\d+)-(\d+)")


class FakeBucket:
    """An S3 bucket in memory, called as a transport: `(url, headers) ->
    Response`. Nothing here touches the network.

    It answers ListObjectsV2 listings (`?list-type=2&prefix=`), `page_size`
    keys a page with continuation tokens, and GETs of the objects `add`ed,
    honouring `Range: bytes=a-b` with a 206. An object is found by the end of
    the URL's path, so the bucket answers through any base URL. Every request
    is recorded in `requests` as (url, range or None); `fail[key]` is answered
    for that object instead."""

    def __init__(self, page_size: int = 1000):
        self.page_size = page_size
        self.objects: dict[str, bytes] = {}
        self.requests: list[tuple[str, str | None]] = []
        self.fail: dict[str, Response] = {}

    def add(self, key: str, data: bytes) -> None:
        self.objects[key] = data

    def __call__(self, url: str, headers: dict[str, str]) -> Response:
        wanted = {name.lower(): value for name, value in headers.items()}.get("range")
        self.requests.append((url, wanted))
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parts.query)
        if query.get("list-type") == ["2"]:
            return self._listing(
                query.get("prefix", [""])[0],
                query.get("continuation-token", [""])[0],
            )
        path = urllib.parse.unquote(parts.path)
        found = [k for k in (*self.objects, *self.fail) if path.endswith("/" + k)]
        if not found:
            return _error(404, "NoSuchKey")
        key = max(found, key=len)
        if key in self.fail:
            return self.fail[key]
        data = self.objects[key]
        match = _RANGE.fullmatch(wanted or "")
        if match is None:
            return Response(200, {"content-length": str(len(data))}, data)
        first, last = int(match[1]), min(int(match[2]), len(data) - 1)
        if first > last:
            return _error(416, "InvalidRange")
        return Response(
            206,
            {
                "content-length": str(last - first + 1),
                "content-range": f"bytes {first}-{last}/{len(data)}",
            },
            data[first : last + 1],
        )

    def _listing(self, prefix: str, token: str) -> Response:
        # A token is shaped like S3's base64 ones: it must be URL-encoded.
        start = 0
        if token:
            if not re.fullmatch(r"\d+\+/=", token):
                return _error(400, "InvalidArgument")
            start = int(token[:-3])
        keys = sorted(k for k in self.objects if k.startswith(prefix))
        page = keys[start : start + self.page_size]
        truncated = start + self.page_size < len(keys)
        contents = "".join(
            f"<Contents><Key>{escape(k)}</Key>"
            "<LastModified>2026-10-21T01:30:00.000Z</LastModified>"
            "<ETag>&quot;0&quot;</ETag>"
            f"<Size>{len(self.objects[k])}</Size>"
            "<StorageClass>STANDARD</StorageClass></Contents>"
            for k in page
        )
        following = ""
        if truncated:
            token = f"{start + self.page_size}+/="
            following = f"<NextContinuationToken>{token}</NextContinuationToken>"
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Name>openintel-public</Name><Prefix>{escape(prefix)}</Prefix>"
            f"<KeyCount>{len(page)}</KeyCount><MaxKeys>{self.page_size}</MaxKeys>"
            f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
            f"{contents}{following}</ListBucketResult>"
        )
        return Response(200, {"content-type": "application/xml"}, body.encode())


def _error(status: int, code: str) -> Response:
    body = f"<Error><Code>{code}</Code></Error>".encode()
    return Response(status, {"content-type": "application/xml"}, body)
