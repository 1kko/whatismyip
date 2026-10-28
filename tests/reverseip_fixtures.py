"""Synthetic OpenINTEL Parquet files for the reverse IP tests: plain helpers
and constants, no pytest fixtures."""

import calendar
from typing import NamedTuple

import pyarrow as pa
import pyarrow.parquet as pq

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
    group, gzip-compressed. `pad_columns` adds string columns of its own."""
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
        arrays[f"pad{i}"] = pa.array(["x" * 32] * len(rows), type=pa.string())
    pq.write_table(
        pa.table(arrays),
        str(path),
        compression="gzip",
        row_group_size=max(len(rows), 1),
    )
