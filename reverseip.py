"""Reverse IP from OpenINTEL's top-list DNS measurements: the source table and
the licence lines that go wherever its data does.

Imports `config` and the standard library only. It must not import `lookup`
or `main`, for `subdomains.py`'s reason, and never `pyarrow`, which only the
build step loads."""

import re
from collections.abc import Sequence
from dataclasses import dataclass

import config

DATABASE_NAME = "reverseip.sqlite3"
SCHEMA_VERSION = 1
COPIES_NAME = "copies.json"

_LABELS = {
    "tranco": "Tranco",
    "umbrella": "Cisco Umbrella",
    "radar": "Cloudflare Radar",
    "majestic": "Majestic Million",
}
_CRUX = "crux"
_COUNTRY = re.compile(r"[a-z]{2}")


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    # The bucket path segment: `source=tranco` or `source=crux/country-code=kr`.
    path: str


def _source(source_id: str) -> Source:
    if source_id in _LABELS:
        return Source(source_id, _LABELS[source_id], f"source={source_id}")
    if source_id.startswith(f"{_CRUX}:"):
        scope = source_id.split(":", 1)[1]
        if scope == "global":
            return Source(source_id, "Chrome UX Report (global)", "source=crux")
        if _COUNTRY.fullmatch(scope):
            return Source(
                source_id,
                f"Chrome UX Report ({scope.upper()})",
                f"source=crux/country-code={scope}",
            )
    raise ValueError(f"unknown reverse IP source: {source_id!r}")


def parse_sources(text: str) -> tuple[Source, ...]:
    """The comma-separated ids of REVERSEIP_SOURCES, in the order given."""
    return tuple(_source(part.strip()) for part in text.split(",") if part.strip())


def file_stem(source_id: str) -> str:
    return source_id.replace(":", "-")


def coverage_sentence(sources: Sequence[Source]) -> str:
    """What the answer covers: only the names on these lists. The CrUX entries
    collapse into one name, at the position of the first."""
    names: list[str] = []
    crux: list[str] = []
    for source in sources:
        if source.id.startswith(f"{_CRUX}:"):
            scope = source.id.split(":", 1)[1]
            if not crux:
                names.append("")
            crux.append("global" if scope == "global" else scope.upper())
        else:
            names.append(source.label)
    if crux:
        names[names.index("")] = f"Chrome UX Report ({', '.join(crux)})"
    if len(names) > 1:
        listed = f"{', '.join(names[:-1])} and {names[-1]}"
    else:
        listed = "".join(names)
    return f"Names on the {listed} top {'lists' if len(names) > 1 else 'list'} only."


def licence_lines(sources: Sequence[Source] | None = None) -> dict:
    """The lines every surface that shows OpenINTEL data carries. Coverage
    names the lists actually read: the given sources, else the configured."""
    if sources is None:
        sources = parse_sources(config.REVERSEIP_SOURCES)
    return {
        "coverage": coverage_sentence(sources),
        "license": config.OPENINTEL_LICENSE,
        "license_url": config.OPENINTEL_LICENSE_URL,
        "terms_url": config.REVERSEIP_TERMS_URL,
        "attribution": config.OPENINTEL_ATTRIBUTION,
    }
