"""Subdomain discovery from Certificate Transparency.

Opt-in per request. The default lookup path never reaches this module, which is
what keeps crt.sh's unpredictable latency — measured at 2.6s and then 13.5s for
the same query within one hour — out of a page view.

Deduplication happens here, once, at ingest: crt.sh publishes no bulk dump, its
Postgres endpoint times out on every query form (21-57s), and its HTTP endpoint
offers no server-side dedup (`&deduplicate=Y` hangs; `&exclude=expired` is
slower for a 23% size reduction). One crt.sh response is mostly redundant —
1,224 rows reduce to 58 names for 1kko.com.

This module must not import `lookup` or `main`. Importing `lookup` executes
GeoIpManager(), TldNamesManager() and DomainManager() at module scope, which
would load the GeoIP database into every test run that touches a subdomain.
"""

import asyncio
import json
import re
import urllib.parse
import urllib.request

from config import (
    SUBDOMAIN_MAX_NAMES,
    SUBDOMAIN_SOURCE_URL,
    SUBDOMAIN_TIMEOUT_SECONDS,
    SUBDOMAIN_USER_AGENT,
)

SOURCE = "crt.sh"

# Underscores are deliberately allowed: _dmarc and _acme-challenge are real DNS
# labels. Anything outside this set is either an encoding artefact or not a
# hostname at all.
_ALLOWED = re.compile(r"^[a-z0-9._-]+$")


class SubdomainError(Exception):
    """The source could not answer. Never returned to a caller as an empty list:
    "no subdomains" and "we could not ask" are different facts."""


def extract_names(payload: object) -> list[str]:
    """Pull every candidate name out of a crt.sh JSON body.

    Defensive about the payload's shape. crt.sh answers with an error object
    rather than a list when it is loaded, and iterating a dict yields its keys —
    strings, which have no .get — so a third-party hiccup would otherwise raise
    AttributeError inside a request.
    """
    if not isinstance(payload, list):
        return []
    names: list[str] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        value = row.get("name_value")
        if isinstance(value, str):
            names.extend(value.split("\n"))
        common = row.get("common_name")
        if isinstance(common, str):
            names.append(common)
    return names


def normalize_names(
    raw: list[str], domain: str, cap: int = SUBDOMAIN_MAX_NAMES
) -> tuple[list[str], int]:
    """Reduce raw CT names to the sorted, deduplicated subdomains of `domain`.

    Returns (names capped at `cap`, true total before capping). The caller needs
    both: a capped list alone cannot be told apart from a short one.
    """
    suffix = "." + domain.lower()
    out: set[str] = set()
    for value in raw:
        name = value.strip().lower().rstrip(".")
        if not name:
            continue
        # rfc822Name SAN entries from S/MIME certificates — real people's email
        # addresses. Checked before anything else so no later rule can rescue
        # one by rewriting it. 551 of these appear in nasa.gov's CT data.
        if "@" in name:
            continue
        if name.startswith("*."):
            name = name[2:]
        # The apex is not a subdomain, and the page already shows it. A wildcard
        # folds onto it by the line above, which is why this follows.
        if name == domain.lower():
            continue
        # endswith the dotted suffix, so "notexample.com" does not pass for a
        # subdomain of "example.com".
        if not name.endswith(suffix):
            continue
        if not _ALLOWED.match(name):
            continue
        out.add(name)
    names = sorted(out)
    return names[:cap], len(names)


def _fetch_sync(domain: str) -> object:
    url = SUBDOMAIN_SOURCE_URL.format(domain=urllib.parse.quote(domain, safe=""))
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": SUBDOMAIN_USER_AGENT}
    )
    # S310: the URL is built from a configured template with the domain
    # percent-encoded into it; the scheme is not caller-controlled.
    with urllib.request.urlopen(  # noqa: S310
        request, timeout=SUBDOMAIN_TIMEOUT_SECONDS
    ) as response:
        return json.load(response)


async def fetch_from_source(domain: str) -> tuple[list[str], int]:
    """One crt.sh round trip, normalized. Raises SubdomainError on any failure.

    urllib blocks, so it runs in a thread — the same shape lookup.py uses for
    RDAP and WHOIS. A 200 carrying an error object is not a failure: it is a
    successful exchange that contained nothing, and extract_names says so.
    """
    try:
        payload = await asyncio.to_thread(_fetch_sync, domain)
    except Exception as exc:
        raise SubdomainError(str(exc)) from exc
    return normalize_names(extract_names(payload), domain)
