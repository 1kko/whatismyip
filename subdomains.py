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
import collections
import datetime
import json
import logging
import re
import time
import urllib.parse
import urllib.request

from config import (
    SUBDOMAIN_CACHE_TTL,
    SUBDOMAIN_ERROR_TTL,
    SUBDOMAIN_FETCH_PER_MINUTE,
    SUBDOMAIN_MAX_CONCURRENT,
    SUBDOMAIN_MAX_NAMES,
    SUBDOMAIN_SOURCE_URL,
    SUBDOMAIN_TIMEOUT_SECONDS,
    SUBDOMAIN_USER_AGENT,
)
from subdomain_store import SubdomainStore

SOURCE = "crt.sh"

# Underscores are deliberately allowed: _dmarc and _acme-challenge are real DNS
# labels. Anything outside this set is either an encoding artefact or not a
# hostname at all.
_ALLOWED = re.compile(r"^[a-z0-9._-]+$")


class SubdomainError(Exception):
    """The source could not answer. Never returned to a caller as an empty list:
    "no subdomains" and "we could not ask" are different facts."""


class SubdomainBudgetError(SubdomainError):
    """The global outbound budget refused this fetch before one was attempted.

    This is our own back-pressure, not a source failure, so it must never be
    recorded into _failures: doing so would durably blacklist a cold domain
    for SUBDOMAIN_ERROR_TTL (5 minutes) purely because the shared 30/min
    budget happened to be spent at that moment -- long after it refills. The
    caller still sees a "busy, try again" style error; only the durable
    negative-cache write is skipped.
    """


def _sanitize_log(value: str) -> str:
    """Strip control characters before logging a caller-supplied domain.

    Duplicated from lookup.sanitize_log_input rather than imported: this
    module must not import `lookup` (see the module docstring) -- doing so
    would construct GeoIpManager(), TldNamesManager() and DomainManager() at
    module scope and pull the GeoIP database into every test that touches
    subdomain code.
    """
    return value.replace("\n", "").replace("\r", "").replace("\x00", "")


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
        # Some exceptions carry no message (bare TimeoutError() from a stdlib
        # timeout has an empty str()) — fall back to the class name so a
        # caller checking `error` for truthiness never sees an empty string.
        raise SubdomainError(str(exc) or type(exc).__name__) from exc
    return normalize_names(extract_names(payload), domain)


class _MinuteBudget:
    """At most `limit` outbound fetches per rolling minute, across every surface.

    The concurrency semaphore caps simultaneous connections but not total
    volume, and the MCP tool makes fan-out cheap: an agent sweeping domains
    inside the 120/min MCP bucket would otherwise drive that many crt.sh
    fetches. Event-loop only, so it needs no lock.
    """

    def __init__(self, limit: int):
        self._limit = limit
        self._hits: collections.deque[float] = collections.deque()

    def take(self) -> bool:
        now = time.monotonic()
        while self._hits and now - self._hits[0] > 60:
            self._hits.popleft()
        if len(self._hits) >= self._limit:
            return False
        self._hits.append(now)
        return True


_store = SubdomainStore()
_semaphore = asyncio.Semaphore(SUBDOMAIN_MAX_CONCURRENT)
_budget = _MinuteBudget(SUBDOMAIN_FETCH_PER_MINUTE)
# Keyed on the domain alone, so a page request and an MCP call for the same cold
# domain share one outbound fetch.
_inflight: dict[str, asyncio.Future] = {}
# Background refreshes are held here until they finish: without a strong
# reference the event loop may collect a task mid-flight.
_background: set[asyncio.Task] = set()
# Failures live here, never in SQLite — a transient outage must not become a
# durable empty answer.
_failures: dict[str, float] = {}


def reset_state(store_path: str | None = None) -> None:
    """Rebuild module state. Tests only."""
    global _store, _budget, _semaphore, _inflight, _background, _failures
    # Request cancellation and drop the references: a background task left
    # over from a previous event loop (a previous test) is bound to a future
    # tied to that closed loop, and a later drain_background() on it raises
    # "attached to a different loop" in a test that never touched it. That
    # same leftover task's loop may already be closed by the time this runs,
    # and Task.cancel() on a closed loop raises RuntimeError from deep inside
    # asyncio's callback scheduling — skip and swallow rather than let
    # cleanup abort the reset itself, which must complete regardless.
    for task in _background:
        if task.get_loop().is_closed():
            continue
        try:
            task.cancel()
        except RuntimeError:
            pass
    _store.close()
    _store = SubdomainStore(path=store_path) if store_path else SubdomainStore()
    _budget = _MinuteBudget(SUBDOMAIN_FETCH_PER_MINUTE)
    _semaphore = asyncio.Semaphore(SUBDOMAIN_MAX_CONCURRENT)
    _inflight = {}
    _background = set()
    _failures = {}


async def drain_background() -> None:
    """Await outstanding background refreshes. Tests only."""
    while _background:
        await asyncio.gather(*list(_background), return_exceptions=True)


def _record_failure(domain: str) -> None:
    """Record a failure for `domain` and sweep out stale ones.

    Nothing else prunes _failures, and reset_state() is test-only, so
    without this a domain that ever fails leaves a permanent entry for the
    life of the process. Sweeping on every write costs nothing extra: writes
    are already capped by _budget, and this is the only path that adds
    entries, so the one just added is never the one removed. No scheduler
    job, matching the rest of this feature.
    """
    now = time.time()
    _failures[domain] = now
    for stale_domain, failed_at in list(_failures.items()):
        if now - failed_at >= SUBDOMAIN_ERROR_TTL:
            del _failures[stale_domain]


def _result(
    names: list[str],
    count: int,
    truncated: bool,
    fetched_at: float | None,
    stale: bool,
    error: str | None,
) -> dict:
    return {
        "names": names,
        "count": count,
        "truncated": truncated,
        "source": SOURCE,
        "fetched_at": (
            datetime.datetime.fromtimestamp(
                fetched_at, tz=datetime.timezone.utc
            ).isoformat()
            if fetched_at
            else None
        ),
        "stale": stale,
        "error": error,
    }


async def _fetch_and_store(domain: str) -> tuple[list[str], int]:
    """One budgeted, single-flighted fetch that writes through to the store."""
    existing = _inflight.get(domain)
    if existing is not None:
        # Shielded: a waiter's own task lives on `existing` as its
        # _fut_waiter while it awaits, so an unshielded await lets
        # Task.cancel() on ONE waiter cancel the future the owner and every
        # other waiter depend on. shield() gives this waiter a future of its
        # own to be cancelled instead, leaving `existing` untouched.
        return await asyncio.shield(existing)

    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    _inflight[domain] = future
    try:
        if not _budget.take():
            raise SubdomainBudgetError(
                "source request budget exhausted; try again shortly"
            )
        async with _semaphore:
            names, count = await fetch_from_source(domain)
        await asyncio.to_thread(
            _store.put, domain, names, count, count > len(names), SOURCE
        )
        if not future.done():
            future.set_result((names, count))
        return names, count
    except BaseException as exc:
        if not future.done():
            if isinstance(exc, asyncio.CancelledError):
                # A cancelled owner must not publish CancelledError onto the
                # shared future: every waiter riding it would then surface as
                # a cancelled task instead of a normal error result. The
                # owner's own cancellation still propagates via `raise` below.
                future.set_exception(SubdomainError("upstream request was cancelled"))
            else:
                future.set_exception(exc)
        raise
    finally:
        _inflight.pop(domain, None)
        # Retrieve the exception so a future nobody else awaited does not log
        # "exception was never retrieved" when it is collected. Guarded on
        # cancelled(): .exception() re-raises CancelledError on a cancelled
        # future, which would replace the real error with a spurious one.
        if future.done() and not future.cancelled():
            future.exception()


def _schedule_refresh(domain: str) -> None:
    async def run():
        try:
            await _fetch_and_store(domain)
        except SubdomainBudgetError as exc:
            # Our own back-pressure, not a source failure -- must not be
            # recorded into _failures. See SubdomainBudgetError.
            logging.info(
                "Subdomain refresh skipped for %s: %s", _sanitize_log(domain), exc
            )
        except SubdomainError as exc:
            # The stale entry stays exactly where it is. A bad refresh must
            # never destroy a good answer. Recorded in _failures too — a
            # domain whose refresh keeps failing must not get a fresh
            # background refresh (and a fresh budget slot) scheduled on every
            # subsequent stale read; one broken popular domain would
            # otherwise starve every other domain's budget.
            _record_failure(domain)
            logging.info(
                "Subdomain refresh failed for %s: %s", _sanitize_log(domain), exc
            )
        except Exception:
            _record_failure(domain)
            logging.exception("Subdomain refresh crashed for %s", _sanitize_log(domain))

    task = asyncio.create_task(run())
    _background.add(task)
    task.add_done_callback(_background.discard)


async def get_subdomains(domain: str) -> dict:
    """Subdomains of `domain`, from the store when possible.

    Stale-while-revalidate on read, with no scheduler job. GeoIP and the public
    suffix list are refreshed ahead of time because every request reads them;
    this store is filled and read on demand, so a periodic sweep would spend
    crt.sh's capacity re-fetching domains nobody asked about again.
    """
    domain = domain.strip().lower().rstrip(".")
    entry = await asyncio.to_thread(_store.get, domain)

    if entry is not None:
        stale = entry.age() > SUBDOMAIN_CACHE_TTL
        if stale:
            failed_at = _failures.get(domain)
            if not failed_at or time.time() - failed_at >= SUBDOMAIN_ERROR_TTL:
                _schedule_refresh(domain)
            # Either way, the stale entry below is still served immediately —
            # a recent refresh failure changes only whether a NEW refresh is
            # scheduled, never whether the caller gets an answer now.
        return _result(
            entry.names, entry.count, entry.truncated, entry.fetched_at, stale, None
        )

    # A refresh failure recorded above can, narrowly, also gate this cold
    # path: if the domain's store row is evicted by SubdomainStore.prune()
    # (LRU by fetched_at) between a failed refresh and the next lookup, the
    # domain lands here and gets "lookup failed recently" with no fetch
    # attempted, for up to SUBDOMAIN_ERROR_TTL. That window is bounded and
    # acceptable, not a scheduler-visible incident — written down here so it
    # doesn't read as a bug later.
    failed_at = _failures.get(domain)
    if failed_at and time.time() - failed_at < SUBDOMAIN_ERROR_TTL:
        return _result([], 0, False, None, False, "lookup failed recently")

    try:
        names, count = await _fetch_and_store(domain)
    except SubdomainBudgetError as exc:
        # Our own back-pressure, not a source failure -- must not be
        # recorded into _failures. See SubdomainBudgetError.
        return _result([], 0, False, None, False, str(exc))
    except SubdomainError as exc:
        _record_failure(domain)
        return _result([], 0, False, None, False, str(exc))
    except Exception:
        logging.exception("Subdomain lookup crashed for %s", _sanitize_log(domain))
        _record_failure(domain)
        return _result([], 0, False, None, False, "lookup failed")

    return _result(names, count, count > len(names), time.time(), False, None)
