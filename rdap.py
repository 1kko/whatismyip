"""RDAP lookups with a python-whois fallback, normalised to one shape.

RDAP (RFC 9082/9083) is the IETF successor to port-43 WHOIS: a single HTTPS GET
that returns structured JSON instead of free-form text. It is faster (usually
<1s vs the ~11s some registrars take on port 43) and needs no fragile text
parsing. Coverage is not total though — most gTLDs publish an RDAP endpoint in
the IANA bootstrap registry, but many ccTLDs (.kr among them) do not, so those
still go through python-whois.

Both sources are normalised into one canonical dict so the API and the template
never have to care which one answered:

    {
        "source": "rdap" | "whois",
        "name": str,                 # domain name, or the network's RIR name
        "handle": str | None,        # registry handle
        "registrar": str | None,     # domains only
        "registrant": str | None,    # org / holder (often REDACTED under GDPR)
        "abuse_email": str | None,
        "status": [str],
        "name_servers": [str],       # domains only
        "created": datetime | None,
        "updated": datetime | None,
        "expires": datetime | None,  # domains only
        "dnssec": bool | str | None,
        "country": str | None,       # IP allocations
        "network": str | None,       # IP: the allocated CIDR/range
        "assignment_type": str | None,  # IP: e.g. "direct allocation"
        "parent_handle": str | None,    # IP: handle of the enclosing block
        "rir": str | None,
        "whois_server": str | None,
        "url": str | None,
    }

datetimes are left as datetime objects on purpose: FastAPI's jsonable_encoder
serialises them to ISO-8601 for the JSON API, and viewmodel.whois_display()
formats them for the browser table. On total failure the dict is {"error": ...}.

The python-whois fallback is for domains only. Given an IP, python-whois
resolves its PTR record and looks up the registration of that hostname's
domain, so it would present the ISP's domain record as the address allocation;
an IP whose RIR does not answer gets RIR_RDAP_UNAVAILABLE instead.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import whoisit

from config import (
    RDAP_BREAKER_COOLDOWN_SECONDS,
    RDAP_BREAKER_FAILURES,
    RDAP_HTTP_RETRIES,
    RDAP_HTTP_TIMEOUT_SECONDS,
)

# whoisit.bootstrap() mutates module-level state; guard it so concurrent lookups
# running in the thread pool cannot race the first bootstrap against each other.
_bootstrap_lock = threading.Lock()


def _configure_whoisit() -> None:
    """Bound every whoisit request before the first one is made.

    The caller's asyncio.wait_for cannot cancel the worker thread, so this is
    what actually limits how long an RDAP thread lives. whoisit reads
    http_timeout on every request, but bakes http_max_retries into the
    requests.Session it builds on first use, so any session built before this
    ran is dropped and the next query gets one with these settings.
    """
    whoisit.utils.http_timeout = RDAP_HTTP_TIMEOUT_SECONDS
    whoisit.utils.http_max_retries = RDAP_HTTP_RETRIES
    whoisit.clear_session()


_configure_whoisit()

# An authoritative "this name has no registration" is a successful lookup with a
# negative answer, not a failure. It travels in `error` so consumers that only
# ask "is there registration data?" keep working unchanged, but anything that
# reports the outcome to a person or a model compares against this sentinel
# instead, because the two read very differently: a subdomain like
# docs.github.com is not registered and never will be, while a timeout means we
# simply do not know.
NOT_REGISTERED = "not registered"

# An IP whose RIR could not be asked (timeout, server error, breaker open). It
# is a failure, rendered like any other WHOIS error, and never an empty record.
RIR_RDAP_UNAVAILABLE = "RIR RDAP temporarily unavailable"

# Fields we surface, in the order the template renders them. Anything empty is
# dropped by whois_display(), so IP results simply omit the domain-only rows.
CANONICAL_FIELDS = (
    "source",
    "name",
    "handle",
    "registrar",
    "registrant",
    "abuse_email",
    "status",
    "name_servers",
    "created",
    "updated",
    "expires",
    "dnssec",
    "country",
    "network",
    "assignment_type",
    "parent_handle",
    "rir",
    "whois_server",
    "url",
)


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def bootstrap_rdap(force: bool = False) -> bool:
    """Load (or refresh) the IANA bootstrap registry whoisit uses to map a TLD
    or IP block to its authoritative RDAP server. Idempotent and thread-safe;
    returns True when the registry is ready, False if it could not be fetched
    (callers then fall back to WHOIS)."""
    with _bootstrap_lock:
        try:
            if force or not whoisit.is_bootstrapped():
                whoisit.bootstrap()
            return whoisit.is_bootstrapped()
        except Exception:
            logging.warning("RDAP bootstrap failed; WHOIS fallback stays in use")
            return False


def refresh_rdap_bootstrap() -> None:
    """Scheduler hook: re-fetch the registry only when it has gone stale."""
    try:
        if not whoisit.is_bootstrapped() or whoisit.bootstrap_is_older_than(7):
            bootstrap_rdap(force=True)
    except Exception:
        logging.warning("RDAP bootstrap refresh failed; keeping the cached registry")


def _entity_name(entities: dict | None, role: str) -> str | None:
    for item in (entities or {}).get(role) or []:
        name = item.get("name")
        if name:
            return name
    return None


def _entity_email(entities: dict | None, role: str) -> str | None:
    for item in (entities or {}).get(role) or []:
        email = item.get("email")
        if email:
            return email
    return None


def _normalize_rdap_domain(raw: dict, target: str) -> dict:
    entities = raw.get("entities") or {}
    return {
        "source": "rdap",
        "name": raw.get("name") or target,
        "handle": raw.get("handle"),
        "registrar": _entity_name(entities, "registrar"),
        "registrant": _entity_name(entities, "registrant"),
        "abuse_email": _entity_email(entities, "abuse"),
        "status": list(raw.get("status") or []),
        "name_servers": list(raw.get("nameservers") or []),
        "created": raw.get("registration_date"),
        "updated": raw.get("last_changed_date"),
        "expires": raw.get("expiration_date"),
        "dnssec": raw.get("dnssec"),
        "whois_server": raw.get("whois_server"),
        "url": raw.get("url"),
    }


def _normalize_rdap_ip(raw: dict, target: str) -> dict:
    entities = raw.get("entities") or {}
    network = raw.get("network")
    return {
        "source": "rdap",
        "name": raw.get("name") or target,
        "handle": raw.get("handle"),
        "registrant": _entity_name(entities, "registrant"),
        "abuse_email": _entity_email(entities, "abuse"),
        "status": list(raw.get("status") or []),
        "created": raw.get("registration_date"),
        "updated": raw.get("last_changed_date"),
        "country": raw.get("country") or None,
        "network": str(network) if network else None,
        # whoisit's clean() hands back "" for an absent field; None keeps the
        # empty case the same as every other canonical field.
        "assignment_type": raw.get("assignment_type") or None,
        "parent_handle": raw.get("parent_handle") or None,
        "rir": raw.get("rir"),
        "whois_server": raw.get("whois_server"),
        "url": raw.get("url"),
    }


class CircuitBreaker:
    """Per-host breaker for RDAP servers.

    When a registry stops answering, every lookup routed to it used to wait out
    the whole RDAP budget and leave a thread behind. After `threshold`
    consecutive failures the host is open for `cooldown` seconds and lookups
    to it fail at once. When the window ends one caller is let through as a
    probe while the rest still fail fast: an answer closes the breaker, a
    failure opens it for another window.

    Lookups run in worker threads, so all state sits behind one lock. `clock`
    is injectable so tests can cross a cooldown without sleeping through it.
    """

    def __init__(
        self,
        threshold: int,
        cooldown: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.threshold = max(threshold, 1)
        self.cooldown = cooldown
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, float] = {}

    def allow(self, host: str) -> bool:
        with self._lock:
            until = self._open_until.get(host)
            if until is None:
                return True
            now = self._clock()
            if now < until:
                return False
            # Re-arm before letting this caller through, so it is the only
            # probe until it reports back.
            self._open_until[host] = now + self.cooldown
            return True

    def record_success(self, host: str) -> None:
        with self._lock:
            self._failures.pop(host, None)
            was_open = self._open_until.pop(host, None) is not None
        if was_open:
            logging.info("RDAP server %s is answering again", host)

    def record_failure(self, host: str) -> None:
        with self._lock:
            count = self._failures.get(host, 0) + 1
            self._failures[host] = count
            if count < self.threshold:
                return
            self._open_until[host] = self._clock() + self.cooldown
        logging.warning(
            "RDAP server %s failed %d times in a row; skipping it for %ds",
            host,
            count,
            self.cooldown,
        )


rdap_breaker = CircuitBreaker(RDAP_BREAKER_FAILURES, RDAP_BREAKER_COOLDOWN_SECONDS)


def _rdap_host(target: str, query_type: str) -> str:
    """The RDAP server whoisit will send `target` to. build_query is the public
    half of whoisit.ip()/domain(): the same bootstrap lookup they start with,
    minus the request, so the breaker keys on the server actually asked."""
    _, url, _ = whoisit.build_query(query_type=query_type, query_value=target)
    return urlsplit(url).hostname or url


def _is_server_failure(exc: Exception) -> bool:
    """Whether an RDAP error says the server is unwell, rather than that it
    answered something we did not want (404, 403, a record whoisit could not
    parse)."""
    if not isinstance(exc, whoisit.errors.QueryError):
        return False
    # whoisit wraps every transport error (timeout, refused, TLS, DNS) in a
    # QueryError with no status code.
    code = exc.status_code or 0
    return code == 0 or code == 429 or code >= 500


def lookup_rdap(target: str) -> dict | None:
    """Query RDAP for a domain or IP and return the canonical dict, or None when
    RDAP cannot answer (unsupported TLD, query error, bootstrap unavailable, or
    the server's breaker is open). The caller then falls back to WHOIS for a
    domain and reports RIR_RDAP_UNAVAILABLE for an IP."""
    if not bootstrap_rdap():
        return None
    ip_target = is_ip(target)
    try:
        host = _rdap_host(target, "ip" if ip_target else "domain")
    except whoisit.errors.UnsupportedError:
        # TLD/allocation has no RDAP endpoint — expected for many ccTLDs.
        return None
    except Exception:
        logging.info("RDAP has no server for %s", target)
        return None
    if not rdap_breaker.allow(host):
        logging.info("RDAP server %s is cooling down; not asking it", host)
        return None
    try:
        if ip_target:
            result = _normalize_rdap_ip(whoisit.ip(target), target)
        else:
            result = _normalize_rdap_domain(whoisit.domain(target), target)
    except whoisit.errors.ResourceDoesNotExist:
        # RDAP authoritatively says the name/allocation is unregistered; do not
        # waste a WHOIS round-trip re-confirming it.
        rdap_breaker.record_success(host)
        return {"error": NOT_REGISTERED}
    except Exception as exc:
        if _is_server_failure(exc):
            rdap_breaker.record_failure(host)
        else:
            rdap_breaker.record_success(host)
        logging.info("RDAP lookup failed for %s: %s", target, exc)
        return None
    rdap_breaker.record_success(host)
    return result


def _first(value: Any) -> Any:
    """python-whois returns several fields (dates especially) as lists."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        # De-duplicate while preserving order; registrars often repeat statuses.
        seen, out = set(), []
        for item in value:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out
    return [value]


def normalize_whois(raw: dict | None, target: str) -> dict:
    """Fold a python-whois record into the same canonical shape as RDAP so the
    fallback path is indistinguishable to the API and the template."""
    if not raw or (isinstance(raw, dict) and raw.get("error")):
        return raw or {"error": "WHOIS lookup failed"}
    return {
        "source": "whois",
        "name": _first(raw.get("domain_name")) or target,
        "registrar": _first(raw.get("registrar")),
        "registrant": _first(raw.get("org")) or _first(raw.get("name")),
        "abuse_email": _first(raw.get("emails")),
        "status": _as_list(raw.get("status")),
        "name_servers": [str(ns).lower() for ns in _as_list(raw.get("name_servers"))],
        "created": _first(raw.get("creation_date")),
        "updated": _first(raw.get("updated_date")),
        "expires": _first(raw.get("expiration_date")),
        "dnssec": _first(raw.get("dnssec")),
        "country": _first(raw.get("country")),
        "whois_server": _first(raw.get("whois_server")),
    }
