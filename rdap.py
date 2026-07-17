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
        "rir": str | None,
        "whois_server": str | None,
        "url": str | None,
    }

datetimes are left as datetime objects on purpose: orjson serialises them to
ISO-8601 natively for the JSON API, and viewmodel.whois_display() formats them
for the browser table. On total failure the dict is just {"error": "..."}.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from typing import Any

import whoisit

# whoisit.bootstrap() mutates module-level state; guard it so concurrent lookups
# running in the thread pool cannot race the first bootstrap against each other.
_bootstrap_lock = threading.Lock()

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
        "rir": raw.get("rir"),
        "whois_server": raw.get("whois_server"),
        "url": raw.get("url"),
    }


def lookup_rdap(target: str) -> dict | None:
    """Query RDAP for a domain or IP and return the canonical dict, or None when
    RDAP cannot answer (unsupported TLD, query error, or bootstrap unavailable) —
    the caller then falls back to WHOIS."""
    if not bootstrap_rdap():
        return None
    try:
        if is_ip(target):
            return _normalize_rdap_ip(whoisit.ip(target), target)
        return _normalize_rdap_domain(whoisit.domain(target), target)
    except whoisit.errors.UnsupportedError:
        # TLD/allocation has no RDAP endpoint — expected for many ccTLDs.
        return None
    except whoisit.errors.ResourceDoesNotExist:
        # RDAP authoritatively says the name/allocation is unregistered; do not
        # waste a WHOIS round-trip re-confirming it.
        return {"error": "not registered"}
    except Exception:
        logging.info("RDAP lookup failed for %s; trying WHOIS", target)
        return None


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
