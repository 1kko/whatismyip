"""Lookup orchestration shared by the HTTP routes and the MCP tools.

Everything here is transport-agnostic: no FastAPI, no Request, no rendering.
`gather()` is the whole pipeline for one target — DNS, reverse DNS, GeoIP,
registration data, and TLS — with the independent legs run concurrently.

This module must not import `main` or `mcp_server`; both import it.
"""

import asyncio
import ipaddress
import logging
import re
import time
from typing import Any

import dns.resolver
import whois

from config import (
    RDAP_TIMEOUT_SECONDS,
    WHOIS_CACHE_ERROR_TTL,
    WHOIS_CACHE_TTL,
    WHOIS_TIMEOUT_SECONDS,
)
from managers import DomainManager, GeoIpManager, SSLManager, TldNamesManager
from rdap import lookup_rdap, normalize_whois


class PrivateAddressError(Exception):
    """The target is (or resolves to) a private/reserved address.

    Raised instead of HTTPException so this module stays free of FastAPI:
    main.py turns it into a 400, mcp_server.py turns it into {"error": ...}.
    """


class TTLCache:
    """Tiny time-bounded cache. Read/written only from the event-loop thread, so
    it needs no lock; eviction is FIFO once it reaches maxsize."""

    def __init__(self, maxsize: int = 1024):
        self._data: dict[str, tuple[float, Any]] = {}
        self._maxsize = maxsize

    def get(self, key: str) -> Any:
        item = self._data.get(key)
        if not item:
            return None
        expires_at, value = item
        if expires_at < time.time():
            self._data.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl: float) -> None:
        if key not in self._data and len(self._data) >= self._maxsize:
            self._data.pop(next(iter(self._data)), None)
        self._data[key] = (time.time() + ttl, value)

    def clear(self) -> None:
        self._data.clear()


_whois_cache = TTLCache()


def sanitize_log_input(value: str) -> str:
    """Remove control characters from log inputs to prevent log injection."""
    return value.replace("\n", "").replace("\r", "").replace("\x00", "")


def normalize_lookup_target(raw: str) -> str:
    """Reduce a pasted URL to the bare host or IP the pipeline can resolve.

    Mirrors static/js/app.js normalizeLookupTarget so a URL typed into the search
    box and one sent straight to the API behave the same: drop the scheme and
    everything from the first '/', '?' or '#' onwards. Without this, is_valid_domain
    (which parses URLs via get_tld) would accept "https://host/path" but the raw
    string would then be handed to DNS/WHOIS/SSL, which cannot resolve it.
    """
    target = (raw or "").strip()
    target = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", target)
    return re.split(r"[/?#]", target, maxsplit=1)[0]


def is_safe_ip(ip_str: str) -> bool:
    """Check if an IP address is safe to query (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        )
    except ValueError:
        return False


geo_ip_manager = GeoIpManager()
# Before DomainManager: it repoints `tld` at the data volume and seeds the
# suffix list there, and is_valid_domain would otherwise read whatever copy the
# first get_tld call happened to find.
tld_names_manager = TldNamesManager()
domain_manager = DomainManager()


async def _whois_fallback(target: str) -> dict:
    """Port-43 WHOIS, normalised into the same shape RDAP produces. Used only for
    the TLDs RDAP does not cover, or when the RDAP server is unreachable."""
    try:
        raw = await asyncio.wait_for(
            asyncio.to_thread(whois.whois, target, quiet=True),
            timeout=WHOIS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        # wait_for cannot cancel the worker thread, so the underlying whois call
        # keeps running and is discarded; the response no longer waits on it.
        logging.warning("WHOIS lookup timed out for %s", sanitize_log_input(target))
        return {"error": "WHOIS lookup timed out"}
    except Exception:
        logging.exception("WHOIS lookup failed for %s", sanitize_log_input(target))
        return {"error": "WHOIS lookup failed"}
    return normalize_whois(raw, target)


async def lookup_whois(target: str) -> dict:
    """Registration data for a domain or IP. RDAP first (fast, structured JSON),
    falling back to port-43 WHOIS for TLDs RDAP does not serve. Both sources are
    normalised to one shape (see rdap.py) and cached under the same key."""
    key = (target or "").strip().lower()
    cached = _whois_cache.get(key)
    if cached is not None:
        return cached

    result = None
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(lookup_rdap, target),
            timeout=RDAP_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logging.info("RDAP timed out for %s; trying WHOIS", sanitize_log_input(target))
    except Exception:
        safe = sanitize_log_input(target)
        logging.exception("RDAP errored for %s; trying WHOIS", safe)

    # lookup_rdap returns None when RDAP cannot answer (unsupported TLD, query
    # error) — only then do we pay for the slow port-43 round-trip.
    if result is None:
        result = await _whois_fallback(target)
    if not result:
        result = {"error": "WHOIS lookup failed"}

    failed = isinstance(result, dict) and result.get("error")
    _whois_cache.set(key, result, WHOIS_CACHE_ERROR_TTL if failed else WHOIS_CACHE_TTL)
    return result


async def lookup_location(ip: str) -> dict:
    data = await asyncio.to_thread(geo_ip_manager.fetch_location, ip)
    data.pop("elapsed_time", None)
    return data


async def gather(target: str) -> dict:
    """Everything known about one domain or IP, with no rendering concerns.

    Lifted from get_ip_info. The visitor's own location is deliberately NOT
    fetched here: it belongs to the page, not to the target, so the caller
    starts that task itself and awaits it alongside this one.
    """
    target = normalize_lookup_target(target)

    # WHOIS takes seconds and depends on nothing else here, so it runs
    # alongside the DNS/SSL work instead of in front of it.
    whois_task = asyncio.create_task(lookup_whois(target))

    ssl_data = None
    resolved_ip = None
    domain_data = None
    reverse_dns_hostname = None

    try:
        if domain_manager.is_valid_domain(target):
            logging.debug("domain=%s", sanitize_log_input(target))
            try:
                a_records = await asyncio.to_thread(dns.resolver.resolve, target, "A")
                resolved_ip = str(a_records[0])
            except Exception as e:
                logging.warning("No A record for %s: %s", sanitize_log_input(target), e)
            if resolved_ip and not is_safe_ip(resolved_ip):
                raise PrivateAddressError(target)

            # The record sweep and the TLS handshake are independent.
            domain_data, ssl_data = await asyncio.gather(
                asyncio.to_thread(
                    lambda: domain_manager.get_records(target, ip=resolved_ip)
                ),
                asyncio.to_thread(SSLManager.get_ssl_info, target, resolved_ip),
                return_exceptions=True,
            )
            if isinstance(domain_data, BaseException):
                logging.exception(
                    "Error getting DNS records for %s", sanitize_log_input(target)
                )
                domain_data = None
            if isinstance(ssl_data, BaseException):
                logging.exception(
                    "Error getting SSL info for %s", sanitize_log_input(target)
                )
                ssl_data = None
        elif domain_manager.is_ipv4(target):
            logging.debug("ip=%s", sanitize_log_input(target))
            if not is_safe_ip(target):
                raise PrivateAddressError(target)
            reverse_dns_hostname = await asyncio.to_thread(
                domain_manager.perform_reverse_lookup, target
            )
            domain_data = (
                await asyncio.to_thread(
                    lambda: domain_manager.get_records(reverse_dns_hostname, ip=target)
                )
                if reverse_dns_hostname
                else {}
            )
            resolved_ip = target
    except BaseException:
        whois_task.cancel()
        raise

    if resolved_ip:
        ip_data = await lookup_location(resolved_ip)
        # The PTR record was already resolved above; don't ask twice.
        if reverse_dns_hostname:
            ip_data["reverse_dns"] = reverse_dns_hostname
    else:
        ip_data = {}

    return {
        "address": target,
        "domain": domain_data,
        "location": ip_data,
        "whois": await whois_task,
        "ssl": ssl_data,
        "resolved_ip": resolved_ip,
        "reverse_dns": reverse_dns_hostname,
    }
