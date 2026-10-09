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
import unicodedata
from typing import Any

import whois

from config import (
    RDAP_TIMEOUT_SECONDS,
    WHOIS_CACHE_ERROR_TTL,
    WHOIS_CACHE_TTL,
    WHOIS_TIMEOUT_SECONDS,
)
from managers import (
    DomainManager,
    GeoIpManager,
    SSLManager,
    TldNamesManager,
    _recursive_resolver,
)
from rdap import lookup_rdap, normalize_whois


class PrivateAddressError(Exception):
    """The target is (or resolves to) an address that is not public unicast.

    Raised instead of HTTPException so this module stays free of FastAPI:
    main.py turns it into a 400, mcp_server.py turns it into {"error": ...}.
    """


class InvalidTargetError(Exception):
    """The target is not something this service can look up, so nothing was
    sent anywhere.

    Same contract as PrivateAddressError. `code` is the stable, machine-readable
    half of the answer and `message` the human one; main.py returns both with a
    400, mcp_server.py returns the message as {"error": ...}.

    An IPv6 literal raises this too, under its own code, for as long as gather()
    has no IPv6 branch to run.
    """

    def __init__(
        self,
        target: str,
        code: str = "invalid_target",
        message: str = "not a domain name or IP address",
    ):
        super().__init__(target)
        self.code = code
        self.message = message


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
    """Whether an address may become the target of an outbound connection.

    An allowlist: only globally reachable unicast passes. The denylist it
    replaced (private, loopback, link-local, reserved) passed every range it
    did not name -- CGNAT 100.64.0.0/10, where Tailscale's MagicDNS answers at
    100.100.100.100, and multicast -- so a domain whose A record pointed there
    got a TLS handshake from this server.

    is_global follows IANA's special-purpose registry but still counts three
    kinds of address as global, so they are refused by hand: multicast; IPv6's
    unassigned blocks (is_reserved), whose ::/8 holds the NAT64 prefix
    64:ff9b::/96 embedding an IPv4 address; and fec0::/10, IPv6's deprecated
    site-local space. The registry's own exceptions, such as 192.0.0.9 and
    192.0.0.10, are public anycast services and pass on purpose.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return False
    return not (ip.version == 6 and ip.is_site_local)


geo_ip_manager = GeoIpManager()
# Before DomainManager: it repoints `tld` at the data volume and seeds the
# suffix list there, and is_valid_domain would otherwise read whatever copy the
# first get_tld call happened to find.
tld_names_manager = TldNamesManager()
domain_manager = DomainManager()

# One hostname label in its ASCII (xn--) form: letters, digits, hyphens, and
# the underscore that service names such as _dmarc carry.
_HOST_LABEL = re.compile(r"[a-z0-9_-]{1,63}", re.IGNORECASE)


def _is_hostname(target: str) -> bool:
    name = target[:-1] if target.endswith(".") else target
    try:
        # The stdlib IDNA codec refuses an empty or over-long label and, for a
        # non-ASCII one, the code points nameprep prohibits.
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if not ascii_name or len(ascii_name) > 253:
        return False
    return all(_HOST_LABEL.fullmatch(label) for label in ascii_name.split("."))


def classify_target(target: str) -> str:
    """What a lookup target is: "domain", "ipv4", "ipv6" or "invalid".

    Pure string work, so gather() can turn a target away before it spends a
    WHOIS query, a resolver round trip or a TLS handshake on it. A domain must
    be a hostname and sit under a public suffix. is_valid_domain alone is far
    looser: get_tld parses its input as a URL, so it says yes to "foo bar.com",
    "user@example.com" and "example.com:443". A control character makes any
    target invalid, since python-whois writes the target into its port-43
    query verbatim, CR/LF included.

    "ipv4" and "ipv6" say nothing about whether the address is public;
    is_safe_ip answers that.
    """
    if not target or any(unicodedata.category(ch) == "Cc" for ch in target):
        return "invalid"
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return "ipv4" if ip.version == 4 else "ipv6"
    if _is_hostname(target) and domain_manager.is_valid_domain(target):
        return "domain"
    return "invalid"


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

    # Before the WHOIS task exists. It used to be created first, so
    # "favicon.ico" or "{target}" cost an RDAP query, a port-43 WHOIS query and
    # an ERROR log line, and came back as an empty 200 page.
    kind = classify_target(target)
    if kind == "invalid":
        raise InvalidTargetError(target)
    if kind == "ipv6":
        # There is no IPv6 branch below: an IPv6 literal got RDAP alone and a
        # normal-looking answer with GeoIP, ASN, PTR and the map all empty.
        raise InvalidTargetError(
            target,
            code="ipv6_not_supported",
            message="IPv6 addresses are not supported yet",
        )
    if kind == "ipv4" and not is_safe_ip(target):
        raise PrivateAddressError(target)

    # WHOIS takes seconds and depends on nothing else here, so it runs
    # alongside the DNS/SSL work instead of in front of it.
    whois_task = asyncio.create_task(lookup_whois(target))

    ssl_data = None
    resolved_ip = None
    domain_data = None
    reverse_dns_hostname = None

    try:
        if kind == "domain":
            logging.debug("domain=%s", sanitize_log_input(target))
            try:
                # Same public resolvers and time budget as the record sweep;
                # the system resolver in the container is Docker's 127.0.0.11.
                a_records = await asyncio.to_thread(
                    _recursive_resolver().resolve, target, "A"
                )
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
        else:
            logging.debug("ip=%s", sanitize_log_input(target))
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
