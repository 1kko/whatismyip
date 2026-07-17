#!/usr/bin/env python3

import asyncio
import datetime
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from logging.handlers import TimedRotatingFileHandler
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import uvicorn
import whois
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from geo import MIN_ROUTE_KM, Gazetteer, haversine_km
from mapgeom import build_canvas
from rdap import lookup_rdap, normalize_whois, refresh_rdap_bootstrap
from viewmodel import build_view, whois_display
from config import (
    BAN_DURATION_RATE_LIMIT,
    BAN_DURATION_SUSPICIOUS,
    CLEANUP_INTERVAL_SECONDS,
    DESKTOP_CANVAS,
    GEOIP_CITY_DB_FILE,
    MOBILE_CANVAS,
    PUBLIC_BASE_URL,
    RATE_LIMIT_CLEANUP_INTERVAL,
    RDAP_TIMEOUT_SECONDS,
    SITE_DOMAIN_FALLBACK,
    TRUSTED_PROXIES,
    WHOIS_CACHE_ERROR_TTL,
    WHOIS_CACHE_TTL,
    WHOIS_TIMEOUT_SECONDS,
)
from managers import DomainManager, GeoIpManager, HeaderManager, SSLManager
from models import GeoRulesUpdate
from security import (
    GeoBlockManager,
    IPBanManager,
    RateLimiter,
    SuspiciousPatternDetector,
    WhitelistManager,
)

# Load environment variables from .env file
load_dotenv()

# First, mount static files
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Configure logging
log_formatter = logging.Formatter(
    "%(asctime)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s"
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# File handler with rotation every 1 days, keeping 7 days of logs
file_handler = TimedRotatingFileHandler(
    "service.log", when="D", interval=1, backupCount=7
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

# Silence APScheduler's job execution logs
logging.getLogger("apscheduler.scheduler").setLevel(logging.WARNING)
logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)


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


# Security Configuration from Environment Variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY or ADMIN_API_KEY == "CHANGE_ME_TO_SECURE_RANDOM_STRING":
    logger.warning(
        "ADMIN_API_KEY not set or using default value in .env file! "
        "Admin endpoints will be disabled. Generate one with: "
        'python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )
    ADMIN_API_KEY = None


def is_safe_ip(ip_str: str) -> bool:
    """Check if an IP address is safe to query (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        )
    except ValueError:
        return False


def _extract_forwarded_ip(request: Request) -> str | None:
    """Extract client IP from proxy headers (x-real-ip or x-forwarded-for)."""
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # X-Forwarded-For format: "client, proxy1, proxy2" - first is the client
        return forwarded_for.split(",")[0].strip()
    return None


def _peer_is_trusted(peer: str | None) -> bool:
    # Explicit allowlist wins.
    if TRUSTED_PROXIES:
        return bool(peer) and peer in TRUSTED_PROXIES
    # No allowlist: only trust proxy headers when the direct peer is a
    # private-range address. Docker/K8s/Traefik sidecars always talk from
    # RFC1918 / CGNAT / link-local space, so this correctly covers the
    # intended reverse-proxy case without requiring per-deploy config.
    # If the app is accidentally exposed directly, peer is the attacker's
    # public IP and headers are ignored (fail-closed).
    if not peer:
        return False
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def get_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else None
    if _peer_is_trusted(peer):
        return _extract_forwarded_ip(request) or peer or "unknown"
    return peer or "unknown"


geo_ip_manager = GeoIpManager()
domain_manager = DomainManager()
gazetteer = Gazetteer.load()


def build_map_payload(
    target_location: dict | None, origin_location: dict | None
) -> tuple[dict | None, float | None, dict | None, dict | None]:
    """Return (map, distance_km, origin, target) for the response.

    `map` is render-only (desktop/mobile canvases). `origin` is a flat location
    object for the visitor (None unless it's a route), and `target` is the
    resolved target coordinates the caller writes back onto `location`. City
    mode (single pin, no arc) when the visitor is the target, their location is
    unknown, or the two points are within MIN_ROUTE_KM of each other.
    """
    target = gazetteer.resolve(target_location)
    if not target:
        return None, None, None, None

    origin = gazetteer.resolve(origin_location)
    distance_km = None
    route_origin = None

    if origin:
        distance_km = haversine_km(
            (origin["lat"], origin["lon"]), (target["lat"], target["lon"])
        )
        if distance_km >= MIN_ROUTE_KM:
            route_origin = origin
        else:
            distance_km = None

    origin_obj = None
    if route_origin:
        ol = origin_location or {}
        origin_obj = {
            "ip": ol.get("ip"),
            "country_code": ol.get("country_code"),
            "country_name": ol.get("country_name"),
            "city_name": ol.get("city_name") or None,
            "lat": route_origin["lat"],
            "lon": route_origin["lon"],
            "accuracy_km": route_origin.get("accuracy_km"),
        }

    payload = {
        "desktop": build_canvas(target, route_origin, **DESKTOP_CANVAS),
        "mobile": build_canvas(target, route_origin, **MOBILE_CANVAS),
    }
    distance = round(distance_km, 1) if distance_km else None
    return payload, distance, origin_obj, target


def _apply_resolved_target(location: dict, target: dict | None) -> None:
    """Write the resolved (displayed) coordinates + precision back onto the flat
    location, so location.lat/lon match the map pin even when they came from the
    gazetteer fallback rather than GeoLite2."""
    if not target:
        return
    location["lat"] = target["lat"]
    location["lon"] = target["lon"]
    location["precision"] = target.get("precision")


def _record_value(kind: str, record) -> str:
    """The part of a record a human reads, not its Python repr.

    DomainManager returns each type with its own shape: A is {ip, ttl}, MX is
    {preference, hostname, ttl, ip}, NS is {hostname, ttl, ip} and TXT is
    {text: [...], ttl}.
    """
    if not isinstance(record, dict):
        return str(record)

    if kind == "A":
        return str(record.get("ip", ""))
    if kind == "MX":
        preference = record.get("preference")
        hostname = record.get("hostname", "")
        if preference is None:
            return hostname
        return f"{preference} {hostname}".strip()
    if kind == "NS":
        return str(record.get("hostname", ""))
    if kind == "TXT":
        text = record.get("text", "")
        return " ".join(text) if isinstance(text, list) else str(text)
    return str(record)


def _dns_rows(response_data: dict) -> list[dict]:
    """Flatten the DNS record dict into table rows."""
    domain = response_data.get("domain") or {}
    address = response_data.get("address", "")

    rows = []
    for kind, key in (("A", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")):
        for record in domain.get(key) or []:
            rows.append(
                {
                    "type": kind,
                    "name": address,
                    "value": _record_value(kind, record),
                    "ttl": record.get("ttl", "") if isinstance(record, dict) else "",
                }
            )

    cname = domain.get("cname")
    if cname:
        rows.append({"type": "CNAME", "name": address, "value": str(cname), "ttl": ""})
    return rows


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


def public_base_url(request: Request) -> str:
    """The URL a visitor would actually type, not the one uvicorn sees.

    Behind a TLS-terminating proxy the ASGI scope still says http://, so the
    copyable curl command would hand out the wrong scheme. Trust
    x-forwarded-proto only from a peer we already trust for x-real-ip; uvicorn's
    own --forwarded-allow-ips is deliberately NOT widened, because it would
    rewrite scope["client"] and defeat get_client_ip()'s spoofing check.
    """
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/") + "/"

    base = str(request.base_url)
    peer = request.client.host if request.client else None
    if not _peer_is_trusted(peer):
        return base

    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    if proto in ("http", "https"):
        _, separator, rest = base.partition("://")
        if separator:
            return f"{proto}://{rest}"
    return base


def site_domain(request: Request) -> str:
    """The domain shown as the footer wordmark: the host the visitor actually
    reached us on, falling back to a fixed domain when that host is missing or
    is a bare IP address (i.e. there is no real domain to show)."""
    host = urlparse(public_base_url(request)).hostname or ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return host if host and not is_ip else SITE_DOMAIN_FALLBACK


def render_page(request: Request, response_data: dict, is_self: bool):
    """Render browser.html from the server-side view model."""
    whois_data = response_data.get("whois") or {}
    view = build_view(response_data, is_self=is_self)

    # map.js labels the pins with the two IPs and draws the distance on the arc.
    # These ride along with the browser's map payload rather than polluting the
    # render-only `map` in the JSON API (they live under location / origin there).
    map_data = response_data.get("map")
    if map_data:
        origin = response_data.get("origin") or {}
        map_data = {
            **map_data,
            "distance_text": view["distance_text"],
            "target_ip": (response_data.get("location") or {}).get("ip"),
            "origin_ip": origin.get("ip"),
        }

    return templates.TemplateResponse(
        request,
        "browser.html",
        {
            "view": view,
            "view_map": map_data is not None,
            "api_base": public_base_url(request),
            "site_domain": site_domain(request),
            "dns_rows": _dns_rows(response_data),
            "headers": response_data.get("headers") or {},
            "whois": whois_display(whois_data),
            "json_data": json.dumps(response_data, indent=2, default=str).replace(
                "</", "<\\/"
            ),
            "map_data": json.dumps(map_data, default=str).replace("</", "<\\/"),
            "nonce": getattr(request.state, "csp_nonce", ""),
        },
    )


# Initialize security managers
ip_ban_manager = IPBanManager()
rate_limiter = RateLimiter()
suspicious_detector = SuspiciousPatternDetector()
whitelist_manager = WhitelistManager()
geo_block_manager = GeoBlockManager(geo_ip_manager)

# Initialize scheduler and add jobs
scheduler = BackgroundScheduler()
scheduler.add_job(geo_ip_manager.update_database, "interval", days=3)
scheduler.add_job(geo_ip_manager.update_city_database, "interval", days=3)
scheduler.add_job(
    ip_ban_manager.cleanup_expired_bans, "interval", seconds=CLEANUP_INTERVAL_SECONDS
)
scheduler.add_job(
    rate_limiter.cleanup_old_records, "interval", seconds=RATE_LIMIT_CLEANUP_INTERVAL
)
# The IANA RDAP bootstrap registry (TLD/IP-block -> RDAP server) rarely changes;
# check daily and only re-fetch when it is older than a week. The first lookup
# bootstraps lazily, so nothing here blocks startup.
scheduler.add_job(refresh_rdap_bootstrap, "interval", days=1)
scheduler.start()
geo_ip_manager.update_database()
# The city DB is ~60MB, so only fetch it on first boot; the scheduler refreshes
# it afterwards. Lookups degrade gracefully to geoip2fast until it lands.
if not os.path.exists(GEOIP_CITY_DB_FILE):
    geo_ip_manager.update_city_database()


class BrowserDetector:
    @staticmethod
    def is_browser(user_agent: str) -> bool:
        browser_patterns = [
            r"Mozilla",
            r"Chrome",
            r"Safari",
            r"Firefox",
            r"Edge",
            r"Opera",
        ]
        return any(
            re.search(pattern, user_agent, re.IGNORECASE)
            for pattern in browser_patterns
        )


# Admin API key authentication dependency
def verify_admin_key(api_key: str = Header(None, alias="api-key")):
    """Dependency for admin endpoint authentication"""
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=404, detail="Not Found")
    if not hmac.compare_digest(api_key or "", ADMIN_API_KEY):
        raise HTTPException(status_code=404, detail="Not Found")
    return True


# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security middleware for IP banning, geo-blocking, and rate limiting"""
    client_ip = get_client_ip(request)
    request_path = request.url.path

    # Admin endpoints: still check bans and rate limits, skip geo/suspicious checks
    if request_path.startswith("/admin/"):
        if ip_ban_manager.is_banned(client_ip):
            logging.warning(
                "SECURITY: Blocked banned IP %s on admin endpoint",
                client_ip,
            )
            return JSONResponse(
                status_code=403,
                content={"error": "IP address is banned"},
            )
        if not rate_limiter.allow_request(client_ip):
            ip_ban_manager.ban_ip(
                client_ip,
                reason="rate_limit_admin",
                duration=BAN_DURATION_RATE_LIMIT,
            )
            return JSONResponse(status_code=429, content={"error": "Too many requests"})
        return await call_next(request)

    # 1. Check if IP is banned (highest priority)
    if ip_ban_manager.is_banned(client_ip):
        logging.warning(f"SECURITY: Blocked banned IP {client_ip}")
        return JSONResponse(
            status_code=403,
            content={"error": "IP address is banned", "contact": "admin@example.com"},
        )

    # 2. Check geographic restrictions
    geo_check = geo_block_manager.check_access(client_ip)
    if not geo_check["allowed"]:
        logging.warning(
            f"SECURITY: Blocked {client_ip} from {geo_check['country']} "
            f"({geo_check['region']}) - {geo_check['reason']}"
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": "Access denied from your location",
                "country": geo_check["country"],
                "reason": geo_check["reason"],
            },
        )

    # 3. Check whitelist (allow static files and main endpoints)
    if whitelist_manager.is_whitelisted(request_path):
        return await call_next(request)

    # 4. Check for suspicious patterns
    if suspicious_detector.is_suspicious(request_path):
        ip_ban_manager.ban_ip(
            client_ip,
            reason="suspicious_request",
            duration=BAN_DURATION_SUSPICIOUS,
            path=request_path,
            country=geo_check["country"],
        )
        logging.warning(
            f"SECURITY: Banned {client_ip} ({geo_check['country']}) "
            f"for suspicious request: {request_path}"
        )
        return JSONResponse(status_code=403, content={"error": "Forbidden"})

    # 5. Rate limit check
    if not rate_limiter.allow_request(client_ip):
        ip_ban_manager.ban_ip(
            client_ip,
            reason="rate_limit",
            duration=BAN_DURATION_RATE_LIMIT,
            country=geo_check["country"],
        )
        logging.warning(
            f"SECURITY: Banned {client_ip} ({geo_check['country']}) "
            f"for rate limit violation"
        )
        return JSONResponse(status_code=429, content={"error": "Too many requests"})

    return await call_next(request)


_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "interest-cohort=(), browsing-topics=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # Per-request nonce lets the inline <script> in browser.html run without
    # 'unsafe-inline'. External scripts are permitted via 'self'.
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    for key, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://tile.openstreetmap.org; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    # Obscure server fingerprinting.
    response.headers["server"] = "hidden"
    return response


@app.get("/", response_model=None)
async def get_self_info(request: Request):
    started = time.perf_counter()
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    client_ip = get_client_ip(request)
    sanitized_ip = sanitize_log_input(client_ip)
    logging.info("client=%s lookup=%s (self)", sanitized_ip, sanitized_ip)

    # WHOIS is the slow one (seconds); it has nothing to do with GeoIP or the
    # reverse lookup, so none of these wait on each other.
    whois_task = asyncio.create_task(lookup_whois(client_ip))
    location_task = asyncio.create_task(lookup_location(client_ip))
    reverse_task = asyncio.create_task(
        asyncio.to_thread(domain_manager.perform_reverse_lookup, client_ip)
    )

    ip_data = await location_task
    reverse_dns_hostname = await reverse_task
    if reverse_dns_hostname:
        ip_data["reverse_dns"] = reverse_dns_hostname

    domain_records = (
        await asyncio.to_thread(
            lambda: domain_manager.get_records(reverse_dns_hostname, ip=client_ip)
        )
        if reverse_dns_hostname
        else {}
    )
    whois_data = await whois_task

    # A self-lookup is never a route: the visitor IS the target, so the
    # distance is 0 km, which build_map_payload collapses to city mode.
    map_payload, _, origin, target = await asyncio.to_thread(
        build_map_payload, ip_data, ip_data
    )
    _apply_resolved_target(ip_data, target)
    response_data = {
        "address": client_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_records,
        "location": ip_data,
        "whois": whois_data,
        "ssl": None,
        "headers": request_headers,
        "map": map_payload,
        "distance_km": None,
        "origin": origin,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
    }

    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return render_page(request, response_data, is_self=True)

    # FastAPI serialises the dict via jsonable_encoder (datetimes -> ISO-8601)
    # and its default JSONResponse (UTF-8, no ASCII escaping).
    return response_data


@app.get("/{domain_ip}", response_model=None)
async def get_ip_info(domain_ip: str, request: Request):
    # Remove the static path check since it's handled by the static files mount
    started = time.perf_counter()
    # Strip any scheme/path a caller pasted (e.g. "https://host/x") down to the
    # bare host before it reaches WHOIS/DNS/SSL. Everything below reads this.
    domain_ip = normalize_lookup_target(domain_ip)
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    request_headers.pop("host", None)

    client_ip = get_client_ip(request)
    logging.info(
        "client=%s lookup=%s",
        sanitize_log_input(client_ip),
        sanitize_log_input(domain_ip),
    )

    # WHOIS takes seconds and depends on nothing else here, so it runs alongside
    # the DNS/SSL work instead of in front of it. Same for the visitor's own
    # location, which only feeds the distance line.
    whois_task = asyncio.create_task(lookup_whois(domain_ip))
    origin_task = asyncio.create_task(lookup_location(client_ip))

    ssl_data = None
    resolved_ip = None
    domain_data = None
    reverse_dns_hostname = None

    if domain_manager.is_valid_domain(domain_ip):
        logging.debug(f"domain={domain_ip}")
        try:
            a_records = await asyncio.to_thread(dns.resolver.resolve, domain_ip, "A")
            resolved_ip = str(a_records[0])  # Get the first A record
        except Exception as e:
            logging.warning(f"No A record for {domain_ip}: {str(e)}")
        if resolved_ip and not is_safe_ip(resolved_ip):
            whois_task.cancel()
            origin_task.cancel()
            raise HTTPException(
                status_code=400,
                detail="Private or reserved IP addresses are not allowed",
            )

        # The record sweep and the TLS handshake are independent of each other.
        domain_data, ssl_data = await asyncio.gather(
            asyncio.to_thread(
                lambda: domain_manager.get_records(domain_ip, ip=resolved_ip)
            ),
            asyncio.to_thread(SSLManager.get_ssl_info, domain_ip, resolved_ip),
            return_exceptions=True,
        )
        if isinstance(domain_data, BaseException):
            logging.exception(
                "Error getting DNS records for %s", sanitize_log_input(domain_ip)
            )
            domain_data = None
        if isinstance(ssl_data, BaseException):
            logging.exception(
                "Error getting SSL info for %s", sanitize_log_input(domain_ip)
            )
            ssl_data = None
    elif domain_manager.is_ipv4(domain_ip):
        logging.debug(f"ip={domain_ip}")
        if not is_safe_ip(domain_ip):
            whois_task.cancel()
            origin_task.cancel()
            raise HTTPException(
                status_code=400,
                detail="Private or reserved IP addresses are not allowed",
            )
        reverse_dns_hostname = await asyncio.to_thread(
            domain_manager.perform_reverse_lookup, domain_ip
        )
        domain_data = (
            await asyncio.to_thread(
                lambda: domain_manager.get_records(reverse_dns_hostname, ip=domain_ip)
            )
            if reverse_dns_hostname
            else {}
        )
        resolved_ip = domain_ip

    if resolved_ip:
        ip_data = await lookup_location(resolved_ip)
        # The PTR record was already resolved above; don't ask twice.
        if reverse_dns_hostname:
            ip_data["reverse_dns"] = reverse_dns_hostname
    else:
        ip_data = {}

    whois_data = await whois_task
    origin_location = await origin_task
    map_payload, distance_km, origin, target = await asyncio.to_thread(
        build_map_payload, ip_data, origin_location
    )
    _apply_resolved_target(ip_data, target)

    response_data = {
        "address": domain_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_data,
        "location": ip_data,
        "whois": whois_data,
        "ssl": ssl_data,
        "headers": request_headers,
        "map": map_payload,
        "distance_km": distance_km,
        "origin": origin,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
    }

    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return render_page(request, response_data, is_self=False)

    # FastAPI serialises the dict via jsonable_encoder (datetimes -> ISO-8601)
    # and its default JSONResponse (UTF-8, no ASCII escaping).
    return response_data


# Admin endpoints for security management
@app.get("/admin/bans")
async def get_all_bans(authenticated: bool = Depends(verify_admin_key)):
    """Get all currently banned IPs"""
    return {"bans": ip_ban_manager.get_all_bans()}


@app.post("/admin/ban/{ip}")
async def manual_ban(
    ip: str,
    duration: int = BAN_DURATION_SUSPICIOUS,
    authenticated: bool = Depends(verify_admin_key),
):
    """Manually ban an IP address"""
    ip_ban_manager.ban_ip(ip, reason="manual", duration=duration)
    return {"status": "banned", "ip": ip, "duration": duration}


@app.delete("/admin/ban/{ip}")
async def manual_unban(ip: str, authenticated: bool = Depends(verify_admin_key)):
    """Remove an IP from the ban list"""
    ip_ban_manager.unban_ip(ip)
    return {"status": "unbanned", "ip": ip}


@app.get("/admin/geo/rules")
async def get_geo_rules(authenticated: bool = Depends(verify_admin_key)):
    """Get current geo-blocking configuration"""
    return geo_block_manager.config


@app.put("/admin/geo/rules")
async def update_geo_rules(
    rules: GeoRulesUpdate, authenticated: bool = Depends(verify_admin_key)
):
    """Update geo-blocking configuration"""
    updates = rules.model_dump(exclude_none=True)

    # Validate mode
    valid_modes = ["disabled", "allowlist", "blocklist"]
    if "mode" in updates and updates["mode"] not in valid_modes:
        raise HTTPException(status_code=400, detail="Invalid mode")

    # Update configuration
    for key in [
        "mode",
        "blocked_countries",
        "allowed_countries",
        "blocked_regions",
        "allowed_regions",
        "block_unknown",
        "bypass_ips",
    ]:
        if key in updates:
            geo_block_manager.config[key] = updates[key]

    geo_block_manager.save_config()
    return {"status": "updated", "config": geo_block_manager.config}


@app.post("/admin/geo/block/country/{country_code}")
async def block_country(
    country_code: str, authenticated: bool = Depends(verify_admin_key)
):
    """Add a country to the blocklist"""
    country_code = country_code.upper()
    if country_code not in geo_block_manager.config["blocked_countries"]:
        geo_block_manager.config["blocked_countries"].append(country_code)
        geo_block_manager.save_config()

    return {"status": "blocked", "country": country_code}


@app.delete("/admin/geo/block/country/{country_code}")
async def unblock_country(
    country_code: str, authenticated: bool = Depends(verify_admin_key)
):
    """Remove a country from the blocklist"""
    country_code = country_code.upper()
    if country_code in geo_block_manager.config["blocked_countries"]:
        geo_block_manager.config["blocked_countries"].remove(country_code)
        geo_block_manager.save_config()

    return {"status": "unblocked", "country": country_code}


@app.post("/admin/geo/allow/country/{country_code}")
async def allow_country(
    country_code: str, authenticated: bool = Depends(verify_admin_key)
):
    """Add a country to the allowlist"""
    country_code = country_code.upper()
    if country_code not in geo_block_manager.config["allowed_countries"]:
        geo_block_manager.config["allowed_countries"].append(country_code)
        geo_block_manager.save_config()

    return {"status": "allowed", "country": country_code}


@app.delete("/admin/geo/allow/country/{country_code}")
async def remove_allowed_country(
    country_code: str, authenticated: bool = Depends(verify_admin_key)
):
    """Remove a country from the allowlist"""
    country_code = country_code.upper()
    if country_code in geo_block_manager.config["allowed_countries"]:
        geo_block_manager.config["allowed_countries"].remove(country_code)
        geo_block_manager.save_config()

    return {"status": "removed", "country": country_code}


@app.get("/admin/geo/lookup/{ip}")
async def lookup_ip_location(ip: str, authenticated: bool = Depends(verify_admin_key)):
    """Get geographic information for an IP address"""
    location = geo_ip_manager.fetch_location(ip)
    return {
        "ip": ip,
        "country_code": location.get("country_code"),
        "country_name": location.get("country_name"),
        "region": (
            f"{location.get('country_code')}-{location.get('subdivision_code')}"
            if location.get("subdivision_code")
            else None
        ),
        "subdivision_name": location.get("subdivision_name"),
        "city": location.get("city_name"),
    }


@app.get("/admin/geo/countries")
async def list_available_countries(authenticated: bool = Depends(verify_admin_key)):
    """List all available countries (ISO 3166-1 alpha-2 codes)"""
    # Common countries for reference
    countries = {
        "US": "United States",
        "CA": "Canada",
        "GB": "United Kingdom",
        "DE": "Germany",
        "FR": "France",
        "CN": "China",
        "RU": "Russia",
        "JP": "Japan",
        "KR": "South Korea",
        "IN": "India",
        "BR": "Brazil",
        "AU": "Australia",
        "MX": "Mexico",
        "IT": "Italy",
        "ES": "Spain",
        "NL": "Netherlands",
        "SE": "Sweden",
        "NO": "Norway",
        "DK": "Denmark",
        "FI": "Finland",
        "PL": "Poland",
        "TR": "Turkey",
        "SA": "Saudi Arabia",
        "AE": "United Arab Emirates",
        "SG": "Singapore",
        "HK": "Hong Kong",
        "TW": "Taiwan",
        "TH": "Thailand",
        "VN": "Vietnam",
        "ID": "Indonesia",
        "MY": "Malaysia",
        "PH": "Philippines",
        "NZ": "New Zealand",
        "ZA": "South Africa",
        "EG": "Egypt",
        "NG": "Nigeria",
        "KE": "Kenya",
        "AR": "Argentina",
        "CL": "Chile",
        "CO": "Colombia",
        "PE": "Peru",
        "VE": "Venezuela",
        "UA": "Ukraine",
        "IL": "Israel",
        "IR": "Iran",
        "IQ": "Iraq",
        "KP": "North Korea",
        "PK": "Pakistan",
        "BD": "Bangladesh",
        "AT": "Austria",
        "BE": "Belgium",
        "CH": "Switzerland",
        "CZ": "Czech Republic",
        "GR": "Greece",
        "PT": "Portugal",
        "RO": "Romania",
        "HU": "Hungary",
        "IE": "Ireland",
    }

    return {"countries": countries}


@app.get("/admin/stats")
async def get_security_stats(authenticated: bool = Depends(verify_admin_key)):
    """Get security statistics"""
    return {
        "banned_ips": len(ip_ban_manager.get_all_bans()),
        "rate_limit_tracked_ips": len(rate_limiter.request_history),
        "geo_blocking_mode": geo_block_manager.config.get("mode"),
        "blocked_countries": len(geo_block_manager.config.get("blocked_countries", [])),
        "allowed_countries": len(geo_block_manager.config.get("allowed_countries", [])),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104
