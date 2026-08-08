#!/usr/bin/env python3

import asyncio
import contextlib
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
from urllib.parse import urlparse

import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from geo import LOCAL_ROUTE_KM, MIN_ROUTE_KM, Gazetteer, haversine_km
from mapgeom import build_canvas
from rdap import refresh_rdap_bootstrap
from viewmodel import build_view, whois_display
from config import (
    BAN_DURATION_RATE_LIMIT,
    BAN_DURATION_SUSPICIOUS,
    CLEANUP_INTERVAL_SECONDS,
    DESKTOP_CANVAS,
    GEOIP_ASN_DB_FILE,
    GEOIP_CITY_DB_FILE,
    GEOIP_UPDATE_RETRY_SECONDS,
    MCP_ENABLED,
    MOBILE_CANVAS,
    PUBLIC_BASE_URL,
    RATE_LIMIT_CLEANUP_INTERVAL,
    SITE_DOMAIN_FALLBACK,
)
from managers import HeaderManager
from mcp_server import McpBarePathRoute, build_mcp, mcp_dispatch
from models import GeoRulesUpdate
from lookup import (
    PrivateAddressError,
    domain_manager,
    gather,
    geo_ip_manager,
    lookup_location,
    lookup_whois,
    normalize_lookup_target,
    sanitize_log_input,
)
from security import (
    GeoBlockManager,
    IPBanManager,
    RateLimiter,
    SuspiciousPatternDetector,
    WhitelistManager,
    _peer_is_trusted,
    get_client_ip,
)

# Load environment variables from .env file
load_dotenv()

if MCP_ENABLED:

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        # A mounted sub-application's lifespan never runs, so the session
        # manager has to be started here. Without this the first /mcp request
        # fails with "RuntimeError: Task group is not initialized". build_mcp()
        # is called fresh on every start (see mcp_dispatch's docstring in
        # mcp_server.py) rather than once at import time, so the session
        # manager it hands back is always one that hasn't been run() yet.
        asgi_app, mcp_instance = build_mcp()
        mcp_dispatch.asgi_app = asgi_app
        async with mcp_instance.session_manager.run():
            yield
        mcp_dispatch.asgi_app = None

else:
    lifespan = None

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
# Before the /{domain_ip} catch-all, for the same reason /healthz is declared
# early: routes match in registration order and the catch-all swallows /mcp.
if MCP_ENABLED:
    app.add_route("/mcp", McpBarePathRoute(mcp_dispatch), include_in_schema=False)
    app.mount("/mcp", mcp_dispatch)
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


# Security Configuration from Environment Variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY or ADMIN_API_KEY == "CHANGE_ME_TO_SECURE_RANDOM_STRING":
    logger.warning(
        "ADMIN_API_KEY not set or using default value in .env file! "
        "Admin endpoints will be disabled. Generate one with: "
        'python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )
    ADMIN_API_KEY = None


gazetteer = Gazetteer.load()


def _is_route(
    distance_km: float, origin_location: dict | None, target_location: dict | None
) -> bool:
    """Whether to draw home -> destination (two pins + arc) rather than a single
    city pin. A genuine trip (>= MIN_ROUTE_KM) always is; and now that GeoIP is
    city-level, two *different* cities closer than that get the route view too,
    as long as they are not essentially the same spot (same-city GeoIP jitter)."""
    if distance_km >= MIN_ROUTE_KM:
        return True
    origin_city = ((origin_location or {}).get("city_name") or "").strip()
    target_city = ((target_location or {}).get("city_name") or "").strip()
    different_cities = (
        origin_city and target_city and origin_city.casefold() != target_city.casefold()
    )
    return bool(different_cities) and distance_km >= LOCAL_ROUTE_KM


def build_map_payload(
    target_location: dict | None, origin_location: dict | None
) -> tuple[dict | None, float | None, dict | None, dict | None]:
    """Return (map, distance_km, origin, target) for the response.

    `map` is render-only (desktop/mobile canvases). `origin` is a flat location
    object for the visitor (None unless it's a route), and `target` is the
    resolved target coordinates the caller writes back onto `location`. City
    mode (single pin, no arc) when the visitor is the target, their location is
    unknown, or the two points are the same place; see _is_route for when a
    nearby-but-different city still draws home -> destination.
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
        if _is_route(distance_km, origin_location, target_location):
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


def _refresh_with_retry(refresh, name: str):
    """Run one GeoIP database refresh; when it fails, retry on a short one-shot
    timer instead of waiting out the 3-day interval — a failed boot-time refresh
    otherwise leaves the bundled country-only DB (no carrier data) serving for
    days. The fixed job id caps the pending retries at one per database."""

    def run():
        if refresh():
            return
        logging.warning(
            "%s refresh failed; retrying in %ss", name, GEOIP_UPDATE_RETRY_SECONDS
        )
        scheduler.add_job(
            run,
            "date",
            run_date=datetime.datetime.now()
            + datetime.timedelta(seconds=GEOIP_UPDATE_RETRY_SECONDS),
            id=f"retry-{name}",
            replace_existing=True,
        )

    return run


refresh_geoip_db = _refresh_with_retry(geo_ip_manager.update_database, "geoip2fast")
refresh_city_db = _refresh_with_retry(
    geo_ip_manager.update_city_database, "GeoLite2-City"
)
refresh_asn_db = _refresh_with_retry(geo_ip_manager.update_asn_database, "GeoLite2-ASN")
scheduler.add_job(refresh_geoip_db, "interval", days=3)
scheduler.add_job(refresh_city_db, "interval", days=3)
scheduler.add_job(refresh_asn_db, "interval", days=3)
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
refresh_geoip_db()
# The mmdb overlays are tens of MB, so only fetch them on first boot; the
# scheduler refreshes them afterwards. Lookups degrade gracefully to geoip2fast
# until they land.
if not os.path.exists(GEOIP_CITY_DB_FILE):
    refresh_city_db()
if not os.path.exists(GEOIP_ASN_DB_FILE):
    refresh_asn_db()


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


@app.get("/healthz")
async def healthz():
    """Liveness plus which GeoIP databases are actually serving lookups, so a
    silent fallback to the bundled country-only DB is visible from outside.
    Declared before /{domain_ip}, which would otherwise swallow the path."""
    return {"status": "ok", "databases": geo_ip_manager.database_status()}


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
    started = time.perf_counter()
    # Normalize before the log line below so it records what the pipeline
    # actually resolves, not a raw pasted URL/path. gather() normalizes again
    # (it must, for its MCP callers); normalize_lookup_target is idempotent,
    # see test_normalize_lookup_target_is_idempotent in tests/test_lookup.py.
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

    # The visitor's own location only feeds the distance line, so it runs
    # alongside the target lookup rather than after it.
    origin_task = asyncio.create_task(lookup_location(client_ip))
    try:
        data = await gather(domain_ip)
    except PrivateAddressError:
        origin_task.cancel()
        raise HTTPException(
            status_code=400,
            detail="Private or reserved IP addresses are not allowed",
        ) from None

    origin_location = await origin_task
    ip_data = data["location"]
    map_payload, distance_km, origin, target = await asyncio.to_thread(
        build_map_payload, ip_data, origin_location
    )
    _apply_resolved_target(ip_data, target)

    response_data = {
        "address": data["address"],
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": data["domain"],
        "location": ip_data,
        "whois": data["whois"],
        "ssl": data["ssl"],
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
