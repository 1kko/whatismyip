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
from fastapi.responses import (
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from geo import LOCAL_ROUTE_KM, MIN_ROUTE_KM, Gazetteer, haversine_km
from mapgeom import build_canvas
from rdap import rdap_breaker, refresh_rdap_bootstrap
from viewmodel import build_view, dns_failure_text, whois_display
from concurrency import LookupBusy, lookup_gate
from config import (
    APP_VERSION,
    BAN_DURATION_RATE_LIMIT,
    BAN_DURATION_SUSPICIOUS,
    CLEANUP_INTERVAL_SECONDS,
    DESKTOP_CANVAS,
    GEOIP_MAX_BUILD_AGE_DAYS,
    GEOIP_UPDATE_RETRY_SECONDS,
    LOOKUP_BUSY_RETRY_AFTER_SECONDS,
    MCP_ENABLED,
    MCP_MAX_BODY_BYTES,
    MCP_RATE_LIMIT_PER_MINUTE,
    MCP_RATE_LIMIT_PER_SECOND,
    MOBILE_CANVAS,
    PUBLIC_BASE_URL,
    RATE_LIMIT_CLEANUP_INTERVAL,
    SITE_DOMAIN_FALLBACK,
    SUBDOMAIN_ENABLED,
    TLD_UPDATE_RETRY_SECONDS,
    WEBRTC_STUN_HOST,
    WEBRTC_STUN_URL,
)
from managers import HeaderManager
from mcp_server import McpBarePathRoute, McpDisabled, build_mcp, mcp_dispatch
from models import GeoRulesUpdate
from lookup import (
    InvalidTargetError,
    PrivateAddressError,
    classify_target,
    domain_manager,
    gather,
    geo_ip_manager,
    is_safe_ip,
    lookup_location,
    lookup_whois,
    normalize_lookup_target,
    sanitize_log_input,
    tld_names_manager,
)
from subdomains import get_subdomains, invalid_target_reason
from textfmt import (
    InvalidFieldError,
    block_fields,
    field_values,
    legs_for,
    parse_fields,
    render_block,
    render_json,
    render_lines,
)
from textfmt import render_error as render_text_error
from security import (
    GeoBlockManager,
    IPBanManager,
    IpRuleManager,
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
else:
    _mcp_disabled = McpDisabled()
    app.add_route("/mcp", _mcp_disabled, include_in_schema=False)
    app.mount("/mcp", _mcp_disabled)
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

    DomainManager returns each type with its own shape: A and AAAA are
    {ip, ttl}, MX is {preference, hostname, ttl, ip}, NS is {hostname, ttl, ip}
    and TXT is {text: [...], ttl}. CNAME is a single {cname, ttl}, not a list.
    """
    if not isinstance(record, dict):
        return str(record)

    if kind in ("A", "AAAA"):
        return str(record.get("ip", ""))
    if kind == "MX":
        preference = record.get("preference")
        hostname = record.get("hostname", "")
        if preference is None:
            return hostname
        return f"{preference} {hostname}".strip()
    if kind == "NS":
        return str(record.get("hostname", ""))
    if kind == "CNAME":
        return str(record.get("cname", ""))
    if kind == "TXT":
        # Chunks are 255-byte wire splits, not words (RFC 7208 §3.3).
        text = record.get("text", "")
        return "".join(text) if isinstance(text, list) else str(text)
    return str(record)


def _dns_rows(response_data: dict) -> list[dict]:
    """Flatten the DNS record dict into table rows."""
    domain = response_data.get("domain") or {}
    address = response_data.get("address", "")

    def failed(kind: str, key: str) -> list[dict]:
        # A query that failed gets a row saying so; left out, it would read
        # exactly like a type the name has no records of.
        text = dns_failure_text(domain, key)
        if not text:
            return []
        return [
            {"type": kind, "name": address, "value": text, "ttl": "", "tone": "warning"}
        ]

    rows = []
    for kind, key in (
        ("A", "a"),
        ("AAAA", "aaaa"),
        ("MX", "mx"),
        ("NS", "ns"),
        ("TXT", "txt"),
    ):
        for record in domain.get(key) or []:
            rows.append(
                {
                    "type": kind,
                    "name": address,
                    "value": _record_value(kind, record),
                    "ttl": record.get("ttl", "") if isinstance(record, dict) else "",
                }
            )
        rows.extend(failed(kind, key))

    cname = domain.get("cname")
    if cname:
        rows.append(
            {
                "type": "CNAME",
                "name": address,
                "value": _record_value("CNAME", cname),
                "ttl": cname.get("ttl", "") if isinstance(cname, dict) else "",
            }
        )
    rows.extend(failed("CNAME", "cname"))
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
    view = build_view(
        response_data, is_self=is_self, subdomains_enabled=SUBDOMAIN_ENABLED
    )

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
            "subdomains_enabled": SUBDOMAIN_ENABLED,
            "stun_url": WEBRTC_STUN_URL,
            "stun_host": WEBRTC_STUN_HOST,
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


def render_error(request: Request, status_code: int, title: str, message: str = ""):
    """Render error.html: what went wrong, the search box, and a link to /.

    Only for a client negotiate() would hand the page. Every other client gets
    the JSON its caller builds, exactly as before: that JSON is the API.
    """
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "status_code": status_code,
            "title": title,
            "message": message,
            "site_domain": site_domain(request),
            "nonce": getattr(request.state, "csp_nonce", ""),
        },
        status_code=status_code,
    )


# Where a home router, an office network, a VPN or the visitor's own machine
# answers: RFC 1918, loopback, link-local, and CGNAT (RFC 6598), which carriers
# and Tailscale hand out, and IPv6's loopback, link-local and unique local
# (fc00::/7, its RFC 1918). static/js/app.js keeps the same list, for the hint
# it shows in the search box before any request is made.
_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    )
)


def render_refused_target(
    request: Request, target: str, exc: PrivateAddressError | InvalidTargetError
):
    """The error page for a target gather() refused, all of them 400s.

    The commonest is a router's address typed into the search box, so a local
    address gets an explanation rather than "not allowed". The target is shown
    only once it is known to be an address or a hostname: free text in the
    path would otherwise let a link put words on this page.
    """
    if isinstance(exc, InvalidTargetError):
        return render_error(
            request,
            400,
            "Not a domain name or IP address",
            "Enter a domain name such as example.com, or an IP address such as "
            "8.8.8.8 or 2001:4860:4860::8888.",
        )
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        # A hostname, refused for the address its A record points at.
        return render_error(
            request,
            400,
            "Not a public address",
            f"{target} resolves to a private or reserved IP address, so there is "
            "nothing public to look up.",
        )
    if any(address in network for network in _LOCAL_NETWORKS):
        return render_error(
            request,
            400,
            f"{address} is a local network address",
            "Addresses like this one only mean something inside a local network, "
            "such as your home, your office, a VPN or this computer, so there is "
            "no public record to look up. From the internet, you appear as your "
            "public IP address.",
        )
    return render_error(
        request,
        400,
        "Not a public address",
        f"{address} is a reserved IP address, not one in use on the public "
        "internet, so there is nothing to look up.",
    )


# Initialize security managers
ip_ban_manager = IPBanManager()
rate_limiter = RateLimiter()
# MCP traffic gets its own bucket: it arrives from a few shared AI-provider
# egress IPs, so it must not consume — or be throttled by — the browser budget.
mcp_rate_limiter = RateLimiter(
    requests_per_minute=MCP_RATE_LIMIT_PER_MINUTE,
    requests_per_second=MCP_RATE_LIMIT_PER_SECOND,
)
ip_rule_manager = IpRuleManager()
suspicious_detector = SuspiciousPatternDetector()
whitelist_manager = WhitelistManager()
geo_block_manager = GeoBlockManager(geo_ip_manager)

# Initialize scheduler and add jobs
scheduler = BackgroundScheduler()

# Consecutive failed refreshes per dataset, for /healthz. Cleared on success.
_refresh_failures: dict[str, int] = {}


def _refresh_with_retry(
    refresh, name: str, retry_seconds: int = GEOIP_UPDATE_RETRY_SECONDS
):
    """Run one dataset refresh; when it fails, retry on a short one-shot timer
    instead of waiting out the full interval — a failed boot-time refresh
    otherwise leaves the bundled country-only DB (no carrier data), or a stale
    suffix list, serving for days. The fixed job id caps the pending retries at
    one per dataset."""

    def run():
        if refresh():
            _refresh_failures.pop(name, None)
            return
        _refresh_failures[name] = _refresh_failures.get(name, 0) + 1
        logging.warning("%s refresh failed; retrying in %ss", name, retry_seconds)
        scheduler.add_job(
            run,
            "date",
            run_date=datetime.datetime.now()
            + datetime.timedelta(seconds=retry_seconds),
            id=f"retry-{name}",
            replace_existing=True,
        )

    return run


refresh_city_db = _refresh_with_retry(
    geo_ip_manager.update_city_database, "GeoLite2-City"
)
refresh_asn_db = _refresh_with_retry(geo_ip_manager.update_asn_database, "GeoLite2-ASN")
refresh_tld_names = _refresh_with_retry(
    tld_names_manager.update, "public-suffix-list", TLD_UPDATE_RETRY_SECONDS
)
scheduler.add_job(refresh_city_db, "interval", days=3)
scheduler.add_job(refresh_asn_db, "interval", days=3)
scheduler.add_job(
    ip_ban_manager.cleanup_expired_bans, "interval", seconds=CLEANUP_INTERVAL_SECONDS
)
scheduler.add_job(
    rate_limiter.cleanup_old_records, "interval", seconds=RATE_LIMIT_CLEANUP_INTERVAL
)
# Without this, allow_request() prunes each IP's own timestamp list but never
# deletes the (now-empty) key, so every distinct IP that ever touches /mcp
# leaves a permanent dict entry for the life of the process.
scheduler.add_job(
    mcp_rate_limiter.cleanup_old_records,
    "interval",
    seconds=RATE_LIMIT_CLEANUP_INTERVAL,
)
# The IANA RDAP bootstrap registry (TLD/IP-block -> RDAP server) rarely changes;
# check daily and only re-fetch when it is older than a week. The first lookup
# bootstraps lazily, so nothing here blocks startup.
scheduler.add_job(refresh_rdap_bootstrap, "interval", days=1)
# The public suffix list is only re-fetched once the local copy is older than
# TLD_MAX_AGE_DAYS, so a daily check costs nothing and a restart does not
# re-download. A fresh container seeds from the bundled snapshot, which is
# stamped expired, so it does pull once on first boot.
scheduler.add_job(refresh_tld_names, "interval", days=1)
scheduler.start()
refresh_tld_names()


def _fetch_unloaded_geoip_dbs():
    """Fetch, at boot, each GeoLite2 database that did not open; the scheduler
    refreshes them afterwards. They are tens of MB, so one that loaded is left
    to the schedule. Keyed on the reader, not the file: a truncated download
    left on the volume exists but will not open, and would otherwise wait out
    the whole interval with country lookups on the bundled geoip2fast snapshot
    and carriers empty."""
    if geo_ip_manager.city_reader is None:
        refresh_city_db()
    if geo_ip_manager.asn_reader is None:
        refresh_asn_db()


_fetch_unloaded_geoip_dbs()


class BrowserDetector:
    @staticmethod
    def is_browser(user_agent: str) -> bool:
        # Clients that open with "Mozilla/5.0" but want data, not a page:
        # PowerShell's Invoke-RestMethod and Invoke-WebRequest, as both 5.1
        # ("WindowsPowerShell/5.1") and 7+ ("PowerShell/7.4") identify. They
        # send no Accept header by default, so the user-agent is all
        # negotiate() has, and "Mozilla" below would otherwise hand them HTML.
        not_browser_patterns = [
            r"PowerShell/",
        ]
        if any(
            re.search(pattern, user_agent, re.IGNORECASE)
            for pattern in not_browser_patterns
        ):
            return False
        # Every client that gets the page when neither ?format= nor Accept
        # says otherwise. That includes the bots that expand a shared link
        # into a preview card: the card is built from the page's og: tags,
        # and most of them never say "Mozilla", so they used to get JSON and
        # the preview came out blank. Discord's and LinkedIn's do say it;
        # they are listed so the intent does not rest on that.
        browser_patterns = [
            r"Mozilla",
            r"Chrome",
            r"Safari",
            r"Firefox",
            r"Edge",
            r"Opera",
            r"facebookexternalhit",
            r"kakaotalk-scrap",
            r"Slackbot",
            r"Twitterbot",
            r"TelegramBot",
            r"WhatsApp",
            r"Discordbot",
            r"LinkedInBot",
        ]
        return any(
            re.search(pattern, user_agent, re.IGNORECASE)
            for pattern in browser_patterns
        )


# The formats a lookup route answers in, each with the media type an Accept
# header asks for it by. Order breaks a tie nothing else in Accept settles.
_FORMAT_MEDIA_TYPES = {
    "html": "text/html",
    "json": "application/json",
    "text": "text/plain",
}


def _accept_preference(accept: str) -> str | None:
    """The format an Accept header asks for, or None if it asks for none.

    Each format takes the q of the most specific range that matches it, as RFC
    9110 has it, so "text/*, text/html;q=0" refuses HTML. Only a format reached
    by its own type or a type/* range counts as asked for. "*/*" matches all
    three alike, and it is what curl, wget and fetch() send by default, so a
    header that reaches ours only through it expresses no preference; neither
    does an image prefetch's "image/webp,*/*". Highest q wins; on a tie, a named
    type beats a type/* range, and then the range listed first wins.
    """
    ranges = []
    for position, item in enumerate(accept.split(",")):
        media_range, *params = (part.strip().lower() for part in item.split(";"))
        q = 1.0
        for param in params:
            name, _, value = param.partition("=")
            if name.strip() == "q":
                try:
                    q = float(value)
                except ValueError:
                    q = -1.0
        # A malformed q drops its range rather than failing the request.
        if media_range and 0.0 <= q <= 1.0:
            ranges.append((media_range, q, position))

    best, best_key = None, None
    for fmt, media_type in _FORMAT_MEDIA_TYPES.items():
        specificity_of = {
            media_type: 2,
            media_type.split("/")[0] + "/*": 1,
        }
        match = None
        for media_range, q, position in ranges:
            specificity = specificity_of.get(media_range)
            if specificity is not None and (match is None or specificity > match[0]):
                match = (specificity, q, position)
        if match is None or match[1] == 0.0:
            continue
        specificity, q, position = match
        key = (q, specificity, -position)
        if best_key is None or key > best_key:
            best, best_key = fmt, key
    return best


def negotiate(request: Request) -> str:
    """Pick the response format for a lookup route: "html", "json" or "text".

    1. `?format=`, because it is the one a link or a shell one-liner can carry.
       An unknown value is a 400, as with `?subdomains=`: a value the server
       does not understand must not be answered as though it were understood.
    2. Accept, when it names one of the formats (see _accept_preference).
    3. The user-agent, only when Accept is absent or says nothing beyond */*.
       That is how every client was answered before Accept was read, and what
       curl, wget and a browser's fetch() still get by default.

    A query parameter rather than a path suffix: the security middleware
    classifies requests by path, and "/nasa.gov.json" matches its `\\.json$`
    rule. `request.url.path` never includes the query, so `?format=` leaves
    rate limiting and the probe detector exactly as they were.
    """
    requested = request.query_params.get("format")
    if requested is not None:
        fmt = requested.lower()
        if fmt not in _FORMAT_MEDIA_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"format must be one of: {', '.join(_FORMAT_MEDIA_TYPES)}",
            )
        return fmt
    return _negotiate_by_headers(request)


def _negotiate_by_headers(request: Request) -> str:
    """Steps 2 and 3 of negotiate(): Accept, then the user-agent."""
    preferred = _accept_preference(request.headers.get("accept", ""))
    if preferred is not None:
        return preferred
    user_agent = request.headers.get("user-agent", "")
    return "html" if BrowserDetector.is_browser(user_agent) else "json"


def wants_page(request: Request) -> bool:
    """Whether to answer an error with the error page: negotiate() says "html".

    An unknown ?format= is itself a 400 from negotiate(), and a 403 or 429 must
    not turn into that, so here the parameter is passed over and the headers
    decide, as they would have without it.
    """
    try:
        return negotiate(request) == "html"
    except HTTPException:
        return _negotiate_by_headers(request) == "html"


# Admin API key authentication dependency
def verify_admin_key(api_key: str = Header(None, alias="api-key")):
    """Dependency for admin endpoint authentication"""
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=404, detail="Not Found")
    if not hmac.compare_digest(api_key or "", ADMIN_API_KEY):
        raise HTTPException(status_code=404, detail="Not Found")
    return True


# Every 403 answers with exactly this. A blocked requester learns that they
# were blocked and nothing else: which rule fired — a manual ban, the country
# filter, a probe pattern — only helps whoever is probing to find the edge of
# it. The reason, the country and the matched path all stay in the log line
# next to each branch, which is where an operator can actually use them.
ACCESS_DENIED = {"error": "Access denied due to the policy"}


def _refusal(
    request: Request, status_code: int, content: dict, message: str = ""
) -> Response:
    """A security-middleware refusal: the error page for a client negotiate()
    would hand the page, and `content` as JSON, exactly as before, for any other.

    The page's heading is content["error"] itself, so the page never says more
    than the JSON does; for a 403 that is the point (see ACCESS_DENIED). /mcp
    gets JSON whatever asked: it is a JSON-RPC surface, and its responses go
    out without the CSP a page relies on.
    """
    path = request.url.path
    if path == "/mcp" or path.startswith("/mcp/"):
        return JSONResponse(status_code=status_code, content=content)
    if wants_page(request):
        response = render_error(request, status_code, content["error"], message)
    else:
        response = JSONResponse(status_code=status_code, content=content)
    # Answered before routing, so security_headers_middleware cannot tell this
    # is a lookup; but the body now depends on both headers wherever it is.
    response.headers.add_vary_header("Accept")
    response.headers.add_vary_header("User-Agent")
    return response


def _access_denied(request: Request) -> Response:
    return _refusal(request, 403, ACCESS_DENIED)


def _too_many_requests(request: Request) -> Response:
    # When to come back, not how long the ban that came with it lasts.
    return _refusal(request, 429, {"error": "Too many requests"}, "Try again later.")


def _suspicious_path_is_ordinary(request_path: str) -> bool:
    """Whether a path that matched a suspicious pattern is in fact ordinary
    traffic, and so must not be banned.

    The patterns match on shape, and a lookup target is a single path segment,
    so "/admin.php" and "/nasa.gov" are the same shape — which is why matching
    alone used to be enough to exempt every single-segment path and let probes
    through. What separates them is whether the segment has a public suffix:
    "admin.php" and ".env" do not, "nasa.gov" does. is_valid_domain answers from
    the list TldNamesManager keeps current, so a newly delegated TLD stops
    reading as a probe within one refresh interval rather than at the next
    release of the `tld` package.

    Static assets are exempt outright: `static/geo/*.json` matches the
    detector's `\\.json$` rule, and banning a visitor for loading the page's own
    data would be absurd.
    """
    if whitelist_manager.is_static(request_path):
        return True
    if not whitelist_manager.is_lookup(request_path):
        return False
    target = request_path.lstrip("/")
    if not target:  # "/" itself
        return True
    return domain_manager.is_valid_domain(target) or domain_manager.is_ipv4(target)


# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security middleware for IP banning, geo-blocking, and rate limiting"""
    client_ip = get_client_ip(request)
    request_path = request.url.path

    # A hand-written rule for this address, if there is one, decided before
    # anything else and honoured by every branch below. `block: true` refuses
    # outright; `block: false` is trust — never banned, no geo check, no probe
    # check — with the rate limiter still applied unless the rule waives it.
    rule = ip_rule_manager.match(client_ip)
    if rule and rule.block:
        logging.warning(
            "SECURITY: Refused %s by IP rule %s",
            sanitize_log_input(client_ip),
            rule.label,
        )
        return _access_denied(request)
    trusted = rule is not None and not rule.block
    rate_limited = rule.ratelimit if trusted else True

    # Admin endpoints: still check bans and rate limits, skip geo/suspicious checks
    if request_path.startswith("/admin/"):
        if not trusted and ip_ban_manager.is_banned(client_ip):
            logging.warning(
                "SECURITY: Blocked banned IP %s on admin endpoint",
                client_ip,
            )
            return _access_denied(request)
        if rate_limited and not rate_limiter.allow_request(client_ip):
            if not trusted:
                ip_ban_manager.ban_ip(
                    client_ip,
                    reason="rate_limit_admin",
                    duration=BAN_DURATION_RATE_LIMIT,
                )
            return _too_many_requests(request)
        return await call_next(request)

    # MCP endpoint: a manual ban still applies, but nothing here escalates.
    # Every user of a hosted AI client shares a handful of provider egress
    # IPs, so an automatic ban would take all of them offline at once, and the
    # provider's datacenter country says nothing about the user — geo-blocking
    # is meaningless. The payload is a JSON-RPC body, not a path, so the
    # suspicious-path detector has nothing to look at either. That includes an
    # automatic ban earned on the lookup paths (rate_limit, suspicious_request):
    # it still holds there, but only a manual ban carries over to /mcp.
    if request_path == "/mcp" or request_path.startswith("/mcp/"):
        if not trusted and ip_ban_manager.is_banned(client_ip, reason="manual"):
            logging.warning(
                "SECURITY: Blocked manually banned IP %s on MCP endpoint",
                sanitize_log_input(client_ip),
            )
            return JSONResponse(status_code=403, content=ACCESS_DENIED)
        # `request.body()` inside the SDK buffers the whole thing into memory
        # with no cap of its own — checked directly against the installed
        # package, there is no content-length check and no 413 anywhere in it.
        # /mcp is this service's first unauthenticated POST endpoint (every
        # other POST route sits behind ADMIN_API_KEY), so a caller with a
        # valid Host header and a multi-GB body can OOM the container before
        # the request ever reaches the SDK. Reject on Content-Length alone,
        # before the body is read; a missing/non-numeric length means chunked
        # transfer-encoding, which has no advertised size to check either.
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length is None or not content_length.isdigit():
                logging.warning(
                    "SECURITY: MCP request from %s has no valid Content-Length "
                    "(missing or chunked)",
                    sanitize_log_input(client_ip),
                )
                return JSONResponse(
                    status_code=413,
                    content={"error": "Content-Length header required"},
                )
            if int(content_length) > MCP_MAX_BODY_BYTES:
                logging.warning(
                    "SECURITY: MCP request from %s exceeds max body size (%s > %s)",
                    sanitize_log_input(client_ip),
                    content_length,
                    MCP_MAX_BODY_BYTES,
                )
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request body too large"},
                )
        if rate_limited and not mcp_rate_limiter.allow_request(client_ip):
            logging.warning(
                "SECURITY: MCP rate limit hit for %s (no ban)",
                sanitize_log_input(client_ip),
            )
            return JSONResponse(status_code=429, content={"error": "Too many requests"})
        return await call_next(request)

    # 1. Check if IP is banned (highest priority)
    if not trusted and ip_ban_manager.is_banned(client_ip):
        logging.warning(f"SECURITY: Blocked banned IP {client_ip}")
        return _access_denied(request)

    # 2. Check geographic restrictions
    geo_check = geo_block_manager.check_access(client_ip)
    if not trusted and not geo_check["allowed"]:
        logging.warning(
            f"SECURITY: Blocked {client_ip} from {geo_check['country']} "
            f"({geo_check['region']}) - {geo_check['reason']}"
        )
        return _access_denied(request)

    # 3. Check for suspicious patterns, unless the request is ordinary traffic.
    # The whitelist used to return early here, which also skipped the rate
    # limit below — so the two paths that do the real work, / and /{domain_ip},
    # were the only ones never rate limited. It now exempts a path from this
    # check alone; the limiter is gated separately, on is_static.
    if (
        not trusted
        and suspicious_detector.is_suspicious(request_path)
        and not _suspicious_path_is_ordinary(request_path)
    ):
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
        return _access_denied(request)

    # 4. Rate limit check. Static assets are exempt — a single page load fetches
    # a dozen of them, which would trip the per-second limit and ban a
    # first-time visitor before the page finished rendering. Everything else is
    # limited, including the lookup surface: that is where the DNS, RDAP/WHOIS
    # and TLS work happens, so it is exactly what needs the ceiling.
    if (
        rate_limited
        and not whitelist_manager.is_static(request_path)
        and not rate_limiter.allow_request(client_ip)
    ):
        if not trusted:
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
        return _too_many_requests(request)

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
    # CSP governs how a browser executes a document. The MCP response is JSON
    # for a non-browser client, so the header is noise there; the rest of the
    # hardening headers still apply.
    #
    # Match the MCP surface exactly, the same way the security middleware does.
    # A bare startswith("/mcp") would also catch "/mcpfoo.com" — a syntactically
    # valid domain, and a reachable HTML page via the /{domain_ip} catch-all —
    # silently stripping CSP from a real browser response.
    #
    # The WebRTC leak test's STUN request is not a fetch: neither default-src
    # nor connect-src covers it, so nothing here was widened for it, and the
    # page footer names the STUN server instead.
    _path = request.url.path
    if not (_path == "/mcp" or _path.startswith("/mcp/")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https://tile.openstreetmap.org; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
    # The lookup routes answer HTML or JSON from one URL depending on Accept
    # and the user-agent (negotiate()), and every answer describes the
    # visitor's own address and request headers: a cache in front must key on
    # both and keep neither. Matched on the endpoint that handled the request,
    # errors included, not on the path: /{domain_ip} is a catch-all, so no
    # path test tells it apart from /healthz.
    if request.scope.get("endpoint") in (get_self_info, get_ip_info, head_lookup):
        response.headers.add_vary_header("Accept")
        response.headers.add_vary_header("User-Agent")
        response.headers["Cache-Control"] = "no-store"
    # Obscure server fingerprinting.
    response.headers["server"] = "hidden"
    return response


_SUBDOMAIN_MODES = ("exclude", "include", "only")


def _subdomain_mode(raw: str | None) -> str:
    """Validate the `subdomains` query parameter.

    An unrecognised value is rejected rather than quietly treated as "exclude",
    following dns_records in mcp_server.py: a value the server does not
    understand must not be answered as though it were understood. "?subdomains=1"
    is therefore an error, not a synonym for "include".
    """
    if raw is None:
        return "exclude"
    if not SUBDOMAIN_ENABLED or raw.lower() not in _SUBDOMAIN_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"subdomains must be one of: {', '.join(_SUBDOMAIN_MODES)}",
        )
    return raw.lower()


# A dataset's refresh must fail this many times in a row before /healthz
# reports it. One failure has a retry an hour later that usually heals it; the
# retry failing too means the dataset is stuck, not unlucky.
REFRESH_FAILURES_DEGRADED = 2
# A scheduler job this far past its run time means the loop that runs jobs has
# stopped, even though the scheduler still reads as running.
SCHEDULER_STALL_SECONDS = 300


def _reason(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def health_reasons() -> list[dict[str, str]]:
    """Why the service is degraded; empty when it is not. Each reason is a
    stable `code` for machines and a `message` for people.

    Only what this process can see without a network call, so /healthz stays
    cheap enough to poll every 30 seconds: the datasets lookups are served
    from, the scheduler that refreshes them, and the RDAP servers currently
    being skipped."""
    reasons = []
    if geo_ip_manager.city_reader is None:
        reasons.append(
            _reason(
                "geoip_bundled",
                "GeoLite2-City is not loaded: country comes from the bundled "
                "geoip2fast snapshot, with no city, coordinates or time zone",
            )
        )
    if geo_ip_manager.asn_reader is None:
        reasons.append(
            _reason(
                "geoip_asn_missing",
                "GeoLite2-ASN is not loaded: carrier fields are empty",
            )
        )
    for edition, age in geo_ip_manager.build_ages().items():
        if age > GEOIP_MAX_BUILD_AGE_DAYS:
            reasons.append(
                _reason(
                    "geoip_build_stale",
                    f"{edition} build is {age:.0f} days old "
                    f"(limit {GEOIP_MAX_BUILD_AGE_DAYS:g})",
                )
            )
    if tld_names_manager.is_overdue():
        age = tld_names_manager.age_days()
        reasons.append(
            _reason(
                "public_suffix_list_overdue",
                f"the public suffix list is {age:.0f} days old"
                if age is not None
                else "the public suffix list has never been downloaded "
                f"(source: {tld_names_manager.status()['source']})",
            )
        )
    if not scheduler.running:
        reasons.append(
            _reason(
                "scheduler_stopped",
                "the background scheduler is not running: nothing is refreshed",
            )
        )
    else:
        now = datetime.datetime.now(datetime.timezone.utc)
        stalled = sorted(
            job.id
            for job in scheduler.get_jobs()
            if job.next_run_time is not None
            and (now - job.next_run_time).total_seconds() > SCHEDULER_STALL_SECONDS
        )
        if stalled:
            reasons.append(
                _reason(
                    "scheduler_stopped",
                    f"scheduler jobs are over {SCHEDULER_STALL_SECONDS}s overdue "
                    f"({', '.join(stalled)}): the loop that runs them has stopped",
                )
            )
    for name, failures in sorted(_refresh_failures.items()):
        if failures >= REFRESH_FAILURES_DEGRADED:
            reasons.append(
                _reason(
                    "refresh_failing",
                    f"{name} refresh has failed {failures} times in a row",
                )
            )
    open_hosts = rdap_breaker.open_hosts()
    if open_hosts:
        reasons.append(
            _reason(
                "rdap_breaker_open",
                "RDAP servers skipped after repeated failures, so their "
                f"lookups fail fast: {', '.join(open_hosts)}",
            )
        )
    return reasons


# HEAD is accepted on the fixed routes below because answering it costs
# nothing: the handler runs as for GET and the server drops the body. FastAPI's
# @app.get answers GET alone, so an uptime monitor's HEAD used to get a 405.
@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthz():
    """Liveness, the deployed commit, "ok" or "degraded" with the `reasons`,
    and which GeoIP databases are actually serving lookups. Declared before
    /{domain_ip}, which would otherwise swallow the path.

    Degraded still answers 200. The container HEALTHCHECK only asks whether the
    process answers, since a restart fixes neither a stale database nor an RDAP
    server that is down; the external probe reads `status` itself.

    `version` is the deployed commit; the deploy workflow reads it back to
    confirm production runs the SHA it shipped. Keep it ahead of the nested
    objects: the runner has no JSON parser, so the workflow takes the first
    "version" in the body."""
    reasons = health_reasons()
    return {
        "status": "degraded" if reasons else "ok",
        "version": APP_VERSION,
        "reasons": reasons,
        "databases": geo_ip_manager.database_status(),
        "public_suffix_list": tld_names_manager.status(),
    }


# Crawlers are welcome on the lookup pages, but the page links "Load
# subdomains" for every domain it shows, and on a cache miss that link is a
# crt.sh round trip. There is deliberately no sitemap: it would need an
# exception to the detector's `\.xml$` rule, and all it would do is send
# crawlers to the expensive pages.
_ROBOTS_TXT = "User-agent: *\nDisallow: /*?subdomains=\n"


@app.api_route("/robots.txt", methods=["GET", "HEAD"])
async def robots_txt():
    """Declared before /{domain_ip}, which would otherwise look robots.txt up
    as a domain and hand the crawler an HTML page."""
    return PlainTextResponse(_ROBOTS_TXT)


@app.api_route("/favicon.ico", methods=["GET", "HEAD"])
async def favicon():
    """The page links its icons under /static, but browsers and link unfurlers
    still ask for /favicon.ico on their own, and the catch-all used to answer
    each one with an RDAP query and a port-43 WHOIS attempt."""
    return RedirectResponse("/static/favicon.ico", status_code=301)


def _text_error(message: str, status_code: int = 400) -> PlainTextResponse:
    return PlainTextResponse(render_text_error(message), status_code=status_code)


def _invalid_field(exc: InvalidFieldError, fmt: str) -> Response:
    """The 400 for a bad ?fields=. Every lookup route checks it before any
    lookup, so a typo costs nothing and reads the same on each of them."""
    if fmt == "text":
        return _text_error(exc.message)
    return JSONResponse(
        status_code=400, content={"error": exc.message, "code": exc.code}
    )


def _busy(request: Request, fmt: str) -> Response:
    """The 503 for a lookup the gate turned away (concurrency.LookupBusy), in
    the format its answer would have had.

    Answered by the route, after the security middleware let the request in,
    so it reaches no ban, probe or escalation logic: a full server is not the
    visitor's doing. The request did count against the visitor's rate limit on
    the way in, as every lookup does; refunding it would let one address send
    without limit for as long as the gate stays full.
    """
    if fmt == "text":
        response = _text_error(LookupBusy.message, 503)
    elif fmt == "html":
        response = render_error(
            request,
            503,
            "Too busy right now",
            "Too many lookups are running at once. Try again in a few seconds.",
        )
    else:
        response = JSONResponse(
            status_code=503, content={"error": LookupBusy.message, "code": "busy"}
        )
    response.headers["Retry-After"] = str(LOOKUP_BUSY_RETRY_AFTER_SECONDS)
    return response


def _fields_response(
    data: dict, names: list[str], kind: str, fmt: str, block: bool = False
) -> Response | dict:
    """`names` cut from a gather()-shaped dict: text when text was negotiated,
    JSON otherwise. There is no page to render for a handful of values, so a
    browser following a ?fields= link gets JSON, as with ?subdomains=only."""
    values, errors = field_values(data, kind)
    if fmt == "text":
        render = render_block if block else render_lines
        return PlainTextResponse(render(names, values, errors))
    return render_json(names, values, errors)


async def _self_fields(client_ip: str, names: list[str]) -> dict:
    """get_self_info's lookups, cut down to the legs `names` need and shaped
    like gather()'s result. Not gather() itself: that refuses a private
    address, and the visitor's own address is answered whatever it is.
    LookupBusy, as from gather(), when the gate has no slot for it."""
    legs = legs_for(names, "ip")
    # The same rule as the full self lookup: a private address has no public
    # registration or PTR, so neither is asked for.
    public_client = is_safe_ip(client_ip)
    networked = legs & {"whois", "ptr"} if public_client else frozenset()
    # Only those two leave the process; GeoIP is a local read. A request for
    # neither, such as ?fields=ip,country_code, takes no slot at the lookup
    # gate, any more than ?format=text does.
    async with lookup_gate.slot() if networked else contextlib.nullcontext():
        whois_task = (
            asyncio.create_task(lookup_whois(client_ip))
            if "whois" in networked
            else None
        )
        reverse_task = (
            asyncio.create_task(
                asyncio.to_thread(domain_manager.perform_reverse_lookup, client_ip)
            )
            if "ptr" in networked
            else None
        )
        location = await lookup_location(client_ip) if "geo" in legs else {}
        return {
            "address": client_ip,
            "resolved_ip": client_ip,
            "reverse_dns": await reverse_task if reverse_task else None,
            "location": location,
            "whois": await whois_task if whois_task else None,
            "ssl": None,
        }


async def _self_lookup(client_ip: str) -> tuple[dict, dict, dict]:
    """get_self_info's lookups: the visitor's location (with its PTR name), the
    record sweep of that name, and the registration of the address. They run
    while a slot at the lookup gate is held, as gather()'s legs do; LookupBusy
    when none comes free."""
    # A private or reserved client address -- a dev server with no proxy in
    # front, or a proxy this server was not told to trust -- has no public
    # registration and no PTR a public resolver would know, so neither is
    # asked for. GeoIP is a local database and still runs.
    public_client = is_safe_ip(client_ip)

    async with lookup_gate.slot():
        # WHOIS is the slow one (seconds); it has nothing to do with GeoIP or
        # the reverse lookup, so none of these wait on each other.
        whois_task = (
            asyncio.create_task(lookup_whois(client_ip)) if public_client else None
        )
        location_task = asyncio.create_task(lookup_location(client_ip))
        reverse_task = (
            asyncio.create_task(
                asyncio.to_thread(domain_manager.perform_reverse_lookup, client_ip)
            )
            if public_client
            else None
        )

        ip_data = await location_task
        reverse_dns_hostname = await reverse_task if reverse_task else None
        if reverse_dns_hostname:
            ip_data["reverse_dns"] = reverse_dns_hostname

        domain_records = (
            await asyncio.to_thread(
                lambda: domain_manager.get_records(reverse_dns_hostname, ip=client_ip)
            )
            if reverse_dns_hostname
            else {}
        )
        # An error, not {} or "not registered": nothing was asked, and the page
        # should say so rather than pass that off as an answer.
        whois_data = (
            await whois_task
            if whois_task
            else {"error": "Not looked up: private or reserved address"}
        )
    return ip_data, domain_records, whois_data


async def _target_fields(target: str, names: list[str] | None, fmt: str):
    """/{domain_ip} as text or as ?fields=: only the legs the fields need, and
    none of the map, the visitor's own location or the subdomain list, which
    neither answer carries. `names` None is the whole text block."""
    kind = "domain" if classify_target(target) == "domain" else "ip"
    block = names is None
    if block:
        names = block_fields(kind)
    try:
        data = await gather(target, legs=legs_for(names, kind))
    except InvalidTargetError as exc:
        if fmt == "text":
            return _text_error(exc.message)
        return JSONResponse(
            status_code=400, content={"error": exc.message, "code": exc.code}
        )
    except PrivateAddressError:
        message = "Private or reserved IP addresses are not allowed"
        if fmt == "text":
            return _text_error(message)
        raise HTTPException(status_code=400, detail=message) from None
    return _fields_response(data, names, kind, fmt, block=block)


@app.head("/")
@app.head("/{domain_ip}")
async def head_lookup(request: Request):
    """HEAD on the lookup surface, answered without looking anything up.

    HEAD is what uptime monitors and link checkers send, and it only asks
    whether the page is there. Running WHOIS, DNS and TLS for a body that is
    then thrown away would make the cheapest request the most expensive one.
    So the answer is 200 with the Content-Type GET would negotiate; whether
    this particular target would get a 400 is not checked, since finding out
    takes the lookup this exists to skip.

    This is a route, not a middleware, so it runs after the security
    middleware like everything else: a banned or geo-blocked address still
    gets its 403, a probe path is still banned, and the request still counts
    against the lookup rate limit. Routing also decides what is a lookup, so
    /healthz, /robots.txt and /mcp keep their own handling.
    """
    # Same negotiation as GET, so a bad ?format= or ?fields= is the same 400.
    fmt = negotiate(request)
    try:
        names = parse_fields(request.query_params.getlist("fields"))
    except InvalidFieldError as exc:
        return _invalid_field(exc, fmt)
    if fmt == "text":
        media_type = "text/plain"
    elif fmt == "json" or names is not None:
        media_type = "application/json"
    else:
        media_type = "text/html"
    response = Response(media_type=media_type)
    # A HEAD response may carry Content-Length only if it equals what GET would
    # send (RFC 9110 8.6). Starlette sets 0 for the empty body, and the real
    # length is unknown without the lookup, so the header goes.
    del response.headers["content-length"]
    return response


@app.get("/", response_model=None)
async def get_self_info(request: Request):
    # First, so an unknown ?format= or ?fields= is refused before any lookup
    # starts.
    fmt = negotiate(request)
    try:
        names = parse_fields(request.query_params.getlist("fields"))
    except InvalidFieldError as exc:
        return _invalid_field(exc, fmt)
    started = time.perf_counter()
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    client_ip = get_client_ip(request)
    sanitized_ip = sanitize_log_input(client_ip)
    logging.info("client=%s lookup=%s (self)", sanitized_ip, sanitized_ip)

    if names is not None:
        try:
            data = await _self_fields(client_ip, names)
        except LookupBusy:
            # In the format the fields would have come in: never the page.
            return _busy(request, "text" if fmt == "text" else "json")
        return _fields_response(data, names, "ip", fmt)
    if fmt == "text":
        # `curl ip.1kko.com?format=text`: the address is already known, so the
        # answer is that and nothing else -- no WHOIS, GeoIP or DNS, and no
        # slot at the lookup gate.
        return PlainTextResponse(client_ip + "\n")

    try:
        ip_data, domain_records, whois_data = await _self_lookup(client_ip)
    except LookupBusy:
        return _busy(request, fmt)

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

    if fmt == "html":
        return render_page(request, response_data, is_self=True)

    # FastAPI serialises the dict via jsonable_encoder (datetimes -> ISO-8601)
    # and its default JSONResponse (UTF-8, no ASCII escaping).
    return response_data


@app.get("/{domain_ip}", response_model=None)
async def get_ip_info(domain_ip: str, request: Request, subdomains: str | None = None):
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

    fmt = negotiate(request)
    try:
        mode = _subdomain_mode(subdomains)
    except HTTPException as exc:
        if fmt == "text":
            return _text_error(exc.detail, exc.status_code)
        raise
    try:
        names = parse_fields(request.query_params.getlist("fields"))
    except InvalidFieldError as exc:
        return _invalid_field(exc, fmt)

    if mode == "only":
        # Skips gather() entirely: this mode exists so the page's toggle can ask
        # for the list alone rather than re-running DNS, TLS, GeoIP and the map
        # payload for data it already has. Always JSON, whatever was
        # negotiated: there is no page to render for a bare list.
        #
        # Not is_valid_domain: that asks only whether the target has a public
        # suffix, and `com` does -- it IS one. The MCP tool asks the same
        # function this does.
        reason = invalid_target_reason(domain_ip)
        if reason:
            raise HTTPException(status_code=400, detail=reason)
        return {
            "address": domain_ip,
            "subdomains": await get_subdomains(domain_ip),
        }

    if fmt == "text" or names is not None:
        # Neither carries a subdomain list, so ?subdomains=include starts no
        # crt.sh fetch here; ?subdomains=only above is the way to ask for one.
        try:
            return await _target_fields(domain_ip, names, fmt)
        except LookupBusy:
            # In the format the answer would have come in: never the page.
            return _busy(request, "text" if fmt == "text" else "json")

    # The visitor's own location only feeds the distance line, so it runs
    # alongside the target lookup rather than after it.
    origin_task = asyncio.create_task(lookup_location(client_ip))
    # An IP target burns a budget slot and a crt.sh round trip that cannot
    # possibly match -- and a public suffix or a wildcard, one that matches
    # far too much -- so `include` gets the same target gate `only` already
    # has above, just without rejecting the request: `include` is additive,
    # so the target still gets its normal lookup, only without a subdomains
    # fetch.
    subdomain_task = (
        asyncio.create_task(get_subdomains(domain_ip))
        if mode == "include" and invalid_target_reason(domain_ip) is None
        else None
    )
    try:
        data = await gather(domain_ip)
    except (PrivateAddressError, InvalidTargetError) as exc:
        origin_task.cancel()
        if subdomain_task is not None:
            subdomain_task.cancel()
        if fmt == "html":
            return render_refused_target(request, domain_ip, exc)
        if isinstance(exc, InvalidTargetError):
            # `code` lets a client tell "not a target at all" from the other
            # 400s (a bad ?fields=, say) without parsing the message.
            return JSONResponse(
                status_code=400, content={"error": exc.message, "code": exc.code}
            )
        raise HTTPException(
            status_code=400,
            detail="Private or reserved IP addresses are not allowed",
        ) from None
    except LookupBusy:
        origin_task.cancel()
        if subdomain_task is not None:
            subdomain_task.cancel()
        return _busy(request, fmt)

    origin_location = await origin_task
    ip_data = data["location"]
    map_payload, distance_km, origin, target = await asyncio.to_thread(
        build_map_payload, ip_data, origin_location
    )
    _apply_resolved_target(ip_data, target)

    response_data = {
        "address": data["address"],
        # Same meaning as in the MCP dns_records tool: the address the target
        # resolved to, and how (see gather()), so a null address says why.
        "resolved_ip": data["resolved_ip"],
        "resolution": data.get("resolution"),
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

    if subdomain_task is not None:
        response_data["subdomains"] = await subdomain_task

    if fmt == "html":
        return render_page(request, response_data, is_self=False)

    # FastAPI serialises the dict via jsonable_encoder (datetimes -> ISO-8601)
    # and its default JSONResponse (UTF-8, no ASCII escaping).
    return response_data


# Admin endpoints for security management
@app.get("/admin/ip-rules")
async def get_ip_rules(authenticated: bool = Depends(verify_admin_key)):
    """The hand-written per-IP overrides currently loaded.

    Read-only on purpose: the file is edited by a person and re-read on mtime
    change, so there is nothing here to write. This exists to answer "is my
    entry actually in effect?" without shelling into the container.
    """
    return {"file": ip_rule_manager.rules_file, "rules": ip_rule_manager.as_list()}


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
