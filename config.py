"""Environment-driven configuration.

Every tunable the app reads from the environment lives here so the managers,
the security subsystem, and the FastAPI wiring can all import the same values
without importing each other. Pure values only — no logging, no I/O, no app
objects — which is what keeps this module free of import cycles.
"""

import os

from dotenv import load_dotenv

# Load .env before any getenv below. load_dotenv() does not override variables
# already set in the environment, so tests (which set them in conftest) win.
load_dotenv()

TIMEOUT_SECONDS = 5

# DNS record sweep: query the fast, cached public resolvers concurrently with a
# bounded per-query budget. Switching to a domain's authoritative nameservers and
# issuing every record type in series turned one slow/distant nameserver (and the
# PTR/MX-host queries those servers never answer) into 20-30s stalls.
PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1"]
DNS_QUERY_TIMEOUT = float(os.getenv("DNS_QUERY_TIMEOUT", "2"))  # per nameserver
DNS_QUERY_LIFETIME = float(os.getenv("DNS_QUERY_LIFETIME", "3"))  # per query, total

# RDAP is a single HTTPS GET, so it answers in well under a second when the TLD
# supports it; give it a tight budget and fall back to port-43 WHOIS otherwise.
# Some registries (naver.com, ibm.com, .pt ...) answer WHOIS in ~11s, so give the
# slow tail room; the result is cached for 6h and the lookup runs in parallel.
RDAP_TIMEOUT_SECONDS = float(os.getenv("RDAP_TIMEOUT_SECONDS", "8"))
WHOIS_TIMEOUT_SECONDS = float(os.getenv("WHOIS_TIMEOUT_SECONDS", "15"))
WHOIS_CACHE_TTL = int(os.getenv("WHOIS_CACHE_TTL", "21600"))  # 6h for a hit
WHOIS_CACHE_ERROR_TTL = int(os.getenv("WHOIS_CACHE_ERROR_TTL", "300"))  # 5m for a miss

# Rate Limiting Configuration
RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
RATE_LIMIT_REQUESTS_PER_SECOND = int(os.getenv("RATE_LIMIT_REQUESTS_PER_SECOND", "10"))

# Ban Duration Configuration (in seconds)
BAN_DURATION_RATE_LIMIT = int(os.getenv("BAN_DURATION_RATE_LIMIT", "3600"))  # 1 hour
BAN_DURATION_SUSPICIOUS = int(os.getenv("BAN_DURATION_SUSPICIOUS", "86400"))  # 24 hours

# File Paths
BANNED_IPS_FILE = os.getenv("BANNED_IPS_FILE", "data/banned_ips.json")
GEO_RULES_FILE = os.getenv("GEO_RULES_FILE", "data/geo_rules.json")
# GeoIP DB lives in a writable volume; the bundled DB inside the geoip2fast
# package directory is read-only when the container runs as a non-root user.
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DATA_FILE = os.getenv(
    "GEOIP_DATA_FILE",
    os.path.join(_APP_DIR, "data", "geoip2fast.dat.gz"),
)

# City-level geolocation from a GeoLite2-City mmdb. geoip2fast supplies country
# and ASN but leaves latitude/longitude null; this overlays real coordinates,
# the precise city, and an accuracy radius. The source URL is configurable, so
# the free mirror can be swapped for a personal MaxMind licence, DB-IP, or a
# local file without any code change.
GEOIP_CITY_DB_URL = os.getenv(
    "GEOIP_CITY_DB_URL",
    "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz",
)
GEOIP_CITY_DB_FILE = os.getenv(
    "GEOIP_CITY_DB_FILE",
    os.path.join(_APP_DIR, "data", "GeoLite2-City.mmdb"),
)

# ASN (carrier/org) from a GeoLite2-ASN mmdb, refreshed twice weekly upstream.
# geoip2fast's own ASN snapshot stays as the fallback, but its release cadence
# stalls for weeks at a time, so the overlay is what keeps carriers current.
GEOIP_ASN_DB_URL = os.getenv(
    "GEOIP_ASN_DB_URL",
    "https://cdn.jsdelivr.net/npm/geolite2-asn/GeoLite2-ASN.mmdb.gz",
)
GEOIP_ASN_DB_FILE = os.getenv(
    "GEOIP_ASN_DB_FILE",
    os.path.join(_APP_DIR, "data", "GeoLite2-ASN.mmdb"),
)

# Official MaxMind GeoLite2 downloads. When both are set, the city and ASN
# overlays are fetched from MaxMind's licensed endpoint (a .tar.gz over HTTP
# Basic auth) instead of the free mirrors above, falling back to those mirrors
# on failure. Get them free at https://www.maxmind.com/en/geolite2/signup.
MAXMIND_ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
MAXMIND_CITY_EDITION = os.getenv("MAXMIND_CITY_EDITION", "GeoLite2-City")
MAXMIND_ASN_EDITION = os.getenv("MAXMIND_ASN_EDITION", "GeoLite2-ASN")

# Public Suffix List (Mozilla), the list `tld` parses and therefore what
# DomainManager.is_valid_domain answers from. It decides whether a single-segment
# request is a real lookup target ("nasa.gov") or a probe ("admin.php"), so a
# stale copy means a newly delegated TLD reads as a probe.
#
# Two problems with leaving it to the `tld` package. Its bundled snapshot ages
# with the release, and on a cache miss it downloads the list synchronously
# inside whichever request needs it first — writing into its own package
# directory, which is root-owned once the container drops to appuser, so the
# write fails and every later lookup retries it. The list therefore lives in the
# writable data volume, seeded from the bundled copy at startup and refreshed on
# a schedule, never from a request.
TLD_NAMES_DIR = os.getenv("TLD_NAMES_DIR", os.path.join(_APP_DIR, "data", "tld"))
TLD_LIST_URL = os.getenv(
    "TLD_LIST_URL", "https://publicsuffix.org/list/public_suffix_list.dat"
)
# The PSL changes most weeks, but only at the margins; a fortnight bounds how
# long a brand-new suffix can be mistaken for a probe.
TLD_MAX_AGE_DAYS = int(os.getenv("TLD_MAX_AGE_DAYS", "14"))
TLD_UPDATE_RETRY_SECONDS = int(os.getenv("TLD_UPDATE_RETRY_SECONDS", "3600"))

# Background Job Intervals (seconds)
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "300"))
RATE_LIMIT_CLEANUP_INTERVAL = int(os.getenv("RATE_LIMIT_CLEANUP_INTERVAL", "60"))
# How soon to retry a failed GeoIP database refresh. The regular refresh runs
# every 3 days; without this, one failed run leaves stale (or bundled-fallback)
# data in place for the whole interval.
GEOIP_UPDATE_RETRY_SECONDS = int(os.getenv("GEOIP_UPDATE_RETRY_SECONDS", "3600"))

# Geographic Blocking Configuration (optional initial values from .env)
GEO_MODE_INITIAL = os.getenv("GEO_MODE", "disabled")
GEO_BLOCKED_COUNTRIES_INITIAL = (
    [c.strip() for c in os.getenv("GEO_BLOCKED_COUNTRIES", "").split(",")]
    if os.getenv("GEO_BLOCKED_COUNTRIES")
    else []
)
GEO_ALLOWED_COUNTRIES_INITIAL = (
    [c.strip() for c in os.getenv("GEO_ALLOWED_COUNTRIES", "").split(",")]
    if os.getenv("GEO_ALLOWED_COUNTRIES")
    else []
)
GEO_BLOCK_UNKNOWN_INITIAL = os.getenv("GEO_BLOCK_UNKNOWN", "false").lower() == "true"

TRUSTED_PROXIES = [
    p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()
]

# Canonical public URL, e.g. https://ip.1kko.com. Set this when the reverse proxy
# does not forward x-forwarded-proto: without it the copyable curl command would
# say http://, the proxy would answer 302, and curl would just print "Found".
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()

# The domain shown as the footer wordmark when the visitor's host is missing or
# a bare IP (i.e. there is no real domain to show).
SITE_DOMAIN_FALLBACK = os.getenv("SITE_DOMAIN_FALLBACK", "ip.1kko.com")

# The desktop hero text sits over the left half of the band, so the map is
# focused right of centre and fitted into the free width beside it. Both canvases
# fetch tiles at native zoom (tile_zoom_offset 0) so roads and place names stay
# legible; that costs ~15 tile requests on desktop and ~6 on mobile.
DESKTOP_CANVAS = {"width": 1440, "height": 380, "focus_x": 0.58, "fit_ratio": 0.4}
MOBILE_CANVAS = {"width": 350, "height": 255, "focus_x": 0.5, "fit_ratio": 0.78}

# MCP (Model Context Protocol) endpoint. Set MCP_ENABLED=false to drop the
# mount and its lifespan entirely, so the endpoint can be turned off with an
# env change and a restart rather than a deploy.
MCP_ENABLED = os.getenv("MCP_ENABLED", "true").lower() != "false"

# streamable_http_app() cannot know the hostname it is served behind, so with
# no allowlist it arms DNS-rebinding protection for localhost only and answers
# EVERY production request with 421 Misdirected Request. Entries are exact
# strings: list both the bare host and the ":*" any-port form.
MCP_ALLOWED_HOSTS = [
    h.strip()
    for h in os.getenv("MCP_ALLOWED_HOSTS", "ip.1kko.com,ip.1kko.com:*").split(",")
    if h.strip()
]

# The SDK's transport_security treats a request with no Origin header as
# same-origin (always allowed — most MCP clients are backend processes and
# never send one), but 403s any request that *does* carry one unless it's
# listed here. Empty by default, matching MCP_ALLOWED_HOSTS's "nothing
# wildcarded unless configured" posture; set this if a specific browser-based
# MCP client needs to be let through.
MCP_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()
]

# MCP traffic gets its own bucket. Every user of a hosted AI client arrives from
# a handful of provider egress IPs, so this is far looser than the browser limit
# and, unlike it, never escalates to a ban (see the /mcp branch in main.py).
MCP_RATE_LIMIT_PER_MINUTE = int(os.getenv("MCP_RATE_LIMIT_PER_MINUTE", "120"))
# 5, not the browser path's 10: no legitimate agent bursts anywhere near that,
# and each request can spin up a nested thread pool (see mcp_server._bounded_gather).
MCP_RATE_LIMIT_PER_SECOND = int(os.getenv("MCP_RATE_LIMIT_PER_SECOND", "5"))

# 256 KiB is generous for a JSON-RPC call — the SDK itself enforces no cap
# (see security_middleware's /mcp branch, which rejects an oversized or
# unbounded-length body with 413 before it's ever read into memory).
MCP_MAX_BODY_BYTES = int(os.getenv("MCP_MAX_BODY_BYTES", str(256 * 1024)))
