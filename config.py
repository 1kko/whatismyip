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

# Official MaxMind GeoLite2-City download. When both are set, the city overlay is
# fetched from MaxMind's licensed endpoint (a .tar.gz over HTTP Basic auth)
# instead of the free mirror above, falling back to that mirror on failure. Get
# them free at https://www.maxmind.com/en/geolite2/signup.
MAXMIND_ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
MAXMIND_CITY_EDITION = os.getenv("MAXMIND_CITY_EDITION", "GeoLite2-City")

# Background Job Intervals (seconds)
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "300"))
RATE_LIMIT_CLEANUP_INTERVAL = int(os.getenv("RATE_LIMIT_CLEANUP_INTERVAL", "60"))

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
