#!/usr/bin/env python3

import asyncio
import datetime
import gzip
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import time
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Dict
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import maxminddb
import orjson
import uvicorn
import whois
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, ORJSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from geoip2fast import GeoIP2Fast
from pydantic import BaseModel

from geo import MIN_ROUTE_KM, Gazetteer, haversine_km
from mapgeom import build_canvas
from rdap import lookup_rdap, normalize_whois, refresh_rdap_bootstrap
from viewmodel import build_view, whois_display
from tld import exceptions as tld_exceptions
from tld import get_tld

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

TIMEOUT_SECONDS = 5

# DNS record sweep: query the fast, cached public resolvers concurrently with a
# bounded per-query budget. The old code switched to the domain's authoritative
# nameservers and issued every record type in series, so one slow or distant
# nameserver (and the PTR/MX-host queries those servers never answer) turned into
# 20-30s stalls. get_records was the single biggest source of tail latency.
PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1"]
DNS_QUERY_TIMEOUT = float(os.getenv("DNS_QUERY_TIMEOUT", "2"))  # per nameserver
DNS_QUERY_LIFETIME = float(os.getenv("DNS_QUERY_LIFETIME", "3"))  # per query, total

# WHOIS is slow (~1.2s median, up to a ~10s timeout ceiling on some registries)
# and its data is effectively static, so cache it and cap how long a single
# lookup may block the response.
# Some registries (naver.com, ibm.com, .pt ...) answer WHOIS in ~11s. A tight
# cap turned those into "lookup timed out" failures, so give the slow tail room;
# the result is cached for 6h and the lookup runs in parallel with everything.
# RDAP is a single HTTPS GET, so it answers in well under a second when the TLD
# supports it; give it a tight budget and fall back to port-43 WHOIS otherwise.
RDAP_TIMEOUT_SECONDS = float(os.getenv("RDAP_TIMEOUT_SECONDS", "8"))
WHOIS_TIMEOUT_SECONDS = float(os.getenv("WHOIS_TIMEOUT_SECONDS", "15"))
WHOIS_CACHE_TTL = int(os.getenv("WHOIS_CACHE_TTL", "21600"))  # 6h for a hit
WHOIS_CACHE_ERROR_TTL = int(os.getenv("WHOIS_CACHE_ERROR_TTL", "300"))  # 5m for a miss


def _recursive_resolver() -> dns.resolver.Resolver:
    """A resolver pointed at the public recursive DNS servers.

    Public resolvers are heavily cached and close to the datacentre, so they
    answer far faster than a domain's own authoritative nameservers, and they
    actually answer PTR / MX-host A queries (which authoritative NS refuse).
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_RESOLVERS)
    resolver.timeout = DNS_QUERY_TIMEOUT
    resolver.lifetime = DNS_QUERY_LIFETIME
    return resolver


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


class SafeORJSONResponse(ORJSONResponse):
    # python-whois returns sets and other non-JSON-native types; fall back to str
    # so the API path matches the browser path's json.dumps(default=str) behavior.
    def render(self, content: Any) -> bytes:
        return orjson.dumps(content, default=str)


def sanitize_log_input(value: str) -> str:
    """Remove control characters from log inputs to prevent log injection."""
    return value.replace("\n", "").replace("\r", "").replace("\x00", "")


# Security Configuration from Environment Variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY or ADMIN_API_KEY == "CHANGE_ME_TO_SECURE_RANDOM_STRING":
    logger.warning(
        "ADMIN_API_KEY not set or using default value in .env file! "
        "Admin endpoints will be disabled. Generate one with: "
        'python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )
    ADMIN_API_KEY = None

# Rate Limiting Configuration
RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
RATE_LIMIT_REQUESTS_PER_SECOND = int(os.getenv("RATE_LIMIT_REQUESTS_PER_SECOND", "10"))

# Ban Duration Configuration (in seconds)
BAN_DURATION_RATE_LIMIT = int(os.getenv("BAN_DURATION_RATE_LIMIT", "3600"))  # 1 hour
BAN_DURATION_SUSPICIOUS = int(os.getenv("BAN_DURATION_SUSPICIOUS", "86400"))  # 24 hours

# File Paths
BANNED_IPS_FILE = os.getenv("BANNED_IPS_FILE", "data/banned_ips.json")
GEO_RULES_FILE = os.getenv("GEO_RULES_FILE", "data/geo_rules.json")
# GeoIP DB lives in a writable volume; the bundled DB inside the
# geoip2fast package directory is read-only when the container runs as a non-root user.
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

# Background Job Intervals
CLEANUP_INTERVAL_SECONDS = int(
    os.getenv("CLEANUP_INTERVAL_SECONDS", "300")
)  # 5 minutes
RATE_LIMIT_CLEANUP_INTERVAL = int(
    os.getenv("RATE_LIMIT_CLEANUP_INTERVAL", "60")
)  # 1 minute

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


class WhoisResponse(BaseModel):
    address: str
    datetime: datetime.datetime
    domain: dict
    location: dict
    whois: dict
    ssl: dict | None
    headers: dict

    class Config:
        json_schema_extra = {
            "example": {
                "address": "8.8.8.8",
                "datetime": "2024-09-24T06:55:45.597769Z",
                "location": {
                    "ip": "8.8.8.8",
                    "country_code": "US",
                    "country_name": "United States",
                    "city": {
                        "name": "",
                        "subdivision_code": "",
                        "subdivision_name": "",
                        "latitude": None,
                        "longitude": None,
                    },
                    "cidr": "8.8.8.0/23",
                    "hostname": "",
                    "asn_name": "GOOGLE",
                    "asn_cidr": "8.8.8.0/24",
                    "is_private": False,
                },
                "whois": {
                    "domain_name": "GOOGLE.COM",
                    "registrar": "MARKMONITOR INC.",
                    "whois_server": "whois.markmonitor.com",
                    "referral_url": None,
                    "updated_date": "2020-09-09 09:21:45",
                    "creation_date": "1997-09-15 04:00:00",
                    "expiration_date": "2028-09-14 04:00:00",
                    "name_servers": [
                        "NS1.GOOGLE.COM",
                        "NS2.GOOGLE.COM",
                        "NS3.GOOGLE.COM",
                        "NS4.GOOGLE.COM",
                    ],
                    "status": "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
                    "emails": "abusecomplaints@markmonitor.com",
                    "dnssec": "unsigned",
                    "name": None,
                    "org": "Google LLC",
                    "address": None,
                    "city": None,
                    "state": "CA",
                    "zipcode": None,
                    "country": "US",
                },
            }
        }


class GeoRulesUpdate(BaseModel):
    model_config = {"extra": "forbid"}

    mode: str | None = None
    blocked_countries: list[str] | None = None
    allowed_countries: list[str] | None = None
    blocked_regions: list[str] | None = None
    allowed_regions: list[str] | None = None
    block_unknown: bool | None = None
    bypass_ips: list[str] | None = None


class GeoIpManager:
    def __init__(self):
        if os.path.exists(GEOIP_DATA_FILE):
            self.instance = GeoIP2Fast(geoip2fast_data_file=GEOIP_DATA_FILE)
        else:
            self.instance = GeoIP2Fast()
        self.city_reader = self._open_city_reader()

    @staticmethod
    def _open_city_reader():
        if os.path.exists(GEOIP_CITY_DB_FILE):
            try:
                return maxminddb.open_database(GEOIP_CITY_DB_FILE)
            except Exception:
                logging.exception("Could not open GeoLite2-City database")
        return None

    def update_database(self):
        try:
            data_dir = os.path.dirname(GEOIP_DATA_FILE)
            if data_dir:
                os.makedirs(data_dir, exist_ok=True)
            update_result = self.instance.update_file(
                "geoip2fast-city-asn-ipv6.dat.gz", GEOIP_DATA_FILE, verbose=False
            )
            # Re-instantiate so the running process picks up the new file.
            self.instance = GeoIP2Fast(geoip2fast_data_file=GEOIP_DATA_FILE)
            logging.info(f"{update_result=}")
        except Exception as e:
            logging.exception(f"Error updating GeoIP2Fast database: {str(e)}")

    def update_city_database(self):
        """Download and unpack the GeoLite2-City mmdb, then hot-swap the reader.
        The mirror tracks MaxMind's twice-weekly release; the URL is env-tunable
        so it can point at a licensed MaxMind download or a local file instead."""
        try:
            os.makedirs(os.path.dirname(GEOIP_CITY_DB_FILE), exist_ok=True)
            # GEOIP_CITY_DB_URL is operator-set config (an https mirror or a
            # local file:// path), not user input, so any scheme is intentional.
            with urllib.request.urlopen(  # noqa: S310
                GEOIP_CITY_DB_URL, timeout=120
            ) as resp:
                data = gzip.decompress(resp.read())
            tmp = GEOIP_CITY_DB_FILE + ".tmp"
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, GEOIP_CITY_DB_FILE)
            old = self.city_reader
            self.city_reader = maxminddb.open_database(GEOIP_CITY_DB_FILE)
            if old:
                old.close()
            logging.info("GeoLite2-City database updated (%d bytes)", len(data))
        except Exception:
            logging.exception("Error updating GeoLite2-City database")

    def fetch_location(self, ip: str) -> Dict[str, Any]:
        """A single flat location record for the IP: country + ASN from
        geoip2fast, precise city/lat/lon/accuracy/time zone overlaid from
        GeoLite2-City. Callers add reverse_dns; the response assembly adds the
        resolved coordinates, the origin_* fields, and distance_km."""
        raw = self.instance.lookup(ip).to_dict()
        city = raw.get("city") if isinstance(raw.get("city"), dict) else {}
        self._overlay_city(ip, raw.get("is_private"), city)
        return {
            "ip": raw.get("ip"),
            "country_code": raw.get("country_code"),
            "country_name": raw.get("country_name"),
            "city_name": city.get("name") or "",
            "subdivision_name": city.get("subdivision_name") or "",
            "subdivision_code": city.get("subdivision_code") or "",
            "lat": city.get("latitude"),
            "lon": city.get("longitude"),
            "accuracy_km": city.get("accuracy_radius"),
            "time_zone": city.get("time_zone"),
            "cidr": raw.get("cidr"),
            "asn_name": raw.get("asn_name"),
            "asn_cidr": raw.get("asn_cidr"),
            "is_private": raw.get("is_private"),
            "hostname": raw.get("hostname"),
        }

    def _overlay_city(self, ip: str, is_private: Any, city: Dict[str, Any]) -> None:
        """Overlay the precise city, coordinates, accuracy and time zone from
        GeoLite2-City onto the (still nested) geoip2fast city dict before it is
        flattened. geoip2fast keeps country/ASN duty; MaxMind supplies the
        latitude/longitude geoip2fast always leaves null."""
        if not self.city_reader or is_private:
            return
        try:
            record = self.city_reader.get(ip)
        except Exception:
            record = None
        if not record:
            return
        loc = record.get("location") or {}
        if loc.get("latitude") is not None and loc.get("longitude") is not None:
            city["latitude"] = loc.get("latitude")
            city["longitude"] = loc.get("longitude")
            city["accuracy_radius"] = loc.get("accuracy_radius")
            city["time_zone"] = loc.get("time_zone")
        mm_city = ((record.get("city") or {}).get("names") or {}).get("en")
        if mm_city:
            city["name"] = mm_city
        subdivisions = record.get("subdivisions") or []
        if subdivisions:
            names = subdivisions[0].get("names") or {}
            if names.get("en"):
                city["subdivision_name"] = names["en"]
            if subdivisions[0].get("iso_code"):
                city["subdivision_code"] = subdivisions[0]["iso_code"]


class DomainManager:
    def is_ipv4(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False

    def is_valid_domain(self, domain) -> bool:
        try:
            get_tld(domain, fix_protocol=True)
            return True
        except tld_exceptions.TldDomainNotFound:
            return False

    def remove_subdomains(self, domain: str) -> str:
        # remove subdomains
        return ".".join(domain.split(".")[-2:])

    def get_records(
        self, domain: str, ns_servers: list | None = None, ip: str | None = None
    ) -> dict:
        # ns_servers is kept for signature compatibility but unused: every query
        # now goes to the cached public resolvers (see _recursive_resolver).
        records = {
            "mx": [],
            "ns": [],
            "cname": None,
            "txt": [],
            "spf": [],
            "ptr": [],
            "a": [],
        }
        base_domain = self.remove_subdomains(domain)

        def a_ip(name: str) -> str | None:
            try:
                return str(_recursive_resolver().resolve(name, "A")[0])
            except Exception:
                return None

        def fetch_ns() -> list:
            try:
                answer = _recursive_resolver().resolve(base_domain, "NS")
            except Exception:
                return []
            targets = [r.target for r in answer]
            with ThreadPoolExecutor(max_workers=max(len(targets), 1)) as pool:
                ips = list(pool.map(lambda t: a_ip(str(t)), targets))
            return [
                {"hostname": t.to_text(), "ttl": answer.rrset.ttl, "ip": ip_}
                for t, ip_ in zip(targets, ips)
            ]

        def fetch_a() -> list:
            try:
                answer = _recursive_resolver().resolve(domain, "A")
            except Exception:
                return []
            return [{"ip": str(r), "ttl": answer.rrset.ttl} for r in answer]

        def fetch_mx() -> list:
            try:
                answer = _recursive_resolver().resolve(base_domain, "MX")
            except Exception:
                return []
            rows = list(answer)
            with ThreadPoolExecutor(max_workers=max(len(rows), 1)) as pool:
                ips = list(pool.map(lambda r: a_ip(str(r.exchange)), rows))
            return [
                {
                    "preference": r.preference,
                    "hostname": r.exchange.to_text(),
                    "ttl": answer.rrset.ttl,
                    "ip": ip_,
                }
                for r, ip_ in zip(rows, ips)
            ]

        def fetch_cname():
            try:
                answer = _recursive_resolver().resolve(domain, "CNAME")
            except Exception:
                return None
            return {
                "cname": answer.rrset[0].target.to_text(),
                "ttl": answer.rrset.ttl,
            }

        def spf_from(answer) -> list:
            spf = []
            for r in answer:
                joined = " ".join(
                    s.decode("utf-8", errors="replace") for s in r.strings
                )
                if joined.startswith("v=spf1"):
                    spf.append({"text": joined, "ttl": answer.rrset.ttl})
            return spf

        def fetch_txt():
            try:
                answer = _recursive_resolver().resolve(domain, "TXT")
            except Exception:
                return [], []
            txt = [
                {
                    "text": [s.decode("utf-8", errors="replace") for s in r.strings],
                    "ttl": answer.rrset.ttl,
                }
                for r in answer
            ]
            return txt, spf_from(answer)

        def fetch_base_spf() -> list:
            if base_domain == domain:
                return []
            try:
                answer = _recursive_resolver().resolve(base_domain, "TXT")
            except Exception:
                return []
            return spf_from(answer)

        def fetch_ptr(lookup_ip: str) -> list:
            try:
                answer = _recursive_resolver().resolve(
                    dns.reversename.from_address(lookup_ip), "PTR"
                )
            except Exception:
                logging.debug("PTR record lookup failed for %s", lookup_ip)
                return []
            return [{"hostname": str(r), "ttl": answer.rrset.ttl} for r in answer]

        # Every record type is independent, so sweep them at once against the
        # cached public resolvers instead of walking them in series.
        with ThreadPoolExecutor(max_workers=7) as pool:
            f_ns = pool.submit(fetch_ns)
            f_a = pool.submit(fetch_a)
            f_mx = pool.submit(fetch_mx)
            f_cname = pool.submit(fetch_cname)
            f_txt = pool.submit(fetch_txt)
            f_base_spf = pool.submit(fetch_base_spf)
            f_ptr = pool.submit(fetch_ptr, ip) if ip else None

            records["ns"] = f_ns.result()
            records["a"] = f_a.result()
            records["mx"] = f_mx.result()
            records["cname"] = f_cname.result()
            records["txt"], records["spf"] = f_txt.result()
            for entry in f_base_spf.result():
                if not any(s["text"] == entry["text"] for s in records["spf"]):
                    records["spf"].append(entry)
            if f_ptr is not None:
                records["ptr"] = f_ptr.result()

        # Fallback only when a caller omits ip (all current callers pass it).
        if not ip and records["a"]:
            records["ptr"] = fetch_ptr(records["a"][0]["ip"])

        return records

    def perform_reverse_lookup(self, ip: str) -> str:
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_records = dns.resolver.resolve(
                reverse_name, "PTR", lifetime=TIMEOUT_SECONDS
            )
            return str(ptr_records[0])
        except Exception as e:
            # Most reverse lookups miss because client IPs lack a PTR record
            # (NXDOMAIN). Log at warning level so SigNoz error metrics stay clean.
            logging.warning(f"Reverse lookup failed for IP {ip}: {str(e)}")
            return None


class SSLManager:
    @staticmethod
    def get_ssl_info(hostname: str, verified_ip: str | None = None) -> dict | None:
        # Connect only to the caller-verified IP. Falling back to hostname
        # would re-resolve DNS and reopen the rebinding window between an
        # earlier is_safe_ip() check and this socket connection.
        if not verified_ip:
            logging.debug("SSL lookup skipped for %s: no verified IP", str(hostname))
            return None
        cert = None
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = socket.socket()
            sock.settimeout(TIMEOUT_SECONDS)
            sock.connect((verified_ip, 443))
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                cert = s.getpeercert()
                if not cert:
                    return None
                # Enrich with connection-level details ("SSL type"): the
                # negotiated TLS protocol and cipher. Must be read inside the
                # with-block, before the socket closes.
                cert = dict(cert)
                cert["protocol"] = s.version()
                negotiated = s.cipher()
                if negotiated:
                    cert["cipher"] = {
                        "name": negotiated[0],
                        "protocol": negotiated[1],
                        "bits": negotiated[2],
                    }
            return cert
        except Exception:
            logging.exception(
                f"Error performing SSL certificate lookup for hostname: {str(hostname)}"
            )
            return None


class HeaderManager:
    @staticmethod
    def filter_out_unwanted(original_headers: dict, exclude_prefixes: list) -> dict:
        return {
            k: v
            for k, v in original_headers.items()
            if not any(k.lower().startswith(prefix) for prefix in exclude_prefixes)
        }


class IPBanManager:
    """Manages IP ban list with persistent storage and TTL support"""

    def __init__(self, ban_file: str = BANNED_IPS_FILE):
        self.ban_file = ban_file
        self.banned_ips = {}
        self.load_bans()

    def load_bans(self):
        """Load banned IPs from JSON file"""
        try:
            os.makedirs(os.path.dirname(self.ban_file), exist_ok=True)
            if os.path.exists(self.ban_file):
                with open(self.ban_file, "r") as f:
                    self.banned_ips = json.load(f)
                    # Remove expired bans on load
                    self.cleanup_expired_bans()
                logging.info(
                    f"Loaded {len(self.banned_ips)} banned IPs from {self.ban_file}"
                )
        except Exception as e:
            logging.error(f"Error loading ban list: {e}")
            self.banned_ips = {}

    def save_bans(self):
        """Save banned IPs to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.ban_file), exist_ok=True)
            with open(self.ban_file, "w") as f:
                json.dump(self.banned_ips, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving ban list: {e}")

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned"""
        if ip not in self.banned_ips:
            return False

        ban_info = self.banned_ips[ip]
        expires_at = datetime.datetime.fromisoformat(ban_info["expires_at"])

        if expires_at < datetime.datetime.now(tz=datetime.timezone.utc):
            # Ban expired, remove it
            del self.banned_ips[ip]
            self.save_bans()
            return False

        return True

    def ban_ip(
        self,
        ip: str,
        reason: str = "manual",
        duration: int = BAN_DURATION_SUSPICIOUS,
        path: str = None,
        country: str = None,
    ):
        """Ban an IP address for a specified duration"""
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        expires_at = now + datetime.timedelta(seconds=duration)

        self.banned_ips[ip] = {
            "banned_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "reason": reason,
            "request_path": path,
            "country": country,
        }
        self.save_bans()
        logging.warning(
            f"Banned IP {ip} ({country or 'UNKNOWN'}) "
            f"for {duration}s - Reason: {reason}"
        )

    def unban_ip(self, ip: str):
        """Remove an IP from the ban list"""
        if ip in self.banned_ips:
            del self.banned_ips[ip]
            self.save_bans()
            logging.info(f"Unbanned IP {ip}")

    def cleanup_expired_bans(self):
        """Remove expired bans from the list"""
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        expired_ips = []

        for ip, ban_info in self.banned_ips.items():
            expires_at = datetime.datetime.fromisoformat(ban_info["expires_at"])
            if expires_at < now:
                expired_ips.append(ip)

        if expired_ips:
            for ip in expired_ips:
                del self.banned_ips[ip]
            self.save_bans()
            logging.info(
                f"Removed {len(expired_ips)} expired ban(s): {', '.join(expired_ips)}"
            )

    def get_all_bans(self) -> dict:
        """Get all current bans"""
        self.cleanup_expired_bans()
        return self.banned_ips


class RateLimiter:
    """Sliding window rate limiter for IP addresses"""

    def __init__(
        self,
        requests_per_minute: int = RATE_LIMIT_REQUESTS_PER_MINUTE,
        requests_per_second: int = RATE_LIMIT_REQUESTS_PER_SECOND,
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_second = requests_per_second
        # Store timestamps of requests per IP
        self.request_history = defaultdict(list)

    def allow_request(self, ip: str) -> bool:
        """Check if a request from this IP should be allowed"""
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        timestamps = self.request_history[ip]

        # Remove timestamps older than 1 minute
        cutoff_minute = now - datetime.timedelta(minutes=1)
        cutoff_second = now - datetime.timedelta(seconds=1)

        timestamps[:] = [ts for ts in timestamps if ts > cutoff_minute]

        # Check per-second limit (burst protection)
        recent_requests = sum(1 for ts in timestamps if ts > cutoff_second)
        if recent_requests >= self.requests_per_second:
            logging.warning(
                f"Rate limit exceeded (per-second) for IP {ip}: "
                f"{recent_requests}/{self.requests_per_second}"
            )
            return False

        # Check per-minute limit
        if len(timestamps) >= self.requests_per_minute:
            logging.warning(
                f"Rate limit exceeded (per-minute) for IP {ip}: "
                f"{len(timestamps)}/{self.requests_per_minute}"
            )
            return False

        # Allow request and record timestamp
        timestamps.append(now)
        return True

    def cleanup_old_records(self):
        """Remove old request history to prevent memory leak"""
        cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
            minutes=5
        )
        ips_to_remove = []

        for ip, timestamps in self.request_history.items():
            timestamps[:] = [ts for ts in timestamps if ts > cutoff]
            if not timestamps:
                ips_to_remove.append(ip)

        if ips_to_remove:
            for ip in ips_to_remove:
                del self.request_history[ip]
            logging.info(
                f"Removed {len(ips_to_remove)} IP(s) from "
                f"rate limit history: {', '.join(ips_to_remove)}"
            )


class SuspiciousPatternDetector:
    """Detect suspicious request patterns"""

    def __init__(self):
        self.suspicious_patterns = [
            r"\.env",  # Environment files
            r"\.php$",  # PHP scripts
            r"\.json$",  # JSON files (except API responses)
            r"\.sql$",  # SQL files
            r"\.bak$",  # Backup files
            r"\.git/",  # Git repository
            r"/admin",  # Admin panels
            r"/wp-",  # WordPress paths
            r"\.aspx?$",  # ASP/ASPX files
            r"/cgi-bin/",  # CGI scripts
            r"\.xml$",  # XML files
            r"\.conf$",  # Config files
            r"\.config$",  # Config files
            r"\.ini$",  # INI files
            r"\.log$",  # Log files
            r"/\..*",  # Hidden files (dotfiles)
        ]
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.suspicious_patterns
        ]

    def is_suspicious(self, path: str) -> bool:
        """Check if a request path matches suspicious patterns"""
        for pattern in self.compiled_patterns:
            if pattern.search(path):
                return True
        return False


class WhitelistManager:
    """Manage whitelisted request patterns"""

    def __init__(self):
        self.whitelist_patterns = [
            r"^/static/.*\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?)$",  # Static files
            r"^/$",  # Root endpoint
            r"^/[a-zA-Z0-9\.\-]+$",  # Domain/IP lookup (main feature)
        ]
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.whitelist_patterns
        ]

    def is_whitelisted(self, path: str) -> bool:
        """Check if a request path is whitelisted"""
        for pattern in self.compiled_patterns:
            if pattern.match(path):
                return True
        return False


class GeoBlockManager:
    """Manage geographic access control using GeoIP"""

    def __init__(self, geo_ip_manager: GeoIpManager, config_file: str = GEO_RULES_FILE):
        self.geo_ip = geo_ip_manager
        self.config_file = config_file
        self.load_config()

    def load_config(self):
        """Load geo-blocking configuration from JSON file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            if os.path.exists(self.config_file):
                with open(self.config_file, "r") as f:
                    self.config = json.load(f)
                logging.info(f"Loaded geo-blocking config from {self.config_file}")
            else:
                # Default configuration from environment or defaults
                self.config = {
                    "mode": GEO_MODE_INITIAL,
                    "blocked_countries": GEO_BLOCKED_COUNTRIES_INITIAL,
                    "blocked_regions": [],
                    "allowed_countries": GEO_ALLOWED_COUNTRIES_INITIAL,
                    "allowed_regions": [],
                    "block_unknown": GEO_BLOCK_UNKNOWN_INITIAL,
                    "bypass_ips": [],
                }
                self.save_config()
        except Exception as e:
            logging.error(f"Error loading geo-blocking config: {e}")
            self.config = {
                "mode": "disabled",
                "blocked_countries": [],
                "blocked_regions": [],
                "allowed_countries": [],
                "allowed_regions": [],
                "block_unknown": False,
                "bypass_ips": [],
            }

    def save_config(self):
        """Save configuration to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving geo-blocking config: {e}")

    def check_access(self, ip: str) -> dict:
        """
        Check if IP is allowed based on geographic rules
        Returns: {
            "allowed": bool,
            "country": str,
            "region": str,
            "reason": str
        }
        """
        # Check bypass list
        if ip in self.config.get("bypass_ips", []):
            return {
                "allowed": True,
                "country": "BYPASS",
                "region": None,
                "reason": "Bypass IP",
            }

        # Get location data
        try:
            location = self.geo_ip.fetch_location(ip)
            country = location.get("country_code", "UNKNOWN")
            subdivision = location.get("subdivision_code") or ""
            region_full = f"{country}-{subdivision}" if subdivision else None
        except Exception as e:
            logging.error(f"GeoIP lookup failed for {ip}: {e}")
            country = "UNKNOWN"
            region_full = None

        mode = self.config.get("mode", "disabled")

        # Disabled mode - allow all
        if mode == "disabled":
            return {
                "allowed": True,
                "country": country,
                "region": region_full,
                "reason": "Geo-blocking disabled",
            }

        # Handle unknown countries
        if country == "UNKNOWN":
            if self.config.get("block_unknown", False):
                return {
                    "allowed": False,
                    "country": country,
                    "region": None,
                    "reason": "Unknown country blocked",
                }
            return {
                "allowed": True,
                "country": country,
                "region": None,
                "reason": "Unknown country allowed",
            }

        # Allowlist mode - only specified countries/regions allowed
        if mode == "allowlist":
            # Check region-specific allowlist first (more specific)
            if region_full and region_full in self.config.get("allowed_regions", []):
                return {
                    "allowed": True,
                    "country": country,
                    "region": region_full,
                    "reason": "Region in allowlist",
                }

            # Check country allowlist
            if country in self.config.get("allowed_countries", []):
                return {
                    "allowed": True,
                    "country": country,
                    "region": region_full,
                    "reason": "Country in allowlist",
                }

            return {
                "allowed": False,
                "country": country,
                "region": region_full,
                "reason": "Not in allowlist",
            }

        # Blocklist mode - block specific countries/regions
        if mode == "blocklist":
            # Check region-specific blocklist first (more specific)
            if region_full and region_full in self.config.get("blocked_regions", []):
                return {
                    "allowed": False,
                    "country": country,
                    "region": region_full,
                    "reason": "Region in blocklist",
                }

            # Check country blocklist
            if country in self.config.get("blocked_countries", []):
                return {
                    "allowed": False,
                    "country": country,
                    "region": region_full,
                    "reason": "Country in blocklist",
                }

            return {
                "allowed": True,
                "country": country,
                "region": region_full,
                "reason": "Not in blocklist",
            }

        # Default allow
        return {
            "allowed": True,
            "country": country,
            "region": region_full,
            "reason": "Default allow",
        }


geo_ip_manager = GeoIpManager()
domain_manager = DomainManager()
gazetteer = Gazetteer.load()

# The desktop hero text sits over the left half of the band, so the map is
# focused right of centre and fitted into the free width beside it. Both canvases
# fetch tiles at native zoom (tile_zoom_offset 0) so roads and place names stay
# legible; that costs ~15 tile requests on desktop and ~6 on mobile.
DESKTOP_CANVAS = {"width": 1440, "height": 380, "focus_x": 0.58, "fit_ratio": 0.4}
MOBILE_CANVAS = {"width": 350, "height": 255, "focus_x": 0.5, "fit_ratio": 0.78}


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


SITE_DOMAIN_FALLBACK = os.getenv("SITE_DOMAIN_FALLBACK", "ip.1kko.com")


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

    return SafeORJSONResponse(response_data)


@app.get("/{domain_ip}", response_model=None)
async def get_ip_info(domain_ip: str, request: Request):
    # Remove the static path check since it's handled by the static files mount
    started = time.perf_counter()
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

    return SafeORJSONResponse(response_data)


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
