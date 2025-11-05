#!/usr/bin/env python3

import datetime
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
from collections import defaultdict
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Dict

import dns.resolver
import dns.reversename
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
from tld import exceptions as tld_exceptions
from tld import get_tld

# Load environment variables from .env file
load_dotenv()

# First, mount static files
app = FastAPI()
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

TIMEOUT_SECONDS = 5

# Security Configuration from Environment Variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY or ADMIN_API_KEY == "CHANGE_ME_TO_SECURE_RANDOM_STRING":
    logger.warning(
        "ADMIN_API_KEY not set or using default value in .env file! "
        "Admin endpoints will be disabled. Generate one with: "
        "python -c \"import secrets; print(secrets.token_urlsafe(32))\""
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

# Background Job Intervals
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "300"))  # 5 minutes
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


class GeoIpManager:
    def __init__(self):
        self.instance = GeoIP2Fast()

    def update_database(self):
        try:
            update_result = self.instance.update_file(
                "geoip2fast-city-asn-ipv6.dat.gz", "geoip2fast.dat.gz", verbose=False
            )
            reload_result = self.instance.reload_data(verbose=False)
            logging.info(f"{update_result=}")
            logging.info(f"{reload_result=}")
        except Exception as e:
            logging.exception(f"Error updating GeoIP2Fast database: {str(e)}")

    def fetch_location(self, ip: str) -> Dict[str, Any]:
        return self.instance.lookup(ip).to_dict()


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

    def get_records(self, domain: str, ns_servers: list | None = None) -> dict:
        records = {"mx": [], "ns": [], "cname": None, "txt": [], "a": []}

        # Get NS records
        resolver = dns.resolver.Resolver(configure=False)
        # Use public DNS servers to avoid Docker DNS issues
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        if ns_servers and len(ns_servers) > 1:
            for ns in ns_servers:
                server = (
                    ns if self.is_ipv4(ns) else str(dns.resolver.resolve(ns, "A")[0])
                )
                resolver.nameservers.append(server)
        else:
            try:
                ns_records = resolver.resolve(self.remove_subdomains(domain), "NS")
                if ns_records:
                    resolver.nameservers = [
                        str(dns.resolver.resolve(str(r.target), "A")[0]) for r in ns_records
                    ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
                logging.warning(f"Failed to get NS records for {domain}: {str(e)}")
                ns_records = None

        # Only process NS records if we successfully retrieved them
        if ns_servers or (not ns_servers and ns_records):
            try:
                for r in ns_records:
                    ns_ip = str(dns.resolver.resolve(str(r.target), "A")[0])
                    records["ns"].append({
                        "hostname": r.target.to_text(),
                        "ttl": ns_records.rrset.ttl,
                        "ip": ns_ip,
                    })
            except Exception as e:
                logging.warning(f"Failed to process NS records: {str(e)}")

        # Get A records
        try:
            a_records = resolver.resolve(domain, "A")
            for r in a_records:
                records["a"].append({"ip": str(r), "ttl": a_records.rrset.ttl})
        except dns.resolver.NoAnswer:
            pass

        try:
            mx_records = resolver.resolve(self.remove_subdomains(domain), "MX")
            for r in mx_records:
                try:
                    mx_ip = str(resolver.resolve(str(r.exchange), "A")[0])
                except Exception as e:
                    mx_ip = None
                records["mx"].append({
                    "hostname": r.exchange.to_text(),
                    "ttl": mx_records.rrset.ttl,
                    "ip": mx_ip,
                })
        except dns.resolver.NoAnswer:
            pass

        try:
            cname_record = resolver.resolve(domain, "CNAME")
            records["cname"] = {
                "cname": cname_record.rrset[0].target.to_text(),
                "ttl": cname_record.rrset.ttl,
            }
        except dns.resolver.NoAnswer:
            records["cname"] = None

        try:
            txt_records = resolver.resolve(domain, "TXT")
            for r in txt_records:
                records["txt"].append({"text": r.strings, "ttl": txt_records.rrset.ttl})
        except dns.resolver.NoAnswer:
            pass

        return records

    def perform_reverse_lookup(self, ip: str) -> str:
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_records = dns.resolver.resolve(reverse_name, "PTR", lifetime=TIMEOUT_SECONDS)
            return str(ptr_records[0])
        except Exception as e:
            logging.error(f"Error performing reverse lookup for IP {ip}: {str(e)}")
            return None


class SSLManager:
    @staticmethod
    def get_ssl_info(hostname: str) -> dict | None:
        cert = None
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(TIMEOUT_SECONDS)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            return cert
        except Exception as e:
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
                logging.info(f"Loaded {len(self.banned_ips)} banned IPs from {self.ban_file}")
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
            f"Banned IP {ip} ({country or 'UNKNOWN'}) for {duration}s - Reason: {reason}"
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

        for ip in expired_ips:
            del self.banned_ips[ip]

        if expired_ips:
            self.save_bans()
            logging.info(f"Cleaned up {len(expired_ips)} expired bans")

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

        for ip in ips_to_remove:
            del self.request_history[ip]

        if ips_to_remove:
            logging.debug(f"Cleaned up rate limit history for {len(ips_to_remove)} IPs")


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
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.suspicious_patterns]

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
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.whitelist_patterns]

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
            subdivision = location.get("city", {}).get("subdivision_code", "")
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

# Initialize security managers
ip_ban_manager = IPBanManager()
rate_limiter = RateLimiter()
suspicious_detector = SuspiciousPatternDetector()
whitelist_manager = WhitelistManager()
geo_block_manager = GeoBlockManager(geo_ip_manager)

# Initialize scheduler and add jobs
scheduler = BackgroundScheduler()
scheduler.add_job(geo_ip_manager.update_database, "interval", days=3)
scheduler.add_job(
    ip_ban_manager.cleanup_expired_bans, "interval", seconds=CLEANUP_INTERVAL_SECONDS
)
scheduler.add_job(
    rate_limiter.cleanup_old_records, "interval", seconds=RATE_LIMIT_CLEANUP_INTERVAL
)
scheduler.start()
geo_ip_manager.update_database()


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
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=404, detail="Not Found")
    return True


# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security middleware for IP banning, geo-blocking, and rate limiting"""
    client_ip = request.headers.get("x-real-ip", request.client.host)
    request_path = request.url.path

    # Skip security checks for admin endpoints (they have their own auth)
    if request_path.startswith("/admin/"):
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


@app.get("/", response_model=None)
async def get_self_info(request: Request):
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    client_ip = request.headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={client_ip} (self)")

    try:
        whois_data = whois.whois(client_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    ip_data = geo_ip_manager.fetch_location(client_ip)
    ip_data.pop("elapsed_time", None)

    reverse_dns_hostname = domain_manager.perform_reverse_lookup(client_ip)
    if reverse_dns_hostname:
        ip_data["reverse_dns"] = reverse_dns_hostname

    response_data = {
        "address": client_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_manager.get_records(reverse_dns_hostname) if reverse_dns_hostname else {},
        "location": ip_data,
        "whois": whois_data,
        "ssl": None,
        "headers": request_headers,
    }

    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return templates.TemplateResponse(
            "browser.html",
            {
                "request": request,
                "json_data": json.dumps(response_data, indent=2, default=str),
            },
        )

    return ORJSONResponse(response_data)


@app.get("/{domain_ip}", response_model=None)
async def get_ip_info(domain_ip: str, request: Request):
    # Remove the static path check since it's handled by the static files mount
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    request_headers.pop("host", None)

    client_ip = request.headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={domain_ip}")

    try:
        whois_data = whois.whois(domain_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    ssl_data = None
    resolved_ip = None
    domain_data = None

    if domain_manager.is_valid_domain(domain_ip):
        logging.debug(f"domain={domain_ip}")
        try:
            a_records = dns.resolver.resolve(domain_ip, "A")
            resolved_ip = str(a_records[0])  # Get the first A record
            domain_data = domain_manager.get_records(domain_ip)
            ssl_data = SSLManager.get_ssl_info(domain_ip)
        except Exception as e:
            logging.exception(f"Error resolving domain {domain_ip}: {str(e)}")
    elif domain_manager.is_ipv4(domain_ip):
        logging.debug(f"ip={domain_ip}")
        reverse_dns_hostname = domain_manager.perform_reverse_lookup(domain_ip)
        domain_data = domain_manager.get_records(reverse_dns_hostname) if reverse_dns_hostname else {}
        resolved_ip = domain_ip

    if resolved_ip:
        ip_data = geo_ip_manager.fetch_location(resolved_ip)
        ip_data.pop("elapsed_time", None)
        # Add reverse DNS for IP lookups
        if domain_manager.is_ipv4(domain_ip):
            reverse_dns_hostname = domain_manager.perform_reverse_lookup(resolved_ip)
            if reverse_dns_hostname:
                ip_data["reverse_dns"] = reverse_dns_hostname
    else:
        ip_data = {}

    response_data = {
        "address": domain_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_data,
        "location": ip_data,
        "whois": whois_data,
        "ssl": ssl_data,
        "headers": request_headers,
    }

    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return templates.TemplateResponse(
            "browser.html",
            {
                "request": request,
                "json_data": json.dumps(response_data, indent=2, default=str),
            },
        )

    return ORJSONResponse(response_data)


# Admin endpoints for security management
@app.get("/admin/bans")
async def get_all_bans(authenticated: bool = Depends(verify_admin_key)):
    """Get all currently banned IPs"""
    return {"bans": ip_ban_manager.get_all_bans()}


@app.post("/admin/ban/{ip}")
async def manual_ban(
    ip: str, duration: int = BAN_DURATION_SUSPICIOUS, authenticated: bool = Depends(verify_admin_key)
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
    rules: dict, authenticated: bool = Depends(verify_admin_key)
):
    """Update geo-blocking configuration"""
    # Validate mode
    if "mode" in rules and rules["mode"] not in ["disabled", "allowlist", "blocklist"]:
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
        if key in rules:
            geo_block_manager.config[key] = rules[key]

    geo_block_manager.save_config()
    return {"status": "updated", "config": geo_block_manager.config}


@app.post("/admin/geo/block/country/{country_code}")
async def block_country(country_code: str, authenticated: bool = Depends(verify_admin_key)):
    """Add a country to the blocklist"""
    country_code = country_code.upper()
    if country_code not in geo_block_manager.config["blocked_countries"]:
        geo_block_manager.config["blocked_countries"].append(country_code)
        geo_block_manager.save_config()

    return {"status": "blocked", "country": country_code}


@app.delete("/admin/geo/block/country/{country_code}")
async def unblock_country(country_code: str, authenticated: bool = Depends(verify_admin_key)):
    """Remove a country from the blocklist"""
    country_code = country_code.upper()
    if country_code in geo_block_manager.config["blocked_countries"]:
        geo_block_manager.config["blocked_countries"].remove(country_code)
        geo_block_manager.save_config()

    return {"status": "unblocked", "country": country_code}


@app.post("/admin/geo/allow/country/{country_code}")
async def allow_country(country_code: str, authenticated: bool = Depends(verify_admin_key)):
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
            f"{location.get('country_code')}-{location.get('city', {}).get('subdivision_code')}"
            if location.get("city", {}).get("subdivision_code")
            else None
        ),
        "subdivision_name": location.get("city", {}).get("subdivision_name"),
        "city": location.get("city", {}).get("name"),
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
    uvicorn.run(app, host="0.0.0.0", port=8000)
