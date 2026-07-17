"""Request-security subsystem: IP bans, rate limiting, suspicious-path
detection, a static-path whitelist, and country-level geo-blocking.
"""

import datetime
import json
import logging
import os
import re
from collections import defaultdict

from config import (
    BAN_DURATION_SUSPICIOUS,
    BANNED_IPS_FILE,
    GEO_ALLOWED_COUNTRIES_INITIAL,
    GEO_BLOCK_UNKNOWN_INITIAL,
    GEO_BLOCKED_COUNTRIES_INITIAL,
    GEO_MODE_INITIAL,
    GEO_RULES_FILE,
    RATE_LIMIT_REQUESTS_PER_MINUTE,
    RATE_LIMIT_REQUESTS_PER_SECOND,
)
from managers import GeoIpManager


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
