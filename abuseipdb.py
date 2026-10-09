"""AbuseIPDB: how often an address has been reported for abuse, and how sure
AbuseIPDB is that it is abusive (its abuseConfidenceScore, 0-100).

Unlike the lists in reputation.py this is an API call per address, with a key
and a daily quota (1,000 checks on the free plan), so it is asked sparingly:
- only for an address looked up directly (lookup.gather() given an IP). Never
  for the address a domain resolves to, and never for the visitor's own (the
  home page, whoami_caller): that would hand every visitor's address to a third
  party unasked
- once a day per address: an answer is cached for ABUSEIPDB_CACHE_TTL
- never past the quota: no request goes out once ABUSEIPDB_DAILY_LIMIT have
  this UTC day, or once AbuseIPDB says none remain (X-RateLimit-Remaining: 0, or
  a 429), until the reset it names

Only the score and the report counts are asked for, not `verbose`: the reports
carry other users' comments, free text that can hold anyone's personal data.

merge() adds the answer to a reputation.ReputationManager.check() result as one
more source: a signal weighted by the score itself when the score is above 0,
so on the default bands a score of 80 or more alone grades "high". A failure, a
spent quota or a timeout is "could not check", never a clean result.

Imports config, reputation and the standard library only: lookup.py builds the
client.
"""

import datetime
import ipaddress
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_CACHE_TTL,
    ABUSEIPDB_DAILY_LIMIT,
    ABUSEIPDB_MAX_AGE_DAYS,
    ABUSEIPDB_TIMEOUT_SECONDS,
    REPUTATION_ENABLED,
    REPUTATION_USER_AGENT,
)
from reputation import grade

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
# The address's own page, linked from the card for the reports themselves.
PAGE_URL = "https://www.abuseipdb.com/check/{ip}"
ATTRIBUTION = "Abuse reports: AbuseIPDB, https://www.abuseipdb.com"
SOURCE = {"id": "abuseipdb", "label": "AbuseIPDB", "source": "AbuseIPDB"}

# A check answers a few hundred bytes without `verbose`.
MAX_RESPONSE_BYTES = 64 * 1024
# How long a failed check stands before the address is asked again.
ERROR_TTL_SECONDS = 300
# Cached answers kept at most; the oldest goes first.
CACHE_SIZE = 4096

DAY = 86400


def _request(url: str, key: str, timeout: float) -> tuple[int, dict, bytes]:
    """GET `url` with the key: the status, the headers (names lower-cased) and
    the body. An HTTP error status is returned, not raised, since a 429's
    headers say when to ask again."""
    request = urllib.request.Request(  # noqa: S310 - a fixed https:// URL
        url,
        headers={
            "Key": key,
            "Accept": "application/json",
            "User-Agent": REPUTATION_USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return (
                response.status,
                {k.lower(): v for k, v in response.headers.items()},
                response.read(MAX_RESPONSE_BYTES + 1),
            )
    except urllib.error.HTTPError as error:
        with error:
            headers = error.headers.items() if error.headers else []
            return (
                error.code,
                {k.lower(): v for k, v in headers},
                error.read(MAX_RESPONSE_BYTES + 1),
            )


def _iso(epoch: float) -> str:
    when = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_iso(value) -> str | None:
    """AbuseIPDB's '2026-10-08T12:34:56+00:00' as '2026-10-08T12:34:56Z'."""
    if not isinstance(value, str):
        return None
    try:
        when = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return _iso(when.timestamp())


def _count(value) -> int | None:
    # bool is an int; a JSON true is not a count.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _number(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _failure(reason: str) -> dict:
    return {"ok": False, "reason": reason}


class AbuseIPDBClient:
    """The check endpoint, behind a per-address cache and the daily quota.

    check() blocks on the network, so lookup.py runs it on its own pool; the
    cache and the quota state are shared by those threads under one lock, and
    the request itself is made outside it.

    Disabled (no key, or REPUTATION_ENABLED=false), it asks nothing and
    lookup.py leaves it out of the answer altogether.
    """

    def __init__(
        self,
        api_key: str = ABUSEIPDB_API_KEY,
        enabled: bool = REPUTATION_ENABLED,
        daily_limit: int = ABUSEIPDB_DAILY_LIMIT,
        max_age_days: int = ABUSEIPDB_MAX_AGE_DAYS,
        cache_ttl: float = ABUSEIPDB_CACHE_TTL,
        timeout: float = ABUSEIPDB_TIMEOUT_SECONDS,
        fetch: Callable[[str, str, float], tuple[int, dict, bytes]] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.enabled = bool(api_key) and enabled
        self._key = api_key
        self.daily_limit = daily_limit
        self.max_age_days = max_age_days
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self._fetch = fetch or _request
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, dict]] = {}
        # Requests sent on `_day` (days since the epoch, UTC).
        self._day = -1
        self._sent = 0
        # No request until then: the quota is spent.
        self._blocked_until = 0.0
        # The last X-RateLimit-Remaining AbuseIPDB sent.
        self._remaining: int | None = None
        self._key_rejected = False

    def _cached(self, ip: str, now: float) -> dict | None:
        item = self._cache.get(ip)
        if item is None:
            return None
        if item[0] <= now:
            del self._cache[ip]
            return None
        return item[1]

    def _store(self, ip: str, answer: dict, ttl: float, now: float) -> None:
        if ip not in self._cache and len(self._cache) >= CACHE_SIZE:
            self._cache.pop(next(iter(self._cache)))
        self._cache[ip] = (now + ttl, answer)

    def cached(self, ip: str) -> dict | None:
        """The answer held for `ip`, or None. Never a request."""
        with self._lock:
            return self._cached(ip, self._clock())

    def _spent(self) -> dict:
        until = datetime.datetime.fromtimestamp(
            self._blocked_until, tz=datetime.timezone.utc
        )
        return _failure(f"today's AbuseIPDB quota is used up, until {until:%H:%M} UTC")

    def _reserve(self, now: float) -> dict | None:
        """Count a request about to go out, or say why none may. Under the lock."""
        day = int(now // DAY)
        if day != self._day:
            self._day = day
            self._sent = 0
        if now < self._blocked_until:
            return self._spent()
        if self._sent >= self.daily_limit:
            self._blocked_until = (day + 1) * DAY
            return self._spent()
        self._sent += 1
        return None

    def _block(self, headers: dict, now: float) -> None:
        """Hold every request until the quota resets: X-RateLimit-Reset (an
        epoch), else Retry-After (seconds), else the next 00:00 UTC."""
        reset = _number(headers.get("x-ratelimit-reset"))
        retry = _number(headers.get("retry-after"))
        if reset is not None and reset > now:
            until = reset
        elif retry is not None and retry > 0:
            until = now + retry
        else:
            until = (int(now // DAY) + 1) * DAY
        self._blocked_until = max(self._blocked_until, until)

    def check(self, ip: str) -> dict:
        """What AbuseIPDB says about `ip`, cached:
        {"ok": True, "score", "reports", "reporters", "last_reported_at",
        "window_days", "as_of", "url"}, or {"ok": False, "reason"} when it could
        not be asked or did not answer. Blocks on the network."""
        address = str(ipaddress.ip_address(ip))
        with self._lock:
            now = self._clock()
            cached = self._cached(address, now)
            if cached is not None:
                return cached
            refused = self._reserve(now)
            if refused is not None:
                return refused

        query = {"ipAddress": address, "maxAgeInDays": self.max_age_days}
        url = f"{CHECK_URL}?{urllib.parse.urlencode(query)}"
        try:
            status, headers, body = self._fetch(url, self._key, self.timeout)
        except Exception as error:
            # urllib raises a connect timeout wrapped in URLError, a read
            # timeout bare. Never the request in the log: its headers carry the
            # key.
            reason = getattr(error, "reason", error)
            if isinstance(reason, TimeoutError):
                answer = _failure("AbuseIPDB did not answer in time")
            else:
                logging.warning("AbuseIPDB check failed: %r", reason)
                answer = _failure("AbuseIPDB could not be reached")
            status, headers, ttl = None, {}, ERROR_TTL_SECONDS
        else:
            answer, ttl = self._answer(address, status, body)

        with self._lock:
            now = self._clock()
            remaining = _number(headers.get("x-ratelimit-remaining"))
            if remaining is not None:
                self._remaining = int(remaining)
            if status == 429:
                self._block(headers, now)
                return self._spent()
            if remaining is not None and remaining <= 0:
                self._block(headers, now)
            if status in (401, 403):
                self._key_rejected = True
            elif status is not None and status < 400:
                self._key_rejected = False
            self._store(address, answer, ttl, now)
        return answer

    def _answer(self, address: str, status: int, body: bytes) -> tuple[dict, float]:
        if status in (401, 403):
            logging.warning("AbuseIPDB refused the API key (HTTP %s)", status)
            reason = "AbuseIPDB rejected this service's API key"
            return _failure(reason), ERROR_TTL_SECONDS
        if status != 200:
            logging.warning("AbuseIPDB answered HTTP %s", status)
            return _failure(f"AbuseIPDB answered HTTP {status}"), ERROR_TTL_SECONDS
        try:
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("oversized")
            data = json.loads(body)["data"]
            score = _count(data["abuseConfidenceScore"])
            if score is None or score > 100:
                raise ValueError("abuseConfidenceScore")
        except (ValueError, KeyError, TypeError):
            logging.warning("AbuseIPDB's answer could not be read")
            return _failure("AbuseIPDB's answer could not be read"), ERROR_TTL_SECONDS
        return {
            "ok": True,
            "score": score,
            "reports": _count(data.get("totalReports")),
            "reporters": _count(data.get("numDistinctUsers")),
            "last_reported_at": _utc_iso(data.get("lastReportedAt")),
            "window_days": self.max_age_days,
            "as_of": _iso(self._clock()),
            "url": PAGE_URL.format(ip=address),
        }, self.cache_ttl

    def status(self) -> dict:
        """For /healthz: the requests sent today against the limit, the last
        count AbuseIPDB reported left, and whether it is holding off."""
        if not self.enabled:
            return {"enabled": False}
        with self._lock:
            now = self._clock()
            today = int(now // DAY) == self._day
            return {
                "enabled": True,
                "requests_today": self._sent if today else 0,
                "daily_limit": self.daily_limit,
                "remaining": self._remaining,
                "quota_spent_until": (
                    _iso(self._blocked_until) if now < self._blocked_until else None
                ),
                "key_rejected": self._key_rejected,
            }

    def problems(self) -> list[str]:
        """For /healthz `reasons`: only what an operator must fix. A spent
        quota is not one; it resets on its own at 00:00 UTC."""
        if self.enabled and self._key_rejected:
            return [
                "AbuseIPDB rejected the API key (ABUSEIPDB_API_KEY): lookups "
                "report it as not checked"
            ]
        return []


def merge(reputation: dict | None, answer: dict | None) -> dict | None:
    """`reputation` (a ReputationManager.check() result) with AbuseIPDB's
    `answer` added as one more source: in `checked`, and in `signals` too when
    its score is above 0, weighted by the score; or in `unavailable` with the
    reason. The level is graded again from the signals. Neither argument is
    changed. With no answer, `reputation` as it was."""
    if answer is None:
        return reputation
    base = reputation or {
        "level": None,
        "signals": [],
        "checked": [],
        "unavailable": [],
        "attribution": [],
    }
    signals = list(base.get("signals") or [])
    checked = list(base.get("checked") or [])
    unavailable = list(base.get("unavailable") or [])
    attribution = list(base.get("attribution") or [])
    if answer.get("ok"):
        details = {
            key: answer[key]
            for key in (
                "score",
                "reports",
                "reporters",
                "last_reported_at",
                "window_days",
                "url",
            )
        }
        checked.append({**SOURCE, "as_of": answer["as_of"], **details})
        if answer["score"] > 0:
            signals.append(
                {
                    **SOURCE,
                    "as_of": answer["as_of"],
                    "weight": answer["score"],
                    **details,
                }
            )
        if ATTRIBUTION not in attribution:
            attribution.append(ATTRIBUTION)
    else:
        unavailable.append({**SOURCE, "reason": answer["reason"]})
    return {
        **base,
        "level": grade(signals) if checked else None,
        "signals": signals,
        "checked": checked,
        "unavailable": unavailable,
        "attribution": attribution,
    }
