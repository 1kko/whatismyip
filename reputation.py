"""IP reputation: which public lists an address is on, and a grade from them.

Key-free lists only (decided 2026-10-08): Spamhaus DROP and ASN-DROP, the Tor
Project's exit list, and X4BNet's VPN and datacenter lists. The scheduler
downloads each into REPUTATION_DIR (main.py's refresh-reputation job); a lookup
is a bisect over sorted intervals held in memory, so it sends nothing anywhere,
opens no new SSRF surface, and costs microseconds.

The answer is evidence first: each list the address is on, with its source and
when the copy was taken, and a grade computed from those signals alone. Being
on no list is not "safe". The lists that were read are named, and one that is
stale or missing is reported as not checked rather than quietly left out.

This service's own ban list is never a signal. It would expose the rules a 403
deliberately does not explain, and brand everyone who shares a CGNAT or office
address with whoever got banned.

FireHOL level1 is not used. It merges DShield (CC BY-NC-SA 4.0: commercial
use restricted, and anything derived under the same licence), Feodo Tracker,
fullbogons and Spamhaus DROP, which is read here directly under its own terms.

Imports config and the standard library only: lookup.py builds the singleton.
"""

import bisect
import dataclasses
import datetime
import ipaddress
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from config import (
    REPUTATION_DATACENTER_V4_URL,
    REPUTATION_DATACENTER_V6_URL,
    REPUTATION_DIR,
    REPUTATION_ENABLED,
    REPUTATION_LEVEL_HIGH,
    REPUTATION_LEVEL_LOW,
    REPUTATION_LEVEL_MEDIUM,
    REPUTATION_MAX_AGE_HOURS,
    REPUTATION_REFRESH_HOURS,
    REPUTATION_RETRY_SECONDS,
    REPUTATION_SPAMHAUS_ASNDROP_URL,
    REPUTATION_SPAMHAUS_DROP_V4_URL,
    REPUTATION_SPAMHAUS_DROP_V6_URL,
    REPUTATION_TOR_EXIT_URL,
    REPUTATION_USER_AGENT,
    REPUTATION_VPN_V4_URL,
    REPUTATION_VPN_V6_URL,
    REPUTATION_WEIGHTS,
)

LEVELS = ("none", "low", "medium", "high")

# Spamhaus: "The DROP list data should not be downloaded from our website more
# than once per day." A term of use, so not configurable.
SPAMHAUS_MIN_REQUEST_SECONDS = 24 * 3600
SPAMHAUS_TERMS_URL = "https://www.spamhaus.org/drop/terms/"

# A download bigger than this is refused unread. The largest list, X4BNet's
# datacenter IPv4 list, is about 0.7 MB.
MAX_LIST_BYTES = 16 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30


class Intervals:
    """Disjoint integer ranges, sorted by start and searched with bisect.

    Overlapping and adjacent ranges are merged on the way in. A list holding a
    /16 and a /24 inside it would otherwise leave bisect on the /24 for an
    address past the /24's end, and report that address as unlisted.
    """

    __slots__ = ("starts", "ends")

    def __init__(self, ranges: Iterable[tuple[int, int]]):
        starts: list[int] = []
        ends: list[int] = []
        for start, end in sorted(ranges):
            if ends and start <= ends[-1] + 1:
                ends[-1] = max(ends[-1], end)
            else:
                starts.append(start)
                ends.append(end)
        self.starts = starts
        self.ends = ends

    def __contains__(self, value: int) -> bool:
        i = bisect.bisect_right(self.starts, value) - 1
        return i >= 0 and value <= self.ends[i]

    def __len__(self) -> int:
        return len(self.starts)


@dataclass(frozen=True)
class ListData:
    """One parsed list file. `entries` counts what the file listed (networks,
    addresses or AS numbers) before merging. `downloaded` is when the copy was
    taken: the file's mtime, which the download sets."""

    v4: Intervals
    v6: Intervals
    asns: frozenset[int]
    entries: int
    notice: str | None = None
    downloaded: float | None = None


class _Ranges:
    """Collects networks as integer ranges per family, so a 44,000-line list
    never holds 44,000 ip_network objects at once."""

    def __init__(self):
        self.v4: list[tuple[int, int]] = []
        self.v6: list[tuple[int, int]] = []

    def add(self, text: str) -> bool:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return False
        family = self.v4 if network.version == 4 else self.v6
        family.append((int(network.network_address), int(network.broadcast_address)))
        return True

    def __len__(self) -> int:
        return len(self.v4) + len(self.v6)


def parse_spamhaus(text: str) -> ListData:
    """Spamhaus's DROP JSON (drop_v4.json, drop_v6.json, asndrop.json): one
    object per line, a {"cidr": ...} or {"asn": ...} per entry, and a closing
    {"type": "metadata"} record.

    A file without that record is refused. It is the last line, so a truncated
    download has none, and it carries the copyright notice Spamhaus asks to
    keep with the data; the notice is shown wherever the data is.
    """
    networks = _Ranges()
    asns: set[int] = set()
    meta = None
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if record.get("type") == "metadata":
            meta = record
        elif "cidr" in record:
            networks.add(str(record["cidr"]))
        elif "asn" in record:
            try:
                asns.add(int(record["asn"]))
            except (TypeError, ValueError):
                continue
    if meta is None:
        raise ValueError("no metadata record: truncated, or not a Spamhaus DROP file")
    # Shown on the page and in every answer, so bounded: it comes off the wire.
    notice = meta.get("copyright")
    return ListData(
        Intervals(networks.v4),
        Intervals(networks.v6),
        frozenset(asns),
        len(networks) + len(asns),
        notice[:200] if isinstance(notice, str) else None,
    )


def parse_lines(text: str) -> ListData:
    """One address or CIDR per line: the Tor bulk exit list, X4BNet's lists.

    Comments, blank lines and anything that is not an address are skipped, so
    an HTML error page parses to nothing and fails its list's minimum.
    """
    networks = _Ranges()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            networks.add(line)
    return ListData(
        Intervals(networks.v4), Intervals(networks.v6), frozenset(), len(networks)
    )


@dataclass(frozen=True)
class ListFile:
    """One downloaded file. `covers` is what it answers for: "4", "6" or
    "asn". A download with fewer than `min_entries` is refused, so an empty
    list or an error page never replaces a working copy."""

    name: str
    url: str
    parse: Callable[[str], ListData]
    covers: str
    min_entries: int


@dataclass(frozen=True)
class Feed:
    """One list as a reader sees it, kept in one file per address family.

    `id`, `label`, `source` and `weight` are what a signal carries, so another
    source (an API, say) can be added as one more Feed without changing the
    shape of the answer. `notice` is the credit shown wherever the list's data
    is, with "{notice}" replaced by the copyright line the file carries.
    `min_request_seconds` is the least time between two requests for one of its
    files, whether the last one worked or not.
    """

    id: str
    label: str
    source: str
    weight: int
    files: tuple[ListFile, ...]
    notice: str
    min_request_seconds: float = 0.0


def default_feeds() -> tuple[Feed, ...]:
    """The lists, in the order they are reported. Each minimum is about a
    quarter of the list's size on 2026-10-09: low enough for any real day,
    high enough that a truncated or substituted file cannot pass."""
    spamhaus = "Spamhaus DROP and ASN-DROP: {notice}, " + SPAMHAUS_TERMS_URL
    x4b = "VPN and datacenter lists: X4BNet lists_vpn, (c) 2024 X4B, MIT licence"
    return (
        Feed(
            "spamhaus_drop",
            "Spamhaus DROP",
            "Spamhaus",
            REPUTATION_WEIGHTS["spamhaus_drop"],
            (
                ListFile(
                    "spamhaus_drop_v4.json",
                    REPUTATION_SPAMHAUS_DROP_V4_URL,
                    parse_spamhaus,
                    "4",
                    400,
                ),
                ListFile(
                    "spamhaus_drop_v6.json",
                    REPUTATION_SPAMHAUS_DROP_V6_URL,
                    parse_spamhaus,
                    "6",
                    20,
                ),
            ),
            spamhaus,
            SPAMHAUS_MIN_REQUEST_SECONDS,
        ),
        Feed(
            "spamhaus_asndrop",
            "Spamhaus ASN-DROP",
            "Spamhaus",
            REPUTATION_WEIGHTS["spamhaus_asndrop"],
            (
                ListFile(
                    "spamhaus_asndrop.json",
                    REPUTATION_SPAMHAUS_ASNDROP_URL,
                    parse_spamhaus,
                    "asn",
                    100,
                ),
            ),
            spamhaus,
            SPAMHAUS_MIN_REQUEST_SECONDS,
        ),
        Feed(
            "tor_exit",
            "Tor exit",
            "Tor Project",
            REPUTATION_WEIGHTS["tor_exit"],
            (ListFile("tor_exit.txt", REPUTATION_TOR_EXIT_URL, parse_lines, "4", 300),),
            "Tor exit list: the Tor Project, check.torproject.org",
        ),
        Feed(
            "vpn",
            "VPN",
            "X4BNet lists_vpn",
            REPUTATION_WEIGHTS["vpn"],
            (
                ListFile(
                    "x4b_vpn_v4.txt", REPUTATION_VPN_V4_URL, parse_lines, "4", 2500
                ),
                ListFile(
                    "x4b_vpn_v6.txt", REPUTATION_VPN_V6_URL, parse_lines, "6", 100
                ),
            ),
            x4b,
        ),
        Feed(
            "datacenter",
            "Datacenter",
            "X4BNet lists_vpn",
            REPUTATION_WEIGHTS["datacenter"],
            (
                ListFile(
                    "x4b_datacenter_v4.txt",
                    REPUTATION_DATACENTER_V4_URL,
                    parse_lines,
                    "4",
                    10000,
                ),
                ListFile(
                    "x4b_datacenter_v6.txt",
                    REPUTATION_DATACENTER_V6_URL,
                    parse_lines,
                    "6",
                    2000,
                ),
            ),
            x4b,
        ),
    )


def grade(signals: list[dict]) -> str:
    """The level for a set of signals: the REPUTATION_LEVEL_* band their summed
    weights fall in. Only the signals decide it. The lists that could not be
    checked are reported beside it, never folded in, and when none could be
    checked there is no level at all (see check())."""
    total = sum(signal["weight"] for signal in signals)
    if total >= REPUTATION_LEVEL_HIGH:
        return "high"
    if total >= REPUTATION_LEVEL_MEDIUM:
        return "medium"
    if total >= REPUTATION_LEVEL_LOW:
        return "low"
    return "none"


def _download(url: str) -> bytes:
    """GET one list. The URL is operator config, never user input."""
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": REPUTATION_USER_AGENT}
    )
    with urllib.request.urlopen(  # noqa: S310
        request, timeout=DOWNLOAD_TIMEOUT_SECONDS
    ) as response:
        data = response.read(MAX_LIST_BYTES + 1)
    if len(data) > MAX_LIST_BYTES:
        raise ValueError(f"{url} is larger than {MAX_LIST_BYTES} bytes")
    return data


def _mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def _iso(epoch: float) -> str:
    when = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_text(hours: float) -> str:
    return f"{hours:.0f} hours" if hours < 48 else f"{hours / 24:.0f} days"


class ReputationManager:
    """The lists in REPUTATION_DIR, loaded into memory, and kept current.

    Built the way TldNamesManager is: a download goes to a temporary file that
    os.replace swaps in only once it has parsed and passed its minimum, a copy
    has an age, and a failed download is tried again later. A copy left by an
    earlier run is loaded at startup, so a restart serves at once and downloads
    nothing that is still fresh.

    Disabled (REPUTATION_ENABLED=false), it loads nothing, downloads nothing,
    and check() answers None, which leaves `reputation` out of every response.
    """

    def __init__(
        self,
        directory: str = REPUTATION_DIR,
        feeds: Iterable[Feed] | None = None,
        enabled: bool = REPUTATION_ENABLED,
        fetch: Callable[[str], bytes] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.directory = directory
        self.feeds = default_feeds() if feeds is None else tuple(feeds)
        self.enabled = enabled
        self._fetch = fetch or _download
        self._clock = clock
        # File name -> its parsed copy. Replaced one item at a time by the
        # scheduler thread and read by lookups; an item assignment is atomic.
        self._lists: dict[str, ListData] = {}
        if enabled:
            for feed in self.feeds:
                for spec in feed.files:
                    self._load(spec)

    def _path(self, spec: ListFile) -> str:
        return os.path.join(self.directory, spec.name)

    def _stamp(self, spec: ListFile) -> str:
        """Its mtime is when the file was last requested, worked or not."""
        return self._path(spec) + ".requested"

    @staticmethod
    def _parse(spec: ListFile, text: str) -> ListData:
        data = spec.parse(text)
        if data.entries < spec.min_entries:
            raise ValueError(
                f"{spec.name} has {data.entries} entries, "
                f"fewer than the {spec.min_entries} expected"
            )
        return data

    def _load(self, spec: ListFile) -> None:
        """Read the copy an earlier run left, if it parses. One that does not
        is left unloaded, which makes it due for a download."""
        path = self._path(spec)
        downloaded = _mtime(path)
        if downloaded is None:
            return
        try:
            with open(path, encoding="utf-8") as handle:
                data = self._parse(spec, handle.read())
        except Exception:
            logging.exception("Ignoring the unreadable reputation list %s", path)
            return
        self._lists[spec.name] = dataclasses.replace(data, downloaded=downloaded)

    def _age_hours(self, spec: ListFile) -> float | None:
        data = self._lists.get(spec.name)
        if data is None:
            return None
        return max(self._clock() - data.downloaded, 0.0) / 3600

    def _current(self, spec: ListFile) -> ListData | None:
        """The copy lookups may read: loaded, and younger than
        REPUTATION_MAX_AGE_HOURS."""
        age = self._age_hours(spec)
        if age is None or age >= REPUTATION_MAX_AGE_HOURS:
            return None
        return self._lists[spec.name]

    def _why_not(self, spec: ListFile) -> str:
        age = self._age_hours(spec)
        if age is None:
            return "the list has not been downloaded"
        return f"the list is {_age_text(age)} old"

    def refresh(self) -> bool:
        """Download every list file that is due; whether all are current after.
        Run by the scheduler, never by a request.

        A file is due when there is no usable copy, or the copy is
        REPUTATION_REFRESH_HOURS old. A due file still waits while its last
        request is under REPUTATION_RETRY_SECONDS old, or under a day for
        Spamhaus. The request time is written to disk before the request is
        sent, so neither wait resets on a restart, and a request that failed
        counts as much as one that worked.
        """
        if not self.enabled:
            return True
        current = True
        for feed in self.feeds:
            for spec in feed.files:
                current = self._refresh_file(feed, spec) and current
        return current

    def _refresh_file(self, feed: Feed, spec: ListFile) -> bool:
        age = self._age_hours(spec)
        if age is not None and age < REPUTATION_REFRESH_HOURS:
            return True
        now = self._clock()
        last = _mtime(self._stamp(spec))
        wait = max(feed.min_request_seconds, REPUTATION_RETRY_SECONDS)
        if last is not None and now - last < wait:
            return False
        try:
            os.makedirs(self.directory, exist_ok=True)
            with open(self._stamp(spec), "w", encoding="utf-8") as handle:
                handle.write(spec.url + "\n")
            os.utime(self._stamp(spec), (now, now))
        except OSError:
            # Unrecorded, nothing would stop the next tick or the next restart
            # from asking again, so the request is not sent at all.
            logging.exception(
                "Cannot record a request for %s; not downloading it", spec.name
            )
            return False
        try:
            raw = self._fetch(spec.url)
            data = self._parse(spec, raw.decode("utf-8"))
            path = self._path(spec)
            tmp = path + ".tmp"
            with open(tmp, "wb") as handle:
                handle.write(raw)
            os.replace(tmp, path)
            os.utime(path, (now, now))
        except Exception:
            logging.exception(
                "Error updating the reputation list %s from %s", spec.name, spec.url
            )
            return False
        self._lists[spec.name] = dataclasses.replace(data, downloaded=now)
        logging.info("Reputation list %s updated (%d entries)", spec.name, data.entries)
        return True

    def check(self, ip: str, asn: int | None = None) -> dict | None:
        """Which lists `ip` is on, read from memory only. `asn` is its AS
        number, for ASN-DROP; without one that list is not checked.

        {level, signals, checked, unavailable, attribution}:
        - signals: {id, label, source, as_of, weight} per list the address is on
        - checked: {id, label, source, as_of} per list that was read, listed or
          not, so "on none of these" can name what "these" were
        - unavailable: {id, label, source, reason} per list that could not
          answer: never downloaded, past REPUTATION_MAX_AGE_HOURS, or not
          covering this address family
        - level: none/low/medium/high from the signals (grade()), or None when
          no list could be checked at all, which is unknown rather than "none"
        - attribution: the credit each list read asks for

        None when disabled, or when `ip` is not an address.
        """
        if not self.enabled:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        family = str(address.version)
        value = int(address)

        signals: list[dict] = []
        checked: list[dict] = []
        unavailable: list[dict] = []
        attribution: list[str] = []
        for feed in self.feeds:
            entry = {"id": feed.id, "label": feed.label, "source": feed.source}
            by_asn = any(spec.covers == "asn" for spec in feed.files)
            spec = next(
                (s for s in feed.files if s.covers == ("asn" if by_asn else family)),
                None,
            )
            data = self._current(spec) if spec else None
            if spec is None:
                covered = " and ".join(f"IPv{s.covers}" for s in feed.files)
                reason = f"the list covers {covered} addresses only"
            elif data is None:
                reason = self._why_not(spec)
            elif by_asn and asn is None:
                reason = "no AS number is known for this address"
            else:
                reason = None
            if reason:
                unavailable.append({**entry, "reason": reason})
                continue

            as_of = _iso(data.downloaded)
            checked.append({**entry, "as_of": as_of})
            if by_asn:
                listed = asn in data.asns
            else:
                listed = value in (data.v4 if family == "4" else data.v6)
            if listed:
                signals.append({**entry, "as_of": as_of, "weight": feed.weight})
            credit = feed.notice.format(notice=data.notice or feed.source)
            if credit not in attribution:
                attribution.append(credit)

        return {
            "level": grade(signals) if checked else None,
            "signals": signals,
            "checked": checked,
            "unavailable": unavailable,
            "attribution": attribution,
        }

    def status(self) -> dict:
        """Per list: its age (the oldest of its files), entries and whether
        lookups can read it, for /healthz."""
        if not self.enabled:
            return {"enabled": False}
        lists = {}
        for feed in self.feeds:
            ages = [self._age_hours(spec) for spec in feed.files]
            missing = None in ages
            oldest = None if missing else max(ages)
            lists[feed.id] = {
                "label": feed.label,
                "age_hours": None if oldest is None else round(oldest, 1),
                "entries": sum(
                    self._lists[spec.name].entries
                    for spec in feed.files
                    if spec.name in self._lists
                ),
                "stale": missing or oldest >= REPUTATION_MAX_AGE_HOURS,
            }
        return {"enabled": True, "lists": lists}

    def stale_lists(self) -> list[str]:
        """One message per list lookups cannot fully read, for /healthz."""
        if not self.enabled:
            return []
        messages = []
        for feed in self.feeds:
            ages = [self._age_hours(spec) for spec in feed.files]
            if None in ages:
                messages.append(
                    f"the {feed.label} list has not been downloaded: lookups "
                    "report it as not checked"
                )
            elif max(ages) >= REPUTATION_MAX_AGE_HOURS:
                messages.append(
                    f"the {feed.label} list is {max(ages):.0f} hours old "
                    f"(limit {REPUTATION_MAX_AGE_HOURS:g}): lookups report it as "
                    "not checked"
                )
        return messages

    def hosts(self) -> list[str]:
        """The servers the lists come from, for /privacy."""
        hosts = []
        for feed in self.feeds:
            for spec in feed.files:
                host = urllib.parse.urlparse(spec.url).hostname or spec.url
                if host not in hosts:
                    hosts.append(host)
        return hosts
