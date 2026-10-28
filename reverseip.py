"""Reverse IP from OpenINTEL's top-list DNS measurements: the source table,
the licence lines that go wherever its data does, and ReverseIpManager, whose
refresh downloads and builds in a child process (`reverseip_build`).

Imports `config` and the standard library only. It must not import `lookup`
or `main`, for `subdomains.py`'s reason, and never `pyarrow` or
`reverseip_build`, which only the child process loads."""

import ipaddress
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
from calendar import timegm
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import config
from config import (
    REVERSEIP_BASE_URL,
    REVERSEIP_BUILD_TIMEOUT_SECONDS,
    REVERSEIP_DIR,
    REVERSEIP_ENABLED,
    REVERSEIP_LIST_LIMIT,
    SUBDOMAIN_MAX_NAMES,
)

logger = logging.getLogger(__name__)

DATABASE_NAME = "reverseip.sqlite3"
SCHEMA_VERSION = 1
COPIES_NAME = "copies.json"
_NOT_DOWNLOADED = "not downloaded yet"
_NOT_BUILT = "the database has not been built"
_UNREADABLE = "the database could not be read"
_OTHER_RELEASE = "the database is from another release"
_NOT_IN_DATABASE = "not in the database"

_LABELS = {
    "tranco": "Tranco",
    "umbrella": "Cisco Umbrella",
    "radar": "Cloudflare Radar",
    "majestic": "Majestic Million",
}
_CRUX = "crux"
_COUNTRY = re.compile(r"[a-z]{2}")


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    # The bucket path segment: `source=tranco`, or `source=crux/country-code=kr`
    # and `source=crux/country-code=global` (CrUX's global list is a country
    # code of its own in the bucket).
    path: str


def _source(source_id: str) -> Source:
    if source_id in _LABELS:
        return Source(source_id, _LABELS[source_id], f"source={source_id}")
    if source_id.startswith(f"{_CRUX}:"):
        scope = source_id.split(":", 1)[1]
        if scope == "global":
            return Source(
                source_id,
                "Chrome UX Report (global)",
                "source=crux/country-code=global",
            )
        if _COUNTRY.fullmatch(scope):
            return Source(
                source_id,
                f"Chrome UX Report ({scope.upper()})",
                f"source=crux/country-code={scope}",
            )
    raise ValueError(f"unknown reverse IP source: {source_id!r}")


def parse_sources(text: str) -> tuple[Source, ...]:
    """The comma-separated ids of REVERSEIP_SOURCES, in the order given. An
    id given twice is kept where it first appears, and the repeat logged: one
    list, one bit in the build and one `source_meta` row."""
    sources: dict[str, Source] = {}
    for part in text.split(","):
        source_id = part.strip()
        if not source_id:
            continue
        source = _source(source_id)
        if source.id in sources:
            logger.warning(
                "REVERSEIP_SOURCES names %s more than once; reading it once",
                source.id,
            )
            continue
        sources[source.id] = source
    return tuple(sources.values())


def file_stem(source_id: str) -> str:
    return source_id.replace(":", "-")


def coverage_sentence(sources: Sequence[Source]) -> str:
    """What the answer covers: only the names on these lists. The CrUX entries
    collapse into one name, at the position of the first."""
    names: list[str] = []
    crux: list[str] = []
    for source in sources:
        if source.id.startswith(f"{_CRUX}:"):
            scope = source.id.split(":", 1)[1]
            if not crux:
                names.append("")
            crux.append("global" if scope == "global" else scope.upper())
        else:
            names.append(source.label)
    if crux:
        names[names.index("")] = f"Chrome UX Report ({', '.join(crux)})"
    if len(names) > 1:
        listed = f"{', '.join(names[:-1])} and {names[-1]}"
    else:
        listed = "".join(names)
    return f"Names on the {listed} top {'lists' if len(names) > 1 else 'list'} only."


def licence_lines(sources: Sequence[Source] | None = None) -> dict:
    """The lines every surface that shows OpenINTEL data carries. Coverage
    names the lists actually read: the given sources, else the configured."""
    if sources is None:
        sources = parse_sources(config.REVERSEIP_SOURCES)
    return {
        "coverage": coverage_sentence(sources),
        "license": config.OPENINTEL_LICENSE,
        "license_url": config.OPENINTEL_LICENSE_URL,
        "terms_url": config.REVERSEIP_TERMS_URL,
        "attribution": config.OPENINTEL_ATTRIBUTION,
    }


# The child runs from this file's directory, where `-m reverseip_build` finds
# the module with no PYTHONPATH.
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_CURRENT_STATES = ("current", "downloaded")


def _log_child(stderr: str | bytes | None) -> None:
    """The child's log lines, each as a line of this process's log: the child
    exports nothing itself."""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    for line in (stderr or "").splitlines():
        if line.strip():
            logger.info("reverseip_build: %s", line)


class ReverseIpManager:
    """The reverse IP database in REVERSEIP_DIR.

    refresh() downloads and builds it in a child process; see there.

    Disabled (REVERSEIP_ENABLED=false), it runs nothing."""

    def __init__(
        self,
        directory: str = REVERSEIP_DIR,
        sources: Sequence[Source] | None = None,
        enabled: bool = REVERSEIP_ENABLED,
        clock: Callable[[], float] = time.time,
        runner: Callable[..., subprocess.CompletedProcess] | None = None,
    ):
        self.directory = directory
        self.path = os.path.join(directory, DATABASE_NAME)
        self.enabled = enabled
        # Read only when enabled: an id this release does not know must not
        # stop the service from starting with the feature off.
        if sources is not None:
            self.sources = tuple(sources)
        elif enabled:
            self.sources = parse_sources(config.REVERSEIP_SOURCES)
        else:
            self.sources = ()
        # Every age check reads this clock.
        self._clock = clock
        # runner(args, **kwargs) -> CompletedProcess, as subprocess.run.
        self._runner = runner or subprocess.run
        # Whether a refresh has run since start, which is what tries to build
        # the database. Before one, a missing database is a fresh volume, not
        # a fault.
        self.build_attempted = False
        self._local = threading.local()
        # The last file that failed to read, logged once rather than per
        # lookup, named by its device, inode, mtime and size.
        self._unreadable: tuple | None = None

    def refresh(self) -> bool:
        """Run `python -m reverseip_build` and wait for it; whether every
        source is current afterwards. Run by the scheduler, one run at a time,
        never by a request.

        The child does the download and the build (reverseip_build.
        refresh_sources) and exits, so pyarrow's memory goes with it. It gets
        this environment without PYTHONPATH, which opentelemetry-instrument
        sets to load its sitecustomize: the child is not instrumented and
        exports nothing, and its log lines reach the log here instead. It may
        run REVERSEIP_BUILD_TIMEOUT_SECONDS before it is stopped.

        False when the child failed, ran out of time or printed no summary,
        or when a source in the summary is `waiting` or `failed`."""
        if not self.enabled:
            return True
        try:
            return self._run_child()
        finally:
            self.build_attempted = True

    def _run_child(self) -> bool:
        settings = {
            # The child's working directory is not this process's.
            "directory": os.path.abspath(self.directory),
            "sources": ",".join(source.id for source in self.sources),
            "base_url": REVERSEIP_BASE_URL,
        }
        args = [sys.executable, "-m", "reverseip_build", json.dumps(settings)]
        env = {
            name: value for name, value in os.environ.items() if name != "PYTHONPATH"
        }
        try:
            done = self._runner(
                args,
                cwd=_APP_DIR,
                env=env,
                capture_output=True,
                text=True,
                timeout=REVERSEIP_BUILD_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            _log_child(exc.stderr)
            logger.error(
                "reverse IP: the build process was stopped after %s seconds",
                REVERSEIP_BUILD_TIMEOUT_SECONDS,
            )
            return False
        _log_child(done.stderr)
        if done.returncode != 0:
            logger.error(
                "reverse IP: the build process failed with exit status %s",
                done.returncode,
            )
            return False
        try:
            summary = json.loads(done.stdout.splitlines()[-1])
            states = [entry["state"] for entry in summary["sources"].values()]
        except (ValueError, LookupError, TypeError, AttributeError):
            logger.error(
                "reverse IP: the build process printed no summary: %r",
                done.stdout[-500:],
            )
            return False
        return all(state in _CURRENT_STATES for state in states)

    # Reads. A request thread reads the live file through its own read-only
    # connection; nothing here makes a request or writes.

    def _file_key(self) -> tuple | None:
        try:
            stat = os.stat(self.path)
        except OSError:
            return None
        return stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size

    def _database(self) -> tuple[sqlite3.Connection | None, dict, str | None]:
        """This thread's open connection and the `source_meta` rows, opened
        again when the file has changed since; or None and why there is none.
        Raises sqlite3.Error when the file does not read."""
        key = self._file_key()
        if key is None:
            self._release()
            return None, {}, (_NOT_BUILT if self.build_attempted else _NOT_DOWNLOADED)
        held = getattr(self._local, "held", None)
        if held is None or held[0] != key:
            self._release()
            held = (key, *self._open())
            self._local.held = held
        return held[1], held[2], held[3]

    def _open(self) -> tuple[sqlite3.Connection | None, dict, str | None]:
        uri = f"file:{urllib.parse.quote(os.path.abspath(self.path))}?mode=ro"
        con = sqlite3.connect(uri, uri=True)
        try:
            version = con.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                logger.warning(
                    "Not reading the reverse IP database %s: schema %s, expected %s",
                    self.path,
                    version,
                    SCHEMA_VERSION,
                )
                con.close()
                return None, {}, _OTHER_RELEASE
            meta = {
                row[0]: row[1:]
                for row in con.execute("SELECT id, date, pairs, error FROM source_meta")
            }
        except sqlite3.Error:
            con.close()
            raise
        return con, meta, None

    def _release(self) -> None:
        """Close this thread's connection, which holds its file open (on disk,
        even after a swap unlinked it) until then."""
        held = getattr(self._local, "held", None)
        self._local.held = None
        if held is not None and held[1] is not None:
            held[1].close()

    def _with_database[T](
        self, use: Callable[[sqlite3.Connection | None, dict, str | None], T]
    ) -> T:
        """`use(con, meta, problem)` on this thread's connection. When it
        fails to read, the file is opened afresh and `use` runs once more (a
        swap fails a read on macOS); a second failure is logged once per file
        and `use` gets no database. A ProgrammingError, a fault in a query
        rather than in the file, raises."""
        error = None
        for _ in range(2):
            try:
                answer = use(*self._database())
            except sqlite3.DatabaseError as exc:
                if isinstance(exc, sqlite3.ProgrammingError):
                    raise
                error = exc
                self._release()
                continue
            if error is not None:
                logger.warning(
                    "Read the reverse IP database %s again after an error (%s)",
                    self.path,
                    error,
                )
            return answer
        key = self._file_key()
        if key != self._unreadable:
            self._unreadable = key
            logger.error(
                "Cannot read the reverse IP database %s (%s)",
                self.path,
                error,
                exc_info=error,
            )
        return use(None, {}, _UNREADABLE)

    def _age_hours(self, date: str | None) -> float | None:
        """Hours from the start of the partition's UTC day, the build's rule."""
        try:
            year, month, day = (int(part) for part in str(date).split("-"))
            started = timegm((year, month, day, 0, 0, 0))
        except (ValueError, OverflowError):
            return None
        return (self._clock() - started) / 3600

    def _availability(
        self, con: sqlite3.Connection | None, meta: dict, problem: str | None
    ) -> tuple[dict[str, str], dict[str, str]]:
        """(dates, reasons): the date of each configured source lookups may
        read, and why each other one may not be."""
        limit = f"{config.REVERSEIP_MAX_AGE_HOURS:g}"
        dates: dict[str, str] = {}
        reasons: dict[str, str] = {}
        for source in self.sources:
            if con is None:
                reasons[source.id] = problem
                continue
            row = meta.get(source.id)
            if row is None:
                reasons[source.id] = _NOT_IN_DATABASE
                continue
            date, _, error = row
            age = self._age_hours(date)
            if error is not None and not error.startswith("older than"):
                reasons[source.id] = error
            elif error is not None or (
                age is not None and age > config.REVERSEIP_MAX_AGE_HOURS
            ):
                reasons[source.id] = f"last measured {date}, older than {limit} hours"
            else:
                dates[source.id] = date
        return dates, reasons

    def _unavailable(self, reasons: dict[str, str]) -> list[dict]:
        labels = {source.id: source.label for source in self.sources}
        return [
            {"source": i, "label": labels[i], "reason": reason}
            for i, reason in reasons.items()
        ]

    def for_address(self, ip: str, limit: int = REVERSEIP_LIST_LIMIT) -> dict | None:
        """The listed names that resolve to `ip`, with its /24 or /48; None
        when disabled. `total` 0 is "no listed name"; `total` None is
        "unknown", with the reasons in `unavailable`."""
        if not self.enabled:
            return None
        address = ipaddress.ip_address(ip)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        packed = address.packed
        prefix = packed[:3] if address.version == 4 else packed[:6]
        shown = (
            f"{ipaddress.IPv4Address(prefix + bytes(1))}/24"
            if address.version == 4
            else f"{ipaddress.IPv6Address(prefix + bytes(10))}/48"
        )

        def read(con, meta, problem):
            dates, reasons = self._availability(con, meta, problem)
            answer = {
                "total": None,
                "names": None,
                "truncated": None,
                "block": None,
                "as_of": None,
                "sources": [],
                "unavailable": self._unavailable(reasons),
            }
            if dates:
                row = con.execute(
                    "SELECT names FROM ip_count WHERE ip = ?", (packed,)
                ).fetchone()
                total = row[0] if row else 0
                names = [
                    name
                    for (name,) in con.execute(
                        "SELECT n.name FROM addr a JOIN names n ON n.id = a.name_id"
                        " WHERE a.ip = ? ORDER BY a.rank, a.name_id LIMIT ?",
                        (packed, limit),
                    )
                ]
                row = con.execute(
                    "SELECT addresses, names FROM block WHERE prefix = ?", (prefix,)
                ).fetchone()
                answer.update(
                    total=total,
                    names=names,
                    truncated=total > len(names),
                    block={
                        "prefix": shown,
                        "addresses": row[0] if row else 0,
                        "names": row[1] if row else 0,
                    },
                    as_of=min(dates.values()),
                )
            labels = {source.id: source.label for source in self.sources}
            answer["sources"] = [
                {"id": i, "label": labels[i], "date": date} for i, date in dates.items()
            ]
            return answer

        return {**self._with_database(read), **licence_lines(self.sources)}

    def names_under(self, domain: str, cap: int = SUBDOMAIN_MAX_NAMES) -> dict | None:
        """The listed names below `domain`, sorted and capped at `cap`; None
        when disabled. `count` is the true total, 0 for none listed and None
        for unknown. The read is bounded by `cap`: past it the kept names are
        the first `cap` in reversed-name order (an index range scan), not the
        alphabetically first `cap`; they are then sorted."""
        if not self.enabled:
            return None
        domain = domain.lower()
        domain = domain[:-1] if domain.endswith(".") else domain
        low = domain[::-1] + "."
        high = domain[::-1] + "/"

        def read(con, meta, problem):
            dates, reasons = self._availability(con, meta, problem)
            answer = {
                "names": None,
                "count": None,
                "truncated": None,
                "as_of": None,
                "unavailable": self._unavailable(reasons),
            }
            if dates:
                where = "FROM sub WHERE rname > ? AND rname < ?"
                (count,) = con.execute(
                    f"SELECT COUNT(*) {where}", (low, high)
                ).fetchone()
                found = sorted(
                    rname[::-1]
                    for (rname,) in con.execute(
                        f"SELECT rname {where} ORDER BY rname LIMIT ?",
                        (low, high, max(cap, 0)),
                    )
                )
                answer.update(
                    names=found,
                    count=count,
                    truncated=count > len(found),
                    as_of=min(dates.values()),
                )
            return answer

        return {**self._with_database(read), **licence_lines(self.sources)}

    def status(self) -> dict:
        """What `/healthz` reports: whether the database opens and, for each
        configured source, its date, age, pairs and whether lookups can read
        it."""
        if not self.enabled:
            return {"enabled": False}

        def read(con, meta, problem):
            _, reasons = self._availability(con, meta, problem)
            sources = {}
            for source in self.sources if con is not None else ():
                date, pairs, _ = meta.get(source.id) or (None, 0, None)
                age = self._age_hours(date)
                sources[source.id] = {
                    "label": source.label,
                    "date": date,
                    "age_hours": None if age is None else round(age, 1),
                    "pairs": pairs,
                    "stale": source.id in reasons,
                }
            return {"enabled": True, "database": con is not None, "sources": sources}

        return self._with_database(read)

    def stale_sources(self) -> list[str]:
        """One message per configured source lookups cannot read; empty when
        there is no database file (a fresh volume is not a fault)."""
        if not self.enabled:
            return []

        def read(con, meta, problem):
            if problem in (_NOT_DOWNLOADED, _NOT_BUILT):
                return []
            _, reasons = self._availability(con, meta, problem)
            return [
                f"the {item['label']} list is unavailable to lookups: {item['reason']}"
                for item in self._unavailable(reasons)
            ]

        return self._with_database(read)

    def hosts(self) -> list[str]:
        return [urllib.parse.urlsplit(REVERSEIP_BASE_URL).hostname]
