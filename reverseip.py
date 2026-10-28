"""Reverse IP from OpenINTEL's top-list DNS measurements: the source table,
the licence lines that go wherever its data does, and ReverseIpManager, whose
refresh downloads and builds in a child process (`reverseip_build`).

Imports `config` and the standard library only. It must not import `lookup`
or `main`, for `subdomains.py`'s reason, and never `pyarrow` or
`reverseip_build`, which only the child process loads."""

import json
import logging
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import config
from config import (
    REVERSEIP_BASE_URL,
    REVERSEIP_BUILD_TIMEOUT_SECONDS,
    REVERSEIP_DIR,
    REVERSEIP_ENABLED,
)

logger = logging.getLogger(__name__)

DATABASE_NAME = "reverseip.sqlite3"
SCHEMA_VERSION = 1
COPIES_NAME = "copies.json"

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
    # The bucket path segment: `source=tranco` or `source=crux/country-code=kr`.
    path: str


def _source(source_id: str) -> Source:
    if source_id in _LABELS:
        return Source(source_id, _LABELS[source_id], f"source={source_id}")
    if source_id.startswith(f"{_CRUX}:"):
        scope = source_id.split(":", 1)[1]
        if scope == "global":
            return Source(source_id, "Chrome UX Report (global)", "source=crux")
        if _COUNTRY.fullmatch(scope):
            return Source(
                source_id,
                f"Chrome UX Report ({scope.upper()})",
                f"source=crux/country-code={scope}",
            )
    raise ValueError(f"unknown reverse IP source: {source_id!r}")


def parse_sources(text: str) -> tuple[Source, ...]:
    """The comma-separated ids of REVERSEIP_SOURCES, in the order given."""
    return tuple(_source(part.strip()) for part in text.split(",") if part.strip())


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
        self.sources = (
            parse_sources(config.REVERSEIP_SOURCES)
            if sources is None
            else tuple(sources)
        )
        self.enabled = enabled
        # Every age check reads this clock.
        self._clock = clock
        # runner(args, **kwargs) -> CompletedProcess, as subprocess.run.
        self._runner = runner or subprocess.run
        # Whether a refresh has run since start, which is what tries to build
        # the database. Before one, a missing database is a fresh volume, not
        # a fault.
        self.build_attempted = False

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
