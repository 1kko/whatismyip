"""Importing main does no network I/O; the app lifespan does the boot work.

main.py used to start the scheduler, refresh the public suffix list and fetch
every GeoLite2 database that did not open, all at module scope, so any test
module that imported it downloaded tens of MB on a fresh checkout, CI included.
That work now runs in the app lifespan, which uvicorn enters once per process
before it binds the port, and which the suite's module-level TestClients never
enter.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi.testclient import TestClient

import main
from main import app

ROOT = Path(__file__).resolve().parent.parent

# Runs in a fresh interpreter, so main is imported for the first time. Every way
# out to the network records its name and raises: the boot refreshes catch
# their own exceptions, so only the record shows they tried.
IMPORT_PROBE = textwrap.dedent(
    """
    import json
    import socket
    import urllib.request

    attempts = []

    def refuse(name):
        def guard(*args, **kwargs):
            attempts.append(name)
            raise OSError(f"network refused for this test: {name}")
        return guard

    socket.socket.connect = refuse("socket.connect")
    socket.socket.connect_ex = refuse("socket.connect_ex")
    socket.socket.sendto = refuse("socket.sendto")
    socket.create_connection = refuse("socket.create_connection")
    socket.getaddrinfo = refuse("socket.getaddrinfo")
    urllib.request.urlopen = refuse("urllib.request.urlopen")

    import main

    print(json.dumps({
        "attempts": attempts,
        "scheduler_running": main.scheduler.running,
    }))
    """
)


def test_importing_main_touches_no_network(tmp_path):
    """On an empty data volume, where the old import fetched the public suffix
    list and both GeoLite2 databases, importing main asks nothing of the
    network and leaves the scheduler stopped."""
    data = tmp_path / "data"
    env = {
        **os.environ,
        # An empty volume: nothing has been downloaded yet, so a boot fetch at
        # import would have something to fetch.
        "GEOIP_CITY_DB_FILE": str(data / "GeoLite2-City.mmdb"),
        "GEOIP_ASN_DB_FILE": str(data / "GeoLite2-ASN.mmdb"),
        "TLD_NAMES_DIR": str(data / "tld"),
        "REPUTATION_DIR": str(data / "reputation"),
        "SUBDOMAIN_STORE_FILE": str(data / "subdomains.sqlite3"),
        "BANNED_IPS_FILE": str(data / "banned_ips.json"),
        "GEO_RULES_FILE": str(data / "geo_rules.json"),
        "IP_RULES_FILE": str(data / "ip_rules.json"),
        # Production's settings. They gate what the lifespan does; importing
        # must stay offline with them on.
        "BACKGROUND_REFRESH_ENABLED": "true",
        "REPUTATION_ENABLED": "true",
    }
    # The interpreter running this suite, on a fixed script.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", IMPORT_PROBE],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["attempts"] == []
    assert report["scheduler_running"] is False


def _record_boot(monkeypatch, scheduler: BackgroundScheduler) -> list:
    """Swap in a scheduler that has never run (a BackgroundScheduler cannot be
    started again once shut down) and record each boot fetch, with whether the
    scheduler was already running, without downloading anything."""
    calls = []
    monkeypatch.setattr(main, "scheduler", scheduler)
    monkeypatch.setattr(
        main, "refresh_tld_names", lambda: calls.append(("tld", scheduler.running))
    )
    monkeypatch.setattr(
        main,
        "_fetch_unloaded_geoip_dbs",
        lambda: calls.append(("geoip", scheduler.running)),
    )
    return calls


def test_the_lifespan_starts_the_scheduler_and_stops_it_on_shutdown(monkeypatch):
    scheduler = BackgroundScheduler()
    calls = _record_boot(monkeypatch, scheduler)
    monkeypatch.setattr(main, "BACKGROUND_REFRESH_ENABLED", True)
    with TestClient(app):
        assert scheduler.running
        # Started first, so the reputation check due at start runs while the
        # fetches hold up startup.
        assert calls == [("tld", True), ("geoip", True)]
    assert not scheduler.running


def test_the_first_reputation_check_is_not_dropped_for_starting_late():
    """refresh-reputation's first run is due the moment main is imported, and
    the scheduler starts later, in the lifespan. APScheduler skips a run that is
    more than misfire_grace_time late (1 s unless the job sets it), which would
    push the first download back a whole check interval."""
    job = main.scheduler.get_job("refresh-reputation")
    assert job.misfire_grace_time is None


def test_the_suite_lifespan_starts_nothing(monkeypatch):
    """tests/conftest.py turns BACKGROUND_REFRESH_ENABLED off, so the many
    `with TestClient(app)` blocks in the MCP tests download nothing."""
    scheduler = BackgroundScheduler()
    calls = _record_boot(monkeypatch, scheduler)
    assert main.BACKGROUND_REFRESH_ENABLED is False
    with TestClient(app):
        assert not scheduler.running
    assert calls == []
