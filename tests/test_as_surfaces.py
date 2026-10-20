"""AS information on the operator's surfaces: the refresh job and /healthz.

The suite runs with ASINFO_ENABLED=false; a test that wants the feature asks
for the `asinfo_enabled` fixture (conftest), or builds its own manager.
"""

import json
import os
import subprocess  # noqa: S404
import sys
from pathlib import Path

from fastapi.testclient import TestClient

import config
import lookup
import main
from asinfo import AsInfoManager
from asinfo_fixtures import HOUR, NOW, build_manager
from test_boot import IMPORT_PROBE

ROOT = Path(__file__).resolve().parent.parent
client = TestClient(main.app)


def _reasons(body: dict) -> dict:
    return {reason["code"]: reason for reason in body["reasons"]}


def test_healthz_reports_asinfo_status_and_stale_datasets(monkeypatch, tmp_path):
    manager = build_manager(tmp_path)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    body = client.get("/healthz").json()
    assert body["asinfo"] == manager.status()
    assert body["asinfo"]["enabled"] is True
    assert body["asinfo"]["database"] is True
    assert "asinfo_dataset_stale" not in _reasons(body)
    assert "asinfo_unavailable" not in _reasons(body)

    # Three days and an hour on: the daily datasets are past ASINFO_MAX_AGE_HOURS.
    later = build_manager(
        tmp_path / "later",
        clock=lambda: NOW + config.ASINFO_MAX_AGE_HOURS * HOUR + HOUR,
    )
    monkeypatch.setattr(main, "asinfo_manager", later)
    body = client.get("/healthz").json()
    stale = [r for r in body["reasons"] if r["code"] == "asinfo_dataset_stale"]
    assert body["status"] == "degraded"
    assert [r["message"] for r in stale] == later.stale_datasets()
    assert len(stale) >= 1
    assert body["asinfo"]["datasets"]["asnames"]["stale"] is True


def test_healthz_says_unavailable_only_after_the_first_build_attempt(
    monkeypatch, tmp_path
):
    empty = tmp_path / "empty"
    manager = AsInfoManager(directory=str(empty), enabled=True)
    monkeypatch.setattr(main, "asinfo_manager", manager)

    # A fresh volume, before the first refresh: not a fault.
    body = client.get("/healthz").json()
    assert body["asinfo"]["database"] is False
    assert "asinfo_unavailable" not in _reasons(body)

    manager.build_attempted = True
    body = client.get("/healthz").json()
    assert body["status"] == "degraded"
    assert "asinfo_unavailable" in _reasons(body)
    # Its absence is reported once, not once per dataset.
    assert "asinfo_dataset_stale" not in _reasons(body)


def test_healthz_says_unavailable_for_a_database_that_will_not_read(
    monkeypatch, tmp_path
):
    built = build_manager(tmp_path / "built")
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / os.path.basename(built.path)).write_bytes(b"this is not sqlite" * 100)
    manager = AsInfoManager(directory=str(broken), enabled=True)
    monkeypatch.setattr(main, "asinfo_manager", manager)

    body = client.get("/healthz").json()
    assert body["asinfo"]["database"] is False
    assert "asinfo_unavailable" in _reasons(body)


def test_healthz_says_nothing_about_asinfo_when_it_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(
        main, "asinfo_manager", AsInfoManager(directory=str(tmp_path), enabled=False)
    )
    body = client.get("/healthz").json()
    assert body["asinfo"] == {"enabled": False}
    assert not [r for r in body["reasons"] if r["code"].startswith("asinfo")]


def test_asinfo_enabled_fixture_turns_the_feature_on(asinfo_enabled):
    assert lookup.asinfo_manager is asinfo_enabled
    assert main.asinfo_manager is asinfo_enabled
    assert asinfo_enabled.enabled is True
    assert client.get("/healthz").json()["asinfo"]["database"] is True


def test_refresh_asinfo_job_is_registered_and_skipped_when_disabled(tmp_path):
    job = main.scheduler.get_job("refresh-asinfo")
    assert job is not None
    assert job.max_instances == 1
    assert job.coalesce is True
    # Due at import, run when the lifespan starts the scheduler.
    assert job.misfire_grace_time is None
    assert job.trigger.interval.total_seconds() == config.ASINFO_CHECK_INTERVAL_SECONDS
    # Not the retry timer, and no failure count.
    assert job.func.__name__ == "refresh"
    assert job.func.__self__ is lookup.asinfo_manager
    assert "asinfo" not in main._refresh_failures

    # The suite runs with the feature off: the job does nothing, downloads
    # nothing and leaves the volume as it was.
    assert lookup.asinfo_manager.enabled is False
    assert job.func() is True
    assert lookup.asinfo_manager.build_attempted is False
    assert not os.path.exists(lookup.asinfo_manager.path)


def test_importing_main_downloads_no_as_data(tmp_path):
    """Production's settings on an empty volume: importing main asks nothing
    of the network, leaves the scheduler stopped and writes no AS file."""
    asinfo_dir = tmp_path / "asinfo"
    env = {
        **os.environ,
        "ASINFO_ENABLED": "true",
        "ASINFO_DIR": str(asinfo_dir),
        "BACKGROUND_REFRESH_ENABLED": "true",
        "TLD_NAMES_DIR": str(tmp_path / "tld"),
        "REPUTATION_DIR": str(tmp_path / "reputation"),
    }
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
    assert not asinfo_dir.exists() or not list(asinfo_dir.iterdir())
