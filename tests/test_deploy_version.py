"""/healthz reports the deployed commit.

The deploy workflow polls it after asking Coolify to deploy and only succeeds
once it reads back the SHA that CI passed, so the field has to be exactly the
commit — and something unmistakably not a commit when none was provided.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

import config
import main

client = TestClient(main.app)

SHA = "0123456789abcdef0123456789abcdef01234567"


def test_healthz_reports_version(monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", SHA)
    response = client.get("/healthz", headers={"user-agent": "curl/8"})
    assert response.status_code == 200
    assert response.json()["version"] == SHA


@pytest.fixture
def reload_config(monkeypatch):
    """APP_VERSION is read once at import, so exercising it means re-importing
    config under a patched environment — and re-importing it again afterwards
    so every later test sees the real environment's values."""
    yield lambda: importlib.reload(config)
    monkeypatch.undo()
    importlib.reload(config)


@pytest.mark.parametrize(
    "raw, expected",
    [
        (SHA, SHA),
        (f"  {SHA}\n", SHA),
        # The Dockerfile declares ENV SOURCE_COMMIT=${SOURCE_COMMIT}, which is
        # set-but-empty whenever the build arg was not passed.
        ("", "unknown"),
    ],
)
def test_app_version_from_source_commit(monkeypatch, reload_config, raw, expected):
    monkeypatch.setenv("SOURCE_COMMIT", raw)
    assert reload_config().APP_VERSION == expected


def test_app_version_when_unset(monkeypatch, reload_config):
    monkeypatch.delenv("SOURCE_COMMIT", raising=False)
    assert reload_config().APP_VERSION == "unknown"
