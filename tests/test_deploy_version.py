"""/healthz reports the deployed commit.

The deploy workflow polls it after asking Coolify to deploy and only succeeds
once it reads back the SHA that CI passed, so the field has to be exactly the
commit — and something unmistakably not a commit when none was provided.
"""

import importlib
import os
import subprocess
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import config
import main

client = TestClient(main.app)

SHA = "0123456789abcdef0123456789abcdef01234567"
WORKFLOW = Path(".github/workflows/deploy.yml")


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


def _served_version_function() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    start = workflow.index("          served_version() {")
    end = workflow.index("\n          }", start) + len("\n          }")
    return textwrap.dedent(workflow[start:end])


def _run_served_version(tmp_path, health, mcp, health_status=0, mcp_status=0):
    curl = tmp_path / "curl"
    curl.write_text(
        """#!/bin/sh
case " $* " in
  *" $HEALTHZ_URL "*) printf '%s' "$HEALTH_RESPONSE"; exit "$HEALTH_STATUS" ;;
  *" $MCP_URL "*) printf '%s' "$MCP_RESPONSE"; exit "$MCP_STATUS" ;;
  *) exit 2 ;;
esac
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "HEALTHZ_URL": "https://example.test/healthz",
        "MCP_URL": "https://example.test/mcp",
        "HEALTH_RESPONSE": health,
        "MCP_RESPONSE": mcp,
        "HEALTH_STATUS": str(health_status),
        "MCP_STATUS": str(mcp_status),
    }
    script = f"set -euo pipefail\n{_served_version_function()}\nserved_version"
    return subprocess.run(  # noqa: S603 - executes the checked-in workflow snippet
        ["/bin/bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_deploy_parser_prefers_healthz_version(tmp_path):
    result = _run_served_version(
        tmp_path,
        health=f'{{"status":"ok","version":"{SHA}"}}',
        mcp="not an MCP response",
    )
    assert result.returncode == 0
    assert result.stdout.strip() == SHA


def test_deploy_parser_falls_back_to_mcp_initialize_version(tmp_path):
    response = (
        '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":'
        f'{{"name":"whatismyip","version":"{SHA}"}}}}'
    )
    result = _run_served_version(
        tmp_path,
        health="policy denied",
        health_status=22,
        mcp=response,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == SHA


@pytest.mark.parametrize(
    "response",
    [
        f'{{"jsonrpc":"2.0","id":1,"result":{{"version":"{SHA}"}}}}',
        (
            '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":'
            f'{{"name":"another-server","version":"{SHA}"}}}}'
        ),
    ],
)
def test_deploy_parser_rejects_arbitrary_mcp_success(tmp_path, response):
    result = _run_served_version(
        tmp_path,
        health="policy denied",
        health_status=22,
        mcp=response,
    )
    assert result.returncode != 0
    assert result.stdout == ""
