"""/mcp honours a manual ban and nothing else.

Every user of a hosted AI client shares a handful of provider egress IPs, so a
ban that one of them earns on the lookup paths — a 1-hour rate_limit or a
24-hour suspicious_request — must not take the whole provider off /mcp. Only a
ban a person placed by hand (reason "manual", via POST /admin/ban/{ip}) does.
The lookup paths keep honouring every ban, exactly as before.

The middleware tests use `with TestClient(app)`: the MCP session manager is
started by the app lifespan, which TestClient only runs as a context manager.
"""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import main
from main import app, ip_ban_manager, rate_limiter
from security import IPBanManager

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "ip.1kko.com",
}

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


@pytest.fixture(autouse=True)
def _isolated_security_state():
    """conftest clears the lookup limiter and the ban list; the MCP bucket is
    separate. Geo-blocking is pinned open so that whatever GEO_RULES_FILE a
    previous run left behind cannot 403 a lookup before it earns its ban."""
    main.mcp_rate_limiter.request_history.clear()
    allowed = {"allowed": True, "country": "US", "region": None, "reason": "test"}
    with patch("main.geo_block_manager.check_access", return_value=allowed):
        yield
    main.mcp_rate_limiter.request_history.clear()
    # Persist the clear too, so no ban from here survives into BANNED_IPS_FILE
    # for the next pytest run to load.
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.save_bans()


def test_rate_limit_ban_from_a_lookup_path_does_not_block_mcp(monkeypatch):
    ip = "203.0.113.21"
    # Any lookup request now breaches the per-second limit: 429 plus a ban.
    monkeypatch.setattr(rate_limiter, "requests_per_second", 0)
    with TestClient(app, client=(ip, 41234)) as client:
        assert client.get("/").status_code == 429
        assert ip_ban_manager.banned_ips[ip]["reason"] == "rate_limit"

        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert response.status_code == 200

        # The settled lookup-path policy is untouched: the ban still holds
        # there, and the /mcp request did not lift it.
        assert client.get("/").status_code == 403


def test_suspicious_request_ban_does_not_block_mcp():
    ip = "203.0.113.22"
    with TestClient(app, client=(ip, 41234)) as client:
        assert client.get("/.git/config").status_code == 403
        assert ip_ban_manager.banned_ips[ip]["reason"] == "suspicious_request"

        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert response.status_code == 200

        assert client.get("/").status_code == 403


def test_manual_ban_from_the_admin_api_still_blocks_mcp():
    """Goes through POST /admin/ban rather than calling ban_ip() directly, so
    the reason the admin route writes and the one /mcp filters on can't drift
    apart unnoticed."""
    ip = "203.0.113.23"
    admin = TestClient(app)
    response = admin.post(f"/admin/ban/{ip}", headers={"api-key": "test-secret-key"})
    assert response.status_code == 200

    with TestClient(app, client=(ip, 41234)) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 403
    assert response.json() == main.ACCESS_DENIED


class TestIsBannedReasonFilter:
    def test_no_reason_matches_any_ban(self, tmp_path):
        """The default is what every caller other than /mcp relies on."""
        mgr = IPBanManager(ban_file=str(tmp_path / "bans.json"))
        mgr.ban_ip("192.0.2.1", reason="rate_limit", duration=3600)
        assert mgr.is_banned("192.0.2.1")

    def test_reason_matches_only_that_reason(self, tmp_path):
        mgr = IPBanManager(ban_file=str(tmp_path / "bans.json"))
        mgr.ban_ip("192.0.2.1", reason="rate_limit", duration=3600)
        mgr.ban_ip("192.0.2.2", reason="manual", duration=3600)
        assert not mgr.is_banned("192.0.2.1", reason="manual")
        assert mgr.is_banned("192.0.2.2", reason="manual")
        # Filtering it out is a read, not an unban.
        assert mgr.is_banned("192.0.2.1")

    def test_expired_ban_is_swept_whatever_the_filter(self, tmp_path):
        """Expiry is checked before the reason: an expired ban counts for no
        reason, and is still removed — from memory and from the file — even by
        a check whose filter it would not have matched."""
        ban_file = tmp_path / "bans.json"
        mgr = IPBanManager(ban_file=str(ban_file))
        mgr.ban_ip("192.0.2.1", reason="rate_limit", duration=-1)
        mgr.ban_ip("192.0.2.2", reason="manual", duration=-1)
        assert not mgr.is_banned("192.0.2.1", reason="manual")
        assert not mgr.is_banned("192.0.2.2", reason="manual")
        assert mgr.banned_ips == {}
        assert json.loads(ban_file.read_text()) == {}
