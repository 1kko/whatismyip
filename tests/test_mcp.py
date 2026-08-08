"""MCP endpoint tests.

Every test here uses `with TestClient(app)` rather than a module-level client.
The MCP session manager is started by the app lifespan, and TestClient only
runs the lifespan when used as a context manager; without it the first request
fails with "RuntimeError: Task group is not initialized".
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

import lookup
from main import app, ip_ban_manager, rate_limiter

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "ip.1kko.com",
}


def setup_function():
    """Undo whatever a previous run left behind before each test.

    Every test here uses the default TestClient(app), whose client IP is
    "testclient" — the same IP tests/test_security.py deliberately bans in its
    own tests. BANNED_IPS_FILE (see tests/conftest.py) persists across pytest
    runs, so a ban or rate-limit history left over from a previous run would
    403 every request below before it ever reaches /mcp. Mirrors
    tests/test_security.py's _reset_security_state().
    """
    rate_limiter.request_history.clear()
    ip_ban_manager.banned_ips.clear()


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


def _rpc(client, method, params=None, id_=2):
    body = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=MCP_HEADERS)


def test_initialize_handshake():
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["serverInfo"]["name"] == "whatismyip"
        assert "tools" in result["capabilities"]


def test_tools_list_exposes_the_lookup_tool():
    """Widened to the full four-tool set in Task 5, once they all exist.

    Asserting the final set here would leave a knowingly-red test sitting in
    three commits, which every task review would (correctly) flag.
    """
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = _rpc(client, "tools/list")
        names = {tool["name"] for tool in response.json()["result"]["tools"]}
        assert "lookup" in names


def test_bad_host_header_is_rejected():
    """transport_security must allowlist the real hostname.

    Without it the SDK arms DNS-rebinding protection with a localhost-only
    allowlist and answers every production request with 421 — the single most
    likely silent misconfiguration in this feature.
    """
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json=INIT,
            headers={**MCP_HEADERS, "Host": "evil.example.com"},
        )
        assert response.status_code == 421


FAKE_LOOKUP = {
    "address": "example.com",
    "domain": {"a": ["93.184.216.34"], "mx": [], "ns": [], "txt": [], "spf": []},
    "location": {
        "ip": "93.184.216.34",
        "country_code": "US",
        "country_name": "United States",
        "city_name": "Norwell",
        "subdivision_name": "Massachusetts",
        "lat": 42.1596,
        "lon": -70.8217,
        "accuracy_km": 20,
        "time_zone": "America/New_York",
        "cidr": "93.184.216.0/24",
        "asn_number": 15133,
        "asn_name": "EDGECAST",
        "asn_cidr": "93.184.216.0/24",
    },
    "whois": {
        "source": "rdap",
        "name": "example.com",
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "registrant": None,
        "abuse_email": "abuse@iana.org",
        "status": ["client delete prohibited"],
        "created": "1995-08-14T04:00:00+00:00",
        "expires": "2026-08-13T04:00:00+00:00",
        "updated": None,
    },
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}


def test_lookup_tool_returns_a_compact_result():
    async def fake_gather(target):
        return FAKE_LOOKUP

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["ip"] == "93.184.216.34"
        assert payload["geo"]["country_code"] == "US"
        assert payload["network"]["asn_number"] == 15133
        assert payload["registration"]["registrar"].startswith("RESERVED")
        # Render-only data must never reach an LLM context.
        for forbidden in ("map", "distance_km", "origin"):
            assert forbidden not in payload


def test_lookup_tool_reports_private_targets_as_an_error():
    async def boom(target):
        raise lookup.PrivateAddressError(target)

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "10.0.0.1"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload
