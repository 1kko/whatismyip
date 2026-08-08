"""MCP endpoint tests.

Every test here uses `with TestClient(app)` rather than a module-level client.
The MCP session manager is started by the app lifespan, and TestClient only
runs the lifespan when used as a context manager; without it the first request
fails with "RuntimeError: Task group is not initialized".
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

import lookup
import main
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
    main.mcp_rate_limiter.request_history.clear()
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


def test_tools_list_exposes_the_four_tools():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = _rpc(client, "tools/list")
        names = {tool["name"] for tool in response.json()["result"]["tools"]}
        assert names == {
            "lookup",
            "dns_records",
            "ssl_certificate",
            "whoami_caller",
        }


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


def test_mcp_uses_its_own_rate_bucket_and_never_bans():
    """A shared provider egress IP must never be banned.

    Every user of a hosted AI client arrives from the same handful of
    addresses, so escalating an MCP rate-limit breach to a ban would take all
    of them offline at once. Over-limit is 429 and nothing more.
    """
    main.mcp_rate_limiter.request_history.clear()
    main.ip_ban_manager.banned_ips.clear()
    limit = main.mcp_rate_limiter.requests_per_minute

    with TestClient(app, client=("203.0.113.7", 41234)) as client:
        statuses = [
            client.post("/mcp", json=INIT, headers=MCP_HEADERS).status_code
            for _ in range(limit + 5)
        ]

    assert 429 in statuses, "the MCP bucket never engaged"
    assert "203.0.113.7" not in main.ip_ban_manager.banned_ips


def test_mcp_response_carries_no_csp():
    """CSP is for the HTML page; the MCP response is JSON."""
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert "Content-Security-Policy" not in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_domain_starting_with_mcp_keeps_its_csp_header():
    """A bare startswith("/mcp") in the CSP skip would also match
    "/mcpfoo.com" — a syntactically valid domain, and a real, reachable page
    via the /{domain_ip} catch-all, not the MCP transport. That page must keep
    its CSP header."""

    async def fake_gather(target):
        return {
            "address": "mcpfoo.com",
            "domain": {
                "a": [{"ip": "93.184.216.34", "ttl": 300}],
                "mx": [],
                "ns": [],
                "txt": [],
                "cname": None,
            },
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city_name": None,
                "lat": None,
                "lon": None,
                "is_private": False,
            },
            "whois": {"source": "rdap", "name": "mcpfoo.com"},
            "ssl": None,
            "resolved_ip": "93.184.216.34",
            "reverse_dns": None,
        }

    async def fake_lookup_location(ip):
        return {
            "country_code": "US",
            "country_name": "United States",
            "city_name": None,
            "lat": None,
            "lon": None,
            "is_private": False,
        }

    with TestClient(app) as client:
        with (
            patch("main.gather", fake_gather),
            patch("main.lookup_location", fake_lookup_location),
        ):
            response = client.get("/mcpfoo.com", headers={"user-agent": "curl/8.0"})
        assert response.status_code == 200
        assert "Content-Security-Policy" in response.headers


def test_manual_ban_still_blocks_mcp():
    """The one MCP security behaviour this branch relies on but never tested
    directly: a pre-existing manual ban must still 403 /mcp requests."""
    main.ip_ban_manager.ban_ip("testclient", reason="manual", duration=3600)
    try:
        with TestClient(app) as client:
            response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        assert response.status_code == 403
    finally:
        # Otherwise this persists to BANNED_IPS_FILE and 403s every other
        # test's requests in later, separate pytest invocations.
        main.ip_ban_manager.unban_ip("testclient")


def test_get_mcp_is_rejected_without_opening_a_stream():
    """A GET here would otherwise reach the SDK's `_handle_get_request` and
    open a standalone SSE stream that `stateless_http=True` never tears down
    — see McpDispatch's and McpBarePathRoute's method guards."""
    with TestClient(app) as client:
        for path in ("/mcp", "/mcp/"):
            response = client.get(path, headers=MCP_HEADERS)
            assert response.status_code == 405
            assert response.headers["allow"] == "POST"


def test_delete_mcp_is_also_rejected():
    with TestClient(app) as client:
        response = client.delete("/mcp", headers=MCP_HEADERS)
        assert response.status_code == 405


def test_oversized_mcp_body_is_rejected_with_413():
    huge_target = "a" * (main.MCP_MAX_BODY_BYTES + 1)
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "lookup", "arguments": {"target": huge_target}},
    }
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = client.post("/mcp", json=body, headers=MCP_HEADERS)
    assert response.status_code == 413


def test_mcp_body_within_the_limit_still_passes():
    with TestClient(app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 200


def test_mcp_body_with_no_content_length_is_rejected_with_413():
    """Chunked transfer-encoding has no advertised length to check against the
    cap, so it is rejected outright rather than read and measured after the
    fact."""

    def stream():
        yield b'{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": '
        yield b'{"protocolVersion": "2026-07-28", "capabilities": {}, '
        yield b'"clientInfo": {"name": "pytest", "version": "0"}}}'

    with TestClient(app) as client:
        response = client.post("/mcp", headers=MCP_HEADERS, content=stream())
    assert response.status_code == 413


def test_mcp_rate_limiter_cleanup_is_scheduled():
    """Without this job, allow_request() prunes each IP's own timestamps but
    never deletes the (now empty) key, so /mcp leaks one dict entry per
    distinct caller IP for the life of the process."""
    funcs = [job.func for job in main.scheduler.get_jobs()]
    assert main.mcp_rate_limiter.cleanup_old_records in funcs


def test_dns_records_returns_the_full_sweep():
    async def fake_gather(target):
        return {
            **FAKE_LOOKUP,
            "domain": {
                "a": ["93.184.216.34"],
                "mx": [{"host": "mail.example.com", "priority": 10}],
                "ns": ["a.iana-servers.net"],
                "txt": ["v=spf1 -all"],
                "spf": ["v=spf1 -all"],
                "cname": None,
                "ptr": [],
            },
        }

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "dns_records", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["records"]["ns"] == ["a.iana-servers.net"]
        assert payload["records"]["txt"] == ["v=spf1 -all"]


def test_dns_records_narrows_to_requested_types():
    async def fake_gather(target):
        return {
            **FAKE_LOOKUP,
            "domain": {"a": ["1.2.3.4"], "mx": [], "ns": ["ns1.example.com"]},
        }

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {
                    "name": "dns_records",
                    "arguments": {"domain": "example.com", "types": ["ns"]},
                },
            )
        payload = response.json()["result"]["structuredContent"]
        assert set(payload["records"]) == {"ns"}


def test_dns_records_with_an_explicit_empty_type_list_returns_nothing():
    """types=[] is a different request from omitting the argument: "narrow to
    nothing", not "everything". Truthiness would conflate the two."""

    async def fake_gather(target):
        return {
            **FAKE_LOOKUP,
            "domain": {"a": ["1.2.3.4"], "mx": [], "ns": ["ns1.example.com"]},
        }

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {
                    "name": "dns_records",
                    "arguments": {"domain": "example.com", "types": []},
                },
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["records"] == {}


def test_dns_records_reports_private_targets_as_an_error():
    async def boom(target):
        raise lookup.PrivateAddressError(target)

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "dns_records", "arguments": {"domain": "10.0.0.1"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload


def test_dns_records_rejects_a_type_it_never_queries():
    """types=["aaaa"] must not come back as {} — indistinguishable from a
    genuinely empty answer, and a confident false negative if relayed to a
    user asking "does this domain support IPv6?"."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = _rpc(
            client,
            "tools/call",
            {
                "name": "dns_records",
                "arguments": {"domain": "example.com", "types": ["aaaa"]},
            },
        )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload
        assert "aaaa" in payload["error"]


def test_lookup_tool_reports_a_timeout():
    async def hang(target):
        raise TimeoutError()

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", hang):
            response = _rpc(
                client,
                "tools/call",
                {"name": "lookup", "arguments": {"target": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"] == "Lookup timed out"


def test_ssl_certificate_reports_the_expiry_clock():
    cert = {
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "protocol": "TLSv1.3",
    }

    async def fake_gather(target):
        return {**FAKE_LOOKUP, "ssl": cert, "resolved_ip": "93.184.216.34"}

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "example.com"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["issuer"] == "Let's Encrypt"
        assert payload["san"] == ["example.com", "www.example.com"]
        assert payload["days_remaining"] > 0


def test_ssl_certificate_without_a_certificate_is_an_error():
    async def fake_gather(target):
        return {**FAKE_LOOKUP, "ssl": None}

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "example.com"}},
            )
        assert "error" in response.json()["result"]["structuredContent"]


def test_ssl_certificate_reports_private_targets_as_an_error():
    async def boom(target):
        raise lookup.PrivateAddressError(target)

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "ssl_certificate", "arguments": {"domain": "10.0.0.1"}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert "error" in payload


def test_whoami_caller_reports_the_connecting_peer_not_the_user():
    async def fake_location(ip):
        return {
            "ip": ip,
            "country_code": "US",
            "country_name": "United States",
            "city_name": "Ashburn",
            "lat": 39.0,
            "lon": -77.5,
        }

    with TestClient(app, client=("203.0.113.9", 41234)) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.lookup_location", fake_location):
            response = _rpc(
                client,
                "tools/call",
                {"name": "whoami_caller", "arguments": {}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["ip"] == "203.0.113.9"
        assert payload["geo"]["country_code"] == "US"
        # The honesty contract: the note must say whose address this actually is,
        # and where the user gets their own. Asserted on the two semantic halves
        # rather than on a hostname substring — `"host" in url` is the exact
        # shape CodeQL flags as bypassable URL sanitisation
        # (py/incomplete-url-substring-sanitization), and a test should not model
        # a check we would never write in production. This is also stricter: it
        # pins the meaning, so softening the note into "returns your IP" fails
        # even if the link survives.
        note = payload["note"]
        assert "rather than the user's own machine" in note
        assert "have them open" in note
        assert "in a browser" in note


def test_whoami_caller_reports_unavailable_when_the_peer_is_unknown():
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.client_ip_from_scope", return_value="unknown"):
            response = _rpc(
                client,
                "tools/call",
                {"name": "whoami_caller", "arguments": {}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"] == "Caller address unavailable"


def test_whoami_caller_reports_an_error_when_location_lookup_fails():
    async def boom(ip):
        raise RuntimeError("geoip database unavailable")

    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.lookup_location", boom):
            response = _rpc(
                client,
                "tools/call",
                {"name": "whoami_caller", "arguments": {}},
            )
        payload = response.json()["result"]["structuredContent"]
        assert payload["error"] == "Location lookup failed"
