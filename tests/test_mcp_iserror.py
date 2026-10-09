"""A tool call that failed outright says so with `isError: true`.

The spec's channel for "this tool could not answer" is a result with isError
set, not a JSON-RPC fault and not a normal result that happens to hold an
`error` key. Every failure used to go out as the latter, so a client could
not tell a failed call from an answer without reading the payload, and the
SDK's OTel middleware, which tags a span `error.type=tool_error` only for an
isError result, never counted one.

The line these tests draw: when nothing usable came back (a refused target, a
timeout, no TLS handshake, the CT source down) the call failed. When the call
answered with a gap in it (one DNS type timed out, the registration leg was
down, the name is not registered, the cached list is stale) it is a normal
result, and the gap is data a model needs alongside the rest.

Every test drives the real /mcp endpoint under `with TestClient(app)`, because
the session manager only runs inside the app lifespan (see tests/test_mcp.py).
"""

import json
from unittest.mock import AsyncMock, patch

import mcp.shared._otel
import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import StatusCode

import lookup
import main
from main import app, ip_ban_manager, rate_limiter

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

GATHERED = {
    "address": "example.com",
    "domain": {
        "a": [{"ip": "93.184.216.34", "ttl": 300}],
        "mx": [],
        "ns": ["a.iana-servers.net"],
        "status": {},
    },
    "location": {"country_code": "US", "asn_number": 15133},
    "whois": {"source": "rdap", "name": "example.com", "registrar": "IANA"},
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "resolution": "ok",
    "reverse_dns": None,
}

CERT = {
    "issuer": ((("organizationName", "Let's Encrypt"),),),
    "subject": ((("commonName", "example.com"),),),
    "subjectAltName": (("DNS", "example.com"),),
    "notAfter": "Dec 31 23:59:59 2099 GMT",
    "protocol": "TLSv1.3",
    "trusted": True,
    "hostname_match": True,
    "verify_error": None,
}

SUBDOMAINS = {
    "names": ["www.example.com"],
    "count": 1,
    "truncated": False,
    "source": "crt.sh",
    "fetched_at": "2026-09-29T00:00:00+00:00",
    "stale": False,
    "error": None,
}


def setup_function():
    """Same reset as tests/test_mcp.py: a ban or rate-limit history left by
    another test file would 403 these requests before they reach /mcp."""
    rate_limiter.request_history.clear()
    main.mcp_rate_limiter.request_history.clear()
    ip_ban_manager.banned_ips.clear()


def _gathered(**overrides):
    async def fake_gather(target):
        return {**GATHERED, **overrides}

    return fake_gather


def _raising(exc):
    async def fake_gather(target):
        raise exc

    return fake_gather


def _call(client, name, arguments):
    client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers=MCP_HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    # A tool failure is a result, never a JSON-RPC error object.
    assert "error" not in body
    return body["result"]


def _failed(result) -> dict:
    assert result["isError"] is True
    payload = result["structuredContent"]
    assert payload["error"]
    # Most clients hand the model the text block, not structuredContent, so
    # it must carry the same object a successful call's text block would.
    assert json.loads(result["content"][0]["text"]) == payload
    return payload


def _answered(result) -> dict:
    assert result["isError"] is False
    return result["structuredContent"]


# --- whole-call failures --------------------------------------------------------

GATHER_TOOLS = [
    ("lookup", "target"),
    ("dns_records", "domain"),
    ("ssl_certificate", "domain"),
]


@pytest.mark.parametrize("tool, argument", GATHER_TOOLS)
@pytest.mark.parametrize(
    "exc, message",
    [
        (
            lookup.PrivateAddressError("10.0.0.1"),
            "Private or reserved addresses are not allowed",
        ),
        (lookup.InvalidTargetError("foo bar"), "not a domain name or IP address"),
        (TimeoutError(), "Lookup timed out"),
    ],
)
def test_a_refused_or_timed_out_target_is_a_failed_call(tool, argument, exc, message):
    with TestClient(app) as client, patch("mcp_server.gather", _raising(exc)):
        payload = _failed(_call(client, tool, {argument: "example.com"}))
    assert payload == {"error": message}


@pytest.mark.parametrize("tool, argument", GATHER_TOOLS)
def test_an_unexpected_lookup_failure_is_a_failed_call(tool, argument):
    boom = _raising(RuntimeError("resolver exploded at 10.1.2.3"))
    with TestClient(app) as client, patch("mcp_server.gather", boom):
        payload = _failed(_call(client, tool, {argument: "example.com"}))
    # The exception text stays in the server log.
    assert "10.1.2.3" not in payload["error"]


def test_an_unsupported_record_type_is_a_failed_call():
    with TestClient(app) as client:
        payload = _failed(
            _call(client, "dns_records", {"domain": "example.com", "types": ["caa"]})
        )
    assert "caa" in payload["error"]


@pytest.mark.parametrize(
    "overrides, expected",
    [
        (
            {"ssl": {"error": "port 443 unreachable", "reason": "connection refused"}},
            "connection refused",
        ),
        ({"ssl": None, "resolved_ip": None}, "no A record"),
        (
            {"ssl": None, "address": "93.184.216.34"},
            "domain names only",
        ),
        ({"ssl": None}, "No TLS certificate served"),
    ],
    ids=["unreachable", "no-a-record", "ip-target", "no-certificate"],
)
def test_no_certificate_read_is_a_failed_call(overrides, expected):
    with TestClient(app) as client, patch("mcp_server.gather", _gathered(**overrides)):
        payload = _failed(_call(client, "ssl_certificate", {"domain": "example.com"}))
    assert set(payload) == {"error"}
    assert expected in payload["error"]


def test_a_subdomain_source_failure_is_a_failed_call():
    failed = {**SUBDOMAINS, "names": [], "count": 0, "error": "source timed out"}
    with (
        TestClient(app) as client,
        patch("mcp_server.get_subdomains", new_callable=AsyncMock, return_value=failed),
    ):
        payload = _failed(_call(client, "subdomains", {"domain": "example.com"}))
    assert payload == {"error": "source timed out", "domain": "example.com"}


def test_a_subdomain_lookup_that_raises_is_a_failed_call():
    with (
        TestClient(app) as client,
        patch(
            "mcp_server.get_subdomains",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ),
    ):
        payload = _failed(_call(client, "subdomains", {"domain": "example.com"}))
    assert payload == {"error": "Subdomain lookup failed"}


@pytest.mark.parametrize(
    "arguments",
    [{"domain": "8.8.8.8"}, {"domain": "example.com", "limit": 0}],
    ids=["ip-target", "zero-limit"],
)
def test_a_subdomain_request_refused_up_front_is_a_failed_call(arguments):
    gate = AsyncMock(return_value=SUBDOMAINS)
    with TestClient(app) as client, patch("mcp_server.get_subdomains", gate):
        _failed(_call(client, "subdomains", arguments))
    gate.assert_not_called()


def test_an_unknown_caller_is_a_failed_call():
    with (
        TestClient(app) as client,
        patch("mcp_server.client_ip_from_scope", return_value="unknown"),
    ):
        payload = _failed(_call(client, "whoami_caller", {}))
    assert payload == {"error": "Caller address unavailable"}


def test_a_caller_location_failure_is_a_failed_call():
    boom = AsyncMock(side_effect=RuntimeError("geoip database unavailable"))
    with (
        TestClient(app, client=("203.0.113.9", 41234)) as client,
        patch("mcp_server.lookup_location", boom),
    ):
        payload = _failed(_call(client, "whoami_caller", {}))
    assert payload == {"error": "Location lookup failed"}


# --- answers with a gap in them stay normal results --------------------------------


def test_a_failed_leg_inside_lookup_is_still_an_answer():
    """The registration leg down and port 443 closed are two facts about a
    target whose location and network did come back. Flagging the call would
    tell a client to discard all of it."""
    gather = _gathered(
        whois={"error": "RIR RDAP temporarily unavailable"},
        ssl={"error": "port 443 unreachable", "reason": "timed out"},
    )
    with TestClient(app) as client, patch("mcp_server.gather", gather):
        payload = _answered(_call(client, "lookup", {"target": "example.com"}))
    assert payload["registration"] == {"error": "RIR RDAP temporarily unavailable"}
    assert "timed out" in payload["tls"]["error"]
    assert payload["geo"]["country_code"] == "US"


def test_not_registered_is_an_answer():
    gather = _gathered(whois={"error": "not registered", "name": "x.example.com"})
    with TestClient(app) as client, patch("mcp_server.gather", gather):
        payload = _answered(_call(client, "lookup", {"target": "x.example.com"}))
    assert payload["registration"]["registered"] is False


def test_one_failed_record_type_is_still_an_answer():
    domain = {**GATHERED["domain"], "status": {"mx": "timeout"}}
    with (
        TestClient(app) as client,
        patch("mcp_server.gather", _gathered(domain=domain)),
    ):
        payload = _answered(_call(client, "dns_records", {"domain": "example.com"}))
    assert payload["records"]["mx"] == {"error": "timeout"}
    assert payload["records"]["ns"] == ["a.iana-servers.net"]


def test_a_name_that_does_not_exist_is_an_answer():
    gather = _gathered(
        domain={"a": [], "mx": [], "status": {}},
        resolved_ip=None,
        resolution="nxdomain",
    )
    with TestClient(app) as client, patch("mcp_server.gather", gather):
        payload = _answered(_call(client, "dns_records", {"domain": "example.com"}))
    assert payload["resolution"] == "nxdomain"


def test_an_untrusted_certificate_is_an_answer():
    untrusted = {
        **CERT,
        "notAfter": "Jan  1 00:00:00 2020 GMT",
        "trusted": False,
        "verify_error": {
            "code": 10,
            "message": "certificate has expired",
            "reason": "expired",
        },
    }
    with (
        TestClient(app) as client,
        patch("mcp_server.gather", _gathered(ssl=untrusted)),
    ):
        payload = _answered(_call(client, "ssl_certificate", {"domain": "example.com"}))
    assert payload["trusted"] is False
    assert payload["verify_error"]["reason"] == "expired"


def test_a_stale_subdomain_list_is_an_answer():
    stale = {**SUBDOMAINS, "stale": True}
    with (
        TestClient(app) as client,
        patch("mcp_server.get_subdomains", new_callable=AsyncMock, return_value=stale),
    ):
        payload = _answered(_call(client, "subdomains", {"domain": "example.com"}))
    assert payload["stale"] is True
    assert payload["names"] == ["www.example.com"]


# --- the output schema survives the mixed return type --------------------------------


def test_every_tool_still_advertises_an_output_schema():
    """Returning a CallToolResult from some paths must not cost the schema
    `dict[str, Any]` gives the others: the SDK builds it from the annotation,
    and a tool without one never gets `structuredContent` on success."""
    with TestClient(app) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        tools = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers=MCP_HEADERS,
        ).json()["result"]["tools"]
    assert tools
    for tool in tools:
        assert tool["outputSchema"]["type"] == "object", tool["name"]


def test_a_successful_call_still_carries_structured_content():
    with TestClient(app) as client, patch("mcp_server.gather", _gathered(ssl=CERT)):
        result = _call(client, "ssl_certificate", {"domain": "example.com"})
    payload = _answered(result)
    assert payload["issuer"] == "Let's Encrypt"
    assert json.loads(result["content"][0]["text"]) == payload


# --- telemetry -------------------------------------------------------------------


@pytest.fixture
def spans():
    """Capture the SDK's own server spans.

    The SDK takes its tracer once, at import, from the global provider, which a
    test cannot reset; swapping the module's tracer captures the same spans
    without touching global state. If an SDK upgrade moves `_tracer`, this
    fixture breaks loudly, which is the point: the tools/call error count in
    SigNoz depends on these spans.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    with patch.object(mcp.shared._otel, "_tracer", provider.get_tracer("test")):
        yield exporter
    provider.shutdown()


def _tool_span(exporter, tool):
    matching = [
        s for s in exporter.get_finished_spans() if s.name == f"tools/call {tool}"
    ]
    assert len(matching) == 1
    return matching[0]


def test_a_failed_call_is_counted_as_a_tool_error(spans):
    with (
        TestClient(app) as client,
        patch("mcp_server.gather", _raising(TimeoutError())),
    ):
        _failed(_call(client, "lookup", {"target": "example.com"}))
    span = _tool_span(spans, "lookup")
    assert span.attributes["error.type"] == "tool_error"
    assert span.status.status_code is StatusCode.ERROR


def test_an_answer_with_a_failed_leg_is_not_counted_as_an_error(spans):
    gather = _gathered(whois={"error": "RIR RDAP temporarily unavailable"})
    with TestClient(app) as client, patch("mcp_server.gather", gather):
        _answered(_call(client, "lookup", {"target": "example.com"}))
    span = _tool_span(spans, "lookup")
    assert "error.type" not in span.attributes
    assert span.status.status_code is not StatusCode.ERROR
