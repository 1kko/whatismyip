"""Four small follow-ups that earlier items left open.

1. gather()'s gating A query logged every miss at WARNING, an IPv6-only name's
   NoAnswer included, though the AAAA fallback then resolved it.
2. MCP initialize reported serverInfo.version as "", the SDK's default.
3. HEAD advertised text/html for /?whois=only and /{target}?subdomains=only,
   which GET always answers in JSON, and 200 for a ?whois= or ?subdomains=
   value GET refuses with a 400.

Every outbound lookup is faked; nothing here touches the network.
"""

import contextlib
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest
from fastapi.testclient import TestClient

import config
import lookup
import main

# --- 1. The gating A query's misses are logged by what they mean -------------------

NAME = "v6only.example.com"
V6 = "2001:4860:4860::8888"


def _timeout():
    return dns.resolver.LifetimeTimeout(timeout=3.0, errors=[])


class _Resolver:
    """Answers each record type from `answers`: a list of addresses, or the
    exception dnspython would raise. A type it was not given has no record."""

    def __init__(self):
        self.answers = {}

    def resolve(self, qname, rdtype="A", *args, **kwargs):
        outcome = self.answers.get(rdtype) or dns.resolver.NoAnswer()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def resolver(monkeypatch, caplog):
    fake = _Resolver()
    monkeypatch.setattr(lookup, "_recursive_resolver", lambda: fake)
    caplog.set_level(logging.DEBUG)
    return fake


def _logged(caplog, level):
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == level and NAME in r.getMessage()
    ]


class TestGatingAQueryLogLevel:
    async def test_an_ipv6_only_name_is_not_a_warning(self, resolver, caplog):
        """The name has no A record and resolves through AAAA: nothing failed,
        so the A miss is a debug line, not one in the warning stream."""
        resolver.answers = {"A": dns.resolver.NoAnswer(), "AAAA": [V6]}
        data = await lookup.gather(NAME, legs={"resolve"})
        assert data["resolved_ip"] == V6
        assert data["resolution"] == "ok"
        assert _logged(caplog, logging.WARNING) == []
        assert any("No A record" in line for line in _logged(caplog, logging.DEBUG))

    @pytest.mark.parametrize(
        "answers, resolution",
        [
            ({"A": dns.resolver.NXDOMAIN()}, "nxdomain"),
            ({"A": dns.resolver.NoAnswer()}, "noanswer"),
            ({"A": dns.resolver.NoAnswer(), "AAAA": dns.resolver.NXDOMAIN()}, None),
        ],
        ids=["nxdomain", "no-address-records", "aaaa-nxdomain"],
    )
    async def test_a_name_with_no_address_is_an_answer_not_a_warning(
        self, resolver, caplog, answers, resolution
    ):
        """A name that does not exist, or has no address records, is what DNS
        said. Like a missing PTR record (#14), it stays out of the warnings."""
        resolver.answers = answers
        data = await lookup.gather(NAME, legs={"resolve"})
        assert data["resolved_ip"] is None
        if resolution:
            assert data["resolution"] == resolution
        assert _logged(caplog, logging.WARNING) == []
        assert _logged(caplog, logging.DEBUG)

    @pytest.mark.parametrize(
        "answers, status",
        [
            ({"A": _timeout()}, "timeout"),
            ({"A": dns.resolver.NoNameservers()}, "servfail"),
            ({"A": RuntimeError("resolver bug")}, "error"),
            ({"A": dns.resolver.NoAnswer(), "AAAA": _timeout()}, None),
            (
                {"A": dns.resolver.NoAnswer(), "AAAA": dns.resolver.NoNameservers()},
                None,
            ),
        ],
        ids=["a-timeout", "a-servfail", "a-error", "aaaa-timeout", "aaaa-servfail"],
    )
    async def test_a_name_that_could_not_be_resolved_still_warns(
        self, resolver, caplog, answers, status
    ):
        """Neither query answered: the resolver failed, so whether the name has
        an address is unknown. That stays visible, once."""
        resolver.answers = answers
        data = await lookup.gather(NAME, legs={"resolve"})
        assert data["resolved_ip"] is None
        if status:
            assert data["resolution"] == status
        assert len(_logged(caplog, logging.WARNING)) == 1


# --- 2. MCP initialize names the deployed build ------------------------------------

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


def test_mcp_initialize_reports_the_deployed_version():
    """The commit /healthz reports (SOURCE_COMMIT, or "unknown"), not the SDK's
    empty default, so a client's log of the handshake names the build."""
    main.mcp_rate_limiter.request_history.clear()
    with TestClient(main.app) as client:
        response = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 200
    server_info = response.json()["result"]["serverInfo"]
    assert server_info["name"] == "whatismyip"
    assert server_info["version"] == config.APP_VERSION
    assert server_info["version"]


# --- 3. HEAD carries the Content-Type and status GET answers with ------------------

# A public peer address, so the self route treats it as an ordinary visitor.
client = TestClient(main.app, client=("8.8.8.8", 41234))

CURL = {"user-agent": "curl/8.7.1"}
BROWSER = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
# What gather() returns when nothing resolves, so a GET renders normally.
EMPTY_LOOKUP = {
    "address": "nasa.gov",
    "domain": {},
    "location": {},
    "whois": {"error": "mocked"},
    "ssl": None,
    "resolved_ip": None,
    "resolution": "nxdomain",
    "reverse_dns": None,
}


@pytest.fixture
def offline_routes():
    """Every lookup GET would make, answered locally. HEAD makes none."""
    with contextlib.ExitStack() as stack:
        for name, mock in {
            "main.gather": AsyncMock(return_value=dict(EMPTY_LOOKUP)),
            "main.lookup_whois": AsyncMock(return_value={"error": "mocked"}),
            "main.lookup_location": AsyncMock(return_value={}),
            "main.get_subdomains": AsyncMock(return_value=[]),
            "lookup.lookup_rdap": MagicMock(return_value=None),
            "lookup.whois.whois": MagicMock(return_value={}),
        }.items():
            stack.enter_context(patch(name, mock))
        stack.enter_context(
            patch.object(
                main.domain_manager,
                "perform_reverse_lookup",
                MagicMock(return_value=None),
            )
        )
        yield


@pytest.mark.parametrize(
    "path, headers, status, media_type",
    [
        # The self route.
        ("/", BROWSER, 200, "text/html"),
        ("/", CURL, 200, "application/json"),
        ("/?format=text", CURL, 200, "text/plain"),
        # The registration alone is JSON whatever was negotiated.
        ("/?whois=only", BROWSER, 200, "application/json"),
        ("/?whois=only", CURL, 200, "application/json"),
        ("/?whois=ONLY", BROWSER, 200, "application/json"),
        ("/?whois=only&format=text", CURL, 200, "application/json"),
        ("/?whois=only&format=html", BROWSER, 200, "application/json"),
        ("/?whois=all", BROWSER, 400, "application/json"),
        ("/?whois=", BROWSER, 400, "application/json"),
        ("/?whois=all&format=text", CURL, 400, "text/plain"),
        ("/?fields=ip", BROWSER, 200, "application/json"),
        ("/?fields=ip&format=text", BROWSER, 200, "text/plain"),
        ("/?fields=nope", BROWSER, 400, "application/json"),
        ("/?fields=nope&format=text", CURL, 400, "text/plain"),
        ("/?format=nope", BROWSER, 400, "application/json"),
        # The self route has no subdomain list: the parameter is not read.
        ("/?subdomains=only", BROWSER, 200, "text/html"),
        ("/?subdomains=nope", BROWSER, 200, "text/html"),
        # A target.
        ("/nasa.gov", BROWSER, 200, "text/html"),
        ("/nasa.gov", CURL, 200, "application/json"),
        ("/nasa.gov?format=text", CURL, 200, "text/plain"),
        # The subdomain list alone is JSON whatever was negotiated.
        ("/nasa.gov?subdomains=only", BROWSER, 200, "application/json"),
        ("/nasa.gov?subdomains=only", CURL, 200, "application/json"),
        ("/nasa.gov?subdomains=only&format=text", CURL, 200, "application/json"),
        ("/nasa.gov?subdomains=include", BROWSER, 200, "text/html"),
        ("/nasa.gov?subdomains=exclude", CURL, 200, "application/json"),
        ("/nasa.gov?subdomains=nope", BROWSER, 400, "application/json"),
        ("/nasa.gov?subdomains=nope&format=text", CURL, 400, "text/plain"),
        ("/nasa.gov?fields=ip", BROWSER, 200, "application/json"),
        ("/nasa.gov?fields=ip&format=text", BROWSER, 200, "text/plain"),
        ("/nasa.gov?fields=nope", BROWSER, 400, "application/json"),
        # A target has no registration-only mode: the parameter is not read.
        ("/nasa.gov?whois=only", BROWSER, 200, "text/html"),
        ("/nasa.gov?whois=nope", CURL, 200, "application/json"),
    ],
)
def test_head_answers_as_get_would(offline_routes, path, headers, status, media_type):
    get = client.get(path, headers=headers)
    head = client.head(path, headers=headers)
    assert get.status_code == status
    assert get.headers["content-type"].split(";")[0] == media_type
    assert head.status_code == get.status_code
    assert head.headers["content-type"] == get.headers["content-type"]
    assert head.content == b""
