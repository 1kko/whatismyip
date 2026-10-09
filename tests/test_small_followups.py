"""Four small follow-ups that earlier items left open.

1. gather()'s gating A query logged every miss at WARNING, an IPv6-only name's
   NoAnswer included, though the AAAA fallback then resolved it.
2. MCP initialize reported serverInfo.version as "", the SDK's default.
3. HEAD advertised text/html for /?whois=only and /{target}?subdomains=only,
   which GET always answers in JSON, and 200 for a ?whois= or ?subdomains=
   value GET refuses with a 400.
4. /?fields=registrant asked the registry for the visitor's address again
   while the self page's lookup of it (#24) was still running.

Every outbound lookup is faked; nothing here touches the network.
"""

import asyncio
import contextlib
import logging
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import httpx
import pytest
from fastapi.testclient import TestClient

import concurrency
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
            # A answered "no A record", then AAAA failed: whether the name has
            # an address is unknown, so `resolution` is the failure, not
            # "noanswer", which would read as "no address at all".
            ({"A": dns.resolver.NoAnswer(), "AAAA": _timeout()}, "timeout"),
            (
                {"A": dns.resolver.NoAnswer(), "AAAA": dns.resolver.NoNameservers()},
                "servfail",
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


# --- 4. ?fields= joins the self page's registration lookup -------------------------
#
# Over httpx's ASGI transport rather than TestClient, as in
# test_self_first_paint.py: the lookup a page leaves running has to still be
# there for the next request, and TestClient gives each request an event loop
# of its own, cancelling what it leaves behind.

CLIENT_IP = "8.8.8.8"
# ARIN's answer for 8.8.8.8, in rdap.py's canonical shape.
RECORD = {
    "source": "rdap",
    "rir": "arin",
    "name": "GOGL",
    "handle": "NET-8-8-8-0-2",
    "registrant": "Google LLC",
    "network": "8.8.8.0/24",
    "abuse_email": "network-abuse@google.com",
}
LOCATION = {
    "country_code": "US",
    "country_name": "United States",
    "city_name": "Mountain View",
    "asn_name": "GOOGLE",
    "is_private": False,
}
GATE = concurrency.lookup_gate
TASKS = main._self_whois_tasks


@pytest.fixture
def self_route():
    """The self route with GeoIP and the PTR answered locally (no PTR name, so
    no record sweep), a soft deadline short enough that a page goes out without
    its registration, and a gate wait of a twentieth of a second."""
    lookup._whois_cache.clear()
    TASKS.clear()
    with (
        patch(
            "main.lookup_location",
            AsyncMock(side_effect=lambda ip: {**LOCATION, "ip": ip}),
        ),
        patch.object(
            lookup.domain_manager,
            "perform_reverse_lookup",
            MagicMock(return_value=None),
        ),
        patch.object(main, "SELF_WHOIS_SOFT_DEADLINE_SECONDS", 0.05),
        patch.object(GATE, "wait", 0.05),
    ):
        yield
    lookup._whois_cache.clear()
    TASKS.clear()


class _SlowRdap:
    """lookup.lookup_rdap holding its registration-pool thread until released,
    so the real lookup_whois runs, and caches, around it."""

    def __init__(self):
        self.calls = []
        self.release = threading.Event()

    def __call__(self, target):
        self.calls.append(target)
        self.release.wait(timeout=3)
        return dict(RECORD)


@pytest.fixture
def rdap(monkeypatch):
    slow = _SlowRdap()
    monkeypatch.setattr(lookup, "lookup_rdap", slow)
    yield slow
    slow.release.set()


def _client():
    transport = httpx.ASGITransport(app=main.app, client=(CLIENT_IP, 41234))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@contextlib.asynccontextmanager
async def _holding(slots):
    """Hold `slots` of the lookup gate's slots for the block."""
    async with contextlib.AsyncExitStack() as stack:
        for _ in range(slots):
            await stack.enter_async_context(GATE.slot())
        yield


async def _until(condition):
    async with asyncio.timeout(2):
        while not condition():
            await asyncio.sleep(0.01)


async def _settle():
    """Wait for every registration lookup a request left running to finish."""
    pending = list(TASKS.values())
    if pending:
        await asyncio.wait(pending, timeout=5)
    await asyncio.sleep(0)  # the done callbacks that drop them from TASKS


@pytest.mark.usefixtures("self_route")
class TestFieldsJoinTheSelfLookup:
    async def test_it_joins_the_lookup_the_page_left_running(self, rdap):
        async with _client() as client:
            page = await client.get("/", headers=BROWSER)
            assert 'id="whois-pending"' in page.text
            fields = asyncio.create_task(
                client.get("/?fields=registrant", headers=CURL)
            )
            await asyncio.sleep(0.1)
            assert not fields.done()  # waiting on the registry, not refused
            rdap.release.set()
            response = await fields
            await _settle()
        assert response.json() == {"registrant": "Google LLC"}
        # One question to the registry for the page and the fields together.
        assert rdap.calls == [CLIENT_IP]

    async def test_the_page_joins_a_lookup_the_fields_started(self, rdap):
        """The other way round: the lookup ?fields= starts is registered where
        a self page and /?whois=only look for one."""
        async with _client() as client:
            fields = asyncio.create_task(
                client.get("/?fields=registrant", headers=CURL)
            )
            await _until(lambda: rdap.calls)
            page = await client.get("/", headers=BROWSER)
            rdap.release.set()
            response = await fields
            await _settle()
        assert 'id="whois-pending"' in page.text
        assert response.json() == {"registrant": "Google LLC"}
        assert rdap.calls == [CLIENT_IP]

    async def test_it_takes_no_slot_to_join_a_running_lookup(self, rdap):
        """The page that left the lookup running still holds a slot for it, so
        joining it starts nothing the gate has not already counted."""
        async with _client() as client:
            await client.get("/", headers=BROWSER)
            async with _holding(GATE.size - 1):
                fields = asyncio.create_task(
                    client.get("/?fields=registrant", headers=CURL)
                )
                await asyncio.sleep(0.1)
                rdap.release.set()
                response = await fields
            await _settle()
        assert response.status_code == 200
        assert response.json() == {"registrant": "Google LLC"}
        assert rdap.calls == [CLIENT_IP]

    async def test_it_takes_no_slot_to_read_the_cache(self, rdap):
        async with _client() as client:
            await client.get("/", headers=BROWSER)
            rdap.release.set()
            await _settle()
            async with _holding(GATE.size):
                response = await client.get("/?fields=registrant", headers=CURL)
        assert response.status_code == 200
        assert response.json() == {"registrant": "Google LLC"}
        assert rdap.calls == [CLIENT_IP]

    async def test_with_nothing_to_join_it_asks_once_and_takes_a_slot(self, rdap):
        rdap.release.set()
        async with _client() as client:
            async with _holding(GATE.size):
                busy = await client.get("/?fields=registrant", headers=CURL)
            response = await client.get("/?fields=registrant", headers=CURL)
        assert busy.status_code == 503
        assert busy.json()["code"] == "busy"
        assert response.json() == {"registrant": "Google LLC"}
        assert rdap.calls == [CLIENT_IP]
        assert TASKS == {}

    async def test_a_reverse_lookup_asked_alongside_still_takes_a_slot(self, rdap):
        """Joining spares the registration only. The PTR is a lookup this
        request starts itself, and is gated like one."""
        async with _client() as client:
            await client.get("/", headers=BROWSER)
            async with _holding(GATE.size - 1):
                busy = await client.get("/?fields=registrant,reverse_dns", headers=CURL)
            rdap.release.set()
            await _settle()
        assert busy.status_code == 503
        assert rdap.calls == [CLIENT_IP]
