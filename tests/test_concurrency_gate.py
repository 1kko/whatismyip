"""One concurrency gate for every lookup, and pools of their own for the slow legs.

Only MCP used to bound how many lookups ran at once (a Semaphore(8)); GET
/{target} and the self page started as many pipelines as there were requests.
And every leg ran on the event loop's default executor, so a pile-up of RDAP,
port-43 WHOIS or crt.sh threads -- seconds each, and still running after the
wait_for that gave up on them -- queued the DNS and TLS legs of every other
lookup behind them.

The HTTP tests use httpx's ASGI transport rather than TestClient. A slot the
test holds has to be in the same event loop as the request it is meant to turn
away, and TestClient runs each request in an event loop of its own.

Every outbound leg is mocked.
"""

import asyncio
import contextlib
import os
import subprocess
import sys
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import concurrency
import config
import lookup
import main
import mcp_server
import subdomains

CLIENT_IP = "8.8.8.8"
CURL = {"user-agent": "curl/8.7.1"}
CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
DOMAIN_IP = "93.184.216.34"
LOCATION = {
    "country_code": "US",
    "country_name": "United States",
    "city_name": "Los Angeles",
    "is_private": False,
}

GATE = concurrency.lookup_gate
MCP_GATE = mcp_server._GATHER_CONCURRENCY
BUSY_MESSAGE = concurrency.LookupBusy.message
RETRY_AFTER = str(config.LOOKUP_BUSY_RETRY_AFTER_SECONDS)

# The real one, taken before any fixture below patches the module attribute.
_real_lookup_whois = lookup.lookup_whois


@pytest.fixture(autouse=True)
def quick_gates():
    """A lookup that finds every slot taken waits LOOKUP_GATE_WAIT_SECONDS
    before it is turned away. A twentieth of a second keeps that wait real
    without making the suite sit through it."""
    with (
        patch.object(GATE, "wait", 0.05),
        patch.object(MCP_GATE, "wait", 0.05),
    ):
        yield


@pytest.fixture(autouse=True)
def empty_whois_cache():
    lookup._whois_cache.clear()
    yield
    lookup._whois_cache.clear()


@pytest.fixture
def legs():
    """Every leg a lookup can reach, on the gather() path and the self path."""
    resolver = MagicMock()
    resolver.resolve.return_value = [DOMAIN_IP]
    mocks = {
        "whois": AsyncMock(side_effect=lambda t: {"source": "rdap", "name": t}),
        "geo": AsyncMock(side_effect=lambda ip: {**LOCATION, "ip": ip}),
        "resolver": MagicMock(return_value=resolver),
        "records": MagicMock(return_value={}),
        "reverse": MagicMock(return_value=None),
        "ssl": MagicMock(return_value=None),
    }
    with (
        patch("lookup.lookup_whois", mocks["whois"]),
        patch("main.lookup_whois", mocks["whois"]),
        patch("lookup.lookup_location", mocks["geo"]),
        patch("main.lookup_location", mocks["geo"]),
        patch("lookup._recursive_resolver", mocks["resolver"]),
        patch.object(lookup.domain_manager, "get_records", mocks["records"]),
        patch.object(lookup.domain_manager, "perform_reverse_lookup", mocks["reverse"]),
        patch("managers.SSLManager.get_ssl_info", mocks["ssl"]),
    ):
        yield mocks


# The legs that leave the process. GeoIP is a local database read.
NETWORK = ("whois", "resolver", "records", "reverse", "ssl")


def _ran(mocks):
    return {name for name in NETWORK if mocks[name].called}


@contextlib.asynccontextmanager
async def holding(gate, slots=None):
    """Hold `slots` of `gate`'s slots, all of them by default, for the block."""
    async with contextlib.AsyncExitStack() as stack:
        for _ in range(gate.size if slots is None else slots):
            await stack.enter_async_context(gate.slot())
        yield


def _client():
    transport = httpx.ASGITransport(app=main.app, client=(CLIENT_IP, 41234))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


class TestTurnedAway:
    async def test_a_lookup_gets_503_with_retry_after(self, legs):
        async with _client() as client, holding(GATE):
            response = await client.get("/example.com", headers=CURL)
        assert response.status_code == 503
        assert response.headers["retry-after"] == RETRY_AFTER
        assert response.json() == {"error": BUSY_MESSAGE, "code": "busy"}
        assert _ran(legs) == set()

    async def test_a_browser_gets_the_error_page(self, legs):
        async with _client() as client, holding(GATE):
            response = await client.get("/example.com", headers=CHROME)
        assert response.status_code == 503
        assert response.headers["retry-after"] == RETRY_AFTER
        assert response.headers["content-type"].startswith("text/html")
        assert "ERROR 503" in response.text
        assert "Content-Security-Policy" in response.headers

    async def test_a_text_client_gets_one_line(self, legs):
        async with _client() as client, holding(GATE):
            response = await client.get("/example.com?format=text", headers=CURL)
        assert response.status_code == 503
        assert response.headers["retry-after"] == RETRY_AFTER
        assert response.text == f"error: {BUSY_MESSAGE}\n"

    async def test_fields_are_refused_as_json_like_their_answer(self, legs):
        """A browser following a ?fields= link gets JSON, so its refusal is
        JSON too, the same as a bad field name."""
        async with _client() as client, holding(GATE):
            response = await client.get("/example.com?fields=registrar", headers=CHROME)
        assert response.status_code == 503
        assert response.headers["retry-after"] == RETRY_AFTER
        assert response.json() == {"error": BUSY_MESSAGE, "code": "busy"}

    async def test_the_self_page_takes_a_slot_too(self, legs):
        """GET / does not go through gather(), and it is the busiest page."""
        async with _client() as client, holding(GATE):
            api = await client.get("/", headers=CURL)
            page = await client.get("/", headers=CHROME)
        assert api.status_code == 503
        assert api.json() == {"error": BUSY_MESSAGE, "code": "busy"}
        assert page.status_code == 503
        assert "ERROR 503" in page.text
        assert page.headers["retry-after"] == RETRY_AFTER
        assert _ran(legs) == set()

    async def test_nothing_is_held_against_the_client(self, legs):
        """The server being full is not the visitor's doing: no ban, and the
        next request once a slot is free is answered."""
        async with _client() as client:
            async with holding(GATE):
                refused = [
                    await client.get(f"/example{n}.com", headers=CURL) for n in range(3)
                ]
            assert [r.status_code for r in refused] == [503, 503, 503]
            assert main.ip_ban_manager.banned_ips == {}
            assert not main.ip_ban_manager.is_banned(CLIENT_IP)
            response = await client.get("/example.com", headers=CURL)
        assert response.status_code == 200


class TestWhatTakesNoSlot:
    async def test_the_bare_address_as_text(self, legs):
        """`curl ip.1kko.com?format=text` does no lookup, so a full gate is
        nothing to it."""
        async with _client() as client, holding(GATE):
            response = await client.get("/?format=text", headers=CURL)
        assert response.status_code == 200
        assert response.text == f"{CLIENT_IP}\n"

    @pytest.mark.parametrize("path", ["/", "/example.com"])
    async def test_head(self, legs, path):
        async with _client() as client, holding(GATE):
            response = await client.head(path, headers=CURL)
        assert response.status_code == 200

    async def test_self_fields_that_need_no_network(self, legs):
        """The visitor's address and its GeoIP record are both local."""
        async with _client() as client, holding(GATE):
            local = await client.get("/?fields=ip,country_code", headers=CURL)
            registration = await client.get("/?fields=registrant", headers=CURL)
        assert local.status_code == 200
        assert local.json() == {"ip": CLIENT_IP, "country_code": "US"}
        assert registration.status_code == 503


class TestTheSlotSpansTheLookup:
    async def test_it_is_held_until_every_leg_has_answered(self, legs):
        started, release = asyncio.Event(), asyncio.Event()

        async def slow_whois(target):
            started.set()
            await release.wait()
            return {"source": "rdap", "name": target}

        legs["whois"].side_effect = slow_whois
        async with _client() as client, holding(GATE, GATE.size - 1):
            first = asyncio.create_task(client.get("/example.com", headers=CURL))
            await asyncio.wait_for(started.wait(), 5)
            while_held = await client.get("/example.org", headers=CURL)
            release.set()
            assert (await first).status_code == 200
            after = await client.get("/example.org", headers=CURL)
        assert while_held.status_code == 503
        assert after.status_code == 200

    async def test_a_lookup_refused_midway_gives_its_slot_back(self, legs):
        """A name whose A record is private is refused after it took a slot."""
        legs["resolver"].return_value.resolve.return_value = ["10.0.0.1"]
        async with _client() as client:
            for _ in range(3):
                response = await client.get("/internal.example.com", headers=CURL)
                assert response.status_code == 400
        # Every slot can still be taken without waiting for one.
        async with holding(GATE):
            pass


class TestSlowLegsHaveTheirOwnPools:
    async def test_rdap_and_port43_run_on_the_registration_pool(self, monkeypatch):
        threads = {}

        def rdap(target):
            threads["rdap"] = threading.current_thread().name
            return None  # RDAP cannot answer, so a domain falls back to port 43

        def port43(target, **kwargs):
            threads["whois"] = threading.current_thread().name
            return {"domain_name": target}

        monkeypatch.setattr(lookup, "lookup_rdap", rdap)
        monkeypatch.setattr(lookup.whois, "whois", port43)
        await _real_lookup_whois("example.com")
        assert threads["rdap"].startswith("registration")
        assert threads["whois"].startswith("registration")

    async def test_crtsh_runs_on_its_own_pool(self, monkeypatch):
        threads = []

        def fetch(domain):
            threads.append(threading.current_thread().name)
            return []

        monkeypatch.setattr(subdomains, "_fetch_sync", fetch)
        await subdomains.fetch_from_source("example.com")
        assert threads[0].startswith("crtsh")

    async def test_geoip_is_read_inline(self, monkeypatch):
        """A memory-mapped mmdb read takes microseconds; a thread hop costs
        more than that and used to queue it behind every slow leg."""
        threads = []

        def fetch_location(ip):
            threads.append(threading.get_ident())
            return {**LOCATION, "ip": ip}

        monkeypatch.setattr(lookup.geo_ip_manager, "fetch_location", fetch_location)
        await lookup.lookup_location(CLIENT_IP)
        assert threads == [threading.get_ident()]

    async def test_stuck_registration_lookups_do_not_hold_up_dns(
        self, legs, monkeypatch
    ):
        """Forty RDAP queries hanging on a dead registry used to fill the
        default executor, min(32, cpus + 4) threads, and the next lookup's A
        query waited behind them. They now queue on their own pool, and DNS,
        TLS and GeoIP answer at once."""
        dead = threading.Event()

        def dead_registry(target):
            dead.wait(timeout=10)
            return None

        monkeypatch.setattr(lookup, "lookup_rdap", dead_registry)
        backlog = [
            asyncio.create_task(_real_lookup_whois(f"198.51.100.{n}"))
            for n in range(40)
        ]
        try:
            await asyncio.sleep(0.2)  # every one of them handed to a thread
            data = await asyncio.wait_for(
                lookup.gather("example.com", legs={"resolve", "dns", "tls", "geo"}),
                timeout=3,
            )
        finally:
            dead.set()
            await asyncio.gather(*backlog)
        assert data["resolved_ip"] == DOMAIN_IP
        assert data["location"]["country_code"] == "US"


class TestMcp:
    @pytest.mark.parametrize(
        "tool, argument",
        [
            ("lookup", "target"),
            ("dns_records", "domain"),
            ("ssl_certificate", "domain"),
        ],
    )
    async def test_a_full_gate_is_an_error_the_model_can_read(
        self, legs, tool, argument
    ):
        async with holding(GATE):
            result = await getattr(mcp_server, tool)(**{argument: "example.com"})
        assert result.is_error
        assert result.structured_content == {"error": BUSY_MESSAGE}
        assert _ran(legs) == set()

    async def test_mcp_has_a_share_of_the_gate_not_all_of_it(self, legs):
        """/mcp never bans, so a burst of agent calls cannot be shed the way a
        burst on the page is. Its own cap nests inside the global gate: with
        every MCP slot taken, the page still has the rest."""
        assert MCP_GATE.size < GATE.size
        async with _client() as client, holding(MCP_GATE):
            result = await mcp_server.lookup("example.com")
            page = await client.get("/example.com", headers=CURL)
        assert result.is_error
        assert result.structured_content == {"error": BUSY_MESSAGE}
        assert page.status_code == 200


class TestGate:
    async def test_a_slot_freed_within_the_wait_goes_to_the_waiter(self):
        """A momentary spike is absorbed rather than refused."""
        gate = concurrency.LookupGate("test", 1, wait=2)
        release = asyncio.Event()

        async def holder():
            async with gate.slot():
                await release.wait()

        held = asyncio.create_task(holder())
        await asyncio.sleep(0)
        asyncio.get_running_loop().call_later(0.05, release.set)
        async with gate.slot():
            pass
        await held

    async def test_a_zero_wait_refuses_only_a_caller_that_would_queue(self):
        gate = concurrency.LookupGate("test", 1, wait=0)
        async with gate.slot():
            with pytest.raises(concurrency.LookupBusy):
                async with gate.slot():
                    pass
        async with gate.slot():
            pass


class TestSizes:
    def test_pools_and_gates_are_sized_from_config(self):
        assert concurrency.registration_pool._max_workers == config.REGISTRATION_WORKERS
        # One thread per simultaneous crt.sh fetch, the cap subdomains.py
        # already enforces with its semaphore.
        assert (
            concurrency.subdomain_pool._max_workers == config.SUBDOMAIN_MAX_CONCURRENT
        )
        assert GATE.size == config.LOOKUP_CONCURRENCY
        assert MCP_GATE.size == config.MCP_LOOKUP_CONCURRENCY

    def test_the_environment_sets_them(self):
        env = {
            **os.environ,
            "REGISTRATION_WORKERS": "3",
            "SUBDOMAIN_MAX_CONCURRENT": "2",
            "LOOKUP_CONCURRENCY": "5",
            "LOOKUP_GATE_WAIT_SECONDS": "0.25",
        }
        script = (
            "import concurrency as c; "
            "print(c.registration_pool._max_workers, c.subdomain_pool._max_workers, "
            "c.lookup_gate.size, c.lookup_gate.wait)"
        )
        # The interpreter running this suite, on a fixed script.
        out = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env=env,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert out.stdout.split() == ["3", "2", "5", "0.25"]
