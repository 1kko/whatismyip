"""How much an RDAP or WHOIS lookup may cost, and what an IP gets when RDAP fails.

Three rules, each with a cost when broken:
- An IP never falls back to python-whois, which answers an address with the
  registration of its PTR hostname's domain: the ISP's domain record shown as
  if it were the address allocation.
- whoisit gives up fast. asyncio.wait_for cannot cancel the worker thread, so
  whoisit's own defaults (10s per request, 3 retries) kept an abandoned thread
  retrying a dead registry long after the response had gone out.
- A registry that keeps failing is skipped for a while, per RDAP host, instead
  of costing every visitor the whole RDAP budget.

No network: whoisit's query functions and python-whois are replaced, and the
breaker runs on a fake clock, so nothing here sleeps through a cooldown.
"""

import asyncio
import threading

import pytest
import whoisit

import lookup
import mcp_server
import rdap
import viewmodel
from config import (
    RDAP_BREAKER_COOLDOWN_SECONDS,
    RDAP_BREAKER_FAILURES,
    RDAP_HTTP_RETRIES,
    RDAP_HTTP_TIMEOUT_SECONDS,
    WHOIS_SOCKET_TIMEOUT_SECONDS,
)

AFRINIC = "rdap.afrinic.net"
VERISIGN = "rdap.verisign.com"
IP = "196.216.2.1"
DOMAIN = "example.com"

RDAP_IP_RESULT = {"name": "AFRINIC-NET", "handle": "196.216.2.0 - 196.216.3.255"}
RDAP_DOMAIN_RESULT = {"name": DOMAIN, "handle": "2336799_DOMAIN_COM-VRSN"}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _timeout() -> whoisit.errors.QueryError:
    # What whoisit raises for a request that never got an HTTP answer: it wraps
    # the requests exception, so there is no status code.
    return whoisit.errors.QueryError(
        f"Failed to make a GET request to https://{AFRINIC}/rdap/ip/{IP}: timed out"
    )


def _status(cls, code: int) -> whoisit.errors.QueryError:
    return cls(f"RDAP request returned {code}", status_code=code)


@pytest.fixture(autouse=True)
def clean_cache():
    lookup._whois_cache.clear()
    yield
    lookup._whois_cache.clear()


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    breaker = rdap.CircuitBreaker(
        RDAP_BREAKER_FAILURES, RDAP_BREAKER_COOLDOWN_SECONDS, clock=fake
    )
    monkeypatch.setattr(rdap, "rdap_breaker", breaker)
    return fake


@pytest.fixture
def port43(monkeypatch):
    """python-whois, recorded. It answers like a registrar would, so a call
    that should not have happened shows up both here and in the result.
    Raising instead would prove nothing: _whois_fallback catches it."""
    calls = []

    def fake_whois(target, **kwargs):
        calls.append((target, kwargs))
        return {"domain_name": target}

    monkeypatch.setattr(lookup.whois, "whois", fake_whois)
    return calls


@pytest.fixture
def registry(monkeypatch, clock, port43):
    """Stand-in for whoisit's network side. build_query resolves IPs to AFRINIC
    and domains to Verisign, as the IANA bootstrap would; ip() and domain()
    count their calls and do whatever `answer[kind]` says (raise it if it is
    an exception, return it otherwise)."""
    state = {
        "calls": {"ip": 0, "domain": 0},
        "answer": {"ip": RDAP_IP_RESULT, "domain": RDAP_DOMAIN_RESULT},
    }

    def build_query(query_type=None, query_value=None, rir=None):
        if query_type == "ip":
            return "GET", f"https://{AFRINIC}/rdap/ip/{query_value}", True
        return "GET", f"https://{VERISIGN}/com/v1/domain/{query_value}", True

    def answer(kind):
        def query(target, **kwargs):
            state["calls"][kind] += 1
            result = state["answer"][kind]
            if isinstance(result, BaseException):
                raise result
            return dict(result)

        return query

    monkeypatch.setattr(rdap, "bootstrap_rdap", lambda force=False: True)
    monkeypatch.setattr(rdap.whoisit, "build_query", build_query)
    monkeypatch.setattr(rdap.whoisit, "ip", answer("ip"))
    monkeypatch.setattr(rdap.whoisit, "domain", answer("domain"))
    return state


class TestIpNeverFallsBackToWhois:
    def test_rdap_miss_reports_the_rir_unavailable(self, monkeypatch, port43):
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: None)

        out = asyncio.run(lookup.lookup_whois(IP))

        assert out == {"error": rdap.RIR_RDAP_UNAVAILABLE}
        assert port43 == []

    def test_rdap_timeout_reports_the_rir_unavailable(self, monkeypatch, port43):
        # The RDAP thread outlives wait_for; the IP must still not reach
        # python-whois while it does.
        release = threading.Event()

        def stuck(target):
            release.wait(5)
            return None

        async def lookup_then_release():
            # Released inside the loop: asyncio.run joins the executor's
            # threads on the way out, and would otherwise wait for this one.
            try:
                return await lookup.lookup_whois(IP)
            finally:
                release.set()

        monkeypatch.setattr(lookup, "lookup_rdap", stuck)
        monkeypatch.setattr(lookup, "RDAP_TIMEOUT_SECONDS", 0.05)
        out = asyncio.run(lookup_then_release())

        assert out == {"error": rdap.RIR_RDAP_UNAVAILABLE}
        assert port43 == []

    def test_failed_rdap_query_for_an_ip_reports_the_rir_unavailable(
        self, registry, port43
    ):
        registry["answer"]["ip"] = _timeout()

        out = asyncio.run(lookup.lookup_whois(IP))

        assert out == {"error": rdap.RIR_RDAP_UNAVAILABLE}
        assert registry["calls"]["ip"] == 1
        assert port43 == []

    def test_ipv6_follows_the_same_rule(self, monkeypatch, port43):
        # gather() refuses IPv6, but the self page looks up the visitor's own
        # address, which can be one.
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: None)

        out = asyncio.run(lookup.lookup_whois("2001:db8::1"))

        assert out == {"error": rdap.RIR_RDAP_UNAVAILABLE}
        assert port43 == []

    def test_the_error_renders_as_a_failure_not_an_answer(self):
        record = {"error": rdap.RIR_RDAP_UNAVAILABLE}

        assert viewmodel.whois_display(record) == {"Error": rdap.RIR_RDAP_UNAVAILABLE}
        column = viewmodel._whois_column(record)
        assert column["rows"][0]["value"] == "unavailable"
        assert mcp_server.compact_registration(record) == {
            "error": rdap.RIR_RDAP_UNAVAILABLE
        }


class TestDomainWhoisIsBounded:
    def test_port43_fallback_passes_a_socket_timeout(self, monkeypatch, port43):
        # Domains still fall back: RDAP does not cover many ccTLDs (.kr).
        monkeypatch.setattr(lookup, "lookup_rdap", lambda target: None)

        out = asyncio.run(lookup.lookup_whois("naver.co.kr"))

        assert out["source"] == "whois"
        [(target, kwargs)] = port43
        assert target == "naver.co.kr"
        assert kwargs.get("timeout") == WHOIS_SOCKET_TIMEOUT_SECONDS
        # python-whois's timeout bounds one socket operation per referral hop;
        # it has to sit well inside the wait_for budget for the whole lookup.
        assert WHOIS_SOCKET_TIMEOUT_SECONDS < lookup.WHOIS_TIMEOUT_SECONDS


class TestWhoisitIsConfigured:
    def test_http_timeout_and_retries(self):
        assert 3 <= RDAP_HTTP_TIMEOUT_SECONDS <= 4
        assert RDAP_HTTP_RETRIES == 0
        assert whoisit.utils.http_timeout == RDAP_HTTP_TIMEOUT_SECONDS
        assert whoisit.utils.http_max_retries == RDAP_HTTP_RETRIES

    def test_the_session_whoisit_queries_with_does_not_retry(self):
        # The retry count is baked into the requests.Session whoisit builds on
        # first use; this is the session every query goes through.
        session = whoisit.utils.get_session()
        adapter = session.get_adapter(f"https://{AFRINIC}/")
        assert adapter.max_retries.total == RDAP_HTTP_RETRIES

    def test_requests_carry_the_timeout(self):
        # Pins the attribute name against the installed whoisit: http_request
        # reads utils.http_timeout at call time, so a rename upstream would
        # silently put the 10s default back.
        seen = {}

        class Session:
            def request(self, method, url, **kwargs):
                seen.update(kwargs)

        whoisit.utils.http_request(Session(), f"https://{AFRINIC}/rdap/ip/{IP}")
        assert seen["timeout"] == RDAP_HTTP_TIMEOUT_SECONDS


class TestCircuitBreaker:
    def _breaker(self, clock, threshold=3, cooldown=600):
        return rdap.CircuitBreaker(threshold, cooldown, clock=clock)

    def test_opens_after_consecutive_failures(self):
        breaker = self._breaker(FakeClock())
        for _ in range(2):
            breaker.record_failure(AFRINIC)
            assert breaker.allow(AFRINIC)
        breaker.record_failure(AFRINIC)
        assert not breaker.allow(AFRINIC)

    def test_a_success_resets_the_count(self):
        breaker = self._breaker(FakeClock())
        breaker.record_failure(AFRINIC)
        breaker.record_failure(AFRINIC)
        breaker.record_success(AFRINIC)
        breaker.record_failure(AFRINIC)
        breaker.record_failure(AFRINIC)
        assert breaker.allow(AFRINIC)

    def test_hosts_are_independent(self):
        breaker = self._breaker(FakeClock())
        for _ in range(3):
            breaker.record_failure(AFRINIC)
        assert not breaker.allow(AFRINIC)
        assert breaker.allow(VERISIGN)

    def test_after_the_window_one_probe_goes_through(self):
        clock = FakeClock()
        breaker = self._breaker(clock)
        for _ in range(3):
            breaker.record_failure(AFRINIC)

        clock.advance(599)
        assert not breaker.allow(AFRINIC)
        clock.advance(2)
        assert breaker.allow(AFRINIC)
        # Everyone else waits for the probe instead of piling on together.
        assert not breaker.allow(AFRINIC)

    def test_a_successful_probe_closes_it(self):
        clock = FakeClock()
        breaker = self._breaker(clock)
        for _ in range(3):
            breaker.record_failure(AFRINIC)
        clock.advance(601)
        assert breaker.allow(AFRINIC)

        breaker.record_success(AFRINIC)

        assert breaker.allow(AFRINIC)
        assert breaker.allow(AFRINIC)

    def test_a_failed_probe_reopens_it_for_another_window(self):
        clock = FakeClock()
        breaker = self._breaker(clock)
        for _ in range(3):
            breaker.record_failure(AFRINIC)
        clock.advance(601)
        assert breaker.allow(AFRINIC)

        breaker.record_failure(AFRINIC)

        clock.advance(599)
        assert not breaker.allow(AFRINIC)
        clock.advance(2)
        assert breaker.allow(AFRINIC)

    def test_counts_failures_from_many_threads(self):
        breaker = self._breaker(FakeClock(), threshold=201)

        def fail():
            for _ in range(25):
                breaker.record_failure(AFRINIC)

        threads = [threading.Thread(target=fail) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert breaker.allow(AFRINIC)  # 200 failures, one short
        breaker.record_failure(AFRINIC)
        assert not breaker.allow(AFRINIC)


class TestLookupRdapUsesTheBreaker:
    def test_open_breaker_short_circuits_without_a_query(self, registry, port43):
        registry["answer"]["ip"] = _timeout()
        for _ in range(RDAP_BREAKER_FAILURES):
            assert rdap.lookup_rdap(IP) is None
        assert registry["calls"]["ip"] == RDAP_BREAKER_FAILURES

        assert rdap.lookup_rdap(IP) is None
        out = asyncio.run(lookup.lookup_whois(IP))

        assert registry["calls"]["ip"] == RDAP_BREAKER_FAILURES
        assert out == {"error": rdap.RIR_RDAP_UNAVAILABLE}
        assert port43 == []

    def test_closes_after_the_window_once_the_registry_answers(self, registry, clock):
        registry["answer"]["ip"] = _timeout()
        for _ in range(RDAP_BREAKER_FAILURES):
            rdap.lookup_rdap(IP)

        clock.advance(RDAP_BREAKER_COOLDOWN_SECONDS + 1)
        registry["answer"]["ip"] = RDAP_IP_RESULT
        first = rdap.lookup_rdap(IP)
        second = rdap.lookup_rdap(IP)

        assert first["source"] == "rdap"
        assert second["source"] == "rdap"
        assert registry["calls"]["ip"] == RDAP_BREAKER_FAILURES + 2

    def test_an_open_registry_sends_a_domain_straight_to_port43(self, registry, port43):
        # For a domain the breaker does not turn into an error: port-43 WHOIS
        # is the right fallback, and it now starts at once instead of after
        # the whole RDAP budget.
        registry["answer"]["domain"] = _timeout()
        for _ in range(RDAP_BREAKER_FAILURES):
            rdap.lookup_rdap(DOMAIN)

        out = asyncio.run(lookup.lookup_whois(DOMAIN))

        assert out["source"] == "whois"
        assert registry["calls"]["domain"] == RDAP_BREAKER_FAILURES
        assert [target for target, _ in port43] == [DOMAIN]

    def test_one_dead_registry_does_not_block_another(self, registry):
        registry["answer"]["ip"] = _timeout()
        for _ in range(RDAP_BREAKER_FAILURES + 2):
            rdap.lookup_rdap(IP)

        assert rdap.lookup_rdap(DOMAIN)["source"] == "rdap"

    @pytest.mark.parametrize(
        "error",
        [
            _status(whoisit.errors.RemoteServerError, 500),
            _status(whoisit.errors.QueryError, 503),
            _status(whoisit.errors.RateLimitedError, 429),
        ],
        ids=["500", "503", "429"],
    )
    def test_server_side_errors_count(self, registry, error):
        registry["answer"]["ip"] = error
        for _ in range(RDAP_BREAKER_FAILURES):
            rdap.lookup_rdap(IP)

        rdap.lookup_rdap(IP)

        assert registry["calls"]["ip"] == RDAP_BREAKER_FAILURES

    @pytest.mark.parametrize(
        "error",
        [
            _status(whoisit.errors.ResourceDoesNotExist, 404),
            _status(whoisit.errors.ResourceAccessDeniedError, 403),
        ],
        ids=["404", "403"],
    )
    def test_answers_from_a_live_server_do_not_count(self, registry, error):
        # The server answered; it is up, whatever it thinks of the question.
        registry["answer"]["ip"] = error
        for _ in range(RDAP_BREAKER_FAILURES + 2):
            rdap.lookup_rdap(IP)

        assert registry["calls"]["ip"] == RDAP_BREAKER_FAILURES + 2

    def test_a_success_between_failures_keeps_it_closed(self, registry):
        for _ in range(3):
            registry["answer"]["ip"] = _timeout()
            for _ in range(RDAP_BREAKER_FAILURES - 1):
                rdap.lookup_rdap(IP)
            registry["answer"]["ip"] = RDAP_IP_RESULT
            assert rdap.lookup_rdap(IP)["source"] == "rdap"
