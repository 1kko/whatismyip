"""The suite runs offline, and stays that way.

tests/conftest.py answers the external lookups the way a machine with no
network would (offline_lookups) and, under that, guards the socket layer. These
pin both halves: the defaults fail like an unreachable network, with a test's
own mock still on top; and a test that reaches past them fails, even when the
code it drives swallows the error, while loopback stays open.

Before them, 36 tests sent real DNS queries to 8.8.8.8 and 1.1.1.1, RDAP
requests to data.iana.org and the RIRs, and a TLS handshake to google.com, and
passed with the network or without it.
"""

from pathlib import Path

import dns.resolver
import pytest
import whois
import whoisit

import lookup
from rdap import RIR_RDAP_UNAVAILABLE

pytest_plugins = ["pytester"]

CONFTEST = Path(__file__).with_name("conftest.py")


def test_dns_fails_as_an_unreachable_resolver_would():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8"]
    with pytest.raises(dns.resolver.NoNameservers):
        resolver.resolve("example.com", "A")
    # zone_apex's SOA walk goes through the same method.
    with pytest.raises(dns.resolver.NoNameservers):
        dns.resolver.zone_for_name("www.example.com", resolver=resolver)


def test_rdap_and_port43_fail_as_unreachable_servers_would():
    with pytest.raises(whoisit.errors.QueryError):
        whoisit.bootstrap()
    with pytest.raises(whoisit.errors.QueryError):
        whoisit.ip("8.8.8.8")
    with pytest.raises(ConnectionRefusedError):
        whois.whois("example.com")


def test_a_tests_own_mock_sits_on_top_of_the_defaults(monkeypatch):
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", lambda self, *a, **k: "ok")
    assert dns.resolver.Resolver(configure=False).resolve("example.com") == "ok"


async def test_an_unmocked_lookup_reports_failures_not_absence(monkeypatch):
    """Through the whole pipeline with nothing mocked, every leg that needs
    the network says it could not find out, never that there is nothing."""
    # Empty, so the answers are this run's and not another test's.
    monkeypatch.setattr(lookup, "_whois_cache", lookup.TTLCache())
    ip = await lookup.gather("8.8.8.8")
    domain = await lookup.gather("example.com")

    assert ip["whois"] == {"error": RIR_RDAP_UNAVAILABLE}
    assert ip["reverse_dns"] is None
    assert ip["location"]["ip"] == "8.8.8.8"  # GeoIP is local

    assert domain["resolution"] == "servfail"
    assert domain["whois"] == {"error": "WHOIS lookup failed"}
    assert domain["ssl"] is None  # no verified address, so no handshake
    assert set(domain["domain"]["status"].values()) == {"servfail"}


# Each swallows its error, as the app does: the guard has to fail the test
# anyway. 192.0.2.0/24 is TEST-NET-1, so even a guard that let these through
# would reach no one.
GUARDED = """
import socket
import threading
import socketserver

import dns.resolver
import pytest

REAL_RESOLVE = dns.resolver.Resolver.resolve


def swallow(attempt):
    try:
        attempt()
    except OSError:
        pass


def test_tcp():
    swallow(lambda: socket.create_connection(("192.0.2.1", 80), timeout=1))


def test_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        swallow(lambda: s.sendto(b"x", ("192.0.2.1", 53)))


def test_name_lookup():
    swallow(lambda: socket.getaddrinfo("example.com", 443))


def test_from_a_worker_thread():
    worker = threading.Thread(
        target=swallow,
        args=(lambda: socket.create_connection(("192.0.2.1", 443), timeout=1),),
    )
    worker.start()
    worker.join()


def test_loopback_stays_open():
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(self.request.recv(16))

    with socketserver.TCPServer(("127.0.0.1", 0), Echo) as server:
        threading.Thread(target=server.handle_request, daemon=True).start()
        with socket.create_connection(server.server_address, timeout=5) as c:
            c.sendall(b"ping")
            assert c.recv(16) == b"ping"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("127.0.0.1", 9))
    socket.getaddrinfo("localhost", 80)
    assert dns.resolver.Resolver.resolve is not REAL_RESOLVE  # stubbed


@pytest.mark.network
def test_needs_the_network():
    # Neither layer: the real resolver, and a UDP connect (which sends
    # nothing; it only picks a route) that the guard lets through.
    assert dns.resolver.Resolver.resolve is REAL_RESOLVE
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        swallow(lambda: s.connect(("192.0.2.1", 9)))
"""


@pytest.fixture
def guarded_run(pytester, monkeypatch):
    """Run GUARDED in a fresh interpreter under a copy of the real conftest,
    so the guard under test is not the one guarding this test."""
    pytester.makeconftest(CONFTEST.read_text(encoding="utf-8"))
    pytester.makepyfile(test_guarded=GUARDED)

    def run(network: bool):
        monkeypatch.delenv("RUN_NETWORK_TESTS", raising=False)
        if network:
            monkeypatch.setenv("RUN_NETWORK_TESTS", "1")
        return pytester.runpytest_subprocess("-p", "no:cacheprovider", "-rs")

    return run


def test_a_test_that_reaches_the_network_fails(guarded_run):
    result = guarded_run(network=False)
    result.assert_outcomes(passed=1, failed=4, skipped=1)
    result.stdout.fnmatch_lines_random(
        [
            "*tried to reach the network*",
            "*connect to ('192.0.2.1', 80)*",
            "*UDP datagram to ('192.0.2.1', 53)*",
            "*getaddrinfo('example.com')*",
            "*connect to ('192.0.2.1', 443)*",
            "*Mock the lookup, or mark the test @pytest.mark.network.*",
            "*needs the network: set RUN_NETWORK_TESTS=1*",
        ]
    )


def test_a_network_test_runs_unguarded_when_enabled(guarded_run):
    result = guarded_run(network=True)
    result.assert_outcomes(passed=2, failed=4)
