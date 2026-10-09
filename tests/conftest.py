"""Test environment.

main.py reads these at import time, and load_dotenv() does not override what is
already set. Any test module that imports main therefore has to see them first —
conftest is the only place guaranteed to run before every test module, so the
suite no longer depends on which file pytest happens to collect first.
"""

import os

os.environ["ADMIN_API_KEY"] = "test-secret-key"
os.environ["TRUSTED_PROXIES"] = "127.0.0.1,10.0.0.1"
os.environ["BANNED_IPS_FILE"] = "/tmp/test_banned_ips.json"
os.environ["GEO_RULES_FILE"] = "/tmp/test_geo_rules.json"
# The app lifespan starts the scheduler and fetches what data/ lacks (GeoLite2,
# the public suffix list), and every `with TestClient(app)` runs that lifespan.
# Off, it does neither, so no lifespan downloads anything. Importing main
# starts and fetches nothing in any case (tests/test_boot.py).
os.environ["BACKGROUND_REFRESH_ENABLED"] = "false"
# Spamhaus allows one reputation download a day: no test run may make it, even
# from a lifespan test that starts a real scheduler. Off, the lookup responses
# are exactly what they were before the feature; test_reputation.py builds
# enabled managers over synthetic lists of its own.
os.environ["REPUTATION_ENABLED"] = "false"

import sys  # noqa: E402  (must follow the env vars above)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def reset_security_state():
    """Clear the rate limiter and ban list around every test.

    The suite drives hundreds of requests through one TestClient in a few
    seconds, and the lookup surface is rate limited with a ban on breach. Without
    this, whichever module first exceeds the limit bans "testclient" and every
    test after it — in any module — gets a 403 instead of a page.

    Read out of sys.modules rather than imported: the pure-unit modules
    (gazetteer, projection, view model) never touch the app, and importing main
    here just to clear it would load the GeoIP database into every one of their
    runs.
    """

    def clear():
        main = sys.modules.get("main")
        if main is None:
            return
        main.rate_limiter.request_history.clear()
        main.ip_ban_manager.banned_ips.clear()

    clear()
    yield
    clear()


# ---------------------------------------------------------------------------
# Offline. No test reaches the network, and one that tries fails.
#
# Two layers. offline_lookups answers every external lookup a request makes
# (DNS, RDAP, port-43 WHOIS) the way a machine with no network would, so a test
# that does not care about a source need not mock it. Under it, a guard on the
# socket layer refuses any connection, UDP datagram or name lookup that is not
# to loopback, and fails the test that made it. Loopback stays open: TestClient
# uses no socket at all, and test_tls_reasons.py and test_healthz_degraded.py
# run real servers on 127.0.0.1.
#
# A test that genuinely needs the network is marked @pytest.mark.network. It is
# skipped unless RUN_NETWORK_TESTS=1, and runs with neither layer in place.
# ---------------------------------------------------------------------------

import errno  # noqa: E402
import ipaddress  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402

import dns.resolver  # noqa: E402
import whois  # noqa: E402
import whoisit  # noqa: E402

RUN_NETWORK_TESTS = os.environ.get("RUN_NETWORK_TESTS") == "1"


class NetworkBlocked(OSError):
    """What the guard raises in place of a real network attempt."""


def _host(address):
    # An AF_UNIX address is a path, never the network.
    if isinstance(address, tuple) and address:
        return address[0]
    return None


def _is_loopback(host) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).split("%", 1)[0]  # an IPv6 zone index
    if host in ("", "localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False  # a name, which only DNS can turn into an address
    # Connecting to the unspecified address reaches this host.
    return address.is_loopback or address.is_unspecified


def _is_numeric(host) -> bool:
    try:
        ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return False
    return True


class _NetworkGuard:
    """Wraps the socket calls every client library ends in. connect and
    connect_ex cover TCP (dnspython's TCP fallback uses connect_ex, and
    python-whois hands connect a hostname), sendto covers UDP (dnspython's
    queries), and the name lookups cover whatever resolves a hostname first:
    requests, urllib, asyncio.

    An attempt is refused before anything leaves the machine, and recorded with
    the test that was running. The refusal alone would not fail the test: the
    app catches it, as it catches any network error, and worker threads make
    most of the attempts. pytest_runtest_makereport turns the record into a
    failure.
    """

    SOCKET_METHODS = ("connect", "connect_ex", "sendto")
    LOOKUPS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex")

    def __init__(self):
        self._lock = threading.Lock()
        self._attempts: list[tuple[str, str]] = []
        self.where = "outside any test"
        self.allow = False
        self._real = {
            name: getattr(socket.socket, name) for name in self.SOCKET_METHODS
        }
        self._real.update({name: getattr(socket, name) for name in self.LOOKUPS})

    def _refuse(self, what: str) -> None:
        with self._lock:
            self._attempts.append((what, self.where))

    def drain(self, nodeid: str | None = None) -> list[str]:
        """The attempts since the last drain, one line each with a count. One
        made while another test was running (a worker thread that outlived it)
        says which."""
        with self._lock:
            attempts, self._attempts = self._attempts, []
        counts = {}
        for attempt in attempts:
            counts[attempt] = counts.get(attempt, 0) + 1
        return [
            what
            + (f" x{n}" if n > 1 else "")
            + (f" (during {where})" if where != nodeid else "")
            for (what, where), n in counts.items()
        ]

    def install(self) -> None:
        guard, real = self, self._real

        def connect(sock, address):
            if guard.allow or _is_loopback(_host(address)):
                return real["connect"](sock, address)
            guard._refuse(f"connect to {address!r}")
            raise NetworkBlocked(errno.ENETUNREACH, "network blocked in tests")

        def connect_ex(sock, address):
            if guard.allow or _is_loopback(_host(address)):
                return real["connect_ex"](sock, address)
            guard._refuse(f"connect to {address!r}")
            return errno.ENETUNREACH

        def sendto(sock, data, *args):
            # sendto(data, address) or sendto(data, flags, address).
            if guard.allow or _is_loopback(_host(args[-1])):
                return real["sendto"](sock, data, *args)
            guard._refuse(f"UDP datagram to {args[-1]!r}")
            raise NetworkBlocked(errno.ENETUNREACH, "network blocked in tests")

        def lookup(name):
            def resolve(host, *args, **kwargs):
                if guard.allow or _is_loopback(host) or _is_numeric(host):
                    return real[name](host, *args, **kwargs)
                guard._refuse(f"{name}({host!r})")
                raise socket.gaierror(socket.EAI_NONAME, "DNS blocked in tests")

            return resolve

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.socket.sendto = sendto
        for name in self.LOOKUPS:
            setattr(socket, name, lookup(name))

    def uninstall(self) -> None:
        for name in self.SOCKET_METHODS:
            setattr(socket.socket, name, self._real[name])
        for name in self.LOOKUPS:
            setattr(socket, name, self._real[name])


# Installed at import, not in a hook, so collection (every test module imports
# its code) is guarded too.
_network_guard = _NetworkGuard()
_network_guard.install()


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "network: needs the real network; skipped unless RUN_NETWORK_TESTS=1",
    )


def pytest_unconfigure(config):
    _network_guard.uninstall()


def pytest_collection_modifyitems(config, items):
    if RUN_NETWORK_TESTS:
        return
    skip = pytest.mark.skip(reason="needs the network: set RUN_NETWORK_TESTS=1")
    for item in items:
        if item.get_closest_marker("network"):
            item.add_marker(skip)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    marked = item.get_closest_marker("network") is not None
    _network_guard.where = item.nodeid
    _network_guard.allow = RUN_NETWORK_TESTS and marked
    try:
        return (yield)
    finally:
        _network_guard.where = "between tests"
        _network_guard.allow = False


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    attempts = _network_guard.drain(item.nodeid)
    if attempts:
        message = (
            "The suite runs offline (tests/conftest.py), and this test tried to "
            "reach the network:\n  "
            + "\n  ".join(attempts)
            + "\nMock the lookup, or mark the test @pytest.mark.network."
        )
        if report.failed:
            report.sections.append(("network guard", message))
        else:
            report.outcome = "failed"
            report.longrepr = message
    return report


def pytest_sessionfinish(session, exitstatus):
    # A worker thread can outlive the test that started it.
    attempts = _network_guard.drain()
    if attempts:
        sys.stderr.write(
            "\nnetwork guard: attempts after the last test report:\n  "
            + "\n  ".join(attempts)
            + "\n"
        )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(autouse=True)
def offline_lookups(request, monkeypatch):
    """Every external lookup fails as it would on a machine with no network.

    DNS: dnspython's Resolver.resolve, which every query the app makes goes
    through (_recursive_resolver, zone_for_name in zone_apex, PTR), raises
    NoNameservers, so the app reports "servfail", never "no records". RDAP:
    whoisit's bootstrap and queries raise QueryError, as whoisit does when a
    request gets no answer. Port-43 WHOIS: python-whois's whois() has its
    connection refused. TLS needs no stub of its own: without DNS a domain has
    no verified address, and SSLManager connects to nothing else.

    These sit at the library edge, under every seam the suite mocks
    (lookup.lookup_rdap, managers._recursive_resolver, a class-level patch of
    Resolver.resolve, ...). A test patches what it asserts on, and its patch,
    applied after this fixture, wins.
    """
    if request.node.get_closest_marker("network"):
        return

    def no_dns(self, *args, **kwargs):
        raise dns.resolver.NoNameservers()

    def no_rdap(*args, **kwargs):
        raise whoisit.errors.QueryError("RDAP is unreachable from the test suite")

    def no_port43(*args, **kwargs):
        raise ConnectionRefusedError("port 43 is unreachable from the test suite")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", no_dns)
    for name in ("bootstrap", "ip", "domain"):
        monkeypatch.setattr(whoisit, name, no_rdap)
    monkeypatch.setattr(whois, "whois", no_port43)
