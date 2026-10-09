"""/healthz says "degraded", and why, instead of a constant "ok".

It used to answer "ok" whatever state the service was in, so a GeoIP database
stuck on a months-old build and an RDAP registry timing out were visible in
telemetry but nothing ever flagged them. Each reason below must flip the status
on its own, the HTTP status must stay 200 (a degraded dependency is not fixed
by restarting the container), and `version` must stay where the deploy
workflow's grep finds it.

Also here: the container HEALTHCHECK script, and the two logging.exception
calls in gather() that ran outside any except block and so logged
"NoneType: None" instead of the real error.
"""

import asyncio
import datetime
import http.server
import logging
import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import config
import healthcheck
import lookup
import main
from rdap import CircuitBreaker

client = TestClient(main.app)

SHA = "0123456789abcdef0123456789abcdef01234567"
CURL = {"user-agent": "curl/8"}
DAY = 86400


class FakeReader:
    """Just enough of a maxminddb reader for /healthz: its build time."""

    def __init__(self, age_days: float):
        self.build_epoch = int(time.time() - age_days * DAY)

    def metadata(self):
        return SimpleNamespace(build_epoch=self.build_epoch)


class FakeScheduler:
    def __init__(self, running=True, jobs=()):
        self.running = running
        self.jobs = list(jobs)

    def get_jobs(self):
        return self.jobs


def job_due(seconds_from_now: float):
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=seconds_from_now
    )
    return SimpleNamespace(id="job", next_run_time=when)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def healthy(monkeypatch):
    """Every input to the status in its healthy state, so a test changes one
    thing and sees only that reason. Without this the result would depend on
    whether this machine could download the GeoIP databases and the suffix
    list when main was imported."""
    geo = main.geo_ip_manager
    monkeypatch.setattr(main, "APP_VERSION", SHA)
    monkeypatch.setattr(geo, "city_reader", FakeReader(age_days=3))
    monkeypatch.setattr(geo, "asn_reader", FakeReader(age_days=1))
    monkeypatch.setattr(main.tld_names_manager, "age_days", lambda: 2.0)
    monkeypatch.setattr(main, "scheduler", FakeScheduler(jobs=[job_due(60)]))
    monkeypatch.setattr(main, "_refresh_failures", {})
    clock = Clock()
    monkeypatch.setattr(main, "rdap_breaker", CircuitBreaker(3, 600, clock=clock))
    return SimpleNamespace(geo=geo, clock=clock, monkeypatch=monkeypatch)


def health():
    response = client.get("/healthz", headers=CURL)
    assert response.status_code == 200
    return response.json()


def codes(body):
    return [reason["code"] for reason in body["reasons"]]


def test_healthy_reports_ok_with_no_reasons(healthy):
    body = health()
    assert body["status"] == "ok"
    assert body["reasons"] == []
    assert body["version"] == SHA


# One entry per reason: what to break, and the code it must produce.
def _no_city(h):
    h.monkeypatch.setattr(h.geo, "city_reader", None)


def _no_asn(h):
    h.monkeypatch.setattr(h.geo, "asn_reader", None)


def _old_city(h):
    age = config.GEOIP_MAX_BUILD_AGE_DAYS + 1
    h.monkeypatch.setattr(h.geo, "city_reader", FakeReader(age_days=age))


def _old_asn(h):
    age = config.GEOIP_MAX_BUILD_AGE_DAYS + 1
    h.monkeypatch.setattr(h.geo, "asn_reader", FakeReader(age_days=age))


def _psl_never_downloaded(h):
    # The bundled seed is stamped mtime 0, which age_days() reports as None.
    h.monkeypatch.setattr(main.tld_names_manager, "age_days", lambda: None)


def _psl_overdue(h):
    age = config.TLD_MAX_AGE_DAYS + 3.0
    h.monkeypatch.setattr(main.tld_names_manager, "age_days", lambda: age)


def _scheduler_shut_down(h):
    h.monkeypatch.setattr(main, "scheduler", FakeScheduler(running=False))


def _scheduler_stalled(h):
    # A job still due ten minutes ago: the loop that runs them is not running.
    stalled = FakeScheduler(jobs=[job_due(60), job_due(-600)])
    h.monkeypatch.setattr(main, "scheduler", stalled)


def _refresh_failing(h):
    h.monkeypatch.setattr(main, "_refresh_failures", {"GeoLite2-City": 2})


def _rdap_breaker_open(h):
    for _ in range(3):
        main.rdap_breaker.record_failure("rdap.afrinic.net")


@pytest.mark.parametrize(
    "breakage, code",
    [
        (_no_city, "geoip_bundled"),
        (_no_asn, "geoip_asn_missing"),
        (_old_city, "geoip_build_stale"),
        (_old_asn, "geoip_build_stale"),
        (_psl_never_downloaded, "public_suffix_list_overdue"),
        (_psl_overdue, "public_suffix_list_overdue"),
        (_scheduler_shut_down, "scheduler_stopped"),
        (_scheduler_stalled, "scheduler_stopped"),
        (_refresh_failing, "refresh_failing"),
        (_rdap_breaker_open, "rdap_breaker_open"),
    ],
)
def test_each_reason_degrades_alone(healthy, breakage, code):
    breakage(healthy)
    body = health()
    assert body["status"] == "degraded"
    assert codes(body) == [code]
    assert body["reasons"][0]["message"]
    assert body["version"] == SHA


def test_reasons_accumulate(healthy):
    _no_city(healthy)
    _rdap_breaker_open(healthy)
    assert codes(health()) == ["geoip_bundled", "rdap_breaker_open"]


def test_messages_name_what_is_wrong(healthy):
    _old_city(healthy)
    healthy.monkeypatch.setattr(main, "_refresh_failures", {"public-suffix-list": 3})
    _rdap_breaker_open(healthy)
    messages = [r["message"] for r in health()["reasons"]]
    assert config.MAXMIND_CITY_EDITION in messages[0]
    assert "public-suffix-list" in messages[1] and "3 times" in messages[1]
    assert re.search(r"\brdap\.afrinic\.net\b", messages[2])


def test_build_just_inside_the_limit_is_fine(healthy):
    age = config.GEOIP_MAX_BUILD_AGE_DAYS - 0.5
    healthy.monkeypatch.setattr(healthy.geo, "city_reader", FakeReader(age_days=age))
    assert health()["status"] == "ok"


def test_suffix_list_gets_a_grace_period_past_its_refresh_age(healthy):
    """is_stale() turns true at TLD_MAX_AGE_DAYS, but the job that acts on it
    runs once a day, so a perfectly healthy list sits up to a day past that.
    Reporting it would make the probe cry wolf every fortnight."""
    age = config.TLD_MAX_AGE_DAYS + 0.9
    healthy.monkeypatch.setattr(main.tld_names_manager, "age_days", lambda: age)
    assert health()["status"] == "ok"


def test_one_failed_refresh_is_not_yet_degraded(healthy):
    """A single failure has a retry an hour later, which usually heals it."""
    healthy.monkeypatch.setattr(main, "_refresh_failures", {"GeoLite2-City": 1})
    assert health()["status"] == "ok"


def test_rdap_breaker_is_reported_only_while_it_fails_fast(healthy):
    _rdap_breaker_open(healthy)
    assert codes(health()) == ["rdap_breaker_open"]
    # Past the cooldown the next lookup goes through as the probe, so the
    # host is no longer being skipped.
    healthy.clock.now += 601
    assert health()["status"] == "ok"


def test_degraded_head_is_still_200(healthy):
    _no_city(healthy)
    response = client.head("/healthz", headers=CURL)
    assert response.status_code == 200


def test_deploy_workflow_still_reads_version_first_when_degraded(healthy):
    """deploy.yml has no JSON parser: it greps the first "version" in the raw
    body. Nothing added for degraded may put another one ahead of it."""
    _no_city(healthy)
    _old_asn(healthy)
    _rdap_breaker_open(healthy)
    raw = client.get("/healthz", headers=CURL).text
    first = re.search(r'"version":"([^"]*)"', raw)
    assert first is not None and first.group(1) == SHA
    assert raw.index('"status"') < raw.index('"version"') < raw.index('"reasons"')


class TestRefreshFailureTracking:
    """_refresh_with_retry is what knows a refresh failed; /healthz reads the
    count it keeps."""

    @pytest.fixture(autouse=True)
    def no_scheduling(self, monkeypatch):
        monkeypatch.setattr(main.scheduler, "add_job", lambda *a, **k: None)
        monkeypatch.setattr(main, "_refresh_failures", {})

    def test_failures_count_up(self):
        refresh = main._refresh_with_retry(lambda: False, "test-db")
        refresh()
        refresh()
        assert main._refresh_failures == {"test-db": 2}

    def test_success_clears_the_count(self):
        outcomes = iter([False, False, True])
        refresh = main._refresh_with_retry(lambda: next(outcomes), "test-db")
        refresh()
        refresh()
        refresh()
        assert main._refresh_failures == {}


def test_open_hosts_lists_only_hosts_failing_fast():
    clock = Clock()
    breaker = CircuitBreaker(2, 600, clock=clock)
    breaker.record_failure("a.example")  # below the threshold
    for _ in range(2):
        breaker.record_failure("b.example")
        breaker.record_failure("c.example")
    assert breaker.open_hosts() == ["b.example", "c.example"]
    breaker.record_success("b.example")
    assert breaker.open_hosts() == ["c.example"]
    clock.now += 601
    assert breaker.open_hosts() == []


class _Server:
    """A loopback HTTP server answering every GET with one canned response."""

    def __init__(self, status: int, body: bytes):
        outer = self
        self.status, self.body = status, body

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/healthz"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    servers = []

    def start(status, body=b"{}"):
        servers.append(_Server(status, body))
        return servers[-1].url

    yield start
    for server in servers:
        server.close()


class TestHealthcheckScript:
    """The Dockerfile HEALTHCHECK. It used to be a bare socket connect, which
    passes for any process holding port 8000, wedged or not."""

    def test_ok_passes(self, serve):
        assert healthcheck.main(serve(200, b'{"status":"ok"}')) == 0

    def test_degraded_still_passes(self, serve):
        """Restarting the container does not bring a stale GeoIP build or a
        down RDAP registry back, and a restart loop would take the whole
        service offline over it."""
        assert healthcheck.main(serve(200, b'{"status":"degraded"}')) == 0

    @pytest.mark.parametrize("status", [403, 429, 500, 503])
    def test_non_200_fails(self, serve, status):
        assert healthcheck.main(serve(status)) == 1

    def test_unreachable_fails(self):
        # Bind and close to get a port nothing listens on.
        server = _Server(200, b"{}")
        url = server.url
        server.close()
        assert healthcheck.main(url) == 1

    def test_ignores_proxy_settings(self, serve, monkeypatch):
        """A proxy in the container's environment must not swallow a loopback
        probe."""
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.delenv("NO_PROXY", raising=False)
        assert healthcheck.main(serve(200)) == 0

    def test_dockerfile_runs_it(self):
        lines = (Path(__file__).parent.parent / "Dockerfile").read_text().splitlines()
        start = next(
            i for i, line in enumerate(lines) if line.startswith("HEALTHCHECK")
        )
        command = " ".join(lines[start : start + 2])
        assert "healthcheck.py" in command
        assert "socket" not in command


class FakeResolver:
    def resolve(self, name, rdtype):
        return ["93.184.216.34"]


def test_gather_logs_the_real_dns_and_tls_exceptions(monkeypatch, caplog):
    """Both legs run under asyncio.gather(return_exceptions=True), so their
    errors come back as values and are logged after the fact, outside any
    except block. logging.exception there logged "NoneType: None"."""
    dns_error = RuntimeError("dns sweep exploded")
    tls_error = RuntimeError("tls handshake exploded")

    def broken_records(*args, **kwargs):
        raise dns_error

    def broken_tls(*args, **kwargs):
        raise tls_error

    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: True)
    monkeypatch.setattr(lookup, "_recursive_resolver", FakeResolver)
    monkeypatch.setattr(lookup.domain_manager, "get_records", broken_records)
    monkeypatch.setattr(lookup.SSLManager, "get_ssl_info", broken_tls)

    with caplog.at_level(logging.ERROR):
        result = asyncio.run(lookup.gather("example.com", legs={"dns", "tls"}))

    assert result["domain"] is None and result["ssl"] is None
    logged = {
        record.getMessage(): record.exc_info
        for record in caplog.records
        if record.levelno == logging.ERROR
    }
    assert logged["Error getting DNS records for example.com"][1] is dns_error
    assert logged["Error getting SSL info for example.com"][1] is tls_error
