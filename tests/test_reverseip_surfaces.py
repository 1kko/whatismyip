"""Reverse IP on the operator's surfaces: the refresh job and /healthz, and
the `reverse_ip` key of an IP lookup.

The suite runs with REVERSEIP_ENABLED=false; a test that wants the feature
asks for the `reverseip_enabled` fixture (conftest), or builds its own manager.
"""

import copy
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import config
import lookup
import main
from reverseip import ReverseIpManager
from reverseip_fixtures import NOW, build_manager

client = TestClient(main.app)
CURL = {"user-agent": "curl/8"}
HOUR = 3600
LISTED_IP = "93.184.215.14"
DOMAIN = "example.com"


def _reasons(body: dict) -> dict:
    return {reason["code"]: reason for reason in body["reasons"]}


def _location(ip):
    return {
        "ip": ip,
        "country_code": "US",
        "country_name": "United States",
        "city_name": "Norwell",
        "asn_name": "EDGECAST",
        "asn_number": 15133,
        "is_private": False,
    }


@pytest.fixture
def legs():
    """Every outbound leg of a lookup answered locally (WHOIS, PTR, the DNS
    sweep, the A query, TLS) and GeoLite2 answering with a fixed location. A
    domain resolves to LISTED_IP."""
    resolver = MagicMock()
    resolver.resolve.return_value = [LISTED_IP]
    location = AsyncMock(side_effect=lambda ip: copy.deepcopy(_location(ip)))
    whois = AsyncMock(return_value={"source": "rdap", "name": "EXAMPLE"})
    with ExitStack() as stack:
        stack.enter_context(patch("lookup.lookup_whois", whois))
        stack.enter_context(patch("main.lookup_whois", whois))
        stack.enter_context(patch("lookup.lookup_location", location))
        stack.enter_context(patch("main.lookup_location", location))
        stack.enter_context(
            patch("lookup._recursive_resolver", MagicMock(return_value=resolver))
        )
        stack.enter_context(
            patch.object(lookup.domain_manager, "get_records", return_value={})
        )
        stack.enter_context(
            patch.object(
                lookup.domain_manager, "perform_reverse_lookup", return_value=None
            )
        )
        stack.enter_context(
            patch("managers.SSLManager.get_ssl_info", return_value=None)
        )
        yield


def test_an_ip_lookup_carries_reverse_ip(reverseip_enabled, legs):
    body = client.get(f"/{LISTED_IP}", headers=CURL).json()
    assert body["reverse_ip"] == reverseip_enabled.for_address(LISTED_IP)
    assert body["reverse_ip"]["total"] == 4
    assert body["reverse_ip"]["attribution"] == config.OPENINTEL_ATTRIBUTION


def test_a_domain_lookup_does_not(reverseip_enabled, legs):
    body = client.get(f"/{DOMAIN}", headers=CURL).json()
    assert "reverse_ip" not in body


def test_disabled_adds_no_key(legs):
    assert lookup.reverse_ip_manager.enabled is False
    assert "reverse_ip" not in client.get(f"/{LISTED_IP}", headers=CURL).json()


async def test_gather_skips_the_leg_unless_asked(reverseip_enabled, legs):
    asked = await lookup.gather(LISTED_IP, legs={"geo", "reverseip"})
    assert asked["reverse_ip"]["total"] == 4
    skipped = await lookup.gather(LISTED_IP, legs={"geo"})
    assert skipped["reverse_ip"] is None
    domain = await lookup.gather(DOMAIN)
    assert domain["reverse_ip"] is None


def test_the_lookup_helpers_are_none_while_disabled():
    assert lookup.reverse_ip_manager.enabled is False
    assert lookup.address_reverse_ip(LISTED_IP) is None
    assert lookup.top_list_subdomains(DOMAIN) is None


def test_the_lookup_helpers_read_the_manager(reverseip_enabled):
    assert lookup.address_reverse_ip(LISTED_IP) == reverseip_enabled.for_address(
        LISTED_IP
    )
    assert lookup.top_list_subdomains(DOMAIN) == reverseip_enabled.names_under(DOMAIN)
    assert lookup.top_list_subdomains(DOMAIN) is not None


def test_the_job_is_scheduled_and_skipped_when_disabled():
    job = main.scheduler.get_job("refresh-reverseip")
    assert job is not None
    assert job.max_instances == 1
    assert job.coalesce is True
    # Due at import, run when the lifespan starts the scheduler.
    assert job.misfire_grace_time is None
    assert (
        job.trigger.interval.total_seconds() == config.REVERSEIP_CHECK_INTERVAL_SECONDS
    )
    assert job.func.__name__ == "refresh"
    assert job.func.__self__ is lookup.reverse_ip_manager
    assert "reverseip" not in main._refresh_failures

    # The suite runs with the feature off: the job starts no child process.
    assert lookup.reverse_ip_manager.enabled is False
    assert job.func() is True
    assert lookup.reverse_ip_manager.build_attempted is False


def test_healthz_reports_the_sources(reverseip_enabled):
    body = client.get("/healthz").json()
    assert body["reverseip"] == reverseip_enabled.status()
    assert body["reverseip"]["sources"]["tranco"]["stale"] is False
    assert "reverseip_unavailable" not in _reasons(body)
    assert "reverseip_source_stale" not in _reasons(body)


def test_healthz_a_stale_source_degrades(reverseip_enabled, monkeypatch, tmp_path):
    (tmp_path / "later").mkdir()
    later = build_manager(tmp_path / "later")
    later._clock = lambda: NOW + 5 * 24 * HOUR
    monkeypatch.setattr(main, "reverse_ip_manager", later)
    body = client.get("/healthz").json()
    stale = [r for r in body["reasons"] if r["code"] == "reverseip_source_stale"]
    assert body["status"] == "degraded"
    assert [r["message"] for r in stale] == later.stale_sources()
    assert len(stale) == 1
    assert body["reverseip"]["sources"]["tranco"]["stale"] is True


def test_healthz_no_database_after_a_build_attempt_degrades(tmp_path, monkeypatch):
    manager = ReverseIpManager(str(tmp_path / "empty"), enabled=True)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    manager.build_attempted = True
    body = client.get("/healthz").json()
    assert body["status"] == "degraded"
    assert "reverseip_unavailable" in _reasons(body)
    # Its absence is reported once, not once per source.
    assert "reverseip_source_stale" not in _reasons(body)


def test_healthz_a_fresh_volume_is_not_degraded(tmp_path, monkeypatch):
    manager = ReverseIpManager(str(tmp_path / "empty"), enabled=True)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    body = client.get("/healthz").json()
    assert body["reverseip"]["database"] is False
    assert not [r for r in body["reasons"] if r["code"].startswith("reverseip")]


def test_healthz_a_database_that_will_not_read_degrades(tmp_path, monkeypatch):
    (tmp_path / "built").mkdir()
    built = build_manager(tmp_path / "built")
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / built.path.rsplit("/", 1)[-1]).write_bytes(b"not sqlite" * 100)
    manager = ReverseIpManager(str(broken), enabled=True)
    monkeypatch.setattr(main, "reverse_ip_manager", manager)
    body = client.get("/healthz").json()
    assert body["reverseip"]["database"] is False
    assert "reverseip_unavailable" in _reasons(body)


def test_healthz_says_nothing_when_it_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(
        main,
        "reverse_ip_manager",
        ReverseIpManager(str(tmp_path), enabled=False),
    )
    body = client.get("/healthz").json()
    assert body["reverseip"] == {"enabled": False}
    assert not [r for r in body["reasons"] if r["code"].startswith("reverseip")]
