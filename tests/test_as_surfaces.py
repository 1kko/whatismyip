"""AS information on the operator's surfaces: the refresh job and /healthz, and
the `as_info` key of an IP, domain or self lookup.

The suite runs with ASINFO_ENABLED=false; a test that wants the feature asks
for the `asinfo_enabled` fixture (conftest), or builds its own manager.
"""

import copy
import json
import os
import subprocess  # noqa: S404
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import config
import lookup
import main
from asinfo import ANSWER_KEYS, AsInfoManager
from asinfo_fixtures import (
    ASNAMES,
    CAIDA_REL,
    HOUR,
    NOW,
    RIS_V4,
    build_manager,
    rebuild,
)
from test_boot import IMPORT_PROBE
from test_reputation import SPAMHAUS_META, make_manager

ROOT = Path(__file__).resolve().parent.parent
client = TestClient(main.app)


def _reasons(body: dict) -> dict:
    return {reason["code"]: reason for reason in body["reasons"]}


def test_healthz_reports_asinfo_status_and_stale_datasets(monkeypatch, tmp_path):
    manager = build_manager(tmp_path)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    body = client.get("/healthz").json()
    assert body["asinfo"] == manager.status()
    assert body["asinfo"]["enabled"] is True
    assert body["asinfo"]["database"] is True
    assert "asinfo_dataset_stale" not in _reasons(body)
    assert "asinfo_unavailable" not in _reasons(body)

    # Three days and an hour on: the daily datasets are past ASINFO_MAX_AGE_HOURS.
    later = build_manager(
        tmp_path / "later",
        clock=lambda: NOW + config.ASINFO_MAX_AGE_HOURS * HOUR + HOUR,
    )
    monkeypatch.setattr(main, "asinfo_manager", later)
    body = client.get("/healthz").json()
    stale = [r for r in body["reasons"] if r["code"] == "asinfo_dataset_stale"]
    assert body["status"] == "degraded"
    assert [r["message"] for r in stale] == later.stale_datasets()
    assert len(stale) >= 1
    assert body["asinfo"]["datasets"]["asnames"]["stale"] is True


def test_healthz_says_unavailable_only_after_the_first_build_attempt(
    monkeypatch, tmp_path
):
    empty = tmp_path / "empty"
    manager = AsInfoManager(directory=str(empty), enabled=True)
    monkeypatch.setattr(main, "asinfo_manager", manager)

    # A fresh volume, before the first refresh: not a fault.
    body = client.get("/healthz").json()
    assert body["asinfo"]["database"] is False
    assert "asinfo_unavailable" not in _reasons(body)

    manager.build_attempted = True
    body = client.get("/healthz").json()
    assert body["status"] == "degraded"
    assert "asinfo_unavailable" in _reasons(body)
    # Its absence is reported once, not once per dataset.
    assert "asinfo_dataset_stale" not in _reasons(body)


def test_healthz_says_unavailable_for_a_database_that_will_not_read(
    monkeypatch, tmp_path
):
    built = build_manager(tmp_path / "built")
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / os.path.basename(built.path)).write_bytes(b"this is not sqlite" * 100)
    manager = AsInfoManager(directory=str(broken), enabled=True)
    monkeypatch.setattr(main, "asinfo_manager", manager)

    body = client.get("/healthz").json()
    assert body["asinfo"]["database"] is False
    assert "asinfo_unavailable" in _reasons(body)


def test_healthz_says_nothing_about_asinfo_when_it_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(
        main, "asinfo_manager", AsInfoManager(directory=str(tmp_path), enabled=False)
    )
    body = client.get("/healthz").json()
    assert body["asinfo"] == {"enabled": False}
    assert not [r for r in body["reasons"] if r["code"].startswith("asinfo")]


def test_asinfo_enabled_fixture_turns_the_feature_on(asinfo_enabled):
    assert lookup.asinfo_manager is asinfo_enabled
    assert main.asinfo_manager is asinfo_enabled
    assert asinfo_enabled.enabled is True
    assert client.get("/healthz").json()["asinfo"]["database"] is True


def test_refresh_asinfo_job_is_registered_and_skipped_when_disabled(tmp_path):
    job = main.scheduler.get_job("refresh-asinfo")
    assert job is not None
    assert job.max_instances == 1
    assert job.coalesce is True
    # Due at import, run when the lifespan starts the scheduler.
    assert job.misfire_grace_time is None
    assert job.trigger.interval.total_seconds() == config.ASINFO_CHECK_INTERVAL_SECONDS
    # Not the retry timer, and no failure count.
    assert job.func.__name__ == "refresh"
    assert job.func.__self__ is lookup.asinfo_manager
    assert "asinfo" not in main._refresh_failures

    # The suite runs with the feature off: the job does nothing, downloads
    # nothing and leaves the volume as it was.
    assert lookup.asinfo_manager.enabled is False
    assert job.func() is True
    assert lookup.asinfo_manager.build_attempted is False
    assert not os.path.exists(lookup.asinfo_manager.path)


def test_importing_main_downloads_no_as_data(tmp_path):
    """Production's settings on an empty volume: importing main asks nothing
    of the network, leaves the scheduler stopped and writes no AS file."""
    asinfo_dir = tmp_path / "asinfo"
    env = {
        **os.environ,
        "ASINFO_ENABLED": "true",
        "ASINFO_DIR": str(asinfo_dir),
        "BACKGROUND_REFRESH_ENABLED": "true",
        "TLD_NAMES_DIR": str(tmp_path / "tld"),
        "REPUTATION_DIR": str(tmp_path / "reputation"),
    }
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", IMPORT_PROBE],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["attempts"] == []
    assert report["scheduler_running"] is False
    assert not asinfo_dir.exists() or not list(asinfo_dir.iterdir())


# --- as_info on lookups ------------------------------------------------------

CURL = {"user-agent": "curl/8"}
KT_IP = "211.252.112.1"  # in 211.252.112.0/24, originated by AS4766
CLOUDFLARE_IP = "1.1.1.1"  # in 1.1.1.0/24, AS13335
# In 14.34.86.32/27, which only 8 RIS peers see: dropped at build, so the
# address is unannounced and the card falls back to GeoLite2's number.
UNANNOUNCED_IP = "14.34.86.40"
# A route a private-use AS (RFC 6996) leaks into the fixture's RIS dump.
LEAKED_IP = "45.67.89.1"
LEAKED_ROUTE = "45.67.89.0/24"
DOMAIN = "kt.example.com"
# What GeoLite2-ASN would say about each address; 64500 otherwise.
GEOLITE_ASNS = {KT_IP: 4766, CLOUDFLARE_IP: 13335, UNANNOUNCED_IP: 4766}
# Every key an `as_info` carries, in order.
AS_INFO_KEYS = [*ANSWER_KEYS, "special"]
# The parts of a card that describe the AS itself: what a special-purpose
# number does not get, since it names no one.
AS_SECTIONS = (
    "name",
    "country",
    "registry",
    "org",
    "prefixes",
    "rpki",
    "upstreams",
    "downstreams",
    "peers",
    "asn_drop",
)


def _location(ip):
    return {
        "ip": ip,
        "country_code": "KR",
        "country_name": "South Korea",
        "city_name": "Seoul",
        "asn_name": "GeoLite2's name",
        "asn_number": GEOLITE_ASNS.get(ip, 64500),
        "is_private": False,
    }


@pytest.fixture
def legs():
    """Every outbound leg of a lookup answered locally (WHOIS, PTR, the DNS
    sweep, the A query, TLS) and GeoLite2 answering from GEOLITE_ASNS. A
    domain resolves to KT_IP."""
    resolver = MagicMock()
    resolver.resolve.return_value = [KT_IP]
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


def as_peer(ip):
    return TestClient(main.app, client=(ip, 41234))


def asn_drop_lists(directory, *asns):
    """An enabled ReputationManager whose Spamhaus ASN-DROP list holds
    `asns`, an hour old, and whose other lists were never downloaded."""
    rows = "".join(
        f'{{"asn":{asn},"rir":"apnic","domain":"example.net","cc":"KR",'
        '"asname":"EXAMPLE-AS"}\n'
        for asn in asns
    )
    return make_manager(
        directory, files={"spamhaus_asndrop.json": rows + SPAMHAUS_META + "\n"}
    )


def test_ip_lookup_json_carries_as_info(asinfo_enabled, legs):
    body = client.get(f"/{KT_IP}", headers=CURL).json()
    as_info = body["as_info"]
    assert list(as_info) == AS_INFO_KEYS
    # The manager's answer, with the two keys lookup.py adds: ASN-DROP is
    # unknown while the reputation lists are off, and AS4766 is no
    # special-purpose number.
    assert as_info == {
        **asinfo_enabled.for_address(KT_IP, 4766),
        "asn_drop": None,
        "special": None,
    }
    assert as_info["asn"] == 4766
    assert as_info["source"] == "route"
    assert as_info["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert as_info["route"] == {
        "prefix": "211.252.112.0/24",
        "origins": [
            {"asn": 4766, "ris_peers": 326, "rpki": {"state": "valid", "reason": None}}
        ],
    }
    assert as_info["unavailable"] == []
    # GeoLite2's keys are untouched.
    assert body["location"]["asn_number"] == 4766
    assert body["location"]["asn_name"] == "GeoLite2's name"


def test_an_unannounced_address_describes_geolite2s_as(asinfo_enabled, legs):
    as_info = client.get(f"/{UNANNOUNCED_IP}", headers=CURL).json()["as_info"]
    assert as_info["route"] is None
    assert as_info["announced"] is False
    assert as_info["source"] == "geolite2"
    assert as_info["asn"] == 4766
    assert as_info["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert as_info["special"] is None


def test_domain_lookup_describes_the_resolved_address(asinfo_enabled, legs):
    body = client.get(f"/{DOMAIN}", headers=CURL).json()
    assert body["resolved_ip"] == KT_IP
    as_info = body["as_info"]
    assert list(as_info) == AS_INFO_KEYS
    assert as_info["route"]["prefix"] == "211.252.112.0/24"
    assert as_info["asn"] == 4766
    assert as_info == {
        **asinfo_enabled.for_address(KT_IP, 4766),
        "asn_drop": None,
        "special": None,
    }


def test_self_page_json_carries_as_info_and_asks_no_one(asinfo_enabled, legs):
    # A lookup reads the database; only the scheduler's refresh downloads.
    asinfo_enabled._fetch = MagicMock(side_effect=AssertionError("downloaded"))
    with patch.object(
        asinfo_enabled, "refresh", side_effect=AssertionError("refreshed")
    ):
        body = as_peer(CLOUDFLARE_IP).get("/", headers=CURL).json()
    assert body["address"] == CLOUDFLARE_IP
    as_info = body["as_info"]
    assert list(as_info) == AS_INFO_KEYS
    assert as_info["asn"] == 13335
    assert as_info["route"]["prefix"] == "1.1.1.0/24"
    assert as_info["name"] == "CLOUDFLARENET - Cloudflare, Inc."
    assert as_info["special"] is None
    asinfo_enabled._fetch.assert_not_called()

    # The visitor's GeoLite2 number is the fallback, as on a lookup.
    body = as_peer(UNANNOUNCED_IP).get("/", headers=CURL).json()
    assert body["as_info"]["source"] == "geolite2"
    assert body["as_info"]["asn"] == 4766


def test_as_info_absent_when_disabled(legs):
    assert lookup.asinfo_manager.enabled is False
    assert "as_info" not in client.get(f"/{KT_IP}", headers=CURL).json()
    assert "as_info" not in client.get(f"/{DOMAIN}", headers=CURL).json()
    assert "as_info" not in as_peer(KT_IP).get("/", headers=CURL).json()
    assert lookup.address_as_info(KT_IP) is None
    # Special-purpose numbers too: the AS route answers its own 400 for them.
    assert lookup.as_info_for_asn(4766) is None
    assert lookup.as_info_for_asn(64512) is None


async def test_gather_carries_as_info_only_when_enabled(asinfo_enabled, legs):
    data = await lookup.gather(KT_IP)
    assert data["as_info"]["route"]["prefix"] == "211.252.112.0/24"
    asinfo_enabled.enabled = False
    assert (await lookup.gather(KT_IP))["as_info"] is None


def test_asn_drop_is_read_from_the_reputation_lists(
    asinfo_enabled, legs, monkeypatch, tmp_path
):
    lists = asn_drop_lists(tmp_path / "reputation", 4766)
    monkeypatch.setattr(lookup, "reputation_manager", lists)
    monkeypatch.setattr(main, "reputation_manager", lists)

    body = client.get(f"/{KT_IP}", headers=CURL).json()
    assert body["as_info"]["asn_drop"] is True
    # The card reads the list; `reputation` is what it always was.
    assert body["reputation"] == lists.check(KT_IP, 4766)
    assert (
        client.get(f"/{CLOUDFLARE_IP}", headers=CURL).json()["as_info"]["asn_drop"]
        is False
    )
    # Matched on the number the card describes, not on GeoLite2's.
    assert lookup.address_as_info(KT_IP, {"asn_number": 13335})["asn_drop"] is True
    assert lookup.as_info_for_asn(4766)["asn_drop"] is True
    assert lookup.as_info_for_asn(13335)["asn_drop"] is False

    assert lists.asn_listed(4766) is True
    assert lists.asn_listed(13335) is False
    assert lists.asn_listed(None) is None
    # Past REPUTATION_MAX_AGE_HOURS the list is not current, so the card
    # cannot say, just as `reputation` puts it in `unavailable`.
    lists._clock.advance(config.REPUTATION_MAX_AGE_HOURS * HOUR)
    assert lists.asn_listed(4766) is None
    assert lookup.address_as_info(KT_IP)["asn_drop"] is None
    # A list never downloaded says nothing either.
    unloaded = make_manager(tmp_path / "empty", files={})
    assert unloaded.asn_listed(4766) is None
    # Nor does a manager that is off.
    lists.enabled = False
    assert lists.asn_listed(4766) is None


def test_fields_without_an_as_field_skip_the_leg(asinfo_enabled, legs, monkeypatch):
    reads = MagicMock(wraps=asinfo_enabled.for_address)
    monkeypatch.setattr(asinfo_enabled, "for_address", reads)

    assert client.get(f"/{KT_IP}?fields=country_code", headers=CURL).json() == {
        "country_code": "KR"
    }
    assert client.get(f"/{KT_IP}?format=text", headers=CURL).status_code == 200
    assert client.get(f"/{DOMAIN}?fields=country_code", headers=CURL).status_code == 200
    assert as_peer(KT_IP).get("/?fields=country_code", headers=CURL).json() == {
        "country_code": "KR"
    }
    reads.assert_not_called()

    # The whole lookup does read it: the count above is not blind.
    assert "as_info" in client.get(f"/{KT_IP}", headers=CURL).json()
    reads.assert_called_once_with(KT_IP, 4766)


async def test_legs_without_asinfo_skip_it(asinfo_enabled, legs, monkeypatch):
    reads = MagicMock(side_effect=AssertionError("read the AS database"))
    monkeypatch.setattr(asinfo_enabled, "for_address", reads)
    data = await lookup.gather(KT_IP, legs={"geo", "reputation"})
    assert data["as_info"] is None
    assert data["location"]["asn_number"] == 4766


def test_special_is_none_for_an_ordinary_asn(asinfo_enabled, legs):
    body = client.get(f"/{KT_IP}", headers=CURL).json()
    assert "special" in body["as_info"]
    assert body["as_info"]["special"] is None

    card = lookup.as_info_for_asn(4766, full=True)
    assert list(card) == AS_INFO_KEYS
    assert card == {
        **asinfo_enabled.for_asn(4766, full=True),
        "asn_drop": None,
        "special": None,
    }
    assert card["prefix_list"]["count"] == 3
    assert lookup.as_info_for_asn(4766)["prefix_list"] is None

    # No AS to describe at all (unannounced, no GeoLite2 number): nothing is
    # special either.
    nobody = lookup.address_as_info(UNANNOUNCED_IP, {"asn_number": None})
    assert nobody["asn"] is None
    assert nobody["special"] is None


def test_an_ip_routed_from_a_special_asn_keeps_its_route_and_names_the_purpose(
    asinfo_enabled, legs, monkeypatch, tmp_path
):
    # AS64512 leaks a route into RIS, and every dataset has something to say
    # about it: a name, a provider, a place on ASN-DROP. None of it is shown.
    rebuild(
        tmp_path,
        texts={
            "ris_v4": RIS_V4 + f"64512\t{LEAKED_ROUTE}\t50\n",
            "asnames": ASNAMES + "64512 LEAKED-PRIVATE - Somebody, US\n",
            "caida_rel": CAIDA_REL + "174|64512|-1|bgp\n",
        },
    )
    lists = asn_drop_lists(tmp_path / "reputation", 64512)
    monkeypatch.setattr(lookup, "reputation_manager", lists)
    monkeypatch.setattr(main, "reputation_manager", lists)
    # Read as it was built: the route and the sections a special number drops.
    raw = asinfo_enabled.for_address(LEAKED_IP)
    assert raw["name"] == "LEAKED-PRIVATE - Somebody"
    assert raw["upstreams"] == [
        {"asn": 174, "name": "COGENT-174 - Cogent Communications"}
    ]
    # The AS's RPKI coverage: counts over every prefix it originates, which
    # for a private number are strangers' routes.
    assert raw["rpki"] == {"valid": 0, "invalid": 0, "not_found": 1}
    assert lists.asn_listed(64512) is True

    response = client.get(f"/{LEAKED_IP}", headers=CURL)
    assert response.status_code == 200
    as_info = response.json()["as_info"]
    assert list(as_info) == AS_INFO_KEYS
    assert as_info["asn"] == 64512
    assert as_info["special"] == lookup.special_asn(64512)
    assert as_info["special"]["code"] == "private_asn"
    assert as_info["special"]["first"] == 64512
    assert as_info["special"]["last"] == 65534
    for section in AS_SECTIONS:
        assert as_info[section] is None, section
    # The route is a fact about the address, and RPKI's verdict on it stands.
    assert as_info["route"] == {
        "prefix": LEAKED_ROUTE,
        "origins": [
            {
                "asn": 64512,
                "ris_peers": 50,
                "rpki": {"state": "not-found", "reason": None},
            }
        ],
    }
    # The coverage counts are the AS's, not the route's: gone with the rest.
    assert as_info["rpki"] is None
    assert as_info["announced"] is True
    assert as_info["source"] == "route"

    # GeoLite2's number is special-purpose and no route covers the address.
    fallback = lookup.address_as_info(UNANNOUNCED_IP, {"asn_number": 4200000000})
    assert fallback["source"] == "geolite2"
    assert fallback["route"] is None
    assert fallback["special"]["code"] == "private_asn"
    for section in AS_SECTIONS:
        assert fallback[section] is None, section


class _Exploding:
    """A manager that is on, and fails any read it is asked for."""

    enabled = True

    def __getattr__(self, name):
        raise AssertionError(f"read {name}")


@pytest.mark.parametrize(
    "asn",
    [
        0,
        23456,
        64496,
        64511,
        65536,
        65551,
        64512,
        65534,
        4200000000,
        4294967294,
        65535,
        4294967295,
        65552,
        131071,
    ],
)
def test_as_info_for_a_special_asn_never_reads_the_manager(monkeypatch, asn):
    monkeypatch.setattr(lookup, "asinfo_manager", _Exploding())
    monkeypatch.setattr(lookup, "reputation_manager", _Exploding())
    for full in (False, True):
        card = lookup.as_info_for_asn(asn, full=full)
        assert list(card) == AS_INFO_KEYS
        assert card == {
            **dict.fromkeys(ANSWER_KEYS),
            "asn": asn,
            "unavailable": [],
            "special": lookup.special_asn(asn),
        }
        assert card["special"] is not None
