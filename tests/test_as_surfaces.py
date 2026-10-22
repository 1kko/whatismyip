"""AS information on the operator's surfaces: the refresh job and /healthz, and
the `as_info` key of an IP, domain or self lookup.

The suite runs with ASINFO_ENABLED=false; a test that wants the feature asks
for the `asinfo_enabled` fixture (conftest), or builds its own manager.
"""

import copy
import json
import os
import re
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
import mcp_server
import viewmodel
from asinfo import ANSWER_KEYS, AsInfoManager, default_datasets
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
from test_mcp_iserror import _call, _failed
from test_reputation import CHROME, SPAMHAUS_META, make_manager, page_text

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
    assert client.get(f"/{DOMAIN}?fields=country_code", headers=CURL).status_code == 200
    assert as_peer(KT_IP).get("/?fields=country_code", headers=CURL).json() == {
        "country_code": "KR"
    }
    reads.assert_not_called()

    # The text block lists the route fields: it reads the leg, a local read.
    assert client.get(f"/{KT_IP}?format=text", headers=CURL).status_code == 200
    assert reads.call_count == 1
    reads.reset_mock()

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
    # Only what the card still shows is credited: the route, from the IPv4
    # dump, and RPKI's verdict on it. The read of the dropped sections took
    # in every dataset, CAIDA's included.
    assert list(raw["datasets"]) == [
        "asnames",
        "nro",
        "ris_v4",
        "ris_v6",
        "rpki",
        "caida_rel",
        "caida_org",
    ]
    assert any("CAIDA" in credit for credit in raw["attribution"])
    assert as_info["datasets"] == {
        "ris_v4": raw["datasets"]["ris_v4"],
        "rpki": raw["datasets"]["rpki"],
    }
    assert as_info["attribution"] == [
        "Source: RIPE NCC",
        "RPKI data validated by rpki-client.org",
    ]
    # The same address written IPv4-mapped is read, and credited, as IPv4.
    mapped = lookup.address_as_info(f"::ffff:{LEAKED_IP}")
    assert mapped["route"] == as_info["route"]
    assert list(mapped["datasets"]) == ["ris_v4", "rpki"]

    # GeoLite2's number is special-purpose and no route covers the address.
    fallback = lookup.address_as_info(UNANNOUNCED_IP, {"asn_number": 4200000000})
    assert fallback["source"] == "geolite2"
    assert fallback["route"] is None
    assert fallback["announced"] is False
    assert fallback["special"]["code"] == "private_asn"
    for section in AS_SECTIONS:
        assert fallback[section] is None, section
    # No route, so no RPKI verdict to credit: only the dump that says so.
    assert list(fallback["datasets"]) == ["ris_v4"]
    assert fallback["attribution"] == ["Source: RIPE NCC"]
    # An IPv6 address is answered from the IPv6 dump, not the IPv4 one that
    # the dropped prefix counts also read.
    v6 = lookup.address_as_info("2a00:1450::1", {"asn_number": 64512})
    assert v6["announced"] is False
    assert list(v6["datasets"]) == ["ris_v6"]
    assert v6["attribution"] == ["Source: RIPE NCC"]


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


# --- the AS panel and the links to AS pages ------------------------------------

BROWSER = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130 Safari/537.36"}

KT_CARD = {
    "asn": 4766,
    "name": "KIXS-AS-KR-KR - Korea Telecom",
    "country": "KR",
    "registry": {
        "rir": "apnic",
        "country": "KR",
        "assigned": "1996-04-22",
        "status": "assigned",
    },
    "org": {
        "id": "@aut-4766-APNIC",
        "name": "Korea Telecom",
        "country": "KR",
        "siblings": [9760],
        "sibling_count": 11,
    },
    "prefixes": {"v4": 2, "v6": 1, "v4_addresses": 131072, "v6_48s": 65536},
    "rpki": {"valid": 2, "invalid": 0, "not_found": 2},
    "upstreams": [{"asn": 174, "name": "COGENT-174"}, {"asn": 701, "name": "UUNET"}],
    "downstreams": {"count": 565, "list": [{"asn": 17858, "name": "POWERVIS"}]},
    "peers": {"count": 1, "list": [{"asn": 9318, "name": "SKB-AS-KR"}]},
    "asn_drop": False,
    "route": {
        "prefix": "211.252.112.0/24",
        "origins": [
            {"asn": 4766, "ris_peers": 326, "rpki": {"state": "valid", "reason": None}}
        ],
    },
    "announced": True,
    "source": "route",
    "datasets": {},
    "unavailable": [],
    "attribution": ["Source: RIPE NCC"],
    "special": None,
}


def _links(asn):
    return f"/AS{asn}" if isinstance(asn, int) else None


def _rows(view):
    return {row["label"]: row for row in view["rows"]}


def test_as_view_rows_and_hint():
    view = viewmodel.as_view(KT_CARD, lambda value: f"/{value}")
    assert [row["label"] for row in view["rows"]] == [
        "Route",
        "RPKI",
        "AS",
        "Holder",
        "Registry",
        "Organization",
        "Prefixes",
        "RPKI coverage",
        "Upstreams",
        "Downstreams",
        "Peers",
        "ASN-DROP",
    ]
    rows = _rows(view)
    assert rows["Route"]["value"].startswith("211.252.112.0/24 · originated by AS4766")
    assert "326" in rows["Route"]["value"]
    assert rows["RPKI"]["value"] == "Valid"
    assert rows["AS"]["value"] == "AS4766"
    assert rows["AS"]["href"] == "/AS4766"
    assert rows["Holder"]["value"] == "KIXS-AS-KR-KR - Korea Telecom · KR"
    assert rows["Registry"]["value"] == "APNIC · KR · assigned 1996-04-22"
    assert rows["Organization"]["value"].startswith("Korea Telecom · 11 sibling ASes")
    assert rows["Prefixes"]["value"] == "IPv4 2 · IPv6 1"
    assert rows["RPKI coverage"]["value"].startswith("50% valid")
    assert "565 customers" in rows["Downstreams"]["value"]
    assert rows["Peers"]["value"].startswith("1 peer")
    assert rows["ASN-DROP"]["value"] == "Not listed"
    assert view["hint"] == "AS4766 · 3 prefixes · RPKI 50% valid"
    # The credits as the template draws them; without credit_links none links.
    assert view["attribution"] == [{"text": "Source: RIPE NCC"}]
    # Every AS number in a list links; the anchor wraps the number alone.
    parts = [p for p in rows["Upstreams"]["parts"] if p.get("href")]
    assert [(p["text"], p["href"]) for p in parts] == [
        ("AS174", "/AS174"),
        ("AS701", "/AS701"),
    ]
    origin = [p for p in rows["Route"]["parts"] if p.get("href")]
    assert [p["text"] for p in origin] == ["AS4766"]
    assert [p["text"] for p in rows["Organization"]["parts"] if p.get("href")] == [
        "AS9760"
    ]
    assert viewmodel.as_view(None) is None
    # Without link_for nothing links.
    plain = viewmodel.as_view(KT_CARD)
    assert not any(p.get("href") for r in plain["rows"] for p in r["parts"])
    assert "href" not in _rows(plain)["AS"]


CAIDA_CITATIONS = {
    "The CAIDA UCSD AS Relationships Dataset, 2026-10-01": (
        "https://www.caida.org/catalog/datasets/as-relationships/"
    ),
    "The CAIDA UCSD AS Organizations Dataset, 2026-10-01": (
        "https://www.caida.org/catalog/datasets/as-organizations/"
    ),
}


def test_as_view_links_the_credits_credit_links_name():
    card = {**KT_CARD, "attribution": ["Source: RIPE NCC", *CAIDA_CITATIONS]}
    view = viewmodel.as_view(card, credit_links=CAIDA_CITATIONS)
    assert view["attribution"] == [
        {"text": "Source: RIPE NCC"},
        *({"text": text, "href": href} for text, href in CAIDA_CITATIONS.items()),
    ]
    # The JSON's lines are what is drawn: a link for a line it lacks adds none.
    alone = viewmodel.as_view(KT_CARD, credit_links=CAIDA_CITATIONS)
    assert alone["attribution"] == [{"text": "Source: RIPE NCC"}]


def test_as_view_unknown_sections_name_their_reason():
    card = {
        **KT_CARD,
        "name": None,
        "registry": None,
        "org": None,
        "upstreams": None,
        "downstreams": None,
        "peers": None,
        "prefixes": None,
        "rpki": None,
        "asn_drop": None,
        "route": None,
        "announced": None,
        "unavailable": [
            {"dataset": "asnames", "label": "RIPE NCC AS names", "reason": "stale"},
            {
                "dataset": "caida_rel",
                "label": "CAIDA AS relationships",
                "reason": "old",
            },
            {"dataset": "ris_v4", "label": "RIS IPv4", "reason": "missing"},
        ],
    }
    rows = _rows(viewmodel.as_view(card))
    assert rows["Holder"]["value"] == "Unknown: stale"
    assert rows["Holder"]["tone"] == "muted"
    assert rows["Upstreams"]["value"] == "Unknown: old"
    assert rows["Peers"]["value"] == "Unknown: old"
    assert rows["Route"]["value"] == "Unknown: missing"
    # Available datasets that lack the AS: not "Unknown".
    assert rows["Registry"]["value"] == "Not in NRO delegated statistics"
    assert rows["Organization"]["value"] == "Not in CAIDA AS organizations"
    assert rows["Registry"]["tone"] == "muted"
    assert rows["ASN-DROP"]["value"] == "Unknown"
    # A fresh volume: nothing known at all.
    empty = {k: None for k in KT_CARD}
    empty["unavailable"] = []
    assert viewmodel.as_view(empty)["hint"] == "unknown"
    # Not announced.
    quiet = {**KT_CARD, "route": None, "announced": False, "source": "geolite2"}
    assert _rows(viewmodel.as_view(quiet))["Route"]["value"] == "Not announced in RIS"


def test_as_row_says_why_the_as_came_from_geolite2():
    # The AS row agrees with the Route row: not announced is a finding, route
    # data that could not be read is not.
    quiet = {**KT_CARD, "route": None, "announced": False, "source": "geolite2"}
    assert _rows(viewmodel.as_view(quiet))["AS"]["value"] == (
        "AS4766 · from GeoLite2, not announced in RIS"
    )
    stale = {
        **quiet,
        "announced": None,
        "unavailable": [
            {"dataset": "ris_v4", "label": "RIPE RIS routes (IPv4)", "reason": "old"}
        ],
    }
    rows = _rows(viewmodel.as_view(stale))
    assert rows["Route"]["value"] == "Unknown: old"
    assert rows["AS"]["value"] == "AS4766 · from GeoLite2, route data unavailable"


def test_as_view_for_an_address_with_no_as_stops_after_the_as_row(asinfo_enabled):
    # 192.0.2.1: no route covers it and GeoLite2 gives no number. Every row
    # below AS would describe an AS there is none of.
    card = {**asinfo_enabled.for_address("192.0.2.1"), "asn_drop": None}
    assert (card["asn"], card["announced"], card["source"]) == (None, False, None)
    view = viewmodel.as_view(card)
    assert [(row["label"], row["value"]) for row in view["rows"]] == [
        ("Route", "Not announced in RIS"),
        ("RPKI", "No route to validate"),
        ("AS", "No AS number found"),
    ]
    assert view["hint"] == "not announced"
    assert view["lists"] == {}
    # With the route data unreadable, nothing is known, and the hint says so.
    unread = {
        **card,
        "announced": None,
        "unavailable": [
            {"dataset": "ris_v4", "label": "RIPE RIS routes (IPv4)", "reason": "old"}
        ],
    }
    view = viewmodel.as_view(unread)
    assert [(row["label"], row["value"]) for row in view["rows"]] == [
        ("Route", "Unknown: old"),
        ("RPKI", "Unknown: old"),
        ("AS", "No AS number found"),
    ]
    assert view["hint"] == "unknown"


def test_as_dataset_labels_are_asinfos():
    # A dataset id asinfo adds without a label here would make _as_absent
    # raise, and every page with the panel answer 500.
    assert viewmodel._AS_DATASET_LABELS == {
        d.id: d.label for d in default_datasets(caida=True)
    }


def test_rpki_invalid_route_is_a_warning_row_and_no_hero_tag():
    route = {
        "prefix": "211.252.112.0/24",
        "origins": [
            {
                "asn": 4766,
                "ris_peers": 300,
                "rpki": {"state": "invalid", "reason": "origin AS differs"},
            }
        ],
    }
    card = {**KT_CARD, "route": route}
    row = _rows(viewmodel.as_view(card))["RPKI"]
    assert row["tone"] == "warning"
    assert row["value"] == "Invalid: origin AS differs"
    view = viewmodel.build_view(
        {"address": "211.252.112.1", "as_info": card, "location": {}}, False
    )
    assert not any("RPKI" in tag["text"].upper() for tag in view["tags"])


def test_as_view_for_a_special_origin_shows_its_purpose():
    card = {
        **dict.fromkeys(KT_CARD),
        "asn": 64512,
        "route": {
            "prefix": "45.67.89.0/24",
            "origins": [
                {"asn": 64512, "ris_peers": 40, "rpki": {"state": "not_found"}}
            ],
        },
        "announced": True,
        "source": "route",
        "unavailable": [
            {"dataset": "caida_rel", "label": "CAIDA AS relationships", "reason": "x"}
        ],
        "attribution": [],
        "special": {
            "code": "private_asn",
            "label": "Private use",
            "first": 64512,
            "last": 65534,
            "defined_in": "RFC 6996",
            "purpose": "For a network's own internal BGP.",
        },
    }
    view = viewmodel.as_view(card, lambda value: f"/{value}")
    assert [r["label"] for r in view["rows"]] == ["Route", "RPKI", "AS", "Purpose"]
    rows = _rows(view)
    assert rows["AS"]["value"] == "AS64512 · Private use"
    assert rows["Purpose"]["value"] == "For a network's own internal BGP. (RFC 6996)"
    assert rows["AS"]["href"] == "/AS64512"
    assert view["hint"] == "AS64512 · private use"
    assert not any("Unknown" in r["value"] for r in view["rows"])
    assert view["attribution"] == []
    assert viewmodel.as_view({**card, "attribution": None})["attribution"] == []


def test_page_has_the_as_accordion_after_geoip(asinfo_enabled, legs):
    html = client.get(f"/{KT_IP}", headers=BROWSER).text
    ids = re.findall(r'<details class="accordion" id="acc-([a-z]+)"', html)
    assert ids.index("as") == ids.index("geoip") + 1
    assert 'id="hint-as"' in html
    assert "AS4766 · 3 prefixes" in html
    assert "Korea Telecom" in html
    assert "Source: RIPE NCC" in html
    assert "RPKI data validated by rpki-client.org" in html
    assert "The CAIDA UCSD AS Relationships Dataset, 2026-10-01" in html


def test_page_has_no_as_accordion_when_disabled(legs):
    html = client.get(f"/{KT_IP}", headers=BROWSER).text
    assert 'id="acc-as"' not in html


def test_lookup_href_links_as_numbers_special_ones_included():
    assert main.lookup_href("AS4766") == "/AS4766"
    assert main.lookup_href("as4766") == "/AS4766"
    assert main.lookup_href("AS64512") == "/AS64512"
    assert main.lookup_href("AS0") == "/AS0"
    assert main.lookup_href("AS04766") == "/AS4766"
    assert main.lookup_href("AS4294967296") is None
    assert main.lookup_href("4766") is None
    assert main.lookup_href("ASxyz") is None


def test_network_org_row_links_its_as_number(asinfo_enabled, legs):
    html = client.get(f"/{KT_IP}", headers=BROWSER).text
    assert re.search(
        r'<span class="kv-label">Org</span>\s*<span class="kv-value[^"]*">'
        r'<a class="lookup-link" href="/AS4766" rel="nofollow">AS4766</a>'
        r" GeoLite2&#39;s name</span>",
        html,
    )


def test_as_links_are_nofollow_lookup_links(asinfo_enabled, legs):
    html = client.get(f"/{KT_IP}", headers=BROWSER).text
    body = html.split('id="acc-as"')[1].split("</details>")[0]
    # The card's rows; the credits after them link out (see below).
    anchors = re.findall(r"<a [^>]*>", body.split("</table>")[0])
    assert anchors
    for anchor in anchors:
        assert 'class="lookup-link"' in anchor
        assert 'rel="nofollow"' in anchor
    for asn in (174, 701, 17858, 38661, 9318, 9760, 4766):
        assert f'href="/AS{asn}"' in body


def test_network_org_row_stays_text_when_as_lookups_are_off(legs):
    html = client.get(f"/{KT_IP}", headers=BROWSER).text
    assert 'href="/AS4766"' not in html
    assert "AS4766 GeoLite2&#39;s name" in html


def _special_card(**overrides):
    card = {
        **dict.fromkeys(KT_CARD),
        "asn": 64512,
        "unavailable": [
            {"dataset": "ris_v4", "label": "RIPE RIS routes (IPv4)", "reason": "x"}
        ],
        "attribution": [],
        "special": {
            "code": "private_asn",
            "label": "Private use",
            "first": 64512,
            "last": 65534,
            "defined_in": "RFC 6996",
            "purpose": "For a network's own internal BGP.",
        },
    }
    return {**card, **overrides}


def test_special_card_with_route_data_unavailable_says_unknown():
    # A lookup page's card for an address GeoLite2 puts in a special-purpose
    # AS, whose route data could not be read: that gap is shown, not hidden.
    view = viewmodel.as_view(_special_card())
    assert [r["label"] for r in view["rows"]] == ["Route", "RPKI", "AS", "Purpose"]
    rows = _rows(view)
    assert rows["Route"]["value"] == rows["RPKI"]["value"] == "Unknown: x"


def test_special_card_from_geolite2_keeps_not_announced():
    view = viewmodel.as_view(
        _special_card(announced=False, source="geolite2"), lambda v: f"/{v}"
    )
    rows = _rows(view)
    assert [r["label"] for r in view["rows"]] == ["Route", "RPKI", "AS", "Purpose"]
    assert rows["Route"]["value"] == "Not announced in RIS"


def test_special_card_with_a_route_keeps_its_route_rows():
    route = {
        "prefix": "45.67.89.0/24",
        "origins": [{"asn": 64512, "ris_peers": 40, "rpki": {"state": "not_found"}}],
    }
    view = viewmodel.as_view(_special_card(route=route, announced=True))
    assert [r["label"] for r in view["rows"]][:2] == ["Route", "RPKI"]


def test_a_route_rpki_does_not_cover_reads_not_found(asinfo_enabled):
    # asinfo spells a route's own state "not-found"; its AS's counts are keyed
    # not_found. Both read "Not found", never "Unknown".
    card = asinfo_enabled.for_address("2001:2d8::1")
    assert card["route"]["origins"][0]["rpki"]["state"] == "not-found"
    assert _rows(viewmodel.as_view(card))["RPKI"]["value"] == "Not found"


def test_page_json_survives_a_comment_opener_in_third_party_text(
    legs, monkeypatch, tmp_path
):
    # An AS name and a WHOIS field are third-party text, and #page-data embeds
    # both. With only "</" broken, "<!--<script" put the tokenizer in its
    # double-escaped state: the block's own </script> no longer ended it, and
    # app.js after it was swallowed. With every < > & a \u escape, nothing in
    # either block is markup, and both parse back whole.
    hostile = "<!--<script>x</script>-->"
    names = ASNAMES.replace("KIXS-AS-KR-KR - Korea Telecom", f"KT {hostile} & Co")
    manager = build_manager(tmp_path, texts={"asnames": names})
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    whois = AsyncMock(
        return_value={"source": "rdap", "name": "EXAMPLE", "registrant": hostile}
    )
    with patch("lookup.lookup_whois", whois), patch("main.lookup_whois", whois):
        html = client.get(f"/{KT_IP}", headers=BROWSER).text
    blocks = dict(
        re.findall(
            r'<script type="application/json" id="([a-z-]+)" nonce="[^"]*">(.*?)'
            r"</script>",
            html,
            re.S,
        )
    )
    assert set(blocks) == {"page-data", "map-data"}
    for name, raw in blocks.items():
        assert not set(raw) & set("<>&"), name
    page = json.loads(blocks["page-data"])
    assert page["as_info"]["name"] == f"KT {hostile} & Co"
    assert page["whois"]["registrant"] == hostile
    map_data = json.loads(blocks["map-data"])
    assert {key: map_data[key] for key in page["map"]} == page["map"]
    # The scripts after the blocks are still elements of their own.
    tail = html.split('id="map-data"')[1]
    assert '<script src="/static/js/app.js"' in tail
    assert '<script src="/static/js/map.js"' in tail


def test_page_scripts_read_the_blocks_with_json_parse():
    # JSON.parse decodes \u003c back to "<"; a script that read a block's text
    # any other way would see the escapes. Writing it back (app.js sets
    # textContent after the WHOIS fill-in) goes through no HTML parser.
    node = (
        r'(?:document\.getElementById\("(?:page|map)-data"\)'
        r"|pageData|pageDataScript|mapDataNode)"
    )
    read = re.compile(rf"{node}\.textContent(?!\s*=(?!=))")
    found = 0
    for path in ("static/js/app.js", "static/js/map.js", "static/js/fingerprint.js"):
        source = (ROOT / path).read_text(encoding="utf-8")
        reads = list(read.finditer(source))
        assert reads, path
        for match in reads:
            assert source[: match.start()].endswith("JSON.parse("), (path, match[0])
        found += len(reads)
    assert found == 5


# --- ?fields= and the text block ---------------------------------------------

ROUTE_FIELDS = "route_prefix,route_origin,rpki_state"
V6_UNCOVERED_IP = "2606:4700::1111"  # in 2606:4700::/32 (AS13335), no VRP


def test_fields_route_and_rpki(asinfo_enabled, legs):
    body = client.get(f"/{KT_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL).json()
    # The fixture's VRP for AS4766 (211.252.0.0/15, max length 24) covers it.
    assert body == {
        "route_prefix": "211.252.112.0/24",
        "route_origin": 4766,
        "rpki_state": "valid",
    }
    body = client.get(
        f"/{V6_UNCOVERED_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL
    ).json()
    assert body == {
        "route_prefix": "2606:4700::/32",
        "route_origin": 13335,
        "rpki_state": "not-found",
    }


def test_fields_route_for_a_domain_reads_the_resolved_address(asinfo_enabled, legs):
    body = client.get(
        f"/{DOMAIN}", params={"fields": ROUTE_FIELDS}, headers=CURL
    ).json()
    assert body["route_prefix"] == "211.252.112.0/24"
    assert body["route_origin"] == 4766


def test_rpki_state_is_the_cards_origin(asinfo_enabled, legs, monkeypatch):
    # Two origins: the card describes the first (most RIS peers); the second's
    # state must not leak into the field.
    real = asinfo_enabled.for_address

    def two_origins(ip, fallback=None):
        answer = real(ip, fallback)
        answer["route"]["origins"].append(
            {"asn": 64999, "ris_peers": 11, "rpki": {"state": "invalid", "reason": "x"}}
        )
        return answer

    monkeypatch.setattr(asinfo_enabled, "for_address", two_origins)
    body = client.get(f"/{KT_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL).json()
    assert body["route_origin"] == 4766
    assert body["rpki_state"] == "valid"


def test_text_block_lists_the_route_fields(asinfo_enabled, legs):
    lines = client.get(f"/{KT_IP}?format=text", headers=CURL).text.splitlines()
    keys = [line.split(":", 1)[0] for line in lines]
    start = keys.index("cidr")
    assert keys[start + 1 : start + 4] == ["route_prefix", "route_origin", "rpki_state"]
    values = dict(line.split(": ", 1) for line in lines)
    assert values["route_prefix"] == "211.252.112.0/24"
    assert values["route_origin"] == "4766"
    assert values["rpki_state"] == "valid"
    lines = client.get(f"/{DOMAIN}?format=text", headers=CURL).text.splitlines()
    assert "route_prefix: 211.252.112.0/24" in lines


def test_route_fields_are_question_marks_when_ris_is_unavailable(
    tmp_path, monkeypatch, legs
):
    from asinfo_fixtures import Clock

    clock = Clock()
    manager = build_manager(tmp_path, clock=clock)
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    clock.advance(hours=config.ASINFO_MAX_AGE_HOURS + 1)
    reason = next(
        e["reason"]
        for e in manager.for_address(KT_IP)["unavailable"]
        if e["dataset"] == "ris_v4"
    )
    body = client.get(f"/{KT_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL).json()
    assert body["route_prefix"] is None
    assert body["errors"] == {name: reason for name in ROUTE_FIELDS.split(",")}
    text = client.get(
        f"/{KT_IP}", params={"fields": ROUTE_FIELDS, "format": "text"}, headers=CURL
    ).text
    assert text == "?\n?\n?\n"


def test_route_fields_are_question_marks_on_a_fresh_volume(tmp_path, monkeypatch, legs):
    manager = AsInfoManager(
        directory=str(tmp_path / "empty"), enabled=True, clock=lambda: NOW
    )
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    text = client.get(
        f"/{KT_IP}", params={"fields": ROUTE_FIELDS, "format": "text"}, headers=CURL
    ).text
    assert text == "?\n?\n?\n"


def test_rpki_state_alone_is_a_question_mark_when_the_vrps_are_unavailable(
    tmp_path, monkeypatch, legs
):
    from asinfo_fixtures import iso

    manager = build_manager(
        tmp_path,
        meta={
            "rpki": {"source_date": iso(NOW - (config.ASINFO_MAX_AGE_HOURS + 5) * HOUR)}
        },
    )
    monkeypatch.setattr(lookup, "asinfo_manager", manager)
    monkeypatch.setattr(main, "asinfo_manager", manager)
    body = client.get(f"/{KT_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL).json()
    assert body["route_prefix"] == "211.252.112.0/24"
    assert body["route_origin"] == 4766
    assert body["rpki_state"] is None
    assert list(body["errors"]) == ["rpki_state"]


def test_route_fields_are_dashes_when_not_announced(asinfo_enabled, legs):
    text = client.get(
        f"/{UNANNOUNCED_IP}",
        params={"fields": ROUTE_FIELDS, "format": "text"},
        headers=CURL,
    ).text
    assert text == "-\n-\n-\n"
    body = client.get(
        f"/{UNANNOUNCED_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL
    ).json()
    assert body == {"route_prefix": None, "route_origin": None, "rpki_state": None}


def test_route_fields_are_dashes_when_the_feature_is_off(legs):
    # Like the reputation fields with REPUTATION_ENABLED=false: no leg answers,
    # so the fields read "-" rather than being refused, when asked for by name.
    body = client.get(f"/{KT_IP}", params={"fields": ROUTE_FIELDS}, headers=CURL).json()
    assert body == {"route_prefix": None, "route_origin": None, "rpki_state": None}
    # The text block leaves them out: there, "-" would read as not announced.
    for target in (KT_IP, DOMAIN):
        lines = client.get(f"/{target}?format=text", headers=CURL).text.splitlines()
        keys = [line.split(":", 1)[0] for line in lines]
        assert "cidr" in keys
        assert not set(keys) & set(ROUTE_FIELDS.split(","))


def test_self_fields_answer_the_route_fields(asinfo_enabled, legs, monkeypatch):
    body = as_peer(KT_IP).get("/", params={"fields": ROUTE_FIELDS}, headers=CURL).json()
    assert body == {
        "route_prefix": "211.252.112.0/24",
        "route_origin": 4766,
        "rpki_state": "valid",
    }
    reads = MagicMock(wraps=asinfo_enabled.for_address)
    monkeypatch.setattr(asinfo_enabled, "for_address", reads)
    as_peer(KT_IP).get("/?fields=country_code", headers=CURL)
    reads.assert_not_called()


# ---------------------------------------------------------------------------
# MCP: the as_info tool, and as_info in lookup and whoami_caller.
# ---------------------------------------------------------------------------


def _with_as_info_tool():
    """patch.dict puts the registry back as it was: the tool is registered at
    import only under ASINFO_ENABLED, which the suite turns off."""
    stack = ExitStack()
    stack.enter_context(patch.dict(mcp_server.mcp._tool_manager._tools))
    mcp_server.mcp.add_tool(
        mcp_server.as_info,
        name="as_info",
        title="Autonomous system",
        annotations=mcp_server._READ_ONLY_LOCAL,
    )
    return stack


def test_as_info_tool_returns_the_compact_card(asinfo_enabled, monkeypatch):
    # Five calls in a burst: more than the MCP bucket allows a second.
    monkeypatch.setattr(main.mcp_rate_limiter, "requests_per_second", 100)
    with _with_as_info_tool(), TestClient(main.app) as mcp_client:
        result = _call(mcp_client, "as_info", {"asn": "AS4766"})
        assert not result.get("isError")
        card = result["structuredContent"]
        # "as4766" and the bare number, as a string or a JSON integer, are the
        # same AS.
        for spelling in ("as4766", " 4766 ", 4766):
            again = _call(mcp_client, "as_info", {"asn": spelling})
            assert again["structuredContent"] == card
        full = _call(mcp_client, "as_info", {"asn": "4766", "full": True})
    assert card["asn"] == 4766
    assert card["name"] == "KIXS-AS-KR-KR - Korea Telecom"
    assert card["country"] == "KR"
    assert card["org"] == {"name": "Korea Telecom", "sibling_count": 1}
    assert card["prefixes"]["v4"] == 2
    assert card["rpki"] == {"valid": 2, "invalid": 0, "not_found": 1}
    assert [up["asn"] for up in card["upstreams"]] == [174, 701]
    # Counts only, no lists, and no dataset dates.
    assert card["downstreams"] == {"count": 3}
    assert card["peers"] == {"count": 1}
    assert "datasets" not in card and "siblings" not in (card["org"] or {})
    assert "prefix_list" not in card
    assert card["unavailable"] == []
    assert "Source: RIPE NCC" in card["attribution"]
    # `full` adds the capped lists.
    full_card = full["structuredContent"]
    assert [d["asn"] for d in full_card["downstreams"]["list"]] == [17858, 38661, 45400]
    assert full_card["downstreams"]["count"] == 3
    assert full_card["peers"]["list"][0]["asn"] == 9318
    assert full_card["prefix_list"]["count"] == len(full_card["prefix_list"]["list"])


def test_as_info_tool_explains_a_special_asn(asinfo_enabled):
    with _with_as_info_tool(), TestClient(main.app) as mcp_client:
        result = _call(mcp_client, "as_info", {"asn": "AS64512"})
    assert not result.get("isError")
    card = result["structuredContent"]
    assert set(card) == {"asn", "special"}
    assert card["asn"] == 64512
    assert card["special"]["code"] == "private_asn"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "AS",
        "AS4294967296",
        "AS99999999999",
        "example.com",
        "4766x",
        "-1",
        -1,
        4294967296,
    ],
)
def test_as_info_tool_refuses_malformed_asns(asinfo_enabled, value):
    with _with_as_info_tool(), TestClient(main.app) as mcp_client:
        result = _call(mcp_client, "as_info", {"asn": value})
    assert _failed(result)["code"] == "invalid_target"


def test_as_info_tool_fails_with_a_code_when_the_manager_is_off():
    # config says on, the manager says off: the only way the tool can be asked.
    with _with_as_info_tool(), TestClient(main.app) as mcp_client:
        result = _call(mcp_client, "as_info", {"asn": "AS4766"})
    assert _failed(result)["code"] == "asinfo_disabled"


@pytest.mark.parametrize("tool", ["lookup", "dns_records", "ssl_certificate"])
def test_lookup_tools_refuse_an_as_target_with_asn_target_code(tool):
    argument = "target" if tool == "lookup" else "domain"
    with TestClient(main.app) as mcp_client:
        result = _call(mcp_client, tool, {argument: "AS4766"})
    assert _failed(result)["code"] == "asn_target"


def test_lookup_and_whoami_carry_compact_as_info(asinfo_enabled, legs):
    async def fake_location(ip):
        return copy.deepcopy(_location(ip))

    with TestClient(main.app, client=(KT_IP, 41234)) as mcp_client:
        looked_up = _call(mcp_client, "lookup", {"target": KT_IP})["structuredContent"]
        with patch("mcp_server.lookup_location", fake_location):
            caller = _call(mcp_client, "whoami_caller", {})["structuredContent"]
    for payload in (looked_up, caller):
        card = payload["as_info"]
        assert card["asn"] == 4766
        assert card["route"] == {
            "prefix": "211.252.112.0/24",
            "origins": [{"asn": 4766, "ris_peers": 326, "rpki": "valid"}],
        }
        assert card["source"] == "route"
        assert card["downstreams"] == {"count": 3}
        assert "datasets" not in card
        assert "special" not in card


def test_compact_as_info_keeps_null_and_the_reasons_for_it():
    card = {
        **dict.fromkeys(ANSWER_KEYS),
        "asn": 4766,
        "unavailable": [{"dataset": "caida_rel", "label": "x", "reason": "stale"}],
        "attribution": [],
        "special": None,
    }
    compact = mcp_server.compact_as_info(card)
    assert compact["upstreams"] is None
    assert compact["downstreams"] is None
    assert compact["org"] is None
    assert compact["rpki"] is None
    assert compact["unavailable"] == [{"dataset": "caida_rel", "reason": "stale"}]
    assert mcp_server.compact_as_info(None) is None


def test_compact_as_info_for_an_address_with_no_as_is_its_route_alone(
    asinfo_enabled,
):
    # No AS: every AS section would be a null that `unavailable` does not
    # explain, so the card keeps only what was looked up.
    card = {**asinfo_enabled.for_address("192.0.2.1"), "asn_drop": None}
    assert mcp_server.compact_as_info(card) == {
        "asn": None,
        "route": None,
        "announced": False,
        "source": None,
        "unavailable": [],
    }
    unread = {
        **card,
        "announced": None,
        "unavailable": [{"dataset": "ris_v4", "label": "x", "reason": "old"}],
    }
    assert mcp_server.compact_as_info(unread)["unavailable"] == [
        {"dataset": "ris_v4", "reason": "old"}
    ]


def test_compact_as_info_for_a_special_address_card_keeps_the_route(asinfo_enabled):
    card = {
        **dict.fromkeys(ANSWER_KEYS),
        "asn": 64512,
        "special": lookup.special_asn(64512),
        "route": {
            "prefix": "45.67.89.0/24",
            "origins": [
                {"asn": 64512, "ris_peers": 50, "rpki": {"state": "not-found"}}
            ],
        },
    }
    assert mcp_server.compact_as_info(card) == {
        "asn": 64512,
        "special": card["special"],
        "route": {
            "prefix": "45.67.89.0/24",
            "origins": [{"asn": 64512, "ris_peers": 50, "rpki": "not-found"}],
        },
    }


def test_as_info_tool_absent_when_disabled():
    assert "as_info" not in mcp_server.registered_tool_names()


# --- /privacy and the credits ---------------------------------------------------


def _privacy_text() -> str:
    return page_text(client.get("/privacy", headers=CHROME).text)


def test_privacy_lists_the_as_datasets_and_says_never_per_lookup(asinfo_enabled):
    hosts = asinfo_enabled.hosts()
    assert {"ftp.ripe.net", "publicdata.caida.org"} <= set(hosts)
    text = _privacy_text()
    for host in hosts:
        assert re.search(rf"(?<![\w.]){re.escape(host)}(?![\w])", text), host
    assert "never for a particular lookup" in text
    assert "Source: RIPE NCC" in text
    assert "RPKI data validated by rpki-client.org" in text
    assert "The CAIDA UCSD AS Relationships Dataset" in text
    assert "The CAIDA UCSD AS Organizations Dataset" in text
    html = client.get("/privacy", headers=CHROME).text
    assert "https://www.caida.org/catalog/datasets/as-relationships/" in html
    assert "https://www.caida.org/catalog/datasets/as-organizations/" in html


def test_privacy_states_each_age_limit_from_the_constants(asinfo_enabled, monkeypatch):
    def days(value):
        return main._span(int(value * 86400))

    text = _privacy_text()
    assert (
        f"A dataset older than {main._span(int(config.ASINFO_MAX_AGE_HOURS * 3600))}"
        f" ({days(config.ASINFO_CAIDA_REL_MAX_AGE_DAYS)} for CAIDA's relationships"
        f" and {days(config.ASINFO_CAIDA_ORG_MAX_AGE_DAYS)} for its organizations,"
        " which it publishes less often) is reported as unknown rather than used."
    ) in text
    # From the constants, not from the template.
    monkeypatch.setattr(main, "ASINFO_CAIDA_REL_MAX_AGE_DAYS", 40)
    assert "40 days for CAIDA's relationships" in _privacy_text()


def test_privacy_omits_them_when_disabled(monkeypatch, tmp_path):
    # The default suite switch is off; a manager that is off keeps its dataset
    # table, so the page must not read the hosts from it.
    off = AsInfoManager(directory=str(tmp_path), enabled=False)
    assert off.hosts()
    monkeypatch.setattr(main, "asinfo_manager", off)
    text = _privacy_text()
    assert "ris.ripe.net" not in text
    assert "publicdata.caida.org" not in text
    assert "CAIDA" not in text
    assert "rpki-client" not in text


def _credits_on(html: str) -> list[str]:
    """The credit paragraphs after the AS card's table."""
    panel = html.split('id="acc-as"')[1].split("</details>")[0]
    return re.findall(
        r'<p class="api-note tone-muted">(.*?)</p>', panel.split("</table>")[1]
    )


def test_as_panel_carries_each_credit(asinfo_enabled, legs):
    # CAIDA's citations link to their dataset pages, as CAIDA's terms ask;
    # the JSON keeps the plain lines.
    html = client.get(f"/{KT_IP}", headers=BROWSER).text
    assert _credits_on(html) == [
        "Source: RIPE NCC",
        "RPKI data validated by rpki-client.org",
        *(
            f'<a href="{href}" rel="noopener noreferrer">{text}</a>'
            for text, href in CAIDA_CITATIONS.items()
        ),
    ]
    body = client.get(f"/{KT_IP}", headers=CURL).json()
    assert body["as_info"]["attribution"][2:] == list(CAIDA_CITATIONS)


def test_privacy_names_caida_only_while_its_datasets_are_in_use(monkeypatch, tmp_path):
    manager = AsInfoManager(
        directory=str(tmp_path),
        enabled=True,
        datasets=[d for d in default_datasets(caida=True) if "caida" not in d.id],
    )
    monkeypatch.setattr(main, "asinfo_manager", manager)
    text = _privacy_text()
    assert "RPKI data validated by rpki-client.org" in text
    assert "CAIDA" not in text


def test_mcp_as_card_keeps_number_and_name_only(asinfo_enabled):
    card = mcp_server.compact_as_info(
        lookup.as_info_for_asn(4766, full=True), full=True
    )
    assert set(card["upstreams"][0]) == {"asn", "name"}
    assert set(card["downstreams"]["list"][0]) == {"asn", "name"}
