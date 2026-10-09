"""IP reputation: which public lists an address is on, and a grade from them.

An IP lookup used to say nothing about risk at all: no Tor, VPN, datacenter or
blocklist signal anywhere in the pipeline, and the MCP whoami_caller tool could
only shrug at whether it was talking to a hosted client.

The lists are downloaded by the scheduler, never by a lookup, so everything
here runs over small synthetic copies written to a temporary directory. The
samples follow the real formats as fetched on 2026-10-09: Spamhaus's DROP JSON
is one object per line closed by a metadata record carrying the copyright, the
Tor bulk exit list one address per line, X4BNet's lists one CIDR per line.
"""

import asyncio
import copy
import dataclasses
import ipaddress
import json
import os
import re
import urllib.request
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import config
import lookup
import main
import mcp_server
import reputation
import textfmt
import viewmodel
from reputation import Intervals, ReputationManager, grade, parse_lines, parse_spamhaus

HOUR = 3600
T0 = 1_791_530_000.0  # 2026-10-09 07:13:20 UTC, just after the samples were taken

SPAMHAUS_META = json.dumps(
    {
        "type": "metadata",
        "timestamp": 1791459842,
        "size": 1,
        "records": 2,
        "copyright": "(c) 2026 The Spamhaus Project SLU",
        "terms": "https://www.spamhaus.org/drop/terms/",
    }
)

# Public addresses, since gather() refuses anything else. Not a claim about
# what any of them really is.
DROP_IP = "1.10.16.7"  # in 1.10.16.0/20
TOR_IP = "185.220.101.1"  # a Tor exit, inside a datacenter block too
VPN_IP = "2.26.157.10"  # on the VPN list and, as X4BNet's README says, the DC one
DC_IP = "104.16.1.1"  # datacenter only
CLEAN_IP = "9.9.9.9"  # on none of the lists
ASN_DROP_IP = "5.6.7.8"  # its AS (below) is on ASN-DROP
DROPPED_ASN = 400001
DROP_V6 = "2001:678:254::1"
DC_V6 = "2001:310::1"

SAMPLES = {
    "spamhaus_drop_v4.json": (
        '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n'
        '{"cidr":"223.254.0.0/16","sblid":"SBL212803","rir":"apnic"}\n'
        + SPAMHAUS_META
        + "\n"
    ),
    "spamhaus_drop_v6.json": (
        '{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}\n'
        + SPAMHAUS_META
        + "\n"
    ),
    "spamhaus_asndrop.json": (
        f'{{"asn":{DROPPED_ASN},"rir":"arin","domain":"example.net","cc":"US",'
        '"asname":"EXAMPLE-AS"}\n' + SPAMHAUS_META + "\n"
    ),
    "tor_exit.txt": "185.220.101.1\n185.220.101.2\n",
    "x4b_vpn_v4.txt": "2.26.157.0/24\n",
    "x4b_vpn_v6.txt": "2001:550:1d05::/48\n",
    "x4b_datacenter_v4.txt": "2.26.157.0/24\n185.220.101.0/24\n104.16.0.0/13\n",
    "x4b_datacenter_v6.txt": "2001:310::/32\n",
}

FEED_IDS = ["spamhaus_drop", "spamhaus_asndrop", "tor_exit", "vpn", "datacenter"]


class Clock:
    def __init__(self, now: float = T0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeFetch:
    """Stands in for the HTTP download. Answers from `bodies` by file name
    (looked up through the feed table), or raises what `failing` holds."""

    def __init__(self, feeds, bodies=None, failing=None):
        self.by_url = {f.url: f.name for feed in feeds for f in feed.files}
        self.bodies = dict(SAMPLES if bodies is None else bodies)
        self.failing = dict(failing or {})
        self.calls: list[str] = []

    def __call__(self, url: str) -> bytes:
        name = self.by_url[url]
        self.calls.append(name)
        if name in self.failing:
            raise self.failing[name]
        return self.bodies[name].encode()

    def count(self, prefix: str) -> int:
        return sum(1 for name in self.calls if name.startswith(prefix))


def small_feeds():
    """The real feed table, with the minimum entry counts dropped to one so a
    two-line sample installs. The minimum itself is tested on its own below."""
    return tuple(
        dataclasses.replace(
            feed,
            files=tuple(dataclasses.replace(f, min_entries=1) for f in feed.files),
        )
        for feed in reputation.default_feeds()
    )


def write_lists(directory, clock, age_hours=1.0, files=None):
    os.makedirs(directory, exist_ok=True)
    when = clock() - age_hours * HOUR
    for name, body in (SAMPLES if files is None else files).items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.utime(path, (when, when))


def make_manager(tmp_path, clock=None, age_hours=1.0, files=None, **kwargs):
    clock = clock or Clock()
    write_lists(tmp_path, clock, age_hours, files)
    kwargs.setdefault("fetch", FakeFetch(small_feeds(), bodies={}))
    return ReputationManager(
        directory=str(tmp_path),
        feeds=small_feeds(),
        enabled=True,
        clock=clock,
        **kwargs,
    )


def ids(entries):
    return [entry["id"] for entry in entries]


# --- parsers ---------------------------------------------------------------------


class TestParsers:
    def test_spamhaus_drop_networks_and_the_notice(self):
        data = parse_spamhaus(SAMPLES["spamhaus_drop_v4.json"])
        assert data.entries == 2
        assert data.notice == "(c) 2026 The Spamhaus Project SLU"
        assert int(ipaddress.ip_address(DROP_IP)) in data.v4
        assert len(data.v6) == 0

    def test_spamhaus_drop_v6(self):
        data = parse_spamhaus(SAMPLES["spamhaus_drop_v6.json"])
        assert data.entries == 1
        assert int(ipaddress.ip_address(DROP_V6)) in data.v6

    def test_spamhaus_asn_drop(self):
        data = parse_spamhaus(SAMPLES["spamhaus_asndrop.json"])
        assert data.asns == frozenset({DROPPED_ASN})
        assert data.entries == 1

    def test_a_spamhaus_file_without_its_closing_metadata_is_refused(self):
        """The metadata record is the last line, so a truncated download has
        none; it also carries the copyright Spamhaus asks to keep with the
        data."""
        truncated = SAMPLES["spamhaus_drop_v4.json"].split(SPAMHAUS_META)[0]
        with pytest.raises(ValueError):
            parse_spamhaus(truncated)

    def test_an_html_error_page_is_not_a_spamhaus_list(self):
        with pytest.raises(ValueError):
            parse_spamhaus("<!DOCTYPE html><html><body>Access denied</body></html>")

    def test_line_lists_take_addresses_and_cidrs_and_skip_the_rest(self):
        data = parse_lines(
            "# comment\n185.220.101.1\n\n10.0.0.0/24\nnot-an-address\n2001:db8::/32\n"
        )
        assert data.entries == 3
        assert int(ipaddress.ip_address("185.220.101.1")) in data.v4
        assert int(ipaddress.ip_address("10.0.0.200")) in data.v4
        assert int(ipaddress.ip_address("2001:db8::5")) in data.v6

    def test_an_html_page_parses_to_nothing(self):
        assert parse_lines("<html>\n<body>rate limited</body>\n</html>\n").entries == 0


# --- interval lookup ---------------------------------------------------------------


class TestIntervals:
    def test_overlapping_and_adjacent_ranges_merge(self):
        ranges = Intervals([(40, 50), (10, 20), (15, 30), (51, 60)])
        assert len(ranges) == 2
        for inside in (10, 20, 30, 40, 50, 51, 60):
            assert inside in ranges
        for outside in (9, 31, 39, 61):
            assert outside not in ranges

    def test_an_address_after_a_nested_range_is_still_found(self):
        """Without merging, bisect lands on the /24 inside the /16 and reads
        an address past the /24's end as unlisted."""
        ranges = Intervals([(0, 100), (10, 20)])
        assert 50 in ranges

    def test_empty(self):
        assert 5 not in Intervals([])

    @pytest.mark.parametrize(
        "ip, listed",
        [
            ("10.0.0.0", True),
            ("10.0.0.255", True),
            ("9.255.255.255", False),
            ("10.0.1.0", False),
        ],
    )
    def test_v4_boundaries(self, tmp_path, ip, listed):
        files = {**SAMPLES, "x4b_datacenter_v4.txt": "10.0.0.0/24\n"}
        result = make_manager(tmp_path, files=files).check(ip)
        assert ("datacenter" in ids(result["signals"])) is listed

    @pytest.mark.parametrize(
        "ip, listed",
        [
            ("2001:678:254::", True),
            ("2001:678:254:ffff:ffff:ffff:ffff:ffff", True),
            ("2001:678:253:ffff:ffff:ffff:ffff:ffff", False),
            ("2001:678:255::", False),
        ],
    )
    def test_v6_boundaries(self, tmp_path, ip, listed):
        result = make_manager(tmp_path).check(ip)
        assert ("spamhaus_drop" in ids(result["signals"])) is listed

    def test_an_ipv4_mapped_address_is_checked_as_ipv4(self, tmp_path):
        result = make_manager(tmp_path).check("::ffff:" + TOR_IP)
        assert "tor_exit" in ids(result["signals"])


# --- check(): signals, checked, unavailable ---------------------------------------


class TestCheck:
    def test_a_tor_exit_in_a_datacenter(self, tmp_path):
        result = make_manager(tmp_path).check(TOR_IP)
        assert result["level"] == "medium"
        assert ids(result["signals"]) == ["tor_exit", "datacenter"]
        tor = result["signals"][0]
        assert tor == {
            "id": "tor_exit",
            "label": "Tor exit",
            "source": "Tor Project",
            "as_of": "2026-10-09T06:13:20Z",
            "weight": config.REPUTATION_WEIGHTS["tor_exit"],
        }
        # ASN-DROP needs an AS number, and none was given.
        assert ids(result["checked"]) == [
            "spamhaus_drop",
            "tor_exit",
            "vpn",
            "datacenter",
        ]
        assert ids(result["unavailable"]) == ["spamhaus_asndrop"]

    def test_checked_entries_carry_source_and_as_of(self, tmp_path):
        result = make_manager(tmp_path).check(CLEAN_IP, asn=13335)
        for entry in result["checked"]:
            assert set(entry) == {"id", "label", "source", "as_of"}
            assert entry["as_of"] == "2026-10-09T06:13:20Z"

    def test_no_signals_is_level_none_with_every_list_checked(self, tmp_path):
        result = make_manager(tmp_path).check(CLEAN_IP, asn=13335)
        assert result["level"] == "none"
        assert result["signals"] == []
        assert ids(result["checked"]) == FEED_IDS
        assert result["unavailable"] == []

    def test_asn_drop_matches_the_as_number(self, tmp_path):
        result = make_manager(tmp_path).check(ASN_DROP_IP, asn=DROPPED_ASN)
        assert ids(result["signals"]) == ["spamhaus_asndrop"]
        assert result["level"] == "high"

    def test_spamhaus_drop_is_high(self, tmp_path):
        result = make_manager(tmp_path).check(DROP_IP, asn=13335)
        assert ids(result["signals"]) == ["spamhaus_drop"]
        assert result["level"] == "high"

    def test_vpn_is_low_and_datacenter_does_not_raise_it(self, tmp_path):
        result = make_manager(tmp_path).check(VPN_IP, asn=13335)
        assert ids(result["signals"]) == ["vpn", "datacenter"]
        assert result["level"] == "low"

    def test_datacenter_alone_is_informational(self, tmp_path):
        result = make_manager(tmp_path).check(DC_IP, asn=13335)
        assert ids(result["signals"]) == ["datacenter"]
        assert result["signals"][0]["weight"] == 0
        assert result["level"] == "none"

    def test_ipv6_on_the_v6_lists(self, tmp_path):
        result = make_manager(tmp_path).check(DC_V6, asn=13335)
        assert ids(result["signals"]) == ["datacenter"]

    def test_the_tor_list_cannot_answer_for_ipv6(self, tmp_path):
        """The bulk exit list holds IPv4 addresses only, so an IPv6 address
        missing from it says nothing; it must not read as 'not a Tor exit'."""
        result = make_manager(tmp_path).check(DC_V6, asn=13335)
        assert "tor_exit" not in ids(result["checked"])
        tor = next(e for e in result["unavailable"] if e["id"] == "tor_exit")
        assert "IPv4" in tor["reason"]

    def test_a_stale_list_is_could_not_check(self, tmp_path):
        clock = Clock()
        write_lists(tmp_path, clock)
        tor = os.path.join(tmp_path, "tor_exit.txt")
        old = clock() - (config.REPUTATION_MAX_AGE_HOURS + 1) * HOUR
        os.utime(tor, (old, old))
        manager = make_manager(tmp_path, clock=clock, files={})
        result = manager.check(TOR_IP, asn=13335)
        assert "tor_exit" not in ids(result["signals"])
        assert "tor_exit" not in ids(result["checked"])
        stale = next(e for e in result["unavailable"] if e["id"] == "tor_exit")
        assert "old" in stale["reason"]
        # The other lists still answer, and the grade comes from them alone.
        assert ids(result["signals"]) == ["datacenter"]

    def test_a_list_going_stale_in_memory_is_could_not_check(self, tmp_path):
        clock = Clock()
        manager = make_manager(tmp_path, clock=clock)
        clock.advance(config.REPUTATION_MAX_AGE_HOURS * HOUR)
        result = manager.check(TOR_IP, asn=13335)
        assert result["signals"] == []
        assert result["checked"] == []
        assert result["level"] is None

    def test_nothing_downloaded_is_unknown_not_none(self, tmp_path):
        manager = make_manager(tmp_path, files={})
        result = manager.check(TOR_IP, asn=13335)
        assert result["level"] is None
        assert result["checked"] == []
        assert ids(result["unavailable"]) == FEED_IDS
        assert all("not been downloaded" in e["reason"] for e in result["unavailable"])

    def test_attribution_names_spamhaus_with_its_copyright(self, tmp_path):
        result = make_manager(tmp_path).check(CLEAN_IP, asn=13335)
        joined = " | ".join(result["attribution"])
        assert "(c) 2026 The Spamhaus Project SLU" in joined
        assert "https://www.spamhaus.org/drop/terms/" in joined
        assert "Tor Project" in joined
        assert "X4BNet" in joined
        # DROP and ASN-DROP share one notice.
        assert sum("Spamhaus" in line for line in result["attribution"]) == 1

    def test_no_attribution_for_a_list_that_was_not_read(self, tmp_path):
        files = {k: v for k, v in SAMPLES.items() if not k.startswith("spamhaus")}
        result = make_manager(tmp_path, files=files).check(CLEAN_IP, asn=13335)
        assert not any("Spamhaus" in line for line in result["attribution"])

    def test_not_an_address(self, tmp_path):
        assert make_manager(tmp_path).check("testclient") is None

    def test_a_check_makes_no_network_call(self, tmp_path):
        manager = make_manager(tmp_path)
        with patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("network")
        ):
            assert manager.check(TOR_IP)["signals"]

    def test_disabled_answers_nothing_and_downloads_nothing(self, tmp_path):
        fetch = FakeFetch(small_feeds())
        manager = ReputationManager(
            directory=str(tmp_path), feeds=small_feeds(), enabled=False, fetch=fetch
        )
        assert manager.check(TOR_IP) is None
        manager.refresh()
        assert fetch.calls == []
        assert manager.stale_lists() == []


# --- grade rule ------------------------------------------------------------------


@pytest.mark.parametrize(
    "signal_ids, level",
    [
        ((), "none"),
        (("datacenter",), "none"),
        (("vpn",), "low"),
        (("vpn", "datacenter"), "low"),
        (("tor_exit",), "medium"),
        (("tor_exit", "datacenter"), "medium"),
        (("tor_exit", "vpn"), "medium"),
        (("spamhaus_drop",), "high"),
        (("spamhaus_asndrop",), "high"),
        (("spamhaus_drop", "tor_exit", "vpn", "datacenter"), "high"),
    ],
)
def test_grade_rule(signal_ids, level):
    signals = [{"id": i, "weight": config.REPUTATION_WEIGHTS[i]} for i in signal_ids]
    assert grade(signals) == level


def test_weights_and_thresholds_live_in_config():
    assert set(config.REPUTATION_WEIGHTS) == set(FEED_IDS)
    assert (
        config.REPUTATION_LEVEL_HIGH
        > config.REPUTATION_LEVEL_MEDIUM
        > config.REPUTATION_LEVEL_LOW
        > 0
    )


# --- downloads ---------------------------------------------------------------------


class TestRefresh:
    def manager(self, tmp_path, fetch, clock, feeds=None):
        return ReputationManager(
            directory=str(tmp_path),
            feeds=feeds or small_feeds(),
            enabled=True,
            fetch=fetch,
            clock=clock,
        )

    def test_boot_downloads_what_is_missing_and_then_serves_it(self, tmp_path):
        clock = Clock()
        fetch = FakeFetch(small_feeds())
        manager = self.manager(tmp_path, fetch, clock)
        assert manager.refresh() is True
        assert sorted(fetch.calls) == sorted(SAMPLES)
        assert "tor_exit" in ids(manager.check(TOR_IP)["signals"])
        assert not any(name.endswith(".tmp") for name in os.listdir(tmp_path))

    def test_a_fresh_copy_is_not_downloaded_again(self, tmp_path):
        clock = Clock()
        write_lists(tmp_path, clock, age_hours=2)
        fetch = FakeFetch(small_feeds())
        assert self.manager(tmp_path, fetch, clock).refresh() is True
        assert fetch.calls == []

    def test_a_day_old_copy_is_refreshed(self, tmp_path):
        clock = Clock()
        write_lists(tmp_path, clock, age_hours=config.REPUTATION_REFRESH_HOURS + 0.1)
        fetch = FakeFetch(small_feeds())
        self.manager(tmp_path, fetch, clock).refresh()
        assert sorted(fetch.calls) == sorted(SAMPLES)

    def test_spamhaus_is_requested_at_most_once_a_day_across_restarts(self, tmp_path):
        clock = Clock()
        fetch = FakeFetch(small_feeds())
        self.manager(tmp_path, fetch, clock).refresh()
        assert fetch.count("spamhaus") == 3

        # A restart an hour later, with the volume kept: nothing to fetch.
        clock.advance(HOUR)
        self.manager(tmp_path, fetch, clock).refresh()
        # Nor when the copy is lost but the request was recorded.
        os.remove(os.path.join(tmp_path, "spamhaus_drop_v4.json"))
        clock.advance(HOUR)
        manager = self.manager(tmp_path, fetch, clock)
        manager.refresh()
        assert fetch.count("spamhaus") == 3
        dropped = next(
            e
            for e in manager.check(DROP_IP)["unavailable"]
            if e["id"] == "spamhaus_drop"
        )
        assert dropped

        # A day after the last request, Spamhaus may be asked again.
        clock.advance(config.REPUTATION_REFRESH_HOURS * HOUR)
        self.manager(tmp_path, fetch, clock).refresh()
        assert fetch.count("spamhaus") == 6

    def test_a_failed_spamhaus_request_still_counts_against_the_day(self, tmp_path):
        clock = Clock()
        error = OSError("HTTP Error 503")
        fetch = FakeFetch(small_feeds(), failing={"spamhaus_drop_v4.json": error})
        manager = self.manager(tmp_path, fetch, clock)
        assert manager.refresh() is False
        assert fetch.count("spamhaus_drop_v4") == 1

        # The hourly retry asks the other lists again, never Spamhaus.
        del fetch.failing["spamhaus_drop_v4.json"]
        for _ in range(23):
            clock.advance(HOUR)
            manager.refresh()
        self.manager(tmp_path, fetch, clock).refresh()  # nor after a restart
        assert fetch.count("spamhaus_drop_v4") == 1

        clock.advance(HOUR)
        assert manager.refresh() is True
        assert fetch.count("spamhaus_drop_v4") == 2

    def test_other_lists_are_retried_after_the_retry_interval(self, tmp_path):
        clock = Clock()
        fetch = FakeFetch(small_feeds(), failing={"tor_exit.txt": OSError("timeout")})
        manager = self.manager(tmp_path, fetch, clock)
        manager.refresh()
        manager.refresh()
        assert fetch.count("tor_exit") == 1
        clock.advance(config.REPUTATION_RETRY_SECONDS)
        del fetch.failing["tor_exit.txt"]
        assert manager.refresh() is True
        assert fetch.count("tor_exit") == 2

    def test_an_error_page_never_replaces_a_working_list(self, tmp_path):
        clock = Clock()
        write_lists(tmp_path, clock, age_hours=config.REPUTATION_REFRESH_HOURS + 1)
        fetch = FakeFetch(
            small_feeds(),
            bodies={**SAMPLES, "tor_exit.txt": "<html><body>blocked</body></html>\n"},
        )
        manager = self.manager(tmp_path, fetch, clock)
        manager.refresh()
        with open(os.path.join(tmp_path, "tor_exit.txt"), encoding="utf-8") as handle:
            assert handle.read() == SAMPLES["tor_exit.txt"]
        assert "tor_exit" in ids(manager.check(TOR_IP)["signals"])

    def test_a_list_below_its_minimum_is_refused(self, tmp_path):
        """The real minimums: a two-address Tor list is a broken download, not
        a Tor network that shrank overnight."""
        clock = Clock()
        feeds = reputation.default_feeds()
        fetch = FakeFetch(feeds)
        manager = self.manager(tmp_path, fetch, clock, feeds=feeds)
        assert manager.refresh() is False
        assert not os.path.exists(os.path.join(tmp_path, "tor_exit.txt"))
        assert manager.check(TOR_IP)["level"] is None

    def test_a_corrupt_copy_on_disk_is_downloaded_again(self, tmp_path):
        clock = Clock()
        write_lists(
            tmp_path, clock, files={**SAMPLES, "tor_exit.txt": "<html></html>\n"}
        )
        fetch = FakeFetch(small_feeds())
        self.manager(tmp_path, fetch, clock).refresh()
        assert fetch.calls == ["tor_exit.txt"]


# --- status and /healthz -------------------------------------------------------------


class TestStatus:
    def test_per_list_age_and_entries(self, tmp_path):
        status = make_manager(tmp_path, age_hours=5).status()
        assert status["enabled"] is True
        tor = status["lists"]["tor_exit"]
        assert tor == {
            "label": "Tor exit",
            "age_hours": 5.0,
            "entries": 2,
            "stale": False,
        }
        assert status["lists"]["spamhaus_drop"]["entries"] == 3

    def test_stale_lists_names_each_one(self, tmp_path):
        clock = Clock()
        manager = make_manager(tmp_path, clock=clock)
        assert manager.stale_lists() == []
        clock.advance(config.REPUTATION_MAX_AGE_HOURS * HOUR)
        messages = manager.stale_lists()
        assert len(messages) == len(FEED_IDS)
        assert any(re.search(r"\bTor exit\b.*\bhours old\b", m) for m in messages)

    def test_never_downloaded(self, tmp_path):
        messages = make_manager(tmp_path, files={}).stale_lists()
        assert all("not been downloaded" in m for m in messages)


@pytest.fixture
def rep(tmp_path, monkeypatch):
    """An enabled manager over the samples, wherever a lookup asks for one.
    The suite runs with REPUTATION_ENABLED=false (tests/conftest.py), so no
    test run ever downloads a list."""
    manager = make_manager(tmp_path)
    monkeypatch.setattr(lookup, "reputation_manager", manager)
    monkeypatch.setattr(main, "reputation_manager", manager)
    return manager


CURL = {"user-agent": "curl/8"}
CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
DOMAIN = "tor-relay.example.com"
ASNS = {DROP_IP: 13335, TOR_IP: 60729, CLEAN_IP: 19281, ASN_DROP_IP: DROPPED_ASN}


def _location(ip):
    return {
        "ip": ip,
        "country_code": "DE",
        "country_name": "Germany",
        "city_name": "Berlin",
        "asn_name": "Example AS",
        "asn_number": ASNS.get(ip, 64500),
        "is_private": False,
    }


@pytest.fixture
def legs():
    """Every outbound leg of a lookup answered locally: WHOIS, PTR, the DNS
    sweep, the A query and TLS."""
    resolver = MagicMock()
    resolver.resolve.return_value = [TOR_IP]
    location = AsyncMock(side_effect=lambda ip: copy.deepcopy(_location(ip)))
    whois = AsyncMock(return_value={"source": "rdap", "name": "EXAMPLE"})
    with ExitStack() as stack:
        stack.enter_context(patch("lookup.lookup_whois", whois))
        stack.enter_context(patch("main.lookup_whois", whois))
        stack.enter_context(patch("lookup.lookup_location", location))
        stack.enter_context(patch("main.lookup_location", location))
        stack.enter_context(patch("mcp_server.lookup_location", location))
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


client = TestClient(main.app)


def as_peer(ip):
    return TestClient(main.app, client=(ip, 41234))


def page_text(html):
    html = re.sub(r"<(script|svg)\b.*?</\1>", " ", html, flags=re.S | re.I)
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def hero_tags(html):
    return re.findall(r'<span class="tag tone-(\w+)">([^<]*)</span>', html)


# --- the JSON API --------------------------------------------------------------------


class TestApi:
    def test_an_ip_lookup_carries_reputation(self, rep, legs):
        body = client.get(f"/{TOR_IP}", headers=CURL).json()
        assert body["reputation"]["level"] == "medium"
        assert ids(body["reputation"]["signals"]) == ["tor_exit", "datacenter"]
        assert ids(body["reputation"]["checked"]) == FEED_IDS
        assert any("Spamhaus" in line for line in body["reputation"]["attribution"])
        # Added, not moved: the keys that were there still are.
        for key in ("address", "resolved_ip", "location", "whois", "ssl", "domain"):
            assert key in body

    def test_the_asn_comes_from_geoip(self, rep, legs):
        body = client.get(f"/{ASN_DROP_IP}", headers=CURL).json()
        assert ids(body["reputation"]["signals"]) == ["spamhaus_asndrop"]
        assert body["reputation"]["level"] == "high"

    def test_a_domain_is_judged_by_the_address_it_resolves_to(self, rep, legs):
        body = client.get(f"/{DOMAIN}", headers=CURL).json()
        assert body["resolved_ip"] == TOR_IP
        assert ids(body["reputation"]["signals"]) == ["tor_exit", "datacenter"]

    def test_the_self_lookup_carries_reputation(self, rep, legs):
        body = as_peer(TOR_IP).get("/", headers=CURL).json()
        assert ids(body["reputation"]["signals"]) == ["tor_exit", "datacenter"]

    def test_disabled_adds_no_key(self, legs):
        assert "reputation" not in client.get(f"/{TOR_IP}", headers=CURL).json()

    def test_the_lookup_reaches_no_list_server(self, rep, legs):
        rep._fetch = MagicMock(side_effect=AssertionError("downloaded in a request"))
        assert client.get(f"/{TOR_IP}", headers=CURL).status_code == 200
        assert as_peer(TOR_IP).get("/", headers=CURL).status_code == 200


class TestFields:
    def test_risk_fields_as_json(self, rep, legs):
        body = client.get(
            f"/{TOR_IP}?fields=risk_level,risk_signals", headers=CURL
        ).json()
        assert body == {"risk_level": "medium", "risk_signals": "tor_exit,datacenter"}

    def test_risk_fields_as_text(self, rep, legs):
        response = client.get(
            f"/{CLEAN_IP}?fields=risk_level,risk_signals&format=text", headers=CURL
        )
        assert response.text == "none\n-\n"

    def test_on_the_self_route(self, rep, legs):
        response = as_peer(TOR_IP).get("/?fields=risk_level&format=text", headers=CURL)
        assert response.text == "medium\n"

    def test_nothing_checked_is_unknown_not_none(self, tmp_path, monkeypatch, legs):
        manager = make_manager(tmp_path, files={})
        monkeypatch.setattr(lookup, "reputation_manager", manager)
        text = client.get(f"/{TOR_IP}?fields=risk_level&format=text", headers=CURL)
        assert text.text == "?\n"
        body = client.get(f"/{TOR_IP}?fields=risk_level", headers=CURL).json()
        assert body["risk_level"] is None
        assert body["errors"]["risk_level"]

    def test_not_in_the_default_text_block(self, rep, legs):
        response = client.get(f"/{TOR_IP}?format=text", headers=CURL)
        assert "risk_level" not in response.text

    def test_the_fields_are_known(self):
        assert {"risk_level", "risk_signals"} <= set(textfmt.FIELDS)


# --- the page -------------------------------------------------------------------------


class TestPage:
    def test_hero_tags_name_the_lists(self, rep, legs):
        html = client.get(f"/{TOR_IP}", headers=CHROME).text
        tags = hero_tags(html)
        assert ("warning", "Tor exit") in tags
        assert ("default", "Datacenter") in tags

    def test_spamhaus_tag_is_danger(self, rep, legs):
        tags = hero_tags(client.get(f"/{DROP_IP}", headers=CHROME).text)
        assert ("danger", "Spamhaus DROP") in tags

    def test_a_domain_gets_no_informational_datacenter_tag(self, rep, legs):
        """Nearly every website is hosted in a datacenter; the tag would be
        on every domain page and mean nothing there."""
        tags = [
            text for _, text in hero_tags(client.get(f"/{DOMAIN}", headers=CHROME).text)
        ]
        assert "Tor exit" in tags
        assert "Datacenter" not in tags

    def test_the_reputation_card(self, rep, legs):
        html = client.get(f"/{TOR_IP}", headers=CHROME).text
        assert 'id="acc-reputation"' in html
        text = page_text(html)
        assert "Reputation" in text
        assert "Listed on Tor exit (as of 2026-10-09 06:13 UTC)" in text
        assert "Not listed on Spamhaus DROP (as of 2026-10-09 06:13 UTC)" in text
        assert "(c) 2026 The Spamhaus Project SLU" in text
        assert "malicious" not in text.lower()

    def test_no_signals_does_not_read_as_safe(self, rep, legs):
        text = page_text(client.get(f"/{CLEAN_IP}", headers=CHROME).text)
        assert "Not on any of the 5 lists checked" in text
        for word in ("safe", "clean", "trusted address"):
            assert word not in text.lower()

    def test_could_not_check_is_shown(self, tmp_path, monkeypatch, legs):
        files = {k: v for k, v in SAMPLES.items() if not k.startswith("tor")}
        monkeypatch.setattr(
            lookup, "reputation_manager", make_manager(tmp_path, files=files)
        )
        text = page_text(client.get(f"/{CLEAN_IP}", headers=CHROME).text)
        assert "Could not check Tor exit" in text

    def test_the_self_page(self, rep, legs):
        html = as_peer(TOR_IP).get("/", headers=CHROME).text
        assert ("warning", "Tor exit") in hero_tags(html)
        assert 'id="acc-reputation"' in html

    def test_disabled_has_no_card(self, legs):
        assert (
            'id="acc-reputation"' not in client.get(f"/{TOR_IP}", headers=CHROME).text
        )

    def test_the_csp_is_unchanged(self, rep, legs, monkeypatch):
        def csp(response):
            policy = response.headers["content-security-policy"]
            return re.sub(r"'nonce-[^']+'", "'nonce'", policy)

        with_card = client.get(f"/{TOR_IP}", headers=CHROME)
        monkeypatch.setattr(lookup.reputation_manager, "enabled", False)
        without = client.get(f"/{TOR_IP}", headers=CHROME)
        assert 'id="acc-reputation"' not in without.text
        assert csp(with_card) == csp(without)
        card = re.search(
            r'<details class="accordion" id="acc-reputation">.*?</details>',
            with_card.text,
            re.S,
        ).group(0)
        assert "<script" not in card and "style=" not in card


class TestViewModel:
    def test_reputation_view_without_data(self):
        assert viewmodel.reputation_view(None) is None

    def test_tag_tones_follow_the_weight(self, tmp_path):
        rep_data = make_manager(tmp_path).check(VPN_IP, asn=1)
        view = viewmodel.build_view(
            {"address": VPN_IP, "location": {}, "reputation": rep_data}, is_self=False
        )
        assert {"text": "VPN", "tone": "warning"} in view["tags"]
        assert {"text": "Datacenter", "tone": "default"} in view["tags"]


# --- /healthz -------------------------------------------------------------------------


class TestHealthz:
    def test_reports_each_list(self, rep):
        body = client.get("/healthz", headers=CURL).json()
        lists = body["reputation"]["lists"]
        assert set(lists) == set(FEED_IDS)
        assert lists["tor_exit"]["age_hours"] == 1.0

    def test_a_stale_list_is_degraded(self, tmp_path, monkeypatch):
        old = config.REPUTATION_MAX_AGE_HOURS + 1
        monkeypatch.setattr(
            main, "reputation_manager", make_manager(tmp_path, age_hours=old)
        )
        body = client.get("/healthz", headers=CURL).json()
        assert body["status"] == "degraded"
        stale = [r for r in body["reasons"] if r["code"] == "reputation_list_stale"]
        assert len(stale) == len(FEED_IDS)
        assert any("Spamhaus DROP" in r["message"] for r in stale)

    def test_disabled_is_not_a_reason(self):
        body = client.get("/healthz", headers=CURL).json()
        assert body["reputation"] == {"enabled": False}
        assert "reputation_list_stale" not in [r["code"] for r in body["reasons"]]

    def test_the_refresh_job_is_scheduled(self):
        assert main.scheduler.get_job("refresh-reputation") is not None


# --- MCP ------------------------------------------------------------------------------


class TestMcp:
    async def test_lookup_summarises_reputation(self, rep, legs):
        payload = await mcp_server.lookup(TOR_IP)
        summary = payload["reputation"]
        assert summary["level"] == "medium"
        assert [s["list"] for s in summary["signals"]] == ["Tor exit", "Datacenter"]
        assert summary["signals"][0]["as_of"] == "2026-10-09T06:13:20Z"
        assert summary["not_listed_on"] == [
            "Spamhaus DROP",
            "Spamhaus ASN-DROP",
            "VPN",
        ]
        assert summary["could_not_check"] == []
        assert any("Spamhaus" in line for line in summary["attribution"])

    async def test_no_signals_carries_a_note_that_it_is_not_safe(self, rep, legs):
        summary = (await mcp_server.lookup(CLEAN_IP))["reputation"]
        assert summary["level"] == "none"
        assert "not" in summary["note"] and "safe" in summary["note"]

    async def test_a_list_it_could_not_check_is_named(
        self, tmp_path, monkeypatch, legs
    ):
        files = {k: v for k, v in SAMPLES.items() if not k.startswith("tor")}
        monkeypatch.setattr(
            lookup, "reputation_manager", make_manager(tmp_path, files=files)
        )
        summary = (await mcp_server.lookup(CLEAN_IP))["reputation"]
        assert [e["list"] for e in summary["could_not_check"]] == ["Tor exit"]

    def test_the_lookup_description_says_none_is_not_safe(self):
        doc = " ".join(mcp_server.lookup.__doc__.split())
        assert "reputation" in doc
        assert re.search(r"never .*\bsafe\b", doc)

    async def _whoami(self, ip):
        token = mcp_server._caller_ip.set(ip)
        try:
            return await mcp_server.whoami_caller()
        finally:
            mcp_server._caller_ip.reset(token)

    async def test_whoami_on_a_datacenter_list_is_likely_hosted(self, rep, legs):
        payload = await self._whoami(DC_IP)
        assert "likely a hosted client" in payload["note"]
        assert payload["reputation"]["signals"][0]["list"] == "Datacenter"

    async def test_whoami_elsewhere_still_cannot_tell(self, rep, legs):
        payload = await self._whoami(CLEAN_IP)
        assert "cannot tell" in payload["note"]
        assert "likely a hosted client" not in payload["note"]

    async def test_whoami_with_reputation_off_is_unchanged(self, legs):
        payload = await self._whoami(DC_IP)
        assert "cannot tell" in payload["note"]
        assert "reputation" not in payload


# --- /privacy -------------------------------------------------------------------------


def _names(name, text):
    return re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", text) is not None


class TestPrivacy:
    def test_names_the_list_servers_and_credits_spamhaus(self, rep):
        text = page_text(client.get("/privacy", headers=CHROME).text)
        for host in (
            "www.spamhaus.org",
            "check.torproject.org",
            "raw.githubusercontent.com",
        ):
            assert _names(host, text), host
        assert "The Spamhaus Project" in text
        assert "once a day" in text

    def test_not_named_when_off(self):
        text = page_text(client.get("/privacy", headers=CHROME).text)
        assert not _names("www.spamhaus.org", text)


def test_the_own_ban_list_is_never_a_signal(rep, legs):
    """Settled principle: the service's bans reveal its rules and would brand
    whoever shares a CGNAT or office address with a banned visitor."""
    ban = {
        "banned_at": "2026-10-09T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "reason": "suspicious_path",
        "request_path": "/.env",
        "country": "DE",
    }
    with patch.dict(main.ip_ban_manager.banned_ips, {CLEAN_IP: ban}):
        result = lookup.ip_reputation(CLEAN_IP, _location(CLEAN_IP))
    assert result["signals"] == []
    assert result["level"] == "none"


def test_reputation_imports_no_app_module():
    """lookup.py builds the singleton; reputation.py importing lookup or main
    back would be a cycle, as for subdomains.py."""
    source = open(reputation.__file__, encoding="utf-8").read()
    imports = re.findall(r"^(?:from|import) (\w+)", source, re.M)
    assert not {"lookup", "main", "mcp_server", "managers"} & set(imports)


def test_runs_in_an_event_loop_without_blocking(rep):
    """check() is a pure in-memory read, so gather() calls it inline."""

    async def run():
        return lookup.ip_reputation(TOR_IP, _location(TOR_IP))

    assert asyncio.run(run())["level"] == "medium"
