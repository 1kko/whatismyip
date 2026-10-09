"""AbuseIPDB: an address's abuse reports, as one more reputation source.

The reputation lists answer "what kind of network is this"; AbuseIPDB answers
"has anyone reported it", which is what people usually mean by a risk score.
It is an API call per address against a daily quota (1,000 on the free plan),
so it is asked only about an address looked up directly, once a day per
address, and never past the quota.

Every test here runs over a fake transport (FakeApi) or a server on loopback:
the suite leaves ABUSEIPDB_API_KEY empty (tests/conftest.py), so no test can
spend the real quota. The answers follow the API's documented shape.
"""

import asyncio
import html
import http.server
import json
import re
import socket
import threading
import urllib.error
import urllib.parse
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import abuseipdb
import lookup
import main
import mcp_server
from abuseipdb import AbuseIPDBClient, merge

KEY = "test-abuseipdb-key-0123456789"
T0 = 1_791_530_000.0  # 2026-10-09 07:13:20 UTC
DAY = 86400
NEXT_MIDNIGHT = 1_791_590_400.0  # 2026-10-10 00:00:00 UTC

# Public addresses, since gather() refuses anything else. Not a claim about
# what either of them really is.
IP = "185.220.101.1"
OTHER = "9.9.9.9"
V6 = "2606:4700:4700::1111"


def body(score=87, reports=152, reporters=40, last="2026-10-08T12:34:56+00:00"):
    return json.dumps(
        {
            "data": {
                "ipAddress": IP,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": score,
                "countryCode": "DE",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Example",
                "domain": "example.net",
                "hostnames": [],
                "isTor": True,
                "totalReports": reports,
                "numDistinctUsers": reporters,
                "lastReportedAt": last,
            }
        }
    ).encode()


OK = (200, {"x-ratelimit-limit": "1000", "x-ratelimit-remaining": "999"}, body())


class Clock:
    def __init__(self, now: float = T0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeApi:
    """Stands in for the HTTPS request. Answers from `responses` in turn, an
    exception in it being raised, then with OK."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, str, float]] = []

    def __call__(self, url, key, timeout):
        self.calls.append((url, key, timeout))
        item = self.responses.pop(0) if self.responses else OK
        if isinstance(item, BaseException):
            raise item
        return item

    def asked(self) -> list[str]:
        return [
            urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["ipAddress"][0]
            for url, _, _ in self.calls
        ]


def make_client(*responses, clock=None, **kwargs):
    api = FakeApi(*responses)
    client = AbuseIPDBClient(
        api_key=KEY, enabled=True, fetch=api, clock=clock or Clock(), **kwargs
    )
    client.api = api
    return client


# --- the client ------------------------------------------------------------------


class TestSwitch:
    def test_off_without_a_key(self):
        assert not AbuseIPDBClient(api_key="", enabled=True).enabled

    def test_off_with_reputation(self):
        assert not AbuseIPDBClient(api_key=KEY, enabled=False).enabled

    def test_the_suite_has_no_key(self):
        """conftest empties it, whatever a developer's .env holds."""
        assert not lookup.abuseipdb_client.enabled

    def test_disabled_reports_only_that(self):
        client = AbuseIPDBClient(api_key="", enabled=True)
        assert client.status() == {"enabled": False}
        assert client.problems() == []


class TestRequest:
    def test_asks_the_check_endpoint_for_the_score_only(self):
        client = make_client()
        client.check(IP)
        [(url, key, timeout)] = client.api.calls
        parts = urllib.parse.urlparse(url)
        assert (parts.scheme, parts.hostname, parts.path) == (
            "https",
            "api.abuseipdb.com",
            "/api/v2/check",
        )
        # No `verbose`: the reports' comments are other people's free text.
        assert urllib.parse.parse_qs(parts.query) == {
            "ipAddress": [IP],
            "maxAgeInDays": ["90"],
        }
        assert key == KEY
        assert timeout == client.timeout

    def test_one_spelling_per_address(self):
        client = make_client()
        client.check(V6.upper())
        client.check(V6)
        assert client.api.asked() == [V6]

    def test_the_answer(self):
        answer = make_client().check(IP)
        assert answer == {
            "ok": True,
            "score": 87,
            "reports": 152,
            "reporters": 40,
            "last_reported_at": "2026-10-08T12:34:56Z",
            "window_days": 90,
            "as_of": "2026-10-09T07:13:20Z",
            "url": f"https://www.abuseipdb.com/check/{IP}",
        }

    def test_never_reported(self):
        never = body(score=0, reports=0, reporters=0, last=None)
        result = make_client((200, {}, never)).check(IP)
        assert (result["score"], result["reports"], result["last_reported_at"]) == (
            0,
            0,
            None,
        )


class TestCache:
    def test_one_check_per_address_a_day(self):
        clock = Clock()
        client = make_client(clock=clock)
        client.check(IP)
        clock.advance(DAY - 1)
        assert client.check(IP)["as_of"] == "2026-10-09T07:13:20Z"
        assert client.cached(IP) is not None
        assert len(client.api.calls) == 1
        clock.advance(2)
        assert client.cached(IP) is None
        client.check(IP)
        assert len(client.api.calls) == 2

    def test_a_failure_is_asked_again_after_five_minutes(self):
        clock = Clock()
        client = make_client((503, {}, b""), clock=clock)
        failed = {"ok": False, "reason": "AbuseIPDB answered HTTP 503"}
        assert client.check(IP) == failed
        client.check(IP)
        assert len(client.api.calls) == 1
        clock.advance(abuseipdb.ERROR_TTL_SECONDS + 1)
        assert client.check(IP)["ok"]
        assert len(client.api.calls) == 2

    def test_bounded(self, monkeypatch):
        monkeypatch.setattr(abuseipdb, "CACHE_SIZE", 2)
        client = make_client()
        for ip in (IP, OTHER, V6):
            client.check(ip)
        assert client.cached(IP) is None
        assert client.cached(V6) is not None


class TestQuota:
    def test_stops_at_the_daily_limit(self):
        clock = Clock()
        client = make_client(clock=clock, daily_limit=2)
        client.check(IP)
        client.check(OTHER)
        refused = client.check(V6)
        assert refused == {
            "ok": False,
            "reason": "today's AbuseIPDB quota is used up, until 00:00 UTC",
        }
        assert client.api.asked() == [IP, OTHER]
        assert client.status()["quota_spent_until"] == "2026-10-10T00:00:00Z"
        clock.now = NEXT_MIDNIGHT
        assert client.check(V6)["ok"]
        assert client.status()["requests_today"] == 1

    def test_a_429_holds_every_address_until_the_reset(self):
        clock = Clock()
        reset = T0 + 3600
        client = make_client(
            (
                429,
                {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(reset))},
                b'{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded",'
                b'"status":429}]}',
            ),
            clock=clock,
        )
        assert "used up, until 08:13 UTC" in client.check(IP)["reason"]
        assert "used up" in client.check(OTHER)["reason"]
        assert client.api.asked() == [IP]
        clock.now = reset + 1
        assert client.check(IP)["ok"]

    def test_a_429_without_a_reset_waits_for_retry_after(self):
        clock = Clock()
        client = make_client((429, {"retry-after": "120"}, b""), clock=clock)
        client.check(IP)
        clock.advance(119)
        client.check(IP)
        clock.advance(2)
        client.check(IP)
        assert client.api.asked() == [IP, IP]

    def test_a_429_with_nothing_waits_for_midnight(self):
        clock = Clock()
        client = make_client((429, {}, b""), clock=clock)
        client.check(IP)
        assert client.status()["quota_spent_until"] == "2026-10-10T00:00:00Z"

    def test_the_last_check_left_still_answers(self):
        """X-RateLimit-Remaining: 0 on a 200: this answer stands, and nothing
        more is sent until the reset."""
        reset = T0 + 600
        headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(reset))}
        client = make_client((200, headers, body()))
        assert client.check(IP)["ok"]
        assert client.check(IP)["ok"]  # from the cache
        assert "used up" in client.check(OTHER)["reason"]
        assert client.api.asked() == [IP]
        assert client.status()["remaining"] == 0

    def test_a_spent_quota_is_not_a_health_problem(self):
        client = make_client((429, {}, b""))
        client.check(IP)
        assert client.problems() == []


class TestFailures:
    @pytest.mark.parametrize(
        "error",
        [
            TimeoutError("timed out"),
            socket.timeout("timed out"),
            urllib.error.URLError(TimeoutError("connect timed out")),
        ],
    )
    def test_a_timeout(self, error):
        answer = make_client(error).check(IP)
        assert answer == {"ok": False, "reason": "AbuseIPDB did not answer in time"}

    def test_unreachable(self, caplog):
        answer = make_client(urllib.error.URLError("nodename nor servname")).check(IP)
        assert answer == {"ok": False, "reason": "AbuseIPDB could not be reached"}
        assert KEY not in caplog.text

    def test_a_rejected_key_is_a_health_problem_until_one_works(self):
        clock = Clock()
        client = make_client(
            (401, {}, b'{"errors":[{"detail":"Authentication failed"}]}'), clock=clock
        )
        assert client.check(IP) == {
            "ok": False,
            "reason": "AbuseIPDB rejected this service's API key",
        }
        assert client.status()["key_rejected"] is True
        assert "ABUSEIPDB_API_KEY" in client.problems()[0]
        clock.advance(abuseipdb.ERROR_TTL_SECONDS + 1)
        assert client.check(IP)["ok"]
        assert client.problems() == []

    @pytest.mark.parametrize(
        "raw",
        [
            b"<html>Cloudflare</html>",
            b'{"data": {}}',
            b'{"data": {"abuseConfidenceScore": 101}}',
            b'{"data": {"abuseConfidenceScore": true}}',
            b'{"data": {"abuseConfidenceScore": "87"}}',
            b"[]",
            b"x" * (abuseipdb.MAX_RESPONSE_BYTES + 1),
        ],
    )
    def test_an_unreadable_answer(self, raw):
        answer = make_client((200, {}, raw)).check(IP)
        assert answer == {"ok": False, "reason": "AbuseIPDB's answer could not be read"}

    def test_odd_counts_are_left_out(self):
        raw = body(reports=-1, reporters="40", last="yesterday")
        answer = make_client((200, {}, raw)).check(IP)
        assert answer["score"] == 87
        assert (answer["reports"], answer["reporters"]) == (None, None)
        assert answer["last_reported_at"] is None


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list[dict] = []
    reply = (200, {}, b"{}")

    def do_GET(self):  # noqa: N802 - the stdlib's name
        type(self).seen.append(dict(self.headers.items()))
        status, headers, payload = type(self).reply
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.seen = []
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/v2/check"
    finally:
        server.shutdown()
        server.server_close()


class TestTransport:
    """abuseipdb._request, the real urllib call, against a server on loopback."""

    def test_sends_the_key_as_a_header(self, local_server):
        _Handler.reply = (200, {"X-RateLimit-Remaining": "998"}, body())
        status, headers, raw = abuseipdb._request(local_server, KEY, 2)
        assert status == 200
        assert headers["x-ratelimit-remaining"] == "998"
        assert json.loads(raw)["data"]["abuseConfidenceScore"] == 87
        [sent] = _Handler.seen
        assert sent["Key"] == KEY
        assert sent["Accept"] == "application/json"

    def test_an_error_status_is_returned_with_its_headers(self, local_server):
        _Handler.reply = (429, {"Retry-After": "29241"}, b'{"errors":[]}')
        status, headers, _ = abuseipdb._request(local_server, KEY, 2)
        assert (status, headers["retry-after"]) == (429, "29241")


# --- merging into the reputation answer ---------------------------------------------


TOR = {
    "id": "tor_exit",
    "label": "Tor exit",
    "source": "Tor Project",
    "as_of": "2026-10-09T06:00:00Z",
}


def lists(signals=(), checked=(TOR,)):
    return {
        "level": "medium" if signals else "none",
        "signals": [{**TOR, "weight": 50}] if signals else [],
        "checked": list(checked),
        "unavailable": [],
        "attribution": ["Tor exit list: the Tor Project, check.torproject.org"],
    }


def answer(score=87, **changes):
    return {**make_client((200, {}, body(score=score))).check(IP), **changes}


def ids(entries):
    return [entry["id"] for entry in entries]


class TestMerge:
    def test_no_answer_changes_nothing(self):
        reputation = lists()
        assert merge(reputation, None) is reputation

    def test_the_score_is_the_weight(self):
        merged = merge(lists(signals=True), answer(87))
        assert ids(merged["signals"]) == ["tor_exit", "abuseipdb"]
        assert merged["signals"][1]["weight"] == 87
        assert merged["level"] == "high"
        assert ids(merged["checked"]) == ["tor_exit", "abuseipdb"]

    @pytest.mark.parametrize(
        "score, level", [(0, "none"), (9, "none"), (10, "low"), (40, "medium")]
    )
    def test_alone_the_score_grades_on_the_usual_bands(self, score, level):
        assert merge(lists(), answer(score))["level"] == level

    def test_a_zero_score_is_checked_not_a_signal(self):
        merged = merge(lists(), answer(0))
        assert merged["signals"] == []
        assert merged["checked"][-1]["score"] == 0

    def test_a_failure_is_could_not_check(self):
        merged = merge(lists(), {"ok": False, "reason": "AbuseIPDB answered HTTP 503"})
        assert merged["unavailable"] == [
            {
                "id": "abuseipdb",
                "label": "AbuseIPDB",
                "source": "AbuseIPDB",
                "reason": "AbuseIPDB answered HTTP 503",
            }
        ]
        assert merged["level"] == "none"

    def test_with_the_lists_off(self):
        """REPUTATION_ENABLED=false turns AbuseIPDB off too, but merge() copes
        with no list answer: the level is AbuseIPDB's alone, or unknown."""
        assert merge(None, answer(50))["level"] == "medium"
        failed = merge(None, {"ok": False, "reason": "x"})
        assert failed["level"] is None

    def test_credits_abuseipdb_once(self):
        merged = merge(merge(lists(), answer()), answer())
        assert merged["attribution"].count(abuseipdb.ATTRIBUTION) == 1

    def test_leaves_its_input_alone(self):
        reputation = lists(signals=True)
        before = json.dumps(reputation, sort_keys=True)
        merge(reputation, answer())
        assert json.dumps(reputation, sort_keys=True) == before


# --- where it is asked, and where it is not ----------------------------------------

CURL = {"user-agent": "curl/8"}
CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
web = TestClient(main.app)


def as_peer(ip):
    return TestClient(main.app, client=(ip, 41234))


@pytest.fixture
def abuse(monkeypatch):
    """An enabled client over FakeApi, wherever a lookup asks for one."""

    def install(*responses):
        enabled = make_client(*responses)
        monkeypatch.setattr(lookup, "abuseipdb_client", enabled)
        monkeypatch.setattr(main, "abuseipdb_client", enabled)
        return enabled

    return install


@pytest.fixture
def legs():
    """Every other leg of a lookup answered locally."""
    resolver = MagicMock()
    resolver.resolve.return_value = [IP]
    location = AsyncMock(
        side_effect=lambda ip: {"ip": ip, "country_code": "DE", "asn_number": 60729}
    )
    whois = AsyncMock(return_value={"source": "rdap", "name": "EXAMPLE"})
    with ExitStack() as stack:
        for target in ("lookup", "main"):
            stack.enter_context(patch(f"{target}.lookup_whois", whois))
            stack.enter_context(patch(f"{target}.lookup_location", location))
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


class TestWhereItIsAsked:
    def test_an_ip_lookup(self, abuse, legs):
        api = abuse().api
        reputation = web.get(f"/{IP}", headers=CURL).json()["reputation"]
        assert api.asked() == [IP]
        assert reputation["level"] == "high"
        [signal] = reputation["signals"]
        assert (signal["id"], signal["score"], signal["reports"]) == (
            "abuseipdb",
            87,
            152,
        )

    def test_an_ipv6_lookup(self, abuse, legs):
        api = abuse().api
        web.get(f"/{V6}", headers=CURL)
        assert api.asked() == [V6]

    def test_not_the_address_a_domain_resolves_to(self, abuse, legs):
        api = abuse().api
        response = web.get("/tor-relay.example.com", headers=CURL)
        assert response.json()["resolved_ip"] == IP
        assert api.calls == []

    def test_not_the_visitors_own_address(self, abuse, legs):
        api = abuse().api
        for headers in (CURL, CHROME):
            assert as_peer(IP).get("/", headers=headers).status_code == 200
        assert as_peer(IP).get("/?fields=abuse_score", headers=CURL).json() == {
            "abuse_score": None
        }
        assert api.calls == []

    def test_not_the_mcp_callers_own_address(self, abuse, legs):
        api = abuse().api

        async def run():
            mcp_server._caller_ip.set(IP)
            return await mcp_server.whoami_caller()

        result = asyncio.run(run())
        assert result["ip"] == IP
        assert api.calls == []

    def test_not_when_the_reputation_leg_is_not_asked_for(self, abuse, legs):
        api = abuse().api
        web.get(f"/{IP}?fields=country_code", headers=CURL)
        assert api.calls == []

    def test_off_asks_nothing(self, legs):
        """The suite's default: no key, so nothing to send and no key added."""
        with patch.object(lookup.abuseipdb_client, "check") as check:
            body = web.get(f"/{IP}", headers=CURL).json()
        check.assert_not_called()
        assert "reputation" not in body

    def test_a_slow_answer_does_not_hold_the_lookup(self, abuse, legs, monkeypatch):
        monkeypatch.setattr(lookup, "ABUSEIPDB_DEADLINE_SECONDS", 0.05)
        release = threading.Event()
        enabled = abuse()
        monkeypatch.setattr(
            enabled, "check", lambda ip: release.wait(5) and {"ok": True}
        )
        try:
            reputation = web.get(f"/{IP}", headers=CURL).json()["reputation"]
        finally:
            release.set()
        assert reputation["unavailable"][-1]["reason"] == (
            "AbuseIPDB did not answer in time"
        )
        assert reputation["level"] is None


class TestFields:
    def test_abuse_score(self, abuse, legs):
        abuse()
        assert web.get(f"/{IP}?fields=abuse_score", headers=CURL).json() == {
            "abuse_score": 87
        }
        text = web.get(f"/{IP}?fields=abuse_score&format=text", headers=CURL)
        assert text.text == "87\n"

    def test_unknown_when_abuseipdb_did_not_answer(self, abuse, legs):
        abuse((503, {}, b""))
        text = web.get(f"/{IP}?fields=abuse_score&format=text", headers=CURL)
        assert text.text == "?\n"

    def test_none_when_off_or_for_a_domain(self, abuse, legs):
        off = web.get(f"/{IP}?fields=abuse_score&format=text", headers=CURL)
        assert off.text == "-\n"
        abuse()
        domain = web.get(
            "/tor-relay.example.com?fields=abuse_score&format=text", headers=CURL
        )
        assert domain.text == "-\n"

    def test_not_in_the_text_block(self, abuse, legs):
        abuse()
        text = web.get(f"/{IP}?format=text", headers=CURL).text
        assert "abuse_score" not in text


def page_text(page):
    page = re.sub(r"<(script|svg)\b.*?</\1>", " ", page, flags=re.S | re.I)
    # Jinja escapes the apostrophe in "today's".
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", page)).split())


class TestPage:
    def test_the_card_row_links_the_reports(self, abuse, legs):
        abuse()
        page = web.get(f"/{IP}", headers=CHROME).text
        text = page_text(page)
        assert (
            "Abuse confidence 87%: 152 reports from 40 users in the last 90 days, "
            "the latest 2026-10-08 12:34 UTC (as of 2026-10-09 07:13 UTC)" in text
        )
        assert f'href="https://www.abuseipdb.com/check/{IP}"' in page
        assert abuseipdb.ATTRIBUTION in text

    def test_the_hero_tag_carries_the_score(self, abuse, legs):
        abuse()
        page = web.get(f"/{IP}", headers=CHROME).text
        tags = re.findall(r'<span class="tag tone-(\w+)">([^<]*)</span>', page)
        assert ("danger", "AbuseIPDB 87%") in tags

    def test_never_reported(self, abuse, legs):
        abuse((200, {}, body(score=0, reports=0, reporters=0, last=None)))
        text = page_text(web.get(f"/{IP}", headers=CHROME).text)
        assert "Abuse confidence 0%: no reports in the last 90 days" in text

    def test_could_not_check(self, abuse, legs):
        abuse((429, {"x-ratelimit-reset": str(int(T0 + 3600))}, b""))
        text = page_text(web.get(f"/{IP}", headers=CHROME).text)
        assert (
            "Could not check AbuseIPDB: today's AbuseIPDB quota is used up, "
            "until 08:13 UTC" in text
        )


class TestMcp:
    def test_compact_reputation_names_the_score(self):
        compact = mcp_server.compact_reputation(merge(lists(), answer(87)))
        assert compact["abuseipdb"] == {
            "abuse_confidence": 87,
            "reports": 152,
            "reporters": 40,
            "last_reported_at": "2026-10-08T12:34:56Z",
            "window_days": 90,
            "as_of": "2026-10-09T07:13:20Z",
            "url": f"https://www.abuseipdb.com/check/{IP}",
        }
        assert "abuseipdb" in [s["id"] for s in compact["signals"]]

    def test_left_out_when_not_asked(self):
        assert "abuseipdb" not in mcp_server.compact_reputation(lists())


class TestHealthz:
    def test_off(self):
        assert web.get("/healthz").json()["abuseipdb"] == {"enabled": False}

    def test_counts_the_days_requests(self, abuse, legs):
        abuse()
        web.get(f"/{IP}", headers=CURL)
        status = web.get("/healthz").json()["abuseipdb"]
        assert status["requests_today"] == 1
        assert status["daily_limit"] == 1000
        assert status["remaining"] == 999

    def test_a_rejected_key_is_degraded(self, abuse, legs):
        abuse((401, {}, b""))
        web.get(f"/{IP}", headers=CURL)
        body = web.get("/healthz").json()
        assert "abuseipdb_key_rejected" in [r["code"] for r in body["reasons"]]
        assert body["status"] == "degraded"


class TestPrivacy:
    def test_named_when_on(self, abuse):
        abuse()
        text = page_text(web.get("/privacy", headers=CHROME).text)
        assert "api.abuseipdb.com" in text
        assert "Never your own address on the home page" in text
        assert "kept in memory for 24 hours" in text

    def test_not_named_when_off(self):
        text = page_text(web.get("/privacy", headers=CHROME).text)
        assert "abuseipdb" not in text.lower()


def test_imports_no_app_module():
    """lookup.py builds the client; abuseipdb.py importing lookup or main back
    would be a cycle."""
    source = open(abuseipdb.__file__, encoding="utf-8").read()
    imports = re.findall(r"^(?:from|import) (\w+)", source, re.M)
    assert not {"lookup", "main", "mcp_server", "managers"} & set(imports)
