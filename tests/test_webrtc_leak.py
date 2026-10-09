"""The Fingerprint panel's WebRTC leak test (static/js/webrtc.js).

A VPN user opens a "what is my IP" page mostly to see whether their real
address gets out. WebRTC is the classic way it does: the browser asks a STUN
server which public address its UDP traffic leaves from, and that can be the
ISP's address while the page itself was fetched over the VPN.

The test is opt-in, asks one STUN server, compares in the browser, and sends
nothing to this server (settled decision 5). The comparison is done per address
family: a dual-stack visitor whose page load went over IPv4 and whose WebRTC
also shows an IPv6 address has not leaked anything, and must not be told so.

The page half runs on TestClient with every lookup mocked. The comparison and
the button's behaviour run webrtc.js itself in node, against a fake DOM and a
fake RTCPeerConnection, so nothing touches the network.
"""

import copy
import json
import re
import shutil
import subprocess
from contextlib import contextmanager
from html import unescape
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import config
from main import app

VISITOR_IP = "118.235.14.201"
client = TestClient(app, client=(VISITOR_IP, 41234))

CHROME = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
VISITOR_LOCATION = {
    "ip": VISITOR_IP,
    "country_code": "KR",
    "country_name": "South Korea",
    "city_name": "Seoul",
    "cidr": "118.235.0.0/16",
    "asn_name": "Korea Telecom",
    "is_private": False,
}
NASA = {
    "address": "nasa.gov",
    "domain": {"a": [{"ip": "192.0.66.108", "ttl": 300}], "mx": [], "ns": []},
    "location": {**VISITOR_LOCATION, "ip": "192.0.66.108", "country_code": "US"},
    "whois": {"source": "rdap", "registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "192.0.66.108",
    "reverse_dns": None,
}


@contextmanager
def mocked_lookups():
    allowed = {"allowed": True, "country": "KR", "region": None, "reason": "test"}
    with (
        patch("main.geo_block_manager.check_access", return_value=allowed),
        patch(
            "main.gather",
            new_callable=AsyncMock,
            side_effect=lambda *_: copy.deepcopy(NASA),
        ),
        patch(
            "main.lookup_location",
            new_callable=AsyncMock,
            side_effect=lambda *_: dict(VISITOR_LOCATION),
        ),
        patch(
            "main.lookup_whois",
            new_callable=AsyncMock,
            return_value={"source": "rdap", "name": "KT"},
        ),
        patch("main.domain_manager.perform_reverse_lookup", return_value=None),
    ):
        yield


def _page(path="/"):
    with mocked_lookups():
        response = client.get(path, headers={"user-agent": CHROME})
    assert response.status_code == 200
    return response


def _attr(html, element_id, name):
    tag = re.search(rf'<[^>]*\bid="{element_id}"[^>]*>', html)
    assert tag, f"no #{element_id}"
    found = re.search(rf'\b{name}="([^"]*)"', tag.group(0))
    assert found, f"#{element_id} has no {name}"
    return unescape(found.group(1))


def _footer(html):
    return re.search(r"<footer\b.*?</footer>", html, re.S).group(0)


# --- The page ------------------------------------------------------------------


class TestSelfPage:
    def test_offers_the_test_as_a_button(self):
        html = _page().text
        assert _attr(html, "webrtc-run", "type") == "button"

    def test_names_the_configured_stun_server(self):
        """The script reads the server from the page, so the one in config is
        the one disclosed and the one used."""
        html = _page().text
        assert _attr(html, "webrtc", "data-stun") == config.WEBRTC_STUN_URL
        assert config.WEBRTC_STUN_URL.startswith("stun:")

    def test_hands_the_script_the_address_this_page_saw(self):
        html = _page().text
        assert _attr(html, "webrtc", "data-observed") == VISITOR_IP

    def test_says_where_the_request_goes_before_it_is_made(self):
        html = _page().text
        test = re.search(r'<div class="webrtc".*?</div>', html, re.S).group(0)
        assert config.WEBRTC_STUN_HOST in test

    def test_footer_discloses_the_stun_server(self):
        """Like the map tiles, the one other host the browser may contact is
        named on the page itself."""
        footer = _footer(_page().text)
        assert config.WEBRTC_STUN_HOST in footer

    def test_loads_the_script_with_the_nonce(self):
        html = _page().text
        assert re.search(
            r'<script src="/static/js/webrtc\.js" nonce="[^"]+" defer></script>', html
        )

    def test_the_script_is_served(self):
        response = client.get("/static/js/webrtc.js")
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]


class TestLookupPage:
    """The test compares against the visitor's own address, which a lookup
    page for someone else's domain does not show."""

    def test_has_no_test_and_no_script(self):
        html = _page("/nasa.gov").text
        assert 'id="webrtc"' not in html
        assert "webrtc.js" not in html

    def test_footer_does_not_mention_stun(self):
        assert config.WEBRTC_STUN_HOST not in _footer(_page("/nasa.gov").text)


def test_unset_stun_server_removes_the_test():
    """WEBRTC_STUN_URL= turns the test off rather than leaving a button that
    can only fail."""
    with patch("main.WEBRTC_STUN_URL", ""), patch("main.WEBRTC_STUN_HOST", ""):
        html = _page().text
    assert 'id="webrtc"' not in html
    assert "webrtc.js" not in html
    assert "STUN" not in _footer(html)


def test_csp_is_not_widened_for_stun():
    """STUN is not a fetch: no CSP directive governs it, so nothing in the
    policy had to change, and nothing did."""
    csp = _page().headers["content-security-policy"]
    assert "connect-src" not in csp
    assert config.WEBRTC_STUN_HOST.split(":")[0] not in csp
    assert "default-src 'self'" in csp


# --- webrtc.js in node ----------------------------------------------------------

WEBRTC_JS = Path("static/js/webrtc.js").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")


def _node(script):
    # The script is a fixed harness plus webrtc.js's own source.
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def _compare(observed, lines):
    return _node(
        f"const m = require({json.dumps(str(WEBRTC_JS))});"
        f"console.log(JSON.stringify(m.compare({json.dumps(observed)}, "
        f"{json.dumps(lines)})));"
    )


def _srflx(address, port=54321):
    return (
        f"candidate:842163049 1 udp 1677729535 {address} {port} typ srflx "
        "raddr 0.0.0.0 rport 0 generation 0 ufrag abcd network-cost 999"
    )


def _host(address):
    return f"candidate:1 1 udp 2122260223 {address} 50000 typ host generation 0"


def _verdicts(result):
    return {f["family"]: f["verdict"] for f in result["families"]}


@needs_node
class TestCompare:
    def test_same_address_is_no_leak(self):
        result = _compare("203.0.113.10", [_srflx("203.0.113.10")])
        assert result["overall"] == "clean"
        assert _verdicts(result) == {4: "same", 6: "none"}

    def test_a_different_address_is_a_leak(self):
        """On a VPN: the page came through the tunnel, STUN went around it."""
        result = _compare("198.51.100.1", [_srflx("203.0.113.10")])
        assert result["overall"] == "leak"
        family = result["families"][0]
        assert family["family"] == 4
        assert family["verdict"] == "different"
        assert family["webrtc"] == ["203.0.113.10"]
        assert family["page"] == "198.51.100.1"

    def test_the_vpn_address_plus_another_is_still_a_leak(self):
        """One srflx per interface: the tunnel's matches, the real one leaks."""
        result = _compare(
            "198.51.100.1", [_srflx("198.51.100.1"), _srflx("203.0.113.10")]
        )
        assert result["overall"] == "leak"
        assert result["families"][0]["webrtc"] == ["198.51.100.1", "203.0.113.10"]

    def test_dual_stack_is_not_a_leak(self):
        """The page saw IPv4; WebRTC also shows IPv6. Nothing to compare the
        IPv6 address with, so it is reported as uncompared, not leaked."""
        result = _compare(
            "203.0.113.10", [_srflx("203.0.113.10"), _srflx("2001:db8::7")]
        )
        assert result["overall"] == "partial"
        families = {f["family"]: f for f in result["families"]}
        assert families[4]["verdict"] == "same"
        assert families[6]["verdict"] == "unverifiable"
        assert families[6]["webrtc"] == ["2001:db8::7"]
        assert families[6]["page"] is None

    def test_dual_stack_seen_over_ipv6(self):
        result = _compare(
            "2001:db8::7", [_srflx("203.0.113.10"), _srflx("2001:db8::7")]
        )
        assert result["overall"] == "partial"
        assert _verdicts(result) == {4: "unverifiable", 6: "same"}

    def test_only_the_other_family_is_not_compared(self):
        result = _compare("203.0.113.10", [_srflx("2001:db8::7")])
        assert result["overall"] == "uncompared"
        assert _verdicts(result) == {4: "none", 6: "unverifiable"}

    def test_ipv6_is_compared_by_value_not_by_spelling(self):
        result = _compare("2001:DB8:0:0:0:0:0:7", [_srflx("2001:db8::7")])
        assert result["overall"] == "clean"

    def test_ipv4_mapped_page_address_is_ipv4(self):
        """A dual-stack socket can report an IPv4 client as ::ffff:a.b.c.d."""
        result = _compare("::ffff:203.0.113.10", [_srflx("203.0.113.10")])
        assert result["overall"] == "clean"

    def test_host_candidates_are_ignored(self):
        """Host candidates are mDNS names in current browsers, or a LAN
        address; neither is what a site sees. Only srflx counts."""
        result = _compare(
            "203.0.113.10",
            [
                _host("0f3a9c1e-5d2b-4c7a-9e8f-1a2b3c4d5e6f.local"),
                _host("192.168.1.20"),
                _host("198.51.100.99"),
                _srflx("203.0.113.10"),
            ],
        )
        assert result["overall"] == "clean"

    def test_no_srflx_is_not_reported_as_safe(self):
        """Blocked UDP and a WebRTC-blocking extension look the same from
        here: no answer. That is "could not check", never "no leak"."""
        result = _compare(
            "203.0.113.10", [_host("0f3a9c1e-5d2b-4c7a-9e8f-1a2b3c4d5e6f.local")]
        )
        assert result["overall"] == "nothing"
        assert _compare("203.0.113.10", [])["overall"] == "nothing"

    def test_sdp_lines_and_duplicates(self):
        """The same candidate can arrive as an event and again in the final
        SDP (with its a= prefix); it is one address."""
        line = _srflx("203.0.113.10")
        result = _compare("203.0.113.10", [line, "a=" + line, line])
        assert result["families"][0]["webrtc"] == ["203.0.113.10"]

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "candidate:",
            "a=end-of-candidates",
            "candidate:1 1 udp 1 not-an-ip 1 typ srflx",
            "candidate:1 1 udp 1 999.1.1.1 1 typ srflx",
            "candidate:1 1 udp 1 203.0.113.10 1 type srflx",
        ],
    )
    def test_malformed_lines_are_skipped(self, line):
        assert _compare("203.0.113.10", [line])["overall"] == "nothing"


# A fake browser: just enough DOM for webrtc.js, a scripted RTCPeerConnection,
# and a tripwire on every way a page could send something to a server.
HARNESS = r"""
const calls = { pc: [], closed: 0, sent: [] };
const listeners = {};
function el(id) {
  return {
    id, textContent: "", className: "", hidden: true, disabled: false,
    dataset: {}, children: [], colSpan: 1,
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; },
    addEventListener(type, fn) { listeners[id + ":" + type] = fn; },
  };
}
const ids = ["webrtc", "webrtc-run", "webrtc-verdict", "webrtc-results", "webrtc-rows"];
const elements = Object.fromEntries(ids.map((id) => [id, el(id)]));
elements["webrtc"].dataset = { stun: "stun:stun.example.net:3478", observed: OBSERVED };
global.window = global;
global.document = {
  getElementById: (id) => elements[id] || null,
  createElement: (tag) => el(tag),
};
global.fetch = (...a) => calls.sent.push("fetch");
global.XMLHttpRequest = function () { calls.sent.push("xhr"); };
global.WebSocket = function () { calls.sent.push("websocket"); };
global.EventSource = function () { calls.sent.push("eventsource"); };
global.Image = function () { calls.sent.push("image"); };
global.navigator = { sendBeacon: () => calls.sent.push("beacon") };
if (CANDIDATES !== null) {
  global.RTCPeerConnection = class {
    constructor(config) {
      calls.pc.push(config);
      this.handlers = {};
      this.iceGatheringState = "new";
    }
    addEventListener(type, fn) { this.handlers[type] = fn; }
    createDataChannel() { return {}; }
    async createOffer() { return { type: "offer", sdp: "v=0\r\n" }; }
    async setLocalDescription(offer) {
      this.localDescription = offer;
      for (const [at, candidate] of CANDIDATES) {
        setTimeout(() => {
          if (candidate !== "END") {
            this.handlers.icecandidate({ candidate: { candidate } });
            return;
          }
          this.iceGatheringState = "complete";
          this.handlers.icecandidate({ candidate: null });
        }, at);
      }
    }
    close() { calls.closed += 1; }
  };
}
require(WEBRTC_JS);
(async () => {
  const before = calls.pc.length;
  const click = listeners["webrtc-run:click"];
  const started = Date.now();
  if (click) await click();
  const elapsed = Date.now() - started;
  const rows = elements["webrtc-rows"].children.map(
    (tr) => tr.children.map((td) => td.textContent));
  console.log(JSON.stringify({
    before, clickable: Boolean(click), elapsed, pc: calls.pc, closed: calls.closed,
    sent: calls.sent, verdict: elements["webrtc-verdict"].textContent,
    verdictClass: elements["webrtc-verdict"].className,
    resultsHidden: elements["webrtc-results"].hidden, rows,
  }));
})();
"""


def _click(observed, candidates, complete=True):
    """Load webrtc.js into the fake browser and press the button once.

    Each candidate is a line, delivered at once, or an (ms, line) pair.
    `complete` ends gathering after the last one, as the spec says a browser
    should; Chrome, measured, often never does. `candidates` None means a
    browser without RTCPeerConnection."""
    timed = None
    if candidates is not None:
        timed = [c if isinstance(c, tuple) else (0, c) for c in candidates]
        if complete:
            timed.append((max([at for at, _ in timed], default=0), "END"))
    script = (
        HARNESS.replace("WEBRTC_JS", json.dumps(str(WEBRTC_JS)))
        .replace("OBSERVED", json.dumps(observed))
        .replace("CANDIDATES", json.dumps(timed))
    )
    return _node(script)


@needs_node
class TestTheButton:
    def test_nothing_runs_until_it_is_clicked(self):
        run = _click("203.0.113.10", [_srflx("203.0.113.10")])
        assert run["clickable"]
        assert run["before"] == 0

    def test_a_click_asks_the_configured_stun_server_once(self):
        run = _click("203.0.113.10", [_srflx("203.0.113.10")])
        assert run["pc"] == [{"iceServers": [{"urls": "stun:stun.example.net:3478"}]}]
        assert run["closed"] == 1

    def test_nothing_is_sent_anywhere(self):
        """Settled decision 5. The CSP would allow a same-origin request, so
        this is the check that keeps it out."""
        run = _click("198.51.100.1", [_srflx("203.0.113.10")])
        assert run["sent"] == []

    def test_a_leak_is_shown_as_one(self):
        run = _click("198.51.100.1", [_srflx("203.0.113.10")])
        assert "tone-danger" in run["verdictClass"]
        assert "leak" in run["verdict"].lower()
        assert not run["resultsHidden"]
        flat = " ".join(" ".join(row) for row in run["rows"])
        assert "203.0.113.10" in flat
        assert "198.51.100.1" in flat

    def test_a_match_is_shown_as_no_leak(self):
        run = _click("203.0.113.10", [_srflx("203.0.113.10")])
        assert "tone-success" in run["verdictClass"]
        assert "no leak" in run["verdict"].lower()

    def test_dual_stack_is_not_shown_as_a_leak(self):
        run = _click("203.0.113.10", [_srflx("203.0.113.10"), _srflx("2001:db8::7")])
        assert "tone-danger" not in run["verdictClass"]
        assert "2001:db8::7" in " ".join(" ".join(row) for row in run["rows"])

    def test_a_browser_that_never_completes_is_not_waited_out(self):
        """Chrome 153 on macOS, measured: srflx after ~100 ms, then no
        end-of-gathering for 15 s and more, because the STUN request on a
        socket with no route keeps being retried. The answer is in by then."""
        run = _click("203.0.113.10", [(50, _srflx("203.0.113.10"))], complete=False)
        assert run["elapsed"] < 3000
        assert "no leak" in run["verdict"].lower()

    def test_a_second_address_arriving_just_after_still_counts(self):
        """Each interface answers separately; the leak can be the later one."""
        run = _click(
            "198.51.100.1",
            [(20, _srflx("198.51.100.1")), (400, _srflx("203.0.113.10"))],
            complete=False,
        )
        assert "tone-danger" in run["verdictClass"]

    def test_no_answer_says_it_could_not_check(self):
        run = _click("203.0.113.10", [])
        assert "tone-success" not in run["verdictClass"]
        assert "no leak" not in run["verdict"].lower()
        assert "cannot tell" in run["verdict"].lower()

    def test_a_browser_without_webrtc(self):
        """No RTCPeerConnection at all: nothing can leak through it."""
        run = _click("203.0.113.10", None)
        assert run["pc"] == []
        assert "no webrtc" in run["verdict"].lower()
