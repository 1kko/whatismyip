"""The self page goes out before a slow registration lookup has answered.

GET / shows the visitor's address, city and ASN from local databases, but it
used to wait for RDAP before sending any of it, so an RIR that stalled held the
most visited page for the whole RDAP budget. A browser's self page now gives
WHOIS SELF_WHOIS_SOFT_DEADLINE_SECONDS and then goes out with the registration
panel loading; app.js fills it from /?whois=only, which joins the lookup the
page left running instead of asking the registry a second time. JSON, text and
?fields= clients still get the whole answer in one response.

The HTTP tests use httpx's ASGI transport rather than TestClient: the lookup a
page leaves running has to still be there for the next request, and TestClient
runs each request in an event loop of its own, which cancels it on the way out.

Every outbound leg is mocked.
"""

import asyncio
import contextlib
import datetime
import gc
import json
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import concurrency
import config
import lookup
import main
from viewmodel import build_view, whois_display, whois_fill

CLIENT_IP = "8.8.8.8"
CURL = {"user-agent": "curl/8.7.1"}
CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
LOCATION = {
    "country_code": "US",
    "country_name": "United States",
    "city_name": "Mountain View",
    "asn_name": "GOOGLE",
    "is_private": False,
}
# ARIN's answer for 8.8.8.8, in rdap.py's canonical shape.
RECORD = {
    "source": "rdap",
    "rir": "arin",
    "name": "GOGL",
    "handle": "NET-8-8-8-0-2",
    "registrant": "Google LLC",
    "network": "8.8.8.0/24",
    "abuse_email": "network-abuse@google.com",
    "updated": datetime.datetime(2023, 12, 28, 17, 24, 56, tzinfo=datetime.UTC),
}

GATE = concurrency.lookup_gate
TASKS = main._self_whois_tasks


@pytest.fixture(autouse=True)
def clean_slate():
    lookup._whois_cache.clear()
    TASKS.clear()
    yield
    lookup._whois_cache.clear()
    TASKS.clear()


@pytest.fixture(autouse=True)
def quick_gate():
    """A lookup that finds every slot taken waits LOOKUP_GATE_WAIT_SECONDS
    before it is turned away; a twentieth of a second keeps the wait real."""
    with patch.object(GATE, "wait", 0.05):
        yield


@pytest.fixture(autouse=True)
def local_legs():
    """What the page waits for besides WHOIS: GeoIP, and a PTR that finds no
    name, so there is no record sweep to mock as well."""
    geo = AsyncMock(side_effect=lambda ip: {**LOCATION, "ip": ip})
    with (
        patch("main.lookup_location", geo),
        patch.object(
            lookup.domain_manager,
            "perform_reverse_lookup",
            MagicMock(return_value=None),
        ),
    ):
        yield


@pytest.fixture
def short_deadline():
    with patch.object(main, "SELF_WHOIS_SOFT_DEADLINE_SECONDS", 0.05):
        yield


class Registry:
    """lookup_whois for an RIR that answers only when told to, or after a few
    seconds, so a page that waits for it fails its test instead of hanging."""

    def __init__(self):
        self.calls = []
        self.release = asyncio.Event()

    async def __call__(self, target):
        self.calls.append(target)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.release.wait(), 3)
        return dict(RECORD)


@pytest.fixture
def registry():
    slow = Registry()
    with patch("main.lookup_whois", slow):
        yield slow


@pytest.fixture
def quick_registry():
    quick = AsyncMock(side_effect=lambda target: dict(RECORD))
    with patch("main.lookup_whois", quick):
        yield quick


class SlowRdap:
    """lookup.lookup_rdap blocking its registration-pool thread until told to
    answer, so the real lookup_whois runs, and caches, around it."""

    def __init__(self):
        self.calls = []
        self.release = threading.Event()

    def __call__(self, target):
        self.calls.append(target)
        self.release.wait(timeout=3)
        return dict(RECORD)


@pytest.fixture
def slow_rdap(monkeypatch):
    rdap = SlowRdap()
    monkeypatch.setattr(lookup, "lookup_rdap", rdap)
    yield rdap
    rdap.release.set()


def _client(ip=CLIENT_IP):
    transport = httpx.ASGITransport(app=main.app, client=(ip, 41234))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@contextlib.asynccontextmanager
async def _holding(slots):
    """Hold `slots` of the lookup gate's slots for the block."""
    async with contextlib.AsyncExitStack() as stack:
        for _ in range(slots):
            await stack.enter_async_context(GATE.slot())
        yield


async def settle():
    """Wait for every registration lookup a page left running to finish."""
    pending = list(TASKS.values())
    if pending:
        await asyncio.wait(pending, timeout=5)
    await asyncio.sleep(0)  # the done callbacks that drop them from TASKS


def _accordion(html, name):
    return html.split(f'id="acc-{name}"')[1].split("</details>")[0]


def _hint(html, name):
    return re.search(rf'id="hint-{name}">([^<]*)<', html).group(1)


def _column(html, name):
    """The (label, value) rows of one column of the facts strip."""
    block = html.split(f'id="facts-{name}"')[1]
    block = re.split(r'<div class="facts__col"|</section>', block)[0]
    return re.findall(
        r'class="kv-label">([^<]*)</span>\s*<span class="kv-value[^"]*">([^<]*)<',
        block,
    )


def _page_data(html):
    raw = re.search(
        r'<script type="application/json" id="page-data"[^>]*>(.*?)</script>',
        html,
        re.S,
    ).group(1)
    return json.loads(raw.replace("<\\/", "</"))


class TestFirstPaint:
    async def test_the_page_does_not_wait_out_a_stalled_registry(self, registry):
        """The configured deadline, not a patched one: the page is sent while
        the registry still has not answered."""
        assert config.SELF_WHOIS_SOFT_DEADLINE_SECONDS == 1.5
        async with _client() as client:
            started = time.perf_counter()
            page = await client.get("/", headers=CHROME)
            elapsed = time.perf_counter() - started
            registry.release.set()
            await settle()
        assert page.status_code == 200
        assert elapsed < config.SELF_WHOIS_SOFT_DEADLINE_SECONDS + 1.0
        assert 'id="whois-pending"' in page.text
        # The rest of the first screen is all there.
        assert f'<h1 class="ip mono">{CLIENT_IP}</h1>' in page.text
        assert "Mountain View" in page.text
        assert "GOOGLE" in page.text

    async def test_the_registration_says_it_is_loading(self, registry, short_deadline):
        """Not "unavailable" or "lookup failed": nothing has failed yet."""
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            registry.release.set()
            await settle()
        html = page.text
        assert _hint(html, "whois") == "loading…"
        assert _column(html, "whois")[0] == ("Status", "loading…")
        assert {value for _, value in _column(html, "whois")[1:]} == {"…"}
        panel = _accordion(html, "whois")
        assert 'role="status"' in panel
        assert "unavailable" not in panel and "lookup failed" not in html
        assert "No WHOIS data" not in panel

    async def test_without_javascript_a_plain_link_reloads(
        self, registry, short_deadline
    ):
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            registry.release.set()
            await settle()
        noscript = _accordion(page.text, "whois").split("<noscript>")[1]
        noscript = noscript.split("</noscript>")[0]
        assert '<a href="/">' in noscript

    async def test_the_loading_panel_keeps_the_csp(self, registry, short_deadline):
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            registry.release.set()
            await settle()
        panel = _accordion(page.text, "whois")
        assert "<script" not in panel
        assert "style=" not in panel
        assert re.search(r"\son\w+=", panel) is None
        csp = page.headers["content-security-policy"]
        assert "script-src 'self' 'nonce-" in csp
        assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]

    async def test_the_raw_json_marks_the_registration_pending(
        self, registry, short_deadline
    ):
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            registry.release.set()
            await settle()
        assert _page_data(page.text)["whois"] == {"pending": True}

    async def test_an_answer_inside_the_deadline_is_rendered_in_place(
        self, quick_registry
    ):
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
        assert 'id="whois-pending"' not in page.text
        assert ("Network", "8.8.8.0/24") in _column(page.text, "whois")
        assert "Google LLC" in _accordion(page.text, "whois")
        assert _page_data(page.text)["whois"]["network"] == "8.8.8.0/24"


class TestWhoisOnly:
    async def test_it_joins_the_lookup_the_page_left_running(
        self, registry, short_deadline
    ):
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            assert 'id="whois-pending"' in page.text
            fill = asyncio.create_task(client.get("/?whois=only", headers=CHROME))
            await asyncio.sleep(0.1)
            assert not fill.done()  # waiting on the registry, not refused
            registry.release.set()
            response = await fill
            await settle()
        assert response.status_code == 200
        body = response.json()
        assert body["address"] == CLIENT_IP
        assert body["whois"]["network"] == "8.8.8.0/24"
        # One question to the registry for the page and its fill-in together.
        assert registry.calls == [CLIENT_IP]

    async def test_it_reads_the_cache_the_lookup_filled(
        self, slow_rdap, short_deadline
    ):
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            assert 'id="whois-pending"' in page.text
            slow_rdap.release.set()
            await settle()
            response = await client.get("/?whois=only", headers=CHROME)
        assert response.status_code == 200
        assert response.json()["whois"]["network"] == "8.8.8.0/24"
        assert slow_rdap.calls == [CLIENT_IP]

    async def test_it_takes_no_slot_to_join_a_running_lookup(
        self, registry, short_deadline
    ):
        """The page that left the lookup running still holds a slot for it, so
        joining it starts nothing the gate has not already counted."""
        async with _client() as client:
            await client.get("/", headers=CHROME)
            async with _holding(GATE.size - 1):
                fill = asyncio.create_task(client.get("/?whois=only", headers=CURL))
                await asyncio.sleep(0.1)
                registry.release.set()
                response = await fill
            await settle()
        assert response.status_code == 200
        assert registry.calls == [CLIENT_IP]

    async def test_it_takes_no_slot_to_read_the_cache(self, slow_rdap, short_deadline):
        async with _client() as client:
            await client.get("/", headers=CHROME)
            slow_rdap.release.set()
            await settle()
            async with _holding(GATE.size):
                response = await client.get("/?whois=only", headers=CURL)
        assert response.status_code == 200
        assert response.json()["whois"]["network"] == "8.8.8.0/24"

    async def test_with_nothing_to_join_it_asks_once_and_takes_a_slot(
        self, quick_registry
    ):
        """The cached answer expired, or a client asked without loading the
        page: this is a lookup like ?fields=registrant, and is gated like one."""
        async with _client() as client:
            async with _holding(GATE.size):
                busy = await client.get("/?whois=only", headers=CURL)
            assert quick_registry.call_count == 0
            response = await client.get("/?whois=only", headers=CURL)
        assert busy.status_code == 503
        assert busy.headers["retry-after"] == str(
            config.LOOKUP_BUSY_RETRY_AFTER_SECONDS
        )
        assert busy.json()["code"] == "busy"
        assert response.status_code == 200
        assert set(response.json()) == {"address", "whois", "display"}
        assert response.json()["whois"]["network"] == "8.8.8.0/24"
        assert quick_registry.call_count == 1

    async def test_it_is_json_even_to_a_browser(self, quick_registry):
        async with _client() as client:
            response = await client.get("/?whois=only", headers=CHROME)
        assert response.headers["content-type"].startswith("application/json")
        assert set(response.json()) == {"address", "whois", "display"}

    async def test_its_display_is_what_the_page_would_have_rendered(
        self, quick_registry
    ):
        """app.js writes these strings into the panel as they are, so a page
        filled in later reads exactly like one that waited."""
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            fill = await client.get("/?whois=only", headers=CHROME)
        display = fill.json()["display"]
        assert display["hint"] == _hint(page.text, "whois")
        assert [(r["label"], r["value"]) for r in display["column"]] == _column(
            page.text, "whois"
        )
        panel = _accordion(page.text, "whois")
        for row in display["rows"]:
            assert f"<td>{row['label']}</td>" in panel
            assert row["value"] in panel

    async def test_a_private_address_is_not_looked_up(self, quick_registry):
        async with _client("10.1.2.3") as client:
            response = await client.get("/?whois=only", headers=CURL)
        assert response.status_code == 200
        assert response.json() == {
            "address": "10.1.2.3",
            "whois": {"error": "Not looked up: private or reserved address"},
            "display": whois_fill(
                {"error": "Not looked up: private or reserved address"}
            ),
        }
        assert quick_registry.call_count == 0

    @pytest.mark.parametrize("value", ["", "all", "include", "1"])
    async def test_any_other_value_is_refused(self, quick_registry, value):
        """As with ?subdomains=: a value the server does not understand is not
        answered as though it were."""
        async with _client() as client:
            response = await client.get(f"/?whois={value}", headers=CURL)
            text = await client.get(f"/?whois={value}&format=text", headers=CURL)
        assert response.status_code == 400
        assert text.status_code == 400
        assert text.text.startswith("error: ")
        assert quick_registry.call_count == 0

    async def test_it_counts_against_the_rate_limit(self, registry, short_deadline):
        """Settled: a lookup path is rate limited, and the fill-in is one. A
        slow page view costs the visitor two requests."""
        async with _client() as client:
            await client.get("/", headers=CHROME)
            fill = asyncio.create_task(client.get("/?whois=only", headers=CHROME))
            await asyncio.sleep(0.05)
            registry.release.set()
            await fill
            await settle()
        assert len(main.rate_limiter.request_history[CLIENT_IP]) == 2


class TestOtherClientsStillWait:
    """Only a browser's self page goes out early. Everything else is an answer
    a program reads once, so its contract is the whole record or an error."""

    @pytest.fixture
    def answer_after_a_while(self, registry):
        """The registry answers well after the (shortened) deadline."""

        async def later():
            await asyncio.sleep(0.3)
            registry.release.set()

        return later

    async def test_json_waits_for_the_registration(
        self, registry, short_deadline, answer_after_a_while
    ):
        async with _client() as client:
            answering = asyncio.create_task(answer_after_a_while())
            response = await client.get("/", headers=CURL)
            await answering
        assert response.status_code == 200
        assert response.json()["whois"]["network"] == "8.8.8.0/24"
        assert TASKS == {}

    async def test_a_browser_asking_for_json_waits_too(
        self, registry, short_deadline, answer_after_a_while
    ):
        async with _client() as client:
            answering = asyncio.create_task(answer_after_a_while())
            response = await client.get("/?format=json", headers=CHROME)
            await answering
        assert response.json()["whois"]["network"] == "8.8.8.0/24"

    async def test_fields_wait(self, registry, short_deadline, answer_after_a_while):
        async with _client() as client:
            answering = asyncio.create_task(answer_after_a_while())
            response = await client.get("/?fields=registrant", headers=CHROME)
            await answering
        assert response.json() == {"registrant": "Google LLC"}

    async def test_text_is_still_the_bare_address(self, registry, short_deadline):
        async with _client() as client:
            response = await client.get("/?format=text", headers=CURL)
        assert response.text == f"{CLIENT_IP}\n"
        assert registry.calls == []


class TestTheGate:
    async def test_the_page_keeps_its_slot_until_the_lookup_ends(
        self, registry, short_deadline
    ):
        """The gate counts lookups, not responses: the one the page left
        running still holds its slot, so a burst of slow self pages is admitted
        exactly as it was when each page waited."""
        async with _client() as client:
            async with _holding(GATE.size - 1):
                page = await client.get("/", headers=CHROME)
                assert 'id="whois-pending"' in page.text
                with pytest.raises(concurrency.LookupBusy):
                    async with GATE.slot():
                        pass
                registry.release.set()
                await settle()
                async with GATE.slot():
                    pass

    async def test_a_page_answered_in_time_gives_its_slot_back(self, quick_registry):
        async with _client() as client:
            await client.get("/", headers=CHROME)
        async with _holding(GATE.size):
            pass

    async def test_a_reload_joins_the_running_lookup_and_holds_no_slot(
        self, registry, short_deadline
    ):
        async with _client() as client:
            first = await client.get("/", headers=CHROME)
            second = await client.get("/", headers=CHROME)
            # The first page's slot is still held for the lookup; the second's
            # came back when it was sent.
            with pytest.raises(concurrency.LookupBusy):
                async with _holding(GATE.size):
                    pass
            async with _holding(GATE.size - 1):
                pass
            registry.release.set()
            await settle()
        assert 'id="whois-pending"' in first.text
        assert 'id="whois-pending"' in second.text
        assert registry.calls == [CLIENT_IP]

    async def test_a_full_gate_still_turns_the_page_away(self, registry):
        async with _client() as client, _holding(GATE.size):
            page = await client.get("/", headers=CHROME)
        assert page.status_code == 503
        assert registry.calls == []
        assert TASKS == {}


class TestTheLookupOutlivesThePage:
    async def test_it_finishes_and_fills_the_cache_after_the_response(
        self, slow_rdap, short_deadline
    ):
        """The page is sent with the lookup still running. It runs to the end
        all the same, fills the cache, and the next visit is answered from it."""
        async with _client() as client:
            page = await client.get("/", headers=CHROME)
            assert 'id="whois-pending"' in page.text
            assert lookup.cached_whois(CLIENT_IP) is None
            gc.collect()
            slow_rdap.release.set()
            await settle()
            again = await client.get("/", headers=CHROME)
        assert lookup.cached_whois(CLIENT_IP)["network"] == "8.8.8.0/24"
        assert TASKS == {}
        assert 'id="whois-pending"' not in again.text
        assert slow_rdap.calls == [CLIENT_IP]

    async def test_one_entry_per_address_and_none_once_done(
        self, registry, short_deadline
    ):
        async with _client() as client, _client("1.1.1.1") as other:
            await client.get("/", headers=CHROME)
            await client.get("/", headers=CHROME)
            await other.get("/", headers=CHROME)
            assert set(TASKS) == {CLIENT_IP, "1.1.1.1"}
            registry.release.set()
            await settle()
        assert TASKS == {}


# --- the view model ---------------------------------------------------------------


def _view(whois):
    return build_view({"address": CLIENT_IP, "whois": whois}, is_self=True)


def _whois_column(view):
    return next(c for c in view["facts"] if c["title"] == "WHOIS")


def _whois_accordion(view):
    return next(a for a in view["accordions"] if a["id"] == "whois")


class TestView:
    def test_pending_reads_as_loading(self):
        view = _view({"pending": True})
        assert view["whois_pending"] is True
        column = _whois_column(view)
        assert column["id"] == "whois"
        assert column["rows"][0] == {
            "label": "Status",
            "value": "loading…",
            "tone": "muted",
        }
        assert {row["value"] for row in column["rows"][1:]} == {"…"}
        assert _whois_accordion(view)["hint"] == "loading…"

    def test_an_answer_is_not_pending(self):
        assert _view(dict(RECORD))["whois_pending"] is False
        assert (
            _view({"error": "RIR RDAP temporarily unavailable"})["whois_pending"]
            is False
        )

    @pytest.mark.parametrize(
        "whois",
        [
            dict(RECORD),
            {"error": "RIR RDAP temporarily unavailable"},
            {"error": "not registered"},
        ],
    )
    def test_the_fill_in_says_what_the_page_would_have(self, whois):
        view = _view(whois)
        fill = whois_fill(whois)
        assert fill["hint"] == _whois_accordion(view)["hint"]
        assert fill["column"] == _whois_column(view)["rows"]
        assert fill["rows"] == [
            {"label": label, "value": value}
            for label, value in whois_display(whois).items()
        ]

    def test_a_failed_lookup_fills_in_as_a_failure(self):
        fill = whois_fill({"error": "RIR RDAP temporarily unavailable"})
        assert fill["hint"] == "lookup failed"
        assert fill["column"][0]["value"] == "unavailable"
        assert fill["rows"] == [
            {"label": "Error", "value": "RIR RDAP temporarily unavailable"}
        ]


# --- static/js/app.js, in node ----------------------------------------------------

APP_JS = Path("static/js/app.js").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")

# Just enough of a browser to load app.js on a self page that went out with
# the registration loading: the elements it looks up by id, and a scripted
# fetch. Every other id is absent, as on a page without that panel.
HARNESS = r"""
const fetched = [];
function el(tag, id) {
  const node = {
    tag, id: id || "", textContent: "", className: "", hidden: false,
    dataset: {}, children: [], attributes: {}, colSpan: 1, href: "",
    replacedWith: null, removed: false,
    append(...nodes) { this.children.push(...nodes); },
    appendChild(node) { this.children.push(node); return node; },
    replaceWith(node) { this.replacedWith = node; },
    remove() { this.removed = true; },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    removeAttribute(name) { delete this.attributes[name]; },
    addEventListener() {},
    querySelectorAll(selector) {
      const cls = selector.replace(/^\./, "");
      return this.children.filter(
        (child) => !child.removed && child.className.split(" ").includes(cls));
    },
    classList: { add() {}, remove() {} },
  };
  return node;
}
function kv(value) {
  const row = el("div");
  row.className = "kv";
  const label = el("span");
  label.className = "kv-label";
  const cell = el("span");
  cell.className = "kv-value tone-muted";
  cell.textContent = value;
  row.append(label, cell);
  row.querySelector = () => cell;
  return row;
}
const column = el("div", "facts-whois");
const title = el("h2");
title.className = "facts__title";
column.append(title, kv("loading…"), kv("…"), kv("…"));
const pageData = el("script", "page-data");
pageData.textContent = JSON.stringify({ address: "8.8.8.8", whois: { pending: true } });
const elements = {
  "lookup-form": el("form"), "lookup-input": el("input"),
  "lookup-error": el("p"), "lookup-status": el("p"), "progress": el("div"),
  "whois-pending": el("div", "whois-pending"),
  "whois-status": el("p", "whois-status"),
  "hint-whois": el("span", "hint-whois"),
  "facts-whois": column, "page-data": pageData,
};
elements["hint-whois"].textContent = "loading…";
global.window = global;
global.addEventListener = () => {};
global.document = {
  getElementById: (id) => elements[id] || null,
  createElement: (tag) => el(tag),
  querySelectorAll: () => [],
  addEventListener() {},
  head: el("head"), body: el("body"),
};
global.fetch = async (url, options) => {
  fetched.push({ url, accept: (options && options.headers || {}).Accept });
  if (RESPONSE === "network-error") throw new TypeError("Failed to fetch");
  return {
    ok: RESPONSE.status === 200,
    status: RESPONSE.status,
    json: async () => RESPONSE.body,
  };
};
require(APP_JS);
setTimeout(() => {
  const text = (node) => node && node.textContent;
  const table = elements["whois-pending"].replacedWith;
  const rows = table
    ? table.children[0].children.map((tr) => tr.children.map(text))
    : null;
  const live = column.children.filter(
    (child) => !child.removed && child.className === "kv");
  console.log(JSON.stringify({
    fetched,
    hint: text(elements["hint-whois"]),
    column: live.map((row) => [text(row.children[0]), text(row.children[1]),
                               row.children[1].className]),
    rows,
    status: text(elements["whois-status"]),
    statusLinks: elements["whois-status"].children.map((a) => [a.href, a.textContent]),
    pageWhois: JSON.parse(pageData.textContent).whois,
  }));
}, 50);
"""


def _load(status=200, body=None, network_error=False):
    response = "network-error" if network_error else {"status": status, "body": body}
    script = f"const RESPONSE = {json.dumps(response)};\n" + HARNESS.replace(
        "APP_JS", json.dumps(str(APP_JS))
    )
    # The script is a fixed harness plus app.js's own source.
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def _payload(whois):
    return {"address": CLIENT_IP, "whois": whois, "display": whois_fill(whois)}


def _jsonable(whois):
    return json.loads(json.dumps(whois, default=lambda d: d.isoformat()))


@needs_node
class TestFillIn:
    def test_it_asks_for_the_registration_alone(self):
        run = _load(body=_jsonable(_payload(RECORD)))
        assert run["fetched"] == [{"url": "/?whois=only", "accept": "application/json"}]

    def test_an_answer_fills_the_column_the_hint_and_the_panel(self):
        fill = whois_fill(RECORD)
        run = _load(body=_jsonable(_payload(RECORD)))
        assert run["hint"] == fill["hint"]
        assert run["column"] == [
            [row["label"], row["value"], f"kv-value tone-{row['tone']}"]
            for row in fill["column"]
        ]
        assert run["rows"] == [[row["label"], row["value"]] for row in fill["rows"]]
        assert run["pageWhois"]["network"] == "8.8.8.0/24"

    def test_a_failed_lookup_is_shown_as_one(self):
        whois = {"error": "RIR RDAP temporarily unavailable"}
        run = _load(body=_payload(whois))
        assert run["hint"] == "lookup failed"
        assert run["column"][0][1] == "unavailable"
        assert run["rows"] == [["Error", "RIR RDAP temporarily unavailable"]]

    @pytest.mark.parametrize(
        "status, body",
        [
            (503, {"error": "busy", "code": "busy"}),
            (429, {"error": "Too many requests"}),
            (200, {"address": CLIENT_IP, "whois": {}}),
            (200, {"display": {"hint": "x", "column": "not a list", "rows": []}}),
        ],
    )
    def test_no_answer_is_never_shown_as_an_empty_record(self, status, body):
        """A refusal, or a 200 without its rows, is "could not load", with a
        way to try again: never a blank panel that reads as no registration."""
        run = _load(status=status, body=body)
        self._assert_could_not_load(run)

    def test_a_network_error_is_could_not_load(self):
        self._assert_could_not_load(_load(network_error=True))

    @staticmethod
    def _assert_could_not_load(run):
        assert run["rows"] is None
        assert run["hint"] == "lookup failed"
        assert run["column"][0][1] == "unavailable"
        assert {row[1] for row in run["column"][1:]} == {"—"}
        assert "Could not load" in run["status"]
        assert run["statusLinks"] == [["/", "Reload"]]
        assert run["pageWhois"] == {"pending": True}
