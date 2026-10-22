# ruff: noqa: E501
"""static/js/as.js: the /AS<n> page's chips, filters and "Show all".

The suite has no browser, so node runs the file the way tests/test_map_pin.py
runs map.js: the pure helpers directly, the row builders against a fake
document whose nodes serialise to HTML. A row drawn in the browser must equal
the row the server drew (viewmodel.as_neighbour_table / as_prefix_table), so
the parity tests compare the two as markup.
"""

import html as htmllib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
import viewmodel

AS_JS = Path("static/js/as.js").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")
client = TestClient(main.app)
BROWSER = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}

# A document just big enough for the row builders; nodes serialise to the HTML
# the template writes (attributes in the order they were set, text escaped).
HARNESS = r"""
function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function node(tag) {
  return {
    tag, attrs: [], children: [], textContent: "",
    setAttribute(name, value) { this.attrs.push([name, String(value)]); },
    appendChild(child) { this.children.push(child); return child; },
    html() {
      const attrs = this.attrs.map(([k, v]) => ` ${k}="${esc(v)}"`).join("");
      const inner = this.textContent ? esc(this.textContent) : "";
      return `<${this.tag}${attrs}>${inner}${this.children.map((c) => c.html()).join("")}</${this.tag}>`;
    },
  };
}
global.document = {
  createElement: (tag) => node(tag),
  createTextNode: (text) => ({ html: () => esc(text) }),
  getElementById: () => null,
};
const as = require(AS_JS);
const out = EXPR;
console.log(JSON.stringify(out === undefined ? null : out, (k, v) => typeof v === "bigint" ? String(v) : v));
"""


def run_js(expr):
    script = HARNESS.replace("AS_JS", json.dumps(str(AS_JS))).replace("EXPR", expr)
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def _js(expr):
    """Evaluate `as.<expr>`; the bare helpers are exported on `as`."""
    return run_js(f"as.{expr}")


@needs_node
@pytest.mark.parametrize(
    "n",
    [0, 999, 1000, 1049, 1050, 9949, 9950, 131072, 999499, 999500, 8666368, 29000000],
)
def test_human_count_matches_python(n):
    assert _js(f"humanCount({n})") == viewmodel.human_count(n)


@needs_node
@pytest.mark.parametrize(
    "name",
    ["LGDACOM-KR - LG DACOM Corporation", "TWELVE99 Arelion Sweden AB", "AS6453", ""],
)
def test_holder_matches_python(name):
    assert _js(f"holderOf({json.dumps(name)})") == (viewmodel.as_holder(name) or "")


@needs_node
@pytest.mark.parametrize("code", ["KR", "us", " de ", "", "K", "K1", "KOR", None])
def test_flag_matches_python(code):
    assert _js(f"countryFlag({json.dumps(code)})") == viewmodel.country_flag(code)


@needs_node
def test_filters():
    rows = [
        [174, "COGENT-174 - Cogent", "US", "upstream", 1, 0],
        [9318, "SKB-AS-KR - SK Broadband", "KR", "peer", 0, 0],
    ]
    assert _js(f"filterNeighbours({json.dumps(rows)}, 'peer', '')") == [rows[1]]
    assert _js(f"filterNeighbours({json.dumps(rows)}, 'all', 'as174')") == [rows[0]]
    assert _js(f"filterNeighbours({json.dumps(rows)}, 'all', '9318')") == [rows[1]]
    assert _js(f"filterNeighbours({json.dumps(rows)}, 'all', 'kr')") == [rows[1]]
    assert _js(f"filterNeighbours({json.dumps(rows)}, 'all', 'COGENT')") == [rows[0]]
    assert _js(f"filterNeighbours({json.dumps(rows)}, 'peer', 'cogent')") == []
    prefixes = [
        ["211.252.0.0/15", 15, 330, "valid", None],
        ["211.252.112.0/24", 24, 326, "valid", None],
    ]
    assert _js(f"filterPrefixes({json.dumps(prefixes)}, '211.252.112.9')") == prefixes
    assert _js(f"filterPrefixes({json.dumps(prefixes)}, '211.253.0.1')") == [
        prefixes[0]
    ]
    assert _js(f"filterPrefixes({json.dumps(prefixes)}, '/24')") == [prefixes[1]]
    assert _js("containsAddress('2001:2d8::/32', '2001:2d8:1::1')") is True
    assert _js("containsAddress('2001:2d8::/32', '2001:2d9::1')") is False
    assert _js("containsAddress('2001:2d8::/32', '211.252.0.1')") is False
    assert _js(f"groupBySlash8({json.dumps(prefixes)})") == [
        {"slash8": "211.0.0.0/8", "count": 2, "addresses": 131072, "signed": 2}
    ]
    assert _js("visibleRows([1,2,3,4,5,6,7,8,9,10,11,12], false).length") == 10
    assert _js("visibleRows([1,2,3,4,5,6,7,8,9,10,11,12], true).length") == 12


@needs_node
def test_groups_are_ordered_and_count_each_address_once():
    rows = [
        ["211.0.0.0/24", 24, 5, "invalid", "origin"],
        ["58.1.0.0/16", 16, 5, "not-found", None],
        ["58.1.2.0/24", 24, 5, None, None],
        ["58.2.0.0/16", 16, 5, "valid", None],
    ]
    assert _js(f"groupBySlash8({json.dumps(rows)})") == [
        {"slash8": "58.0.0.0/8", "count": 3, "addresses": 131072, "signed": 1},
        {"slash8": "211.0.0.0/8", "count": 1, "addresses": 256, "signed": 1},
    ]


def _squeeze(markup):
    """Template indentation and the one space between a flag and its country
    code are both whitespace between tags; compare without either."""
    return re.sub(r">\s+<", "><", markup.strip())


def _tbody(page, ident):
    block = re.search(rf'<tbody id="{ident}">(.*?)</tbody>', page, re.S).group(1)
    return _squeeze(block)


def _lists(page):
    return json.loads(
        htmllib.unescape(
            re.search(
                r'<script type="application/json" id="as-lists"[^>]*>(.*?)</script>',
                page,
                re.S,
            ).group(1)
        )
    )


@needs_node
def test_neighbour_rows_equal_the_servers(asinfo_enabled):
    page = client.get("/AS4766", headers=BROWSER).text
    lists = _lists(page)["neighbours"]
    drawn = run_js(
        f"{json.dumps(lists)}.rows.slice(0, 10).map((r) => as.neighbourRow(r, {lists['max_customers']}).html()).join('')"
    )
    assert _squeeze(drawn) == _tbody(page, "neighbour-rows")
    assert "lookup-link" in drawn


@needs_node
@pytest.mark.parametrize("family", ["v4", "v6"])
def test_prefix_rows_equal_the_servers(family):
    entries = [
        ("2001:db8::/32", 32, 400, {"state": "valid"}),
        ("2001:db8:1::/48", 48, 3, {"state": "invalid", "reason": "length"}),
        ("2001:db8:1:1::/64", 64, None, {"state": "not-found"}),
        ("10.0.0.0/8", 8, 1234, {"state": "valid"}),
        ("10.1.0.0/16", 16, 12, {"state": "invalid", "reason": "origin"}),
        ("10.1.2.0/24", 24, 7, {"state": "not-found"}),
        ("10.1.2.128/25", 25, 7, {}),
    ]
    part = {"v4": [], "v6": []}
    for prefix, plen, peers, rpki in entries:
        part["v6" if ":" in prefix else "v4"].append(
            {"prefix": prefix, "plen": plen, "ris_peers": peers, "rpki": rpki}
        )
    # as_prefix_table draws IPv4 first and IPv6 only when there is no IPv4.
    if family == "v6":
        part["v4"] = []
    page = {
        "prefixes": {
            key: {"count": len(value), "list": value} for key, value in part.items()
        }
    }
    table = viewmodel.as_prefix_table({}, page)
    server = "".join(
        f'<tr><td class="mono">{r["prefix"]}</td>'
        f'<td><span class="size-cell"><span class="size-bar" aria-hidden="true"><i style="width:{r["bar_pct"]}%"></i></span>'
        f'<span class="mono">{htmllib.escape(r["size_text"])}</span></span></td>'
        f'<td class="mono">{r["peers_text"]}</td>'
        f'<td class="tone-{r["rpki_tone"]}">{htmllib.escape(r["rpki_text"])}</td></tr>'
        for r in table["rows"]
    )
    rows = table["payload"][family]
    drawn = run_js(
        f"(() => {{ const rows = {json.dumps(rows)}; const top = as.topSize(rows, {json.dumps(family)});"
        f" return rows.map((r) => as.prefixRow(r, {json.dumps(family)}, top).html()).join(''); }})()"
    )
    assert drawn == server


def test_the_page_loads_as_js_with_the_nonce(asinfo_enabled):
    html = client.get("/AS4766", headers=BROWSER).text
    assert re.search(
        r'<script src="/static/js/as\.js" nonce="[^"]+" defer></script>', html
    )
    assert "onclick=" not in html


def test_as_js_writes_no_markup_from_data():
    source = AS_JS.read_text()
    for banned in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
        "document.write",
    ):
        assert banned not in source


# A page-shaped fake for the wiring: elements with hidden/value/attributes,
# listeners and children, found by the ids and selectors as.js asks for.
WIRING = r"""
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.hidden = true; this.textContent = ""; this.value = ""; this.disabled = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); }
  get firstChild() { return this.children[0] || null; }
  addEventListener(t, f) { this.listeners[t] = f; }
  fire(t) { this.listeners[t](); }
  scrollIntoView() { calls.push(["scroll", this.attrs.id]); }
  focus(opts) { calls.push(["focus", opts]); }
}
const calls = [];
const docListeners = {};
const ids = {};
const make = (id, tag, attrs = {}) => { const e = new El(tag); Object.assign(e.attrs, attrs); if (id) ids[id] = e; return e; };
const rel = ["all", "upstream", "downstream", "peer"].map((k) => make(null, "button", { "data-relation": k, "aria-pressed": k === "all" ? "true" : "false" }));
const fam = ["v4", "v6"].map((k) => make(null, "button", { "data-family": k, "aria-pressed": k === "v4" ? "true" : "false" }));
const jump = make(null, "a", { "data-relation": "upstream" });
const lists = LISTS;
const script = make("as-lists", "script"); script.textContent = JSON.stringify(lists);
["neighbour-rows", "neighbours-more", "neighbour-filter", "prefix-rows", "prefixes-more", "prefix-filter", "prefix-group"].forEach((i) => make(i, "x", i === "prefix-group" ? { "aria-pressed": "false" } : {}));
if (CITY_MARKUP) {
  make("prefix-city", "button"); make("prefix-here-col", "th"); make("as-prefixes", "section", { id: "as-prefixes" });
}
global.document = {
  addEventListener: (t, f) => { docListeners[t] = f; },
  createElement: (t) => new El(t),
  createTextNode: (t) => ({ text: t }),
  getElementById: (i) => ids[i] || null,
  querySelectorAll: (s) => (s.includes("data-relation") ? rel : s.includes("data-family") ? fam : []),
  querySelector: (s) => (s.startsWith("a.") ? jump : fam.find((f) => f.attrs["aria-pressed"] === "true") || null),
};
require(AS_JS);
const text = (e) => e.children.map((r) => r.children.length ? r.children[0].children.length && r.children[0].children[0].textContent : "");
SCENARIO
"""


def run_wiring(lists, scenario, city_markup=True):
    script = WIRING.replace("AS_JS", json.dumps(str(AS_JS)))
    script = script.replace("CITY_MARKUP", "true" if city_markup else "false")
    script = script.replace("LISTS", json.dumps(lists)).replace("SCENARIO", scenario)
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def _neighbours(n):
    return [
        [
            1000 + i,
            f"H{i} - Holder {i}",
            "KR",
            "peer" if i % 2 else "upstream",
            n - i,
            0,
        ]
        for i in range(n)
    ]


@needs_node
def test_the_controls_appear_and_show_all_toggles():
    lists = {
        "neighbours": {"rows": _neighbours(25), "max_customers": 25},
        "prefixes": {"v4": [], "v6": []},
    }
    out = run_wiring(
        lists,
        """
const rows = ids["neighbour-rows"], more = ids["neighbours-more"], filter = ids["neighbour-filter"];
const log = [];
log.push([filter.hidden, rel.every((c) => !c.hidden), more.hidden, more.textContent]);
more.fire("click"); log.push([rows.children.length, more.textContent]);
more.fire("click"); log.push([rows.children.length, more.textContent]);
rel[1].fire("click"); log.push([rel[1].attrs["aria-pressed"], rel[0].attrs["aria-pressed"], rows.children.length, more.hidden]);
filter.value = "zzz"; filter.fire("input");
log.push([rows.children.length, rows.children[0].children[0].textContent, rows.children[0].children[0].attrs.colspan, more.hidden]);
filter.value = ""; rel[0].fire("click"); filter.value = "as1003"; filter.fire("input");
log.push([rows.children.length, more.hidden]);
filter.value = ""; jump.fire("click"); log.push(rel[1].attrs["aria-pressed"]);
console.log(JSON.stringify(log));
""",
    )
    assert out == [
        [False, True, False, "Show all 25 neighbours"],
        [25, "Show fewer"],
        [10, "Show all 25 neighbours"],
        ["true", "false", 10, False],
        [1, "No neighbours match the filter.", "6", True],
        [1, True],
        "true",
    ]


@needs_node
def test_the_family_switch_and_grouping():
    v4 = [[f"58.{i}.0.0/16", 16, 5, "valid", None] for i in range(12)]
    v6 = [["2001:db8::/32", 32, 5, None, None]]
    lists = {
        "neighbours": {"rows": [], "max_customers": 0},
        "prefixes": {"v4": v4, "v6": v6},
    }
    out = run_wiring(
        lists,
        """
const rows = ids["prefix-rows"], more = ids["prefixes-more"], group = ids["prefix-group"];
const log = [];
log.push([group.hidden, more.textContent]);
group.fire("click"); log.push([group.attrs["aria-pressed"], rows.children.length, rows.children[0].children[0].children[0].tag, more.hidden]);
fam[1].fire("click"); log.push([group.disabled, group.attrs["aria-pressed"], rows.children.length, more.hidden, fam[1].attrs["aria-pressed"]]);
fam[0].fire("click"); log.push([group.disabled, rows.children.length, more.textContent]);
console.log(JSON.stringify(log));
""",
    )
    assert out == [
        [False, "Show all 12 prefixes"],
        ["true", 1, "details", True],
        [True, "false", 1, True, "true"],
        [False, 10, "Show all 12 prefixes"],
    ]


@needs_node
def test_city_rows_follow_the_pairs_and_skip_bad_indices():
    rows = [["a"], ["b"], ["c"]]
    pairs = [[2, "100%"], [9, "5%"], [0, "50%"]]
    assert _js(f"cityRows({json.dumps(rows)}, {json.dumps(pairs)})") == [
        {"row": ["c"], "here": "100%"},
        {"row": ["a"], "here": "50%"},
    ]


@needs_node
def test_a_here_cell_follows_the_rpki_cell():
    row = ["58.1.0.0/16", 16, 5, "valid", None]
    drawn = run_js(f"as.prefixRow({json.dumps(row)}, 'v4', 65536, '6%').html()")
    assert drawn.endswith(
        '<td class="tone-success">Valid</td><td class="mono">6%</td></tr>'
    )
    plain = run_js(f"as.prefixRow({json.dumps(row)}, 'v4', 65536).html()")
    assert plain.endswith('<td class="tone-success">Valid</td></tr>')


@needs_node
def test_city_filter_combines_and_clears():
    v4 = [[f"58.{i}.0.0/16", 16, 5, "valid", None] for i in range(12)]
    v6 = [["2001:db8::/32", 32, 5, None, None]]
    lists = {
        "neighbours": {"rows": [], "max_customers": 0},
        "prefixes": {"v4": v4, "v6": v6},
    }
    out = run_wiring(
        lists,
        """
const rows = ids["prefix-rows"], more = ids["prefixes-more"], group = ids["prefix-group"];
const filter = ids["prefix-filter"], chip = ids["prefix-city"], col = ids["prefix-here-col"];
const first = (r) => r.children[0].textContent;
const log = [];
docListeners["as:city"]({ detail: { name: "Seoul", pairs: [[3, "100%"], [1, "40%"], [5, "under 1%"]] } });
log.push([chip.hidden, chip.textContent, chip.attrs["aria-label"], col.hidden,
  rows.children.map(first), rows.children.map((r) => r.children.length),
  rows.children.map((r) => r.children[4].textContent),
  fam[0].attrs["aria-pressed"], more.hidden, calls.filter((c) => c[0] === "scroll").length,
  calls.filter((c) => c[0] === "focus").length]);
filter.value = "58.1.0.0"; filter.fire("input");
log.push(rows.children.map(first));
filter.value = ""; filter.fire("input");
group.fire("click");
log.push(rows.children.map((r) => r.children[0].children[0].children[1].children[0].children.map((t) => t.children[0].textContent)));
group.fire("click");
fam[1].fire("click");
log.push([chip.hidden, col.hidden, rows.children.map(first)]);
fam[0].fire("click");
docListeners["as:city"]({ detail: { name: "Busan", pairs: [[0, "9%"]] } });
log.push([chip.textContent, rows.children.length]);
chip.fire("click");
log.push([chip.hidden, col.hidden, rows.children.length, more.textContent]);
console.log(JSON.stringify(log));
""",
    )
    assert out == [
        [
            False,
            "Seoul \u2715",
            "Clear the city filter: Seoul",
            False,
            ["58.3.0.0/16", "58.1.0.0/16", "58.5.0.0/16"],
            [5, 5, 5],
            ["100%", "40%", "under 1%"],
            "true",
            True,
            1,
            1,
        ],
        ["58.1.0.0/16"],
        [["58.3.0.0/16", "58.1.0.0/16", "58.5.0.0/16"]],
        [True, True, ["2001:db8::/32"]],
        ["Busan \u2715", 1],
        [True, True, 10, "Show all 12 prefixes"],
    ]


@needs_node
def test_a_city_event_without_the_new_markup_is_ignored():
    lists = {
        "neighbours": {"rows": [], "max_customers": 0},
        "prefixes": {"v4": [["58.1.0.0/16", 16, 5, "valid", None]] * 12, "v6": []},
    }
    out = run_wiring(
        lists,
        """
const rows = ids["prefix-rows"];
const before = rows.children.length;
if (docListeners["as:city"]) docListeners["as:city"]({ detail: { name: "Seoul", pairs: [[0, "1%"]] } });
console.log(JSON.stringify([before, rows.children.length, calls.length]));
""",
        city_markup=False,
    )
    assert out == [0, 0, 0]
