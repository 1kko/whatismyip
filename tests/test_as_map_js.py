# ruff: noqa: E501
"""static/js/as-map.js: the /AS<n> map's zoom, pan and bubbles.

Leaflet does not run in node, so the file keeps what it decides in pure
functions (the widest zoom, which dot a click picks and how the dots stack,
the world copy a dot is drawn on, what a key does, where the arrow keys move
the focus, the bubble) and node runs those against a fake
document the way tests/test_as_page_js.py runs as.js. Leaflet is not loaded
here, so the map itself never starts; a browser checks the wiring, and the
few wiring rules that decide behaviour are pinned by text.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

AS_MAP_JS = Path("static/js/as-map.js").resolve()
CSS = Path("static/css/whatismyip.css").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")

# tests/test_as_page_js.py's document, with what a bubble's button needs: nodes
# take listeners, and the document records the events dispatched on it and
# the ids asked for.
HARNESS = r"""
function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function node(tag) {
  return {
    tag, attrs: [], children: [], textContent: "", listeners: {},
    setAttribute(name, value) { this.attrs.push([name, String(value)]); },
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
    html() {
      const attrs = this.attrs.map(([k, v]) => ` ${k}="${esc(v)}"`).join("");
      const inner = this.textContent ? esc(this.textContent) : "";
      return `<${this.tag}${attrs}>${inner}${this.children.map((c) => c.html()).join("")}</${this.tag}>`;
    },
  };
}
const events = [];
const lookups = [];
global.document = {
  createElement: (tag) => node(tag),
  createTextNode: (text) => ({ html: () => esc(text) }),
  getElementById: (id) => { lookups.push(id); return null; },
  dispatchEvent: (event) => { events.push(event); return true; },
};
const m = require(AS_MAP_JS);
const out = EXPR;
console.log(JSON.stringify(out === undefined ? null : out));
"""


def run_js(expr):
    script = HARNESS.replace("AS_MAP_JS", json.dumps(str(AS_MAP_JS)))
    script = script.replace("EXPR", expr)
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


@needs_node
def test_min_zoom_fills_the_width_once():
    assert run_js("m.minZoomFor(512)") == 1
    assert abs(run_js("m.minZoomFor(550)") - 1.1033) < 1e-3
    assert run_js("m.minZoomFor(100)") == 0


@needs_node
def test_outside_every_disk_the_nearest_dot_wins_and_far_clicks_miss():
    pts = "[{x:0,y:0,r:3},{x:10,y:0,r:3},{x:100,y:0,r:30}]"
    assert run_js(f"m.pickDot({pts}, 4, 0)") == 0
    assert run_js(f"m.pickDot({pts}, 7, 0)") == 1
    # 30 from #1 (hit 12), 60 from #2 (hit 30)
    assert run_js(f"m.pickDot({pts}, 40, 0)") == -1
    assert run_js(f"m.pickDot({pts}, 75, 0)") == 2
    assert run_js(f"m.pickDot({pts}, 5, 0)") == 0  # a tie: the lower index
    assert run_js("m.pickDot([], 5, 0)") == -1


@needs_node
def test_a_click_opens_the_disk_drawn_on_top():
    """A smaller dot is drawn above a bigger one (stackOffset), so a point in
    both disks opens the smaller; the bigger one's uncovered ring opens the
    bigger, even within the smaller one's 12px hit radius."""
    pts = "[{x:0,y:0,r:20},{x:3,y:0,r:4}]"
    assert run_js(f"m.pickDot({pts}, 3, 0)") == 1
    assert run_js(f"m.pickDot({pts}, 0, 0)") == 1  # 3px from #1's centre
    assert run_js(f"m.pickDot({pts}, 10, 0)") == 0  # 7px from #1, in its hit area
    assert run_js(f"m.pickDot({pts}, -15, 0)") == 0
    assert run_js(f"m.pickDot({pts}, 0, 19)") == 0
    # Just outside the big disk nothing is in reach: its hit radius is its own.
    assert run_js(f"m.pickDot({pts}, 0, 21)") == -1


@needs_node
def test_overlapping_disks_of_one_size_go_to_the_nearest_centre():
    pts = "[{x:0,y:0,r:6},{x:4,y:0,r:6},{x:4,y:0,r:6}]"
    assert run_js(f"m.pickDot({pts}, 1, 0)") == 0
    assert run_js(f"m.pickDot({pts}, 3, 0)") == 1  # #1 and #2 coincide: the lower
    # A smaller dot later in the list still wins inside its disk.
    assert run_js("m.pickDot([{x:0,y:0,r:6},{x:0,y:0,r:5.9}], 0, 0)") == 1


@needs_node
def test_a_smaller_dot_is_stacked_above_any_bigger_one():
    """Leaflet stacks a marker by its y on the map plus zIndexOffset; the y
    spans at most a world's height at zoom 10 (256 * 2**10 px), so one tenth
    of a pixel of radius, the payload's precision, must be worth more."""
    radii = [round(2.5 + i / 10, 1) for i in range(161)]  # 2.5 to 18.5
    offsets = run_js(f"{json.dumps(radii)}.map(m.stackOffset)")
    world = 256 * 2**10
    assert all(a - b > world for a, b in zip(offsets, offsets[1:]))
    assert all(abs(offset) + world < 2**31 for offset in offsets)


@needs_node
def test_a_dot_is_drawn_on_the_world_copy_in_view():
    """mapgeom.unwrap_lon: worldCopyJump keeps the view's centre within one
    world, so a dot unwrapped past 180 moves to the copy nearest the centre."""
    assert run_js("m.nearestCopy(186, -179)") == -174
    assert run_js("m.nearestCopy(-186, 179)") == 174
    assert run_js("m.nearestCopy(127, 127.5)") == 127
    assert run_js("m.nearestCopy(127, 10)") == 127
    # The Americas in the middle of a world-wide view: Seoul is the copy west.
    assert run_js("m.nearestCopy(127, -100)") == -233


@needs_node
def test_keys_open_a_dot_as_a_button_does():
    """Enter on its keydown; Space on its keyup, with the keydown held so the
    page does not scroll and no later key event lands in the bubble."""
    cases = [
        ("keydown", "Enter", "open"),
        ("keyup", "Enter", None),
        ("keydown", " ", "hold"),
        ("keyup", " ", "open"),
        ("keydown", "a", None),
        ("keydown", "Escape", None),
    ]
    for kind, key, action in cases:
        assert run_js(f"m.keyAction({json.dumps(kind)}, {json.dumps(key)})") == action


@needs_node
def test_arrow_keys_step_between_the_dots_without_wrapping():
    """One dot is a Tab stop; the arrows move along the payload's order
    (largest first), Home and End to its ends, and stop there."""
    cases = [
        (5, 0, "ArrowRight", 1),
        (5, 0, "ArrowDown", 1),
        (5, 3, "ArrowLeft", 2),
        (5, 3, "ArrowUp", 2),
        (5, 3, "Home", 0),
        (5, 1, "End", 4),
        (5, 4, "ArrowRight", 4),  # no wrap
        (5, 4, "ArrowDown", 4),
        (5, 0, "ArrowLeft", 0),
        (5, 0, "ArrowUp", 0),
        (5, 0, "Home", 0),
        (5, 4, "End", 4),
        (5, 2, "Enter", 2),  # not a step
        (5, 2, "a", 2),
        (5, 2, "Tab", 2),
        (5, 2, "constructor", 2),
        (1, 0, "ArrowRight", 0),
        (1, 0, "End", 0),
    ]
    for count, index, key, expected in cases:
        assert run_js(f"m.stepDot({count}, {index}, {json.dumps(key)})") == expected, (
            count,
            index,
            key,
        )


def test_one_dot_is_a_tab_stop_and_the_arrows_move_focus_without_scrolling():
    """Leaflet makes every keyboard marker a Tab stop; the map keeps one
    (a roving tabindex) and moves it with the focus. A dot off the view is
    panned in before it takes focus, which must not scroll Leaflet's
    overflow-hidden box. Leaflet's own pan on focus is off: it stops with a
    dot's centre on the edge, half of it and its ring cut off, so a Tab into
    the map brings the dot in whole through the same pan."""
    source = AS_MAP_JS.read_text(encoding="utf-8")
    assert re.search(
        r'setAttribute\("tabindex", (?:index|i) === (?:current|roving)\s*\?\s*"0"\s*:\s*"-1"\)',
        source,
    )
    assert "autoPanOnFocus: false" in source
    assert re.search(r"panInside\([^;]*animate: false", source)
    roving = source.split("function wireRoving")[1].split("\n}\n")[0]
    assert re.search(
        r'addEventListener\("focus", function \(\) \{\s*reveal\(index\);', roving
    )
    assert re.search(
        r"reveal\(next\);\s*markers\[next\]\.getElement\(\)\.focus\(\{ preventScroll: true \}\);",
        roving,
    )
    assert "stepDot(markers.length" in roving


DOT = {
    "name": "Busan",
    "place": "Busan, South Korea",
    "share_text": "9%",
    "top": [
        ["211.234.96.0/19", "100%"],
        ["106.101.128.0/18", "88%"],
        ["1.208.0.0/12", "6%"],
    ],
    "count": 61,
    "pairs": [[4, "100%"]],
    "lookup": {"text": "211.234.96.1", "href": "/211.234.96.1"},
}


@needs_node
def test_bubble_markup():
    assert run_js(f"m.bubble({json.dumps(DOT)}).html()") == (
        '<div class="as-bubble"><p class="as-bubble__place">Busan, South Korea</p>'
        '<p class="as-bubble__share tone-muted">9% of its IPv4 space</p>'
        '<p class="as-bubble__head">Prefixes with addresses here</p>'
        '<ul class="as-bubble__prefixes">'
        '<li><span class="mono">211.234.96.0/19</span> <span class="tone-muted">· 100% here</span></li>'
        '<li><span class="mono">106.101.128.0/18</span> <span class="tone-muted">· 88% here</span></li>'
        '<li><span class="mono">1.208.0.0/12</span> <span class="tone-muted">· 6% here</span></li></ul>'
        '<p class="as-bubble__more tone-muted">… 61 prefixes in all</p>'
        '<button type="button" class="as-bubble__filter">Show these in Prefixes</button>'
        '<a class="lookup-link" href="/211.234.96.1" rel="nofollow">Look up 211.234.96.1 →</a></div>'
    )


@needs_node
def test_bubble_without_lookup_or_more():
    dot = dict(DOT, top=DOT["top"][:2], count=2, lookup=None)
    markup = run_js(f"m.bubble({json.dumps(dot)}).html()")
    assert "in all" not in markup
    assert "<a " not in markup
    assert markup.endswith(
        '<button type="button" class="as-bubble__filter">Show these in Prefixes</button></div>'
    )
    assert markup.count("<li>") == 2


@needs_node
def test_bubble_counts_with_thousands_separators():
    dot = dict(DOT, count=1234)
    assert "… 1,234 prefixes in all" in run_js(f"m.bubble({json.dumps(dot)}).html()")


@needs_node
def test_bubble_without_prefixes_has_no_list_or_button():
    dot = dict(DOT, top=[], count=0, pairs=[], lookup=None)
    assert run_js(f"m.bubble({json.dumps(dot)}).html()") == (
        '<div class="as-bubble"><p class="as-bubble__place">Busan, South Korea</p>'
        '<p class="as-bubble__share tone-muted">9% of its IPv4 space</p></div>'
    )


@needs_node
def test_bubble_falls_back_to_the_name():
    dot = dict(DOT, place=None)
    assert run_js(f"m.bubble({json.dumps(dot)}).html()").startswith(
        '<div class="as-bubble"><p class="as-bubble__place">Busan</p>'
    )


@needs_node
def test_bubble_writes_names_as_text():
    dot = dict(
        DOT,
        place="<img src=x onerror=alert(1)>",
        top=[["<b>1.0.0.0/8</b>", "<i>9%</i>"]],
        lookup={"text": "<svg>", "href": '/x" onclick="y'},
    )
    markup = run_js(f"m.bubble({json.dumps(dot)}).html()")
    assert (
        '<p class="as-bubble__place">&lt;img src=x onerror=alert(1)&gt;</p>' in markup
    )
    assert '<span class="mono">&lt;b&gt;1.0.0.0/8&lt;/b&gt;</span>' in markup
    assert "· &lt;i&gt;9%&lt;/i&gt; here" in markup
    assert 'href="/x&quot; onclick=&quot;y"' in markup
    assert "Look up &lt;svg&gt; →" in markup
    assert "<img" not in markup and "<b>" not in markup and "<svg" not in markup


def test_as_map_js_writes_no_markup_from_data():
    source = AS_MAP_JS.read_text()
    for banned in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
        "document.write",
        'bindPopup("',
        "bindPopup('",
        "setContent('<",
        'setContent("<',
    ):
        assert banned not in source


@needs_node
def test_the_filter_button_dispatches_as_city():
    out = run_js(
        f"""(() => {{
  const log = [];
  const box = m.bubble({json.dumps(DOT)}, () => log.push(["closed", events.length]));
  const button = box.children.find((child) => child.tag === "button");
  button.listeners.click.forEach((listener) => listener({{}}));
  return {{
    events: events.map((event) => [event.type, event.detail, event instanceof CustomEvent]),
    log,
  }};
}})()"""
    )
    assert out["events"] == [
        ["as:city", {"name": "Busan", "pairs": [[4, "100%"]]}, True]
    ]
    # The bubble closes after the city has been handed over, not before.
    assert out["log"] == [["closed", 1]]


@needs_node
def test_the_filter_button_works_without_a_close_callback():
    out = run_js(
        f"""(() => {{
  const box = m.bubble({json.dumps(DOT)});
  box.children.find((child) => child.tag === "button").listeners.click.forEach((f) => f({{}}));
  return events.length;
}})()"""
    )
    assert out == 1


@needs_node
def test_nothing_starts_without_leaflet():
    """L is undefined here: the file defines its helpers and reads nothing
    from the page, so a failed Leaflet load leaves the static map alone."""
    assert run_js("[typeof L, lookups]") == ["undefined", []]


def test_the_node_steps_aside_for_an_open_bubble_on_desktop():
    """Leaflet keeps its bubbles inside its map pane, one stacking context, so
    no z-index puts the node over the dots and under a bubble. Above 900px,
    where the node sits on the map, it hides while a bubble is open; at 900px
    and below it hangs above the canvas, clear of every bubble, and stays."""
    css = CSS.read_text(encoding="utf-8")
    desktop = re.search(r"@media \(min-width: 901px\) \{(.*?)\n\}", css, re.S)
    assert desktop
    assert re.search(
        r"\.as-map--bubble \.as-map__node\s*\{\s*visibility:\s*hidden;",
        desktop.group(1),
    )
    source = AS_MAP_JS.read_text(encoding="utf-8")
    assert re.search(
        r'map\.on\("popupopen", function \(\) \{\s*figure\.classList\.add\("as-map--bubble"\)',
        source,
    )
    assert re.search(
        r'map\.on\("popupclose", function \(\) \{\s*figure\.classList\.remove\("as-map--bubble"\)',
        source,
    )


def test_only_a_press_in_the_map_turns_the_wheel_on():
    """The design: off until the visitor clicks into the map. Focus alone (a
    tab into the map with the pointer resting on it) must not turn it on;
    leaving it, by pointer or by focus, turns it off."""
    source = AS_MAP_JS.read_text(encoding="utf-8")
    wheel = source.split("function wireWheel")[1].split("\n}\n")[0]
    calls = re.findall(
        r'(?:map\.on|live\.addEventListener)\("([a-z]+)", function \(\w*\) \{\s*(.*?)\n  \}\);',
        wheel,
        re.S,
    )
    turns_on = [event for event, body in calls if "wheel(true)" in body]
    turns_off = [event for event, body in calls if "wheel(false)" in body]
    assert turns_on == ["mousedown"]
    assert sorted(turns_off) == ["focusout", "mouseleave"]
