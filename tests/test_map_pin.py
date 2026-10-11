"""map.js's pin(): a fix that is not city-level is drawn as an approximate pin.

The server grades every fix (lookup.lookup_location, main._apply_resolved_target)
and render_page hands map.js `target_precision` and `origin_precision`. A pin
that is not city-level -- GeoLite2's country centroid for 8.8.8.8, ± 1000 km,
or the gazetteer's for a registered-only block like 1.1.1.1 -- gets the
map__pin--approx class, which the CSS dashes, and a halo half as wide again,
so it reads as "around here" rather than "here". pin(), and the page wiring
that feeds it #map-data and draws the distance chip, run here in node against
a fake document, the way tests/test_webrtc_leak.py runs webrtc.js: the suite
has no browser.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

MAP_JS = Path("static/js/map.js").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")

# Just enough DOM for pin(): createElementNS makes a node that records its
# attributes and children. There is no #map-data, so loading map.js paints
# nothing, which is also what a page without a map gets.
HARNESS = r"""
function node(tag) {
  return {
    tag, attrs: {}, children: [], textContent: "",
    setAttribute(name, value) { this.attrs[name] = String(value); },
    appendChild(child) { this.children.push(child); return child; },
  };
}
global.document = {
  createElementNS: (ns, tag) => node(tag),
  getElementById: () => null,
};
const map = require(MAP_JS);
const out = {};
for (const [name, args] of Object.entries(CASES)) {
  const group = map.pin(...args);
  out[name] = {
    class: group.attrs.class,
    children: group.children.map((child) => ({
      tag: child.tag,
      class: child.attrs.class,
      r: child.attrs.r,
      text: child.textContent,
    })),
  };
}
console.log(JSON.stringify(out));
"""


def _pins(cases):
    """Run pin() once per case: name -> [x, y, isOrigin, compact, label, approx]."""
    script = HARNESS.replace("MAP_JS", json.dumps(str(MAP_JS))).replace(
        "CASES", json.dumps(cases)
    )
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def _parts(pin):
    return {child["class"]: child for child in pin["children"]}


@needs_node
class TestPin:
    def test_a_city_pin_is_drawn_as_before(self):
        pin = _pins({"city": [100, 50, False, False, "8.8.8.8", False]})["city"]
        assert pin["class"] == "map__pin"
        parts = _parts(pin)
        assert parts["map__pin-halo"]["r"] == "48"
        assert parts["map__pin-ring"]["r"] == "24"
        assert parts["map__pin-dot"]["r"] == "7"
        assert parts["map__pin-label"]["text"] == "8.8.8.8"

    def test_a_country_level_pin_is_approximate_and_wider(self):
        pins = _pins(
            {
                "city": [100, 50, False, False, "8.8.8.8", False],
                "approx": [100, 50, False, False, "8.8.8.8", True],
            }
        )
        approx = pins["approx"]
        assert approx["class"] == "map__pin map__pin--approx"
        assert float(_parts(approx)["map__pin-halo"]["r"]) > float(
            _parts(pins["city"])["map__pin-halo"]["r"]
        )
        # Still a pin: the ring, the dot and the label stay, so the address is
        # still marked; only the halo says how far to trust it.
        assert {
            "map__pin-halo",
            "map__pin-ring",
            "map__pin-dot",
            "map__pin-label",
        } <= set(_parts(approx))

    def test_the_compact_pin_scales_the_same_way(self):
        pins = _pins(
            {
                "city": [10, 10, False, True, None, False],
                "approx": [10, 10, False, True, None, True],
            }
        )
        assert _parts(pins["city"])["map__pin-halo"]["r"] == "30"
        assert float(_parts(pins["approx"])["map__pin-halo"]["r"]) > 30

    def test_the_visitors_own_pin_can_be_approximate_too(self):
        pin = _pins({"home": [100, 50, True, False, "203.0.113.7", True]})["home"]
        assert pin["class"] == "map__pin map__pin--origin map__pin--approx"
        parts = _parts(pin)
        assert "map__pin-home" in parts
        assert float(parts["map__pin-halo"]["r"]) > 24

    def test_a_precise_home_pin_has_no_approx_class(self):
        pin = _pins({"home": [100, 50, True, False, None, False]})["home"]
        assert pin["class"] == "map__pin map__pin--origin"
        assert _parts(pin)["map__pin-halo"]["r"] == "24"


@needs_node
def test_loading_without_map_data_paints_nothing():
    """A page with no map (a private visitor, a target with no coordinates)
    has no #map-data; map.js must load and do nothing, as it did before it
    exported pin()."""
    assert _pins({}) == {}


# The page: a fake document whose #map-data holds what render_page embeds, two
# map containers, and a window that answers matchMedia, so loading map.js runs
# its page wiring and paints the desktop canvas. No tile is requested: `tiles`
# is empty.
PAGE_HARNESS = r"""
function node(tag) {
  return {
    tag, attrs: {}, children: [], textContent: "", className: "", style: {},
    clientWidth: 1440, clientHeight: 400,
    setAttribute(name, value) { this.attrs[name] = String(value); },
    appendChild(child) { this.children.push(child); return child; },
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; },
  };
}
const containers = { "page-map": node("div"), "mobile-map": node("div") };
global.window = {
  matchMedia: () => ({ matches: false, addEventListener() {} }),
  addEventListener() {},
};
global.document = {
  createElementNS: (ns, tag) => node(tag),
  createElement: (tag) => node(tag),
  getElementById: (id) =>
    id === "map-data" ? { textContent: MAP_DATA } : containers[id] || null,
};
require(MAP_JS);
const pins = [];
(function walk(n) {
  if (n.tag === "g") pins.push(n.attrs.class);
  for (const child of n.children) if (child && typeof child === "object") walk(child);
})(containers["page-map"]);
const chips = containers["page-map"].children.filter(
  (child) => child.className === "map__distance",
);
console.log(JSON.stringify({ pins, chips: chips.map((chip) => chip.textContent) }));
"""


def _page(map_data):
    """Load map.js into a page whose #map-data is `map_data`: the class of
    every pin it drew, and the text of every distance chip."""
    script = PAGE_HARNESS.replace("MAP_JS", json.dumps(str(MAP_JS))).replace(
        "MAP_DATA", json.dumps(json.dumps(map_data))
    )
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


# render_page's #map-data for a route, cut to what paint() reads.
ROUTE = {
    "desktop": {
        "width": 1440,
        "height": 400,
        "tile_size": 256,
        "tiles": [],
        "origin": {"x": 300, "y": 200},
        "target": {"x": 1100, "y": 220},
        "line": [[300, 200], [700, 120], [1100, 220]],
    },
    "mobile": None,
    "distance_text": "≈ 9,010 km from you",
    "origin_ip": "118.235.14.201",
    "target_ip": "8.8.8.8",
    "origin_precision": "city",
    "target_precision": "city",
}


@needs_node
class TestPageWiring:
    """render_page's target_precision / origin_precision reach pin(), and
    distance_text, null unless both ends are city-level, decides the chip."""

    def test_two_city_fixes_draw_solid_pins_and_the_chip(self):
        page = _page(ROUTE)
        assert page["pins"] == ["map__pin map__pin--origin", "map__pin"]
        assert page["chips"] == ["≈ 9,010 km from you"]

    def test_a_country_level_visitor_gets_a_dashed_home_and_no_chip(self):
        page = _page({**ROUTE, "origin_precision": "country", "distance_text": None})
        assert page["pins"] == [
            "map__pin map__pin--origin map__pin--approx",
            "map__pin",
        ]
        assert page["chips"] == []

    def test_a_country_level_target_gets_a_dashed_pin_and_no_chip(self):
        page = _page({**ROUTE, "target_precision": "country", "distance_text": None})
        assert page["pins"] == [
            "map__pin map__pin--origin",
            "map__pin map__pin--approx",
        ]
        assert page["chips"] == []
