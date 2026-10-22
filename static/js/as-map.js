/* The /AS<n> page's live map: Leaflet over the static picture, with zoom,
 * pan and a bubble per city dot.
 *
 * The server draws the static map (tiles and an SVG of dots), the page's
 * view without this file, and embeds #as-map-data: the frame, the zoom
 * limits and, per dot, what its bubble says. This builds the Leaflet map in
 * #as-map-live, hidden, and swaps it in once its first tiles have drawn (the
 * `as-map--live` class). A failure anywhere before that leaves the picture.
 *
 * The dots' icons take no pointer events: a click on the map opens the dot
 * drawn on top under the pointer, smaller dots being drawn above bigger ones
 * (drawnAbove), else the nearest within its hit area (pickDot), so dots that
 * overlap each stay reachable. "Show these in Prefixes" hands the city to
 * as.js as an `as:city` event on the document.
 *
 * Text goes in with textContent and nodes with createElement only: a city
 * name is third-party text, and a bubble is an element, never a string.
 */
"use strict";

/* A dot's hit radius is at least this: a 24px target (WCAG 2.2, 2.5.8). */
var MIN_HIT_RADIUS = 12;
/* Leaflet stacks a marker by its y on the map, within a world's height
 * (262,144px at zoom 10), plus its zIndexOffset: a step of the drawing order
 * outweighs any latitude, and 4,000 steps stay inside a z-index. */
var STACK_STEP = 1 << 19;
/* The initial view leaves this share of the box free on each side, so the
 * frame takes mapgeom.FIT_MARGIN's 0.8 of it, as on the static map. */
var FIT_PADDING = 0.1;

/* ---- pure helpers (exported for node) ---------------------------------- */

/* The zoom at which the world just fills `width` pixels once, fractional, so
 * no width shows it twice; never below 0. */
function minZoomFor(width) {
  return Math.max(0, Math.log2(width / 256));
}

/* The drawing order, the one rule the z-index (stackOffsets) and the click
 * (pickDot) both read: dot a (radius ra, payload index ia) is drawn above dot
 * b when it is smaller, so a small dot on a big one stays visible, or the
 * same size and later in the payload. */
function drawnAbove(ra, ia, rb, ib) {
  return ra < rb || (ra === rb && ia > ib);
}

/* Each dot's zIndexOffset: its place in drawnAbove's order, bottom first,
 * a STACK_STEP apart. */
function stackOffsets(radii) {
  var order = radii.map(function (r, index) {
    return index;
  });
  order.sort(function (a, b) {
    return drawnAbove(radii[a], a, radii[b], b) ? 1 : -1;
  });
  var offsets = [];
  order.forEach(function (index, place) {
    offsets[index] = place * STACK_STEP;
  });
  return offsets;
}

/* The index of the dot a click at (x, y) opens, else -1. What the eye sees
 * wins: of the drawn disks that hold the point, the one on top (drawnAbove).
 * Outside every disk, the nearest centre within its hit radius, on a tie the
 * lower index. Points are container pixels with a radius `r`, in the
 * payload's order. */
function pickDot(points, x, y) {
  var drawn = -1;
  var near = -1;
  var nearDistance = Infinity;
  points.forEach(function (point, index) {
    var distance = Math.hypot(point.x - x, point.y - y);
    if (
      distance <= point.r &&
      (drawn === -1 || drawnAbove(point.r, index, points[drawn].r, drawn))
    ) {
      drawn = index;
    }
    if (distance <= Math.max(point.r, MIN_HIT_RADIUS) && distance < nearDistance) {
      near = index;
      nearDistance = distance;
    }
  });
  return drawn !== -1 ? drawn : near;
}

/* The keys that move the focus between the dots: one along the payload's
 * order (largest first), or to its first or last dot. */
var STEPS = {
  ArrowRight: 1,
  ArrowDown: 1,
  ArrowLeft: -1,
  ArrowUp: -1,
  Home: -Infinity,
  End: Infinity,
};

/* The index the focus moves to from dot `index` of `count` on `key`: the
 * same index for any other key and at either end, which does not wrap. */
function stepDot(count, index, key) {
  var step = STEPS[key];
  if (typeof step !== "number") return index;
  return Math.max(0, Math.min(count - 1, index + step));
}

/* The dot that carries the Tab stop once the map has moved: `current` while
 * it is in view, else the first dot in view in the payload's order, else
 * `current`. A Tab into the map then never lands on a dot off the view, which
 * Chrome would scroll the page to before the dot could be panned in. */
function stopAfterMove(current, inView) {
  if (inView[current]) return current;
  var first = inView.indexOf(true);
  return first === -1 ? current : first;
}

/* The live map's label: the static picture's and, for city dots, how to move
 * between them, since they are one Tab stop (wireRoving). */
function regionLabel(label, approx) {
  if (approx) return label;
  var sentence = /[.!?]$/.test(label) ? label : label + ".";
  return sentence + " Use the arrow keys to move between places.";
}

/* lon moved by a multiple of 360 to lie within 180 of centerLon, as
 * mapgeom.unwrap_lon: the world copy a dot is drawn on. */
function nearestCopy(lon, centerLon) {
  return lon + 360 * Math.round((centerLon - lon) / 360);
}

/* What a key does on a focused dot, as on a native button: Enter opens the
 * bubble on its keydown; Space holds its keydown (the page does not scroll)
 * and opens on its keyup, so no later event of that press lands on the
 * bubble's button that has just taken focus. */
function keyAction(type, key) {
  if (key === "Enter") return type === "keydown" ? "open" : null;
  if (key === " ") return type === "keydown" ? "hold" : type === "keyup" ? "open" : null;
  return null;
}

/* ---- the bubble -------------------------------------------------------- */

function el(tag, className, text) {
  var node = document.createElement(tag);
  if (className) node.setAttribute("class", className);
  if (text !== undefined) node.textContent = text;
  return node;
}

function thousands(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/* A city's place and share, its first prefixes with how much of each is
 * there, the count when there are more, the button that filters the Prefixes
 * table to them and an address to look up. The server rounded every share.
 * `done`, when given, runs once the button has handed the city to as.js. */
function bubble(dot, done) {
  var box = el("div", "as-bubble");
  box.appendChild(el("p", "as-bubble__place", dot.place || dot.name || ""));
  box.appendChild(el("p", "as-bubble__share tone-muted", dot.share_text + " of its IPv4 space"));
  if (dot.count > 0) {
    box.appendChild(el("p", "as-bubble__head", "Prefixes with addresses here"));
    var list = el("ul", "as-bubble__prefixes");
    dot.top.forEach(function (entry) {
      var item = el("li");
      item.appendChild(el("span", "mono", entry[0]));
      item.appendChild(document.createTextNode(" "));
      item.appendChild(el("span", "tone-muted", "· " + entry[1] + " here"));
      list.appendChild(item);
    });
    box.appendChild(list);
    if (dot.count > dot.top.length) {
      box.appendChild(
        el("p", "as-bubble__more tone-muted", "… " + thousands(dot.count) + " prefixes in all")
      );
    }
    var button = el("button");
    button.setAttribute("type", "button");
    button.setAttribute("class", "as-bubble__filter");
    button.textContent = "Show these in Prefixes";
    button.addEventListener("click", function () {
      document.dispatchEvent(
        new CustomEvent("as:city", { detail: { name: dot.name, pairs: dot.pairs } })
      );
      if (done) done();
    });
    box.appendChild(button);
  }
  if (dot.lookup) {
    var link = el("a", "lookup-link", "Look up " + dot.lookup.text + " →");
    link.setAttribute("href", dot.lookup.href);
    link.setAttribute("rel", "nofollow");
    box.appendChild(link);
  }
  return box;
}

/* ---- the map ----------------------------------------------------------- */

function initMap() {
  var figure = document.getElementById("as-map");
  var live = document.getElementById("as-map-live");
  var script = document.getElementById("as-map-data");
  if (!figure || !live || !script) return;
  var data = JSON.parse(script.textContent);
  var frame = data.frame;
  var home = L.latLngBounds([frame.south, frame.west], [frame.north, frame.east]);

  var map = L.map(live, {
    zoomSnap: 0.25,
    zoomControl: false,
    attributionControl: false,
    scrollWheelZoom: false,
    worldCopyJump: true,
    // On a touch screen one finger scrolls the page and two move the map.
    dragging: !window.matchMedia("(pointer: coarse)").matches,
    maxZoom: data.zoom_limit,
    minZoom: minZoomFor(live.clientWidth),
  });

  function fitHome() {
    var size = map.getSize();
    map.fitBounds(home, {
      maxZoom: data.fit_max_zoom,
      padding: [size.x * FIT_PADDING, size.y * FIT_PADDING],
    });
  }
  fitHome();
  map.on("resize", function () {
    map.setMinZoom(minZoomFor(live.clientWidth));
  });

  L.control.zoom({ position: "topright" }).addTo(map);
  var reset = L.control({ position: "topright" });
  reset.onAdd = function () {
    var bar = el("div", "leaflet-bar leaflet-control");
    var button = el("button", null, "⟲");
    button.setAttribute("type", "button");
    button.setAttribute("aria-label", "Reset the map");
    button.addEventListener("click", fitHome);
    bar.appendChild(button);
    // A press is not a click on the map, which would open the nearest bubble.
    L.DomEvent.disableClickPropagation(bar);
    return bar;
  };
  reset.addTo(map);

  var offsets = stackOffsets(
    data.dots.map(function (dot) {
      return dot.r;
    })
  );
  var markers = data.dots.map(function (dot, index) {
    var size = 2 * dot.r;
    var marker = L.marker([dot.lat, dot.lon], {
      icon: L.divIcon({
        className: "as-dot" + (data.approx ? " as-dot--approx" : ""),
        iconSize: [size, size],
      }),
      keyboard: !data.approx,
      interactive: !data.approx,
      zIndexOffset: offsets[index],
      // wireRoving pans a focused dot in itself.
      autoPanOnFocus: false,
    }).addTo(map);
    var element = marker.getElement();
    // The country pin is a picture, not a control: it has no bubble.
    element.setAttribute("role", data.approx ? "img" : "button");
    element.setAttribute("aria-label", dot.label);
    return marker;
  });

  // worldCopyJump keeps the view's centre within one world of 0°; each dot
  // follows to the copy nearest it, so an AS across the Pacific keeps its
  // dots on whichever side the visitor pans to.
  map.on("move", function () {
    var center = map.getCenter().lng;
    markers.forEach(function (marker) {
      var at = marker.getLatLng();
      var lng = nearestCopy(at.lng, center);
      if (lng !== at.lng) marker.setLatLng([at.lat, lng]);
    });
  });

  if (!data.approx) {
    wireBubbles(map, figure, live, data, markers);
    wireRoving(map, data, markers);
  }
  wireWheel(map, live);

  // The static picture's own description, for the map that replaces it.
  var picture = figure.querySelector(".as-map__dots");
  if (picture && picture.getAttribute("aria-label")) {
    live.setAttribute("role", "region");
    live.setAttribute(
      "aria-label",
      regionLabel(picture.getAttribute("aria-label"), data.approx)
    );
  }

  // Last, so a failure above leaves the static map in place.
  var tiles = L.tileLayer(data.tile_url, {
    maxZoom: data.zoom_limit,
    referrerPolicy: "strict-origin",
  });
  tiles.once("load", function () {
    figure.classList.add("as-map--live");
  });
  tiles.addTo(map);
}

function wireBubbles(map, figure, live, data, markers) {
  function pick(point) {
    var points = markers.map(function (marker, index) {
      // Where Leaflet draws the icon: its layer point rounded to a pixel.
      var at = map.layerPointToContainerPoint(
        map.latLngToLayerPoint(marker.getLatLng()).round()
      );
      return { x: at.x, y: at.y, r: data.dots[index].r };
    });
    return pickDot(points, point.x, point.y);
  }

  // One bubble at a time: Leaflet closes the open one when another opens.
  // Focus goes to the bubble's first control, and back to the dot on close
  // when a key opened it, unless the bubble closed for the Prefixes table.
  function open(index, fromKey) {
    var marker = markers[index];
    var returnTo = fromKey ? marker.getElement() : null;
    var popup = L.popup({ maxWidth: 260, autoPanPadding: [12, 12] });
    popup.setLatLng(marker.getLatLng()).setContent(
      bubble(data.dots[index], function () {
        returnTo = null;
        map.closePopup(popup);
      })
    );
    popup.on("remove", function () {
      if (returnTo) returnTo.focus({ preventScroll: true });
    });
    popup.openOn(map);
    var element = popup.getElement();
    // Leaflet's own Esc listens only while the map itself has focus.
    element.addEventListener("keydown", function (event) {
      if (event.key === "Escape") map.closePopup(popup);
    });
    var first = element.querySelector("button, a[href]");
    if (first) first.focus({ preventScroll: true });
  }

  map.on("click", function (event) {
    var index = pick(event.containerPoint);
    if (index !== -1) open(index, false);
  });
  // Above 900px the node sits on the map, over Leaflet's whole map pane and
  // so over any bubble: it steps aside while one is open.
  map.on("popupopen", function () {
    figure.classList.add("as-map--bubble");
  });
  map.on("popupclose", function () {
    figure.classList.remove("as-map--bubble");
  });
  map.on("mousemove", function (event) {
    live.classList.toggle("as-map__live--hit", pick(event.containerPoint) !== -1);
  });
  markers.forEach(function (marker, index) {
    // Pointers fall through to the map; a click on the dot itself comes from
    // the keyboard or a screen reader.
    marker.on("click", function () {
      open(index, true);
    });
    var element = marker.getElement();
    ["keydown", "keyup"].forEach(function (type) {
      element.addEventListener(type, function (event) {
        var action = keyAction(type, event.key);
        if (!action) return;
        event.preventDefault();
        if (action === "open") open(index, true);
      });
    });
  });
}

/* One dot is a Tab stop, the first (the largest) until the focus moves:
 * Leaflet makes every keyboard marker one, and getting past a map of a
 * hundred dots would take a hundred presses. The arrow keys, Home and End
 * move the focus between the dots (stepDot), and the Tab stop goes with it;
 * a move of the map that takes it off the view hands it to a dot in view
 * (stopAfterMove). */
function wireRoving(map, data, markers) {
  var current = 0;
  function rove(index) {
    current = index;
    markers.forEach(function (marker, i) {
      marker.getElement().setAttribute("tabindex", i === current ? "0" : "-1");
    });
  }
  // A dot off the view is brought in whole, with its focus ring. Leaflet's
  // own pan on focus (off) stops with the dot's centre on the edge.
  function reveal(index) {
    var pad = data.dots[index].r + 4;
    map.panInside(markers[index].getLatLng(), { padding: [pad, pad], animate: false });
  }
  // Whole in the view with its focus ring, the margin reveal pans to.
  function inView(index) {
    var at = map.latLngToContainerPoint(markers[index].getLatLng());
    var size = map.getSize();
    var pad = data.dots[index].r + 4;
    return at.x >= pad && at.y >= pad && at.x <= size.x - pad && at.y <= size.y - pad;
  }
  rove(0);
  map.on("moveend", function () {
    var visible = markers.map(function (marker, index) {
      return inView(index);
    });
    var next = stopAfterMove(current, visible);
    if (next !== current) rove(next);
  });
  markers.forEach(function (marker, index) {
    var element = marker.getElement();
    element.addEventListener("focus", function () {
      reveal(index);
      if (index !== current) rove(index);
    });
    element.addEventListener("keydown", function (event) {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      if (typeof STEPS[event.key] !== "number") return;
      // The page does not scroll, even at the first or the last dot.
      event.preventDefault();
      var next = stepDot(markers.length, index, event.key);
      if (next === index) return;
      // Panned in first: focusing a dot off the view would scroll Leaflet's
      // overflow-hidden box.
      reveal(next);
      markers[next].getElement().focus({ preventScroll: true });
    });
  });
}

/* The wheel zooms only once the visitor has pressed the mouse in the map, and
 * stops when the pointer or the focus leaves it: scrolling the page past the
 * map never zooms it, nor does tabbing into it with the pointer resting on
 * it. */
function wireWheel(map, live) {
  function wheel(on) {
    if (on) map.scrollWheelZoom.enable();
    else map.scrollWheelZoom.disable();
  }
  map.on("mousedown", function () {
    wheel(true);
  });
  live.addEventListener("mouseleave", function () {
    wheel(false);
  });
  live.addEventListener("focusout", function (event) {
    if (!live.contains(event.relatedTarget)) wheel(false);
  });
}

if (typeof module === "object" && module.exports) {
  module.exports = {
    minZoomFor: minZoomFor,
    drawnAbove: drawnAbove,
    stackOffsets: stackOffsets,
    pickDot: pickDot,
    nearestCopy: nearestCopy,
    keyAction: keyAction,
    stepDot: stepDot,
    stopAfterMove: stopAfterMove,
    regionLabel: regionLabel,
    bubble: bubble,
  };
}
if (typeof document !== "undefined" && typeof L !== "undefined") {
  try {
    initMap();
  } catch (error) {
    // The static map stays: the page reads without this file.
  }
}
