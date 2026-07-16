// Paints what the server projected. All the Mercator/antimeridian/great-circle
// math lives in mapgeom.py and is covered by tests/test_mapgeom.py.
const mapDataNode = document.getElementById("map-data");
const mapData = mapDataNode ? JSON.parse(mapDataNode.textContent) : null;

const SVG_NS = "http://www.w3.org/2000/svg";
const MOBILE = window.matchMedia("(max-width: 900px)");

function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  return node;
}

// A small house silhouette centred on (x, y): a roof that overhangs the walls
// so it still reads as a home at pin size. `s` is roughly the half-height.
function housePath(x, y, s) {
  const eave = s; // roof half-width, wider than the walls
  const wall = s * 0.62; // body half-width
  const shoulderY = y - s * 0.18; // where the roof eaves meet the walls
  const top = y - s; // roof apex
  const base = y + s * 0.92; // bottom of the walls
  return [
    `M ${x} ${top}`,
    `L ${x + eave} ${shoulderY}`,
    `L ${x + wall} ${shoulderY}`,
    `L ${x + wall} ${base}`,
    `L ${x - wall} ${base}`,
    `L ${x - wall} ${shoulderY}`,
    `L ${x - eave} ${shoulderY}`,
    "Z",
  ].join(" ");
}

function pin(x, y, isOrigin, compact) {
  const group = svg("g", {
    class: isOrigin ? "map__pin map__pin--origin" : "map__pin",
  });
  if (isOrigin) {
    // [halo radius, house half-height]
    const [halo, house] = compact ? [16, 7] : [24, 10];
    group.appendChild(svg("circle", { class: "map__pin-halo", cx: x, cy: y, r: halo }));
    group.appendChild(svg("path", { class: "map__pin-home", d: housePath(x, y, house) }));
    return group;
  }
  // [halo radius, ring radius, dot radius]
  const [halo, ring, dot] = compact ? [30, 15, 5] : [48, 24, 7];
  group.appendChild(svg("circle", { class: "map__pin-halo", cx: x, cy: y, r: halo }));
  group.appendChild(svg("circle", { class: "map__pin-ring", cx: x, cy: y, r: ring }));
  group.appendChild(svg("circle", { class: "map__pin-dot", cx: x, cy: y, r: dot }));
  return group;
}

function attribution() {
  const box = document.createElement("div");
  box.className = "map__attribution";
  const link = document.createElement("a");
  link.href = "https://www.openstreetmap.org/copyright";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "OpenStreetMap";
  box.append("© ", link, " contributors");
  return box;
}

function paint(container, canvas, distanceText) {
  // Everything the server projected lives on a fixed-size stage that is scaled
  // to cover the band. Tiles, pins and the arc scale together, so they stay
  // aligned at any viewport width instead of leaving dead space on wide screens.
  const stage = document.createElement("div");
  stage.className = "map__stage";
  stage.style.width = `${canvas.width}px`;
  stage.style.height = `${canvas.height}px`;

  const tiles = document.createElement("div");
  tiles.className = "map__tiles";
  for (const tile of canvas.tiles) {
    const img = document.createElement("img");
    img.src = tile.url;
    img.alt = "";
    img.referrerPolicy = "no-referrer";
    img.width = canvas.tile_size;
    img.height = canvas.tile_size;
    img.style.left = `${tile.x}px`;
    img.style.top = `${tile.y}px`;
    tiles.appendChild(img);
  }
  stage.appendChild(tiles);

  // The scrim dims the TILES only. It has to sit under the overlay, or it would
  // crush the pins and the arc along with the basemap.
  const scrim = document.createElement("div");
  scrim.className = "map__scrim";
  stage.appendChild(scrim);

  const overlay = svg("svg", {
    class: "map__overlay",
    width: canvas.width,
    height: canvas.height,
    viewBox: `0 0 ${canvas.width} ${canvas.height}`,
  });
  // A pin sized for the 1440px band swamps the little mobile card.
  const compact = canvas.width < 600;
  if (canvas.line) {
    const points = canvas.line.map(([x, y]) => `${x},${y}`).join(" ");
    overlay.appendChild(svg("polyline", { class: "map__line", points }));
    // Small arrows flowing along the arc toward the destination — replaces the
    // old dotted overlay and the single static arrowhead. offset-path animates
    // each arrow along the exact projected polyline; a staggered negative delay
    // spaces them out and offset-rotate keeps them tangent (pointing forward).
    const d = "M " + canvas.line.map(([x, y]) => `${x} ${y}`).join(" L ");
    const count = compact ? 1 : 2;
    const size = compact ? 4 : 6;
    const dur = compact ? 4.5 : 6;
    const head = `M ${size} 0 L ${-size * 0.7} ${size * 0.62} L ${-size * 0.7} ${-size * 0.62} Z`;
    for (let i = 0; i < count; i++) {
      const arrow = svg("path", { class: "map__flow-arrow", d: head });
      arrow.style.offsetPath = `path("${d}")`;
      arrow.style.offsetDistance = `${(i / count) * 100}%`;
      arrow.style.animationDuration = `${dur}s`;
      arrow.style.animationDelay = `${(-i / count) * dur}s`;
      overlay.appendChild(arrow);
    }
  }
  if (canvas.origin) {
    overlay.appendChild(pin(canvas.origin.x, canvas.origin.y, true, compact));
  }
  overlay.appendChild(pin(canvas.target.x, canvas.target.y, false, compact));
  stage.appendChild(overlay);

  container.appendChild(stage);

  // The fade belongs to the BAND, not the stage: inside the stage it would be
  // scaled with the tiles and pushed off the bottom edge on wide screens, which
  // is exactly where the hard seam against the content area came from.
  const fade = document.createElement("div");
  fade.className = "map__fade";
  container.appendChild(fade);

  container.appendChild(attribution());

  // The distance rides above the middle of the arc, clear of both pins. It lives
  // outside the scaled stage so the type stays the same size at any width.
  let chip = null;
  const apex = canvas.line ? canvas.line[Math.floor(canvas.line.length / 2)] : null;
  if (apex && distanceText) {
    chip = document.createElement("div");
    chip.className = "map__distance";
    chip.textContent = distanceText;
    container.appendChild(chip);
  }

  const cover = () => {
    const scale = Math.max(
      container.clientWidth / canvas.width,
      container.clientHeight / canvas.height,
    );
    stage.style.transform = `translate(-50%, -50%) scale(${scale})`;

    if (chip) {
      const x = container.clientWidth / 2 + (apex[0] - canvas.width / 2) * scale;
      const y = container.clientHeight / 2 + (apex[1] - canvas.height / 2) * scale;
      chip.style.left = `${x}px`;
      chip.style.top = `${y - 12}px`;
    }
  };
  cover();
  return cover;
}

if (mapData) {
  const containers = {
    desktop: document.getElementById("page-map"),
    mobile: document.getElementById("mobile-map"),
  };
  let cover = null;
  let painted = null;

  // Crossing the breakpoint swaps the band map for the mobile card, and each
  // has its own projected canvas — repaint on the change instead of making the
  // user reload. Only the active breakpoint's tiles are ever requested.
  const render = () => {
    const variant = MOBILE.matches ? "mobile" : "desktop";
    if (variant === painted) {
      return;
    }
    painted = variant;
    for (const container of Object.values(containers)) {
      if (container) {
        container.replaceChildren();
      }
    }
    const container = containers[variant];
    const canvas = mapData[variant];
    cover =
      container && canvas
        ? paint(container, canvas, mapData.distance_text)
        : null;
  };

  render();
  MOBILE.addEventListener("change", render);
  window.addEventListener("resize", () => cover && cover());
}
