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

function pin(x, y, isOrigin, compact) {
  const group = svg("g", {
    class: isOrigin ? "map__pin map__pin--origin" : "map__pin",
  });
  const sizes = compact
    ? { origin: [16, 0, 4], target: [30, 15, 5] }
    : { origin: [24, 0, 6], target: [48, 24, 7] };
  const [halo, ring, dot] = isOrigin ? sizes.origin : sizes.target;
  group.appendChild(svg("circle", { class: "map__pin-halo", cx: x, cy: y, r: halo }));
  if (ring) {
    group.appendChild(svg("circle", { class: "map__pin-ring", cx: x, cy: y, r: ring }));
  }
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

function paint(container, canvas) {
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

  const fade = document.createElement("div");
  fade.className = "map__fade";
  stage.appendChild(fade);

  const overlay = svg("svg", {
    class: "map__overlay",
    width: canvas.width,
    height: canvas.height,
    viewBox: `0 0 ${canvas.width} ${canvas.height}`,
  });
  if (canvas.line) {
    overlay.appendChild(
      svg("polyline", {
        class: "map__line",
        points: canvas.line.map(([x, y]) => `${x},${y}`).join(" "),
      }),
    );
  }
  // A pin sized for the 1440px band swamps the little mobile card.
  const compact = canvas.width < 600;
  if (canvas.origin) {
    overlay.appendChild(pin(canvas.origin.x, canvas.origin.y, true, compact));
  }
  overlay.appendChild(pin(canvas.target.x, canvas.target.y, false, compact));
  stage.appendChild(overlay);

  container.appendChild(stage);
  container.appendChild(attribution());

  const cover = () => {
    const scale = Math.max(
      container.clientWidth / canvas.width,
      container.clientHeight / canvas.height,
    );
    stage.style.transform = `translate(-50%, -50%) scale(${scale})`;
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
    cover = container && canvas ? paint(container, canvas) : null;
  };

  render();
  MOBILE.addEventListener("change", render);
  window.addEventListener("resize", () => cover && cover());
}
