// Paints what the server projected. All the Mercator/antimeridian/great-circle
// math lives in mapgeom.py and is covered by tests/test_mapgeom.py.
const mapDataNode = document.getElementById("map-data");
const mapData = mapDataNode ? JSON.parse(mapDataNode.textContent) : null;

const SVG_NS = "http://www.w3.org/2000/svg";

function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  return node;
}

function pin(x, y, isOrigin) {
  const group = svg("g", {
    class: isOrigin ? "map__pin map__pin--origin" : "map__pin",
  });
  const [halo, ring, dot] = isOrigin ? [24, 0, 6] : [48, 24, 7];
  group.appendChild(svg("circle", { class: "map__pin-halo", cx: x, cy: y, r: halo }));
  if (ring) {
    group.appendChild(svg("circle", { class: "map__pin-ring", cx: x, cy: y, r: ring }));
  }
  group.appendChild(svg("circle", { class: "map__pin-dot", cx: x, cy: y, r: dot }));
  return group;
}

function paint(container, canvas) {
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
  container.appendChild(tiles);

  // The scrim dims the TILES only. It has to sit under the overlay, or it
  // would crush the pins and the arc along with the basemap.
  const scrim = document.createElement("div");
  scrim.className = "map__scrim";
  container.appendChild(scrim);

  const fade = document.createElement("div");
  fade.className = "map__fade";
  container.appendChild(fade);

  const overlay = svg("svg", {
    class: "map__overlay",
    viewBox: `0 0 ${canvas.width} ${canvas.height}`,
    preserveAspectRatio: "xMidYMid slice",
  });

  if (canvas.line) {
    overlay.appendChild(
      svg("polyline", {
        class: "map__line",
        points: canvas.line.map(([x, y]) => `${x},${y}`).join(" "),
      }),
    );
  }
  if (canvas.origin) {
    overlay.appendChild(pin(canvas.origin.x, canvas.origin.y, true));
  }
  overlay.appendChild(pin(canvas.target.x, canvas.target.y, false));
  container.appendChild(overlay);

  const attribution = document.createElement("div");
  attribution.className = "map__attribution";
  const link = document.createElement("a");
  link.href = "https://www.openstreetmap.org/copyright";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "OpenStreetMap";
  attribution.append("© ", link, " contributors");
  container.appendChild(attribution);
}

if (mapData) {
  // Only the visible breakpoint's tiles are ever requested.
  const isMobile = window.matchMedia("(max-width: 900px)").matches;
  const container = document.getElementById(isMobile ? "mobile-map" : "page-map");
  const canvas = isMobile ? mapData.mobile : mapData.desktop;
  if (container && canvas) {
    paint(container, canvas);
  }
}
