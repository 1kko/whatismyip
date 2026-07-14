# WhatIsMyIP Frontend Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the WhatIsMyIP page as an answer-first, dark product surface with an OpenStreetMap location band, a great-circle distance line to the lookup target, and the JSON tree demoted to a collapsed Raw JSON accordion.

**Architecture:** All map math lives in Python so it is unit-testable: the server resolves coordinates from a local gazetteer (geoip2fast never returns lat/lon), computes the haversine distance, and emits a ready-to-render map payload (tile URLs with pixel offsets + a projected great-circle polyline) for two fixed canvases (desktop band, mobile card). The browser only paints what it is given — `<img>` tiles plus an SVG polyline. The page is server-rendered from a pure view-model function; JavaScript is limited to accordions, copy, search, map painting, and lazily booting JSONEditor inside Raw JSON.

**Tech Stack:** FastAPI + Jinja2, no build step. Pure CSS with design tokens, self-hosted woff2 fonts. Vanilla ES modules served from `/static/js`. pytest (unit + FastAPI TestClient).

## Global Constraints

- **No build step.** No npm, no bundler, no CSS preprocessor. Everything ships as static files.
- **CSP.** `script-src 'self' 'nonce-…'` — no inline event handlers (`onclick=` is forbidden); all handlers via `addEventListener` in `/static/js/*.js`. `style-src 'self' 'unsafe-inline'`. The only CSP change allowed in this plan: add `https://tile.openstreetmap.org` to `img-src`.
- **Dark theme only.** No light mode, no `prefers-color-scheme` branches.
- **Tokens.** Colors only from the CSS custom properties defined in Task 6. `--accent: #5B8CFF` is the single accent; `--success: #34D399`, `--warning: #FBBF24`, `--danger: #FB7185` carry meaning only.
- **Fonts.** Inter (sans) + JetBrains Mono (mono), self-hosted from `static/fonts/`. Every technical value (IP, ASN, CIDR, domain, TTL, dates) is mono with `font-variant-numeric: tabular-nums`.
- **Wordmark.** The product name renders exactly as `WhatIsMyIP`.
- **OSM attribution is mandatory.** `© OpenStreetMap contributors` visible on the map and in the footer, plus the footer notice `Map tiles load directly from openstreetmap.org`.
- **Distances are approximate.** Always prefixed with `≈`. City-centroid based.
- **JSON API contract is additive only.** Existing keys (`address`, `datetime`, `domain`, `location`, `whois`, `ssl`, `headers`) keep their current shape. New keys: `map`, `distance_km`, `origin`.
- **Lint.** `poetry run ruff check .` must pass (`select = ["E", "F", "S"]` — bandit rules are on, so every outbound HTTP call needs an explicit `timeout=`).
- Design source of truth: `screen.pen` (Desktop/Home, Desktop/Lookup, Mobile/Home, Mobile/Lookup) and `docs/superpowers/specs/2026-07-14-whatismyip-redesign-design.md`.

---

## File Structure

**New:**
- `geo.py` — gazetteer loading, city/country coordinate resolution, haversine distance
- `mapgeom.py` — Web Mercator projection, tile grid with antimeridian wraparound, zoom fitting, great-circle polyline projection
- `viewmodel.py` — pure `response_data → view` mapping (hero, facts columns, accordion hints, flag emoji, certificate parsing)
- `scripts/build_gazetteer.py` — generates `static/geo/cities.json` + `static/geo/countries.json` from GeoNames
- `scripts/fetch_fonts.sh` — vendors Inter + JetBrains Mono woff2 into `static/fonts/`
- `static/geo/cities.json`, `static/geo/countries.json` — committed generated data
- `static/fonts/*.woff2` — committed vendored fonts
- `static/js/app.js` — accordions, copy, search, lazy JSONEditor
- `static/js/map.js` — paints tiles + SVG polyline from the server payload
- `tests/test_geo.py`, `tests/test_mapgeom.py`, `tests/test_viewmodel.py`, `tests/test_page.py`

**Modified:**
- `main.py` — build `map`/`distance_km`/`origin` into both routes, pass `view` to the template, add the OSM host to `img-src`
- `templates/browser.html` — full rewrite (server-rendered)
- `static/css/whatismyip.css` — full rewrite (tokens + new layout)
- `README.md`, `CLAUDE.md` — document the new modules and the gazetteer/font scripts

---

## Task 1: Gazetteer data

Builds the coordinate tables. geoip2fast gives city names but `latitude`/`longitude` are always `null`, so coordinates must come from our own data.

**Files:**
- Create: `scripts/build_gazetteer.py`
- Create (generated, committed): `static/geo/cities.json`, `static/geo/countries.json`
- Test: `tests/test_geo.py`

**Interfaces:**
- Produces: `static/geo/cities.json` — `{"KR:seoul": [37.5665, 126.978], ...}` keyed by `"{country_code}:{normalized city name}"`, values `[lat, lon]`.
- Produces: `static/geo/countries.json` — `{"KR": [36.5, 127.9], ...}` population-weighted centroid per country code.

- [ ] **Step 1: Write the failing test**

Create `tests/test_geo.py`:

```python
import json
from pathlib import Path

CITIES = Path("static/geo/cities.json")
COUNTRIES = Path("static/geo/countries.json")


class TestGazetteerData:
    def test_cities_file_has_known_cities(self):
        cities = json.loads(CITIES.read_text(encoding="utf-8"))
        lat, lon = cities["KR:seoul"]
        assert 37.0 < lat < 38.0
        assert 126.5 < lon < 127.5

        lat, lon = cities["US:mountain view"]
        assert 37.0 < lat < 37.7
        assert -122.5 < lon < -121.9

    def test_countries_file_covers_major_codes(self):
        countries = json.loads(COUNTRIES.read_text(encoding="utf-8"))
        assert len(countries) > 180
        for code in ("KR", "US", "DE", "JP", "AU"):
            lat, lon = countries[code]
            assert -90.0 <= lat <= 90.0
            assert -180.0 <= lon <= 180.0

    def test_city_keys_are_normalized(self):
        cities = json.loads(CITIES.read_text(encoding="utf-8"))
        for key in list(cities)[:500]:
            code, _, name = key.partition(":")
            assert len(code) == 2 and code.isupper()
            assert name == name.lower().strip()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_geo.py -v`
Expected: FAIL — `FileNotFoundError: static/geo/cities.json`

- [ ] **Step 3: Write the build script**

Create `scripts/build_gazetteer.py`:

```python
#!/usr/bin/env python3
"""Build the coordinate gazetteer from GeoNames.

geoip2fast resolves city NAMES but its latitude/longitude are always null,
so the map needs its own coordinate source. GeoNames cities15000 gives us
every city above 15k population; country centroids are derived from the same
download as a population-weighted mean, so there is only one source to trust.

Usage: poetry run python scripts/build_gazetteer.py
"""

import csv
import io
import json
import pathlib
import unicodedata
import zipfile

import requests

CITIES_URL = "https://download.geonames.org/export/dump/cities15000.zip"
OUT_DIR = pathlib.Path("static/geo")
TIMEOUT = 120


def normalize_city(name: str) -> str:
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return " ".join(stripped.lower().split())


def fetch_rows() -> list[list[str]]:
    response = requests.get(CITIES_URL, timeout=TIMEOUT)
    response.raise_for_status()
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    raw = archive.read("cities15000.txt").decode("utf-8")
    return list(csv.reader(io.StringIO(raw), delimiter="\t", quoting=csv.QUOTE_NONE))


def build(rows: list[list[str]]) -> tuple[dict, dict]:
    cities: dict[str, list[float]] = {}
    populations: dict[str, int] = {}
    country_sum: dict[str, list[float]] = {}
    country_pop: dict[str, int] = {}

    for row in rows:
        name, asciiname = row[1], row[2]
        lat, lon = float(row[4]), float(row[5])
        country = row[8]
        population = int(row[14] or 0)
        if not country:
            continue

        for label in {name, asciiname}:
            key = f"{country}:{normalize_city(label)}"
            # Keep the most populous city when names collide (e.g. two Springfields).
            if population >= populations.get(key, -1):
                cities[key] = [round(lat, 4), round(lon, 4)]
                populations[key] = population

        weight = max(population, 1)
        acc = country_sum.setdefault(country, [0.0, 0.0])
        acc[0] += lat * weight
        acc[1] += lon * weight
        country_pop[country] = country_pop.get(country, 0) + weight

    countries = {
        code: [
            round(acc[0] / country_pop[code], 4),
            round(acc[1] / country_pop[code], 4),
        ]
        for code, acc in country_sum.items()
    }
    return cities, countries


def main() -> None:
    cities, countries = build(fetch_rows())
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "cities.json").write_text(
        json.dumps(cities, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_DIR / "countries.json").write_text(
        json.dumps(countries, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"cities={len(cities)} countries={len(countries)}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Generate the data**

Run: `poetry run python scripts/build_gazetteer.py`
Expected: prints something like `cities=45000 countries=250` and writes both files.

- [ ] **Step 5: Run the test to verify it passes**

Run: `poetry run pytest tests/test_geo.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add scripts/build_gazetteer.py static/geo tests/test_geo.py
git commit -m "feat(geo): add GeoNames gazetteer for city and country coordinates"
```

---

## Task 2: `geo.py` — coordinate resolution and distance

**Files:**
- Create: `geo.py`
- Test: `tests/test_geo.py` (append)

**Interfaces:**
- Consumes: `static/geo/cities.json`, `static/geo/countries.json` from Task 1.
- Produces:
  - `Gazetteer.load(cities_file=..., countries_file=...) -> Gazetteer`
  - `Gazetteer.resolve(location: dict) -> dict | None` → `{"lat": float, "lon": float, "precision": "city"|"country"}`
  - `haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float`
  - Constants `CITY_ZOOM = 10`, `COUNTRY_ZOOM = 4`, `MIN_ROUTE_KM = 25.0`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_geo.py`:

```python
import pytest

from geo import CITY_ZOOM, COUNTRY_ZOOM, Gazetteer, haversine_km, normalize_city


@pytest.fixture(scope="module")
def gazetteer():
    return Gazetteer.load()


class TestResolve:
    def test_city_hit_wins_over_country(self, gazetteer):
        location = {
            "country_code": "KR",
            "city": {"name": "Seoul"},
            "is_private": False,
        }
        result = gazetteer.resolve(location)
        assert result["precision"] == "city"
        assert 37.0 < result["lat"] < 38.0

    def test_falls_back_to_country_centroid_when_city_missing(self, gazetteer):
        location = {"country_code": "US", "city": {"name": ""}, "is_private": False}
        result = gazetteer.resolve(location)
        assert result["precision"] == "country"
        assert 20.0 < result["lat"] < 55.0

    def test_unknown_city_falls_back_to_country(self, gazetteer):
        location = {
            "country_code": "KR",
            "city": {"name": "Nowhere-in-particular"},
            "is_private": False,
        }
        assert gazetteer.resolve(location)["precision"] == "country"

    def test_private_ip_has_no_coordinates(self, gazetteer):
        location = {"country_code": "--", "city": {}, "is_private": True}
        assert gazetteer.resolve(location) is None

    def test_missing_country_has_no_coordinates(self, gazetteer):
        assert gazetteer.resolve({"city": {}}) is None

    def test_accents_and_case_are_normalized(self, gazetteer):
        location = {"country_code": "BR", "city": {"name": "SÃO PAULO"}}
        assert gazetteer.resolve(location)["precision"] == "city"

    def test_zoom_constants(self):
        assert CITY_ZOOM == 10
        assert COUNTRY_ZOOM == 4


class TestHaversine:
    def test_seoul_to_mountain_view(self):
        seoul = (37.5665, 126.978)
        mountain_view = (37.3861, -122.0839)
        # Great-circle distance is ~9,000 km; assert a tight band.
        assert 8900 < haversine_km(seoul, mountain_view) < 9200

    def test_zero_distance(self):
        assert haversine_km((37.5, 127.0), (37.5, 127.0)) == 0.0

    def test_symmetric(self):
        a, b = (51.5, -0.12), (-33.87, 151.21)
        assert haversine_km(a, b) == pytest.approx(haversine_km(b, a))

    def test_normalize_city_strips_accents(self):
        assert normalize_city("  SÃO  Paulo ") == "sao paulo"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_geo.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'geo'`

- [ ] **Step 3: Write the implementation**

Create `geo.py`:

```python
"""Coordinate lookup and great-circle distance.

geoip2fast returns city names but its latitude/longitude fields are always
null, so coordinates come from the local gazetteer built by
scripts/build_gazetteer.py.
"""

from __future__ import annotations

import json
import math
import os
import unicodedata
from typing import Any

CITIES_FILE = os.getenv("GEO_CITIES_FILE", "static/geo/cities.json")
COUNTRIES_FILE = os.getenv("GEO_COUNTRIES_FILE", "static/geo/countries.json")

CITY_ZOOM = 10
COUNTRY_ZOOM = 4
MIN_ROUTE_KM = 25.0
EARTH_RADIUS_KM = 6371.0088


def normalize_city(name: str) -> str:
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return " ".join(stripped.lower().split())


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(h))


class Gazetteer:
    def __init__(
        self, cities: dict[str, list[float]], countries: dict[str, list[float]]
    ) -> None:
        self.cities = cities
        self.countries = countries

    @classmethod
    def load(
        cls, cities_file: str = CITIES_FILE, countries_file: str = COUNTRIES_FILE
    ) -> "Gazetteer":
        with open(cities_file, encoding="utf-8") as handle:
            cities = json.load(handle)
        with open(countries_file, encoding="utf-8") as handle:
            countries = json.load(handle)
        return cls(cities, countries)

    def resolve(self, location: dict[str, Any] | None) -> dict[str, Any] | None:
        """Best-effort coordinates for a geoip2fast location dict."""
        if not location or location.get("is_private"):
            return None

        country = (location.get("country_code") or "").strip().upper()
        if not country or len(country) != 2 or not country.isalpha():
            return None

        city = (location.get("city") or {}).get("name") or ""
        if city:
            point = self.cities.get(f"{country}:{normalize_city(city)}")
            if point:
                return {"lat": point[0], "lon": point[1], "precision": "city"}

        point = self.countries.get(country)
        if point:
            return {"lat": point[0], "lon": point[1], "precision": "country"}
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_geo.py -v`
Expected: all passed.

- [ ] **Step 5: Lint**

Run: `poetry run ruff check geo.py scripts/build_gazetteer.py && poetry run ruff format geo.py scripts/build_gazetteer.py`
Expected: `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add geo.py tests/test_geo.py
git commit -m "feat(geo): resolve coordinates from gazetteer and compute haversine distance"
```

---

## Task 3: `mapgeom.py` — projection, tiles, great-circle polyline

The hard part, and the reason it lives in Python: Seoul → California crosses the Pacific. In Mercator pixel space a naive straight line runs the wrong way across Europe. Centering on the shortest-path midpoint longitude and unwrapping longitudes fixes both the tile grid and the arc.

**Files:**
- Create: `mapgeom.py`
- Test: `tests/test_mapgeom.py`

**Interfaces:**
- Consumes: nothing (pure math).
- Produces:
  - `TILE_URL_TEMPLATE`, `TILE_SIZE = 256`
  - `midpoint_lon(lon_a: float, lon_b: float) -> float`
  - `fit_zoom(a, b, width, height) -> int` where `a`/`b` are `(lat, lon)`
  - `great_circle_points(a, b, samples=48) -> list[tuple[float, float]]`
  - `build_canvas(target, origin, width, height) -> dict` — the payload the browser paints:
    ```python
    {
      "width": 1440, "height": 300, "zoom": 3,
      "tiles": [{"url": "https://tile.openstreetmap.org/3/1/3.png", "x": -40, "y": -12}, ...],
      "target": {"x": 980.0, "y": 120.0},
      "origin": {"x": 420.0, "y": 150.0} | None,
      "line": [[420.0, 150.0], ...] | None,
    }
    ```
    `target`/`origin` are `{"lat","lon"}` dicts; `origin=None` means city mode (single pin, no line).

- [ ] **Step 1: Write the failing test**

Create `tests/test_mapgeom.py`:

```python
import math

import pytest

from mapgeom import (
    TILE_SIZE,
    build_canvas,
    fit_zoom,
    great_circle_points,
    midpoint_lon,
)

SEOUL = {"lat": 37.5665, "lon": 126.978}
MOUNTAIN_VIEW = {"lat": 37.3861, "lon": -122.0839}
LONDON = {"lat": 51.5074, "lon": -0.1278}
DESKTOP = (1440, 300)


class TestMidpointLon:
    def test_simple_midpoint(self):
        assert midpoint_lon(10.0, 20.0) == pytest.approx(15.0)

    def test_crosses_antimeridian_the_short_way(self):
        # Seoul (127E) to Mountain View (122W): the short path is over the
        # Pacific, so the midpoint is near the dateline, NOT near longitude 2.
        mid = midpoint_lon(126.978, -122.0839)
        assert abs(mid) > 150.0

    def test_stays_in_range(self):
        for a, b in [(179.0, -179.0), (-170.0, 170.0), (0.0, 0.0)]:
            assert -180.0 <= midpoint_lon(a, b) <= 180.0


class TestGreatCirclePoints:
    def test_endpoints_are_preserved(self):
        points = great_circle_points(
            (SEOUL["lat"], SEOUL["lon"]),
            (MOUNTAIN_VIEW["lat"], MOUNTAIN_VIEW["lon"]),
            samples=16,
        )
        assert len(points) == 17
        assert points[0] == pytest.approx((SEOUL["lat"], SEOUL["lon"]), abs=1e-6)
        assert points[-1] == pytest.approx(
            (MOUNTAIN_VIEW["lat"], MOUNTAIN_VIEW["lon"]), abs=1e-6
        )

    def test_pacific_route_bulges_north_and_crosses_dateline(self):
        points = great_circle_points(
            (SEOUL["lat"], SEOUL["lon"]),
            (MOUNTAIN_VIEW["lat"], MOUNTAIN_VIEW["lon"]),
            samples=48,
        )
        # The great circle arcs north of both endpoints...
        assert max(lat for lat, _ in points) > 45.0
        # ...and passes through the Pacific near the dateline.
        assert any(abs(lon) > 170.0 for _, lon in points)

    def test_identical_points_do_not_divide_by_zero(self):
        points = great_circle_points((37.5, 127.0), (37.5, 127.0), samples=8)
        assert all(p == pytest.approx((37.5, 127.0)) for p in points)


class TestFitZoom:
    def test_far_apart_points_zoom_out(self):
        z = fit_zoom(
            (SEOUL["lat"], SEOUL["lon"]),
            (MOUNTAIN_VIEW["lat"], MOUNTAIN_VIEW["lon"]),
            *DESKTOP,
        )
        assert 1 <= z <= 3

    def test_close_points_zoom_in(self):
        z = fit_zoom((37.5665, 126.978), (37.4979, 127.0276), *DESKTOP)
        assert z >= 8


class TestBuildCanvas:
    def test_city_mode_single_pin_no_line(self):
        canvas = build_canvas(SEOUL, None, *DESKTOP)
        assert canvas["origin"] is None
        assert canvas["line"] is None
        assert canvas["zoom"] == 10
        # The target sits at the centre of the canvas.
        assert canvas["target"]["x"] == pytest.approx(720.0, abs=1.0)
        assert canvas["target"]["y"] == pytest.approx(150.0, abs=1.0)

    def test_tiles_cover_the_canvas(self):
        canvas = build_canvas(SEOUL, None, *DESKTOP)
        assert canvas["tiles"]
        for tile in canvas["tiles"]:
            assert tile["url"].startswith("https://tile.openstreetmap.org/10/")
            assert tile["url"].endswith(".png")
        # Every tile is placed so that the canvas is fully covered.
        assert min(t["x"] for t in canvas["tiles"]) <= 0
        assert max(t["x"] for t in canvas["tiles"]) + TILE_SIZE >= DESKTOP[0]
        assert min(t["y"] for t in canvas["tiles"]) <= 0
        assert max(t["y"] for t in canvas["tiles"]) + TILE_SIZE >= DESKTOP[1]

    def test_tile_x_wraps_around_the_dateline(self):
        canvas = build_canvas(MOUNTAIN_VIEW, SEOUL, *DESKTOP)
        z = canvas["zoom"]
        limit = 2**z
        for tile in canvas["tiles"]:
            _, _, tx, ty = tile["url"].rsplit("/", 3)
            assert 0 <= int(tx) < limit
            assert 0 <= int(ty.removesuffix(".png")) < limit

    def test_route_mode_line_connects_both_pins(self):
        canvas = build_canvas(MOUNTAIN_VIEW, SEOUL, *DESKTOP)
        assert canvas["origin"] is not None
        line = canvas["line"]
        assert len(line) >= 32
        assert line[0] == pytest.approx(
            [canvas["origin"]["x"], canvas["origin"]["y"]], abs=0.5
        )
        assert line[-1] == pytest.approx(
            [canvas["target"]["x"], canvas["target"]["y"]], abs=0.5
        )

    def test_route_line_does_not_backtrack_across_the_map(self):
        # The bug this guards: an un-unwrapped Mercator line from Seoul to
        # California runs west across Europe, so x would sweep the full canvas.
        canvas = build_canvas(MOUNTAIN_VIEW, SEOUL, *DESKTOP)
        xs = [x for x, _ in canvas["line"]]
        deltas = [b - a for a, b in zip(xs, xs[1:])]
        assert all(d >= -1e-6 for d in deltas) or all(d <= 1e-6 for d in deltas)

    def test_both_pins_land_inside_the_canvas(self):
        canvas = build_canvas(MOUNTAIN_VIEW, SEOUL, *DESKTOP)
        for pin in (canvas["target"], canvas["origin"]):
            assert 0 <= pin["x"] <= DESKTOP[0]
            assert 0 <= pin["y"] <= DESKTOP[1]

    def test_mobile_canvas_is_smaller_but_valid(self):
        canvas = build_canvas(MOUNTAIN_VIEW, SEOUL, 350, 170)
        assert canvas["width"] == 350
        assert canvas["height"] == 170
        assert 0 <= canvas["target"]["x"] <= 350
        assert not math.isnan(canvas["target"]["y"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_mapgeom.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mapgeom'`

- [ ] **Step 3: Write the implementation**

Create `mapgeom.py`:

```python
"""Web Mercator geometry for the OpenStreetMap band.

The browser is deliberately dumb: it paints the tiles and the polyline this
module produces. Keeping the projection here means the antimeridian handling
is covered by pytest instead of by eyeballing a map.
"""

from __future__ import annotations

import math

TILE_SIZE = 256
TILE_URL_TEMPLATE = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
CITY_ZOOM = 10
MIN_ZOOM = 1
MAX_ZOOM = 12
LINE_SAMPLES = 48
# Keep both pins away from the canvas edges.
FIT_MARGIN = 0.8


def _wrap180(degrees: float) -> float:
    return ((degrees + 180.0) % 360.0) - 180.0


def midpoint_lon(lon_a: float, lon_b: float) -> float:
    """Midpoint longitude along the SHORTER path (may cross the dateline)."""
    delta = _wrap180(lon_b - lon_a)
    return _wrap180(lon_a + delta / 2.0)


def _world_x(lon: float) -> float:
    return (lon + 180.0) / 360.0


def _world_y(lat: float) -> float:
    clamped = max(min(lat, 85.05112878), -85.05112878)
    sin_lat = math.sin(math.radians(clamped))
    return 0.5 - math.log((1 + sin_lat) / (1 - sin_lat)) / (4 * math.pi)


def great_circle_points(
    a: tuple[float, float], b: tuple[float, float], samples: int = LINE_SAMPLES
) -> list[tuple[float, float]]:
    """Sample the great circle from a to b as (lat, lon) pairs."""
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])

    central = 2 * math.asin(
        math.sqrt(
            math.sin((lat2 - lat1) / 2) ** 2
            + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
        )
    )
    if central < 1e-9:
        return [(a[0], a[1])] * (samples + 1)

    points: list[tuple[float, float]] = []
    for step in range(samples + 1):
        fraction = step / samples
        scale_a = math.sin((1 - fraction) * central) / math.sin(central)
        scale_b = math.sin(fraction * central) / math.sin(central)
        x = scale_a * math.cos(lat1) * math.cos(lon1) + scale_b * math.cos(
            lat2
        ) * math.cos(lon2)
        y = scale_a * math.cos(lat1) * math.sin(lon1) + scale_b * math.cos(
            lat2
        ) * math.sin(lon2)
        z = scale_a * math.sin(lat1) + scale_b * math.sin(lat2)
        points.append(
            (
                math.degrees(math.atan2(z, math.hypot(x, y))),
                math.degrees(math.atan2(y, x)),
            )
        )
    return points


def _unwrapped_x(lon: float, center_lon: float, scale: float) -> float:
    """World x for lon, expressed continuously around center_lon."""
    return _world_x(center_lon + _wrap180(lon - center_lon)) * scale


def fit_zoom(
    a: tuple[float, float], b: tuple[float, float], width: int, height: int
) -> int:
    """Largest integer zoom where both points fit inside the canvas."""
    center_lon = midpoint_lon(a[1], b[1])
    for zoom in range(MAX_ZOOM, MIN_ZOOM - 1, -1):
        scale = TILE_SIZE * (2**zoom)
        span_x = abs(
            _unwrapped_x(a[1], center_lon, scale) - _unwrapped_x(b[1], center_lon, scale)
        )
        span_y = abs(_world_y(a[0]) * scale - _world_y(b[0]) * scale)
        if span_x <= width * FIT_MARGIN and span_y <= height * FIT_MARGIN:
            return zoom
    return MIN_ZOOM


def build_canvas(
    target: dict[str, float],
    origin: dict[str, float] | None,
    width: int,
    height: int,
) -> dict:
    """Tiles, pin positions and the projected arc for one fixed canvas."""
    target_point = (target["lat"], target["lon"])

    if origin is None:
        zoom = CITY_ZOOM
        center_lat, center_lon = target_point
    else:
        origin_point = (origin["lat"], origin["lon"])
        zoom = fit_zoom(target_point, origin_point, width, height)
        center_lon = midpoint_lon(origin["lon"], target["lon"])
        center_lat = (origin["lat"] + target["lat"]) / 2.0

    scale = TILE_SIZE * (2**zoom)
    center_x = _world_x(center_lon) * scale
    center_y = _world_y(center_lat) * scale
    left = center_x - width / 2.0
    top = center_y - height / 2.0

    def project(lat: float, lon: float) -> tuple[float, float]:
        return (
            _unwrapped_x(lon, center_lon, scale) - left,
            _world_y(lat) * scale - top,
        )

    tile_count = 2**zoom
    tiles = []
    first_col = math.floor(left / TILE_SIZE)
    last_col = math.floor((left + width - 1) / TILE_SIZE)
    first_row = math.floor(top / TILE_SIZE)
    last_row = math.floor((top + height - 1) / TILE_SIZE)

    for col in range(first_col, last_col + 1):
        for row in range(first_row, last_row + 1):
            if row < 0 or row >= tile_count:
                continue
            tiles.append(
                {
                    "url": TILE_URL_TEMPLATE.format(
                        z=zoom, x=col % tile_count, y=row
                    ),
                    "x": round(col * TILE_SIZE - left, 2),
                    "y": round(row * TILE_SIZE - top, 2),
                }
            )

    target_x, target_y = project(*target_point)
    canvas = {
        "width": width,
        "height": height,
        "zoom": zoom,
        "tiles": tiles,
        "target": {"x": round(target_x, 2), "y": round(target_y, 2)},
        "origin": None,
        "line": None,
    }

    if origin is not None:
        origin_x, origin_y = project(origin["lat"], origin["lon"])
        canvas["origin"] = {"x": round(origin_x, 2), "y": round(origin_y, 2)}
        canvas["line"] = [
            [round(px, 2), round(py, 2)]
            for px, py in (
                project(lat, lon)
                for lat, lon in great_circle_points(
                    (origin["lat"], origin["lon"]), target_point
                )
            )
        ]
    return canvas
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_mapgeom.py -v`
Expected: all passed. If `test_route_line_does_not_backtrack_across_the_map` fails, the longitude unwrapping in `_unwrapped_x` is wrong — do not "fix" the test.

- [ ] **Step 5: Lint**

Run: `poetry run ruff check mapgeom.py && poetry run ruff format mapgeom.py`
Expected: `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add mapgeom.py tests/test_mapgeom.py
git commit -m "feat(map): project tiles and great-circle arcs with antimeridian wraparound"
```

---

## Task 4: Wire `map`, `distance_km`, `origin` into the API

**Files:**
- Modify: `main.py` (imports near line 17-31; CSP at 1072-1080; `get_self_info` 1086-1141; `get_ip_info` 1144-1250)
- Test: `tests/test_page.py`

**Interfaces:**
- Consumes: `geo.Gazetteer`, `geo.haversine_km`, `geo.MIN_ROUTE_KM`, `mapgeom.build_canvas`.
- Produces: `build_map_payload(target_location, origin_location) -> tuple[dict | None, float | None]` in `main.py`, plus these response keys:
  ```python
  "map": {"desktop": <canvas>, "mobile": <canvas>, "precision": "city",
          "origin_city": "Seoul", "origin_country": "KR"} | None,
  "distance_km": 9010.4 | None,
  "origin": {"lat": 37.5665, "lon": 126.978, "precision": "city"} | None,
  ```
  Canvas sizes: desktop `1440×300`, mobile `350×170`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_page.py`:

```python
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)
JSON_UA = {"user-agent": "curl/8.0"}


class TestMapPayload:
    def test_remote_lookup_has_distance_and_route(self):
        response = client.get(
            "/8.8.8.8", headers={**JSON_UA, "x-real-ip": "118.235.14.201"}
        )
        assert response.status_code == 200
        body = response.json()

        assert body["origin"]["precision"] in ("city", "country")
        assert body["distance_km"] > 1000
        desktop = body["map"]["desktop"]
        assert desktop["origin"] is not None
        assert len(desktop["line"]) >= 32
        assert desktop["tiles"][0]["url"].startswith(
            "https://tile.openstreetmap.org/"
        )
        assert body["map"]["mobile"]["width"] == 350

    def test_self_lookup_has_no_distance_and_no_line(self):
        response = client.get("/", headers={**JSON_UA, "x-real-ip": "118.235.14.201"})
        body = response.json()

        assert body["distance_km"] is None
        assert body["map"]["desktop"]["line"] is None
        assert body["map"]["desktop"]["origin"] is None
        assert body["map"]["desktop"]["zoom"] == 10

    def test_private_client_gets_no_map(self):
        response = client.get("/", headers={**JSON_UA, "x-real-ip": "127.0.0.1"})
        body = response.json()

        assert body["map"] is None
        assert body["distance_km"] is None
        assert body["origin"] is None

    def test_nearby_target_is_city_mode_not_route(self):
        # Same city on both ends: show one pin, no arc, no distance.
        response = client.get(
            "/1.201.0.1", headers={**JSON_UA, "x-real-ip": "1.201.0.1"}
        )
        body = response.json()
        if body["map"] is not None and body["origin"] is not None:
            assert body["map"]["desktop"]["line"] is None
            assert body["distance_km"] is None

    def test_legacy_keys_are_untouched(self):
        body = client.get("/8.8.8.8", headers=JSON_UA).json()
        for key in ("address", "datetime", "domain", "location", "whois", "ssl", "headers"):
            assert key in body


class TestSecurityHeaders:
    def test_csp_allows_only_the_osm_tile_host(self):
        csp = client.get("/", headers=JSON_UA).headers["content-security-policy"]
        assert "img-src 'self' data: https://tile.openstreetmap.org" in csp
        assert "script-src 'self' 'nonce-" in csp
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_page.py -v`
Expected: FAIL — `KeyError: 'origin'` / `KeyError: 'map'`.

- [ ] **Step 3: Add the imports and the payload builder**

In `main.py`, add to the import block (after `from geoip2fast import GeoIP2Fast`):

```python
from geo import MIN_ROUTE_KM, Gazetteer, haversine_km
from mapgeom import build_canvas
```

After the `geo_ip_manager = GeoIpManager()` instantiation (search for it near the module-level manager setup), add:

```python
gazetteer = Gazetteer.load()

DESKTOP_CANVAS = (1440, 300)
MOBILE_CANVAS = (350, 170)


def build_map_payload(
    target_location: dict | None, origin_location: dict | None
) -> tuple[dict | None, float | None, dict | None]:
    """Return (map, distance_km, origin) for the response.

    City mode (single pin, no arc) when the target is the visitor themselves,
    when the visitor's own location is unknown, or when the two points are
    within MIN_ROUTE_KM of each other.
    """
    target = gazetteer.resolve(target_location)
    if not target:
        return None, None, None

    origin = gazetteer.resolve(origin_location)
    distance_km = None
    route_origin = None

    if origin:
        distance_km = haversine_km(
            (origin["lat"], origin["lon"]), (target["lat"], target["lon"])
        )
        if distance_km >= MIN_ROUTE_KM:
            route_origin = origin
        else:
            distance_km = None

    payload = {
        "desktop": build_canvas(target, route_origin, *DESKTOP_CANVAS),
        "mobile": build_canvas(target, route_origin, *MOBILE_CANVAS),
        "precision": target["precision"],
        "origin_city": ((origin_location or {}).get("city") or {}).get("name") or None
        if route_origin
        else None,
        "origin_country": (origin_location or {}).get("country_code")
        if route_origin
        else None,
    }
    return payload, (round(distance_km, 1) if distance_km else None), origin
```

- [ ] **Step 4: Wire it into `get_self_info`**

In `main.py`, replace the `response_data = {...}` block in `get_self_info` (currently lines 1118-1126) with:

```python
    map_payload, distance_km, origin = await asyncio.to_thread(
        build_map_payload, ip_data, ip_data
    )
    # A self-lookup is never a route: the visitor is the target.
    response_data = {
        "address": client_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_records,
        "location": ip_data,
        "whois": whois_data,
        "ssl": None,
        "headers": request_headers,
        "map": map_payload,
        "distance_km": None,
        "origin": origin,
    }
```

Because `build_map_payload` is called with the same location twice, the distance is 0 km, which is below `MIN_ROUTE_KM`, so the canvas comes back in city mode with `line: None`. `distance_km` is forced to `None` for clarity.

- [ ] **Step 5: Wire it into `get_ip_info`**

In `main.py`, replace the `response_data = {...}` block in `get_ip_info` (currently lines 1227-1235) with:

```python
    origin_location = await asyncio.to_thread(geo_ip_manager.fetch_location, client_ip)
    origin_location.pop("elapsed_time", None)
    map_payload, distance_km, origin = await asyncio.to_thread(
        build_map_payload, ip_data, origin_location
    )

    response_data = {
        "address": domain_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_data,
        "location": ip_data,
        "whois": whois_data,
        "ssl": ssl_data,
        "headers": request_headers,
        "map": map_payload,
        "distance_km": distance_km,
        "origin": origin,
    }
```

- [ ] **Step 6: Extend the CSP**

In `main.py`, in `security_headers_middleware` (line 1076), change:

```python
        "img-src 'self' data:; "
```

to:

```python
        "img-src 'self' data: https://tile.openstreetmap.org; "
```

- [ ] **Step 7: Run the tests**

Run: `poetry run pytest tests/test_page.py tests/test_geo.py tests/test_mapgeom.py -v`
Expected: all passed.

- [ ] **Step 8: Lint and commit**

```bash
poetry run ruff check . && poetry run ruff format main.py
git add main.py tests/test_page.py
git commit -m "feat(api): return map canvases, origin and great-circle distance"
```

---

## Task 5: `viewmodel.py` — server-rendered view

Turns the raw response into exactly what the template prints. Pure function, so the hero copy, the 3-column facts grid and the certificate math are all unit-testable.

**Files:**
- Create: `viewmodel.py`
- Test: `tests/test_viewmodel.py`

**Interfaces:**
- Consumes: `response_data` from Task 4.
- Produces: `build_view(response_data: dict, is_self: bool) -> dict`:
  ```python
  {
    "eyebrow": "YOUR IP ADDRESS" | "LOOKUP",
    "target": "118.235.14.201",
    "tags": [{"text": "IPv4", "tone": "default"}, ...],
    "flag": "🇰🇷", "country_name": "Korea, Republic of",
    "city_line": "Seoul · Seoul", "asn_line": "AS3786 · LG DACOM",
    "distance_text": "≈ 9,010 km from you" | None,
    "facts": [{"title": "NETWORK", "rows": [{"label": "CIDR", "value": "…", "tone": "default"}]}, …],  # exactly 3
    "accordions": [{"id": "whois", "title": "WHOIS", "hint": "…"}, …],  # exactly 4
  }
  ```
  Tones: `default | muted | success | warning | danger`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_viewmodel.py`:

```python
import pytest

from viewmodel import build_view, country_flag, format_distance

IP_RESPONSE = {
    "address": "8.8.8.8",
    "location": {
        "ip": "8.8.8.8",
        "country_code": "US",
        "country_name": "United States",
        "city": {"name": "", "subdivision_name": ""},
        "cidr": "8.8.8.0/23",
        "asn_name": "Google LLC",
        "asn_cidr": "8.8.8.0/24",
        "is_private": False,
        "reverse_dns": "dns.google.",
    },
    "domain": {"a": [{"ip": "8.8.8.8", "ttl": 300}], "mx": [], "ns": [], "txt": []},
    "whois": {"error": "WHOIS lookup failed"},
    "ssl": None,
    "headers": {"user-agent": "curl/8.0"},
    "distance_km": 9010.4,
}

DOMAIN_RESPONSE = {
    "address": "google.com",
    "location": {
        "country_code": "US",
        "country_name": "United States",
        "city": {"name": "Mountain View", "subdivision_name": "California"},
        "cidr": "142.250.192.0/19",
        "asn_name": "Google LLC",
        "is_private": False,
    },
    "domain": {
        "a": [{"ip": "142.250.207.46", "ttl": 300}],
        "mx": [{"host": "smtp.google.com."}],
        "ns": [{"hostname": "ns1.google.com."}] * 4,
        "txt": ["v=spf1"] * 12,
    },
    "whois": {
        "registrar": "MarkMonitor Inc.",
        "creation_date": "1997-09-15 04:00:00",
        "expiration_date": "2028-09-14 04:00:00",
    },
    "ssl": {
        "issuer": ((("countryName", "US"),), (("organizationName", "Google Trust Services"),)),
        "notAfter": "Sep 14 08:00:00 2026 GMT",
        "subjectAltName": (("DNS", "*.google.com"), ("DNS", "google.com")),
    },
    "headers": {},
    "distance_km": None,
}


class TestHero:
    def test_self_lookup_eyebrow_and_tags(self):
        view = build_view(IP_RESPONSE, is_self=True)
        assert view["eyebrow"] == "YOUR IP ADDRESS"
        assert view["target"] == "8.8.8.8"
        assert {"text": "IPv4", "tone": "default"} in view["tags"]

    def test_remote_lookup_eyebrow_and_distance(self):
        view = build_view(IP_RESPONSE, is_self=False)
        assert view["eyebrow"] == "LOOKUP"
        assert view["distance_text"] == "≈ 9,010 km from you"

    def test_no_distance_when_missing(self):
        assert build_view(DOMAIN_RESPONSE, is_self=False)["distance_text"] is None

    def test_flag_from_country_code(self):
        assert country_flag("KR") == "🇰🇷"
        assert country_flag("us") == "🇺🇸"
        assert country_flag("") == ""
        assert country_flag("--") == ""

    def test_domain_target_shows_resolved_ip_tag(self):
        view = build_view(DOMAIN_RESPONSE, is_self=False)
        assert view["target"] == "google.com"
        assert any(tag["text"] == "DOMAIN" for tag in view["tags"])
        assert any("142.250.207.46" in tag["text"] for tag in view["tags"])

    def test_city_line_falls_back_to_country_when_city_unknown(self):
        view = build_view(IP_RESPONSE, is_self=True)
        assert view["country_name"] == "United States"
        assert view["city_line"] == ""


class TestFacts:
    def test_ip_columns(self):
        titles = [column["title"] for column in build_view(IP_RESPONSE, is_self=True)["facts"]]
        assert titles == ["NETWORK", "REVERSE DNS", "WHOIS"]

    def test_domain_columns(self):
        titles = [
            column["title"] for column in build_view(DOMAIN_RESPONSE, is_self=False)["facts"]
        ]
        assert titles == ["NETWORK", "DNS", "CERTIFICATE"]

    def test_failed_whois_is_a_warning_not_an_error_page(self):
        whois_column = build_view(IP_RESPONSE, is_self=True)["facts"][2]
        status = whois_column["rows"][0]
        assert status["value"] == "unavailable"
        assert status["tone"] == "warning"

    def test_certificate_column_reads_the_raw_getpeercert_dict(self):
        cert = build_view(DOMAIN_RESPONSE, is_self=False)["facts"][2]
        rows = {row["label"]: row for row in cert["rows"]}
        assert rows["Issuer"]["value"] == "Google Trust Services"
        assert rows["SAN"]["value"] == "2 names"
        assert rows["Expires"]["value"] == "2026-09-14"
        assert rows["Status"]["tone"] in ("success", "warning", "danger")

    def test_dns_column_counts_records(self):
        dns_column = build_view(DOMAIN_RESPONSE, is_self=False)["facts"][1]
        rows = {row["label"]: row["value"] for row in dns_column["rows"]}
        assert rows["A"] == "1 record"
        assert rows["NS"] == "4 records"
        assert rows["TXT"] == "12 records"

    def test_empty_dns_records_render_as_dash(self):
        response = dict(DOMAIN_RESPONSE, domain={})
        dns_column = build_view(response, is_self=False)["facts"][1]
        assert all(row["value"] == "—" for row in dns_column["rows"])


class TestAccordions:
    def test_four_accordions_in_order(self):
        ids = [item["id"] for item in build_view(IP_RESPONSE, is_self=True)["accordions"]]
        assert ids == ["whois", "dns", "headers", "raw"]

    def test_hints_summarise_content(self):
        items = {i["id"]: i["hint"] for i in build_view(DOMAIN_RESPONSE, is_self=False)["accordions"]}
        assert "MarkMonitor" in items["whois"]
        assert items["dns"] == "A 1 · MX 1 · NS 4 · TXT 12"

    def test_failed_whois_hint(self):
        items = {i["id"]: i["hint"] for i in build_view(IP_RESPONSE, is_self=True)["accordions"]}
        assert items["whois"] == "lookup failed"
        assert items["headers"] == "1 header"


class TestFormatDistance:
    def test_thousands_separator_and_approx_sign(self):
        assert format_distance(9010.4) == "≈ 9,010 km from you"

    def test_none_stays_none(self):
        assert format_distance(None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_viewmodel.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'viewmodel'`

- [ ] **Step 3: Write the implementation**

Create `viewmodel.py`:

```python
"""Map the API response onto exactly what the template prints.

Pure functions only: no request, no I/O. The template does no logic beyond
looping over what comes out of build_view().
"""

from __future__ import annotations

import datetime
import ipaddress
from typing import Any

DASH = "—"


def country_flag(country_code: str | None) -> str:
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def format_distance(distance_km: float | None) -> str | None:
    if not distance_km:
        return None
    return f"≈ {round(distance_km):,} km from you"


def _count(items: Any, unit: str = "record") -> str:
    total = len(items or [])
    if not total:
        return DASH
    return f"{total} {unit}{'s' if total != 1 else ''}"


def _is_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def _cert_issuer(ssl_data: dict) -> str:
    for rdn in ssl_data.get("issuer", ()):
        for key, value in rdn:
            if key == "organizationName":
                return value
    return DASH


def _cert_expiry(ssl_data: dict) -> tuple[str, int | None]:
    raw = ssl_data.get("notAfter")
    if not raw:
        return DASH, None
    parsed = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc
    )
    days_left = (parsed - datetime.datetime.now(tz=datetime.timezone.utc)).days
    return parsed.date().isoformat(), days_left


def _network_column(location: dict, domain: dict, address: str) -> dict:
    rows = [
        {"label": "CIDR", "value": location.get("cidr") or DASH, "tone": "default"},
        {"label": "ASN", "value": location.get("asn_cidr") or DASH, "tone": "default"},
        {"label": "Org", "value": location.get("asn_name") or DASH, "tone": "default"},
    ]
    if _is_ip(address):
        rows.append(
            {
                "label": "Scope",
                "value": "private" if location.get("is_private") else "public",
                "tone": "warning" if location.get("is_private") else "default",
            }
        )
    else:
        rows.append(
            {
                "label": "rDNS",
                "value": location.get("reverse_dns") or DASH,
                "tone": "default" if location.get("reverse_dns") else "muted",
            }
        )
    return {"title": "NETWORK", "rows": rows}


def _dns_column(domain: dict) -> dict:
    domain = domain or {}
    return {
        "title": "DNS",
        "rows": [
            {"label": "A", "value": _count(domain.get("a")), "tone": "default"},
            {"label": "MX", "value": _count(domain.get("mx")), "tone": "default"},
            {"label": "NS", "value": _count(domain.get("ns")), "tone": "default"},
            {"label": "TXT", "value": _count(domain.get("txt")), "tone": "default"},
        ],
    }


def _reverse_column(location: dict, domain: dict) -> dict:
    domain = domain or {}
    reverse = location.get("reverse_dns")
    ttl = next(iter(domain.get("a") or []), {}).get("ttl")
    return {
        "title": "REVERSE DNS",
        "rows": [
            {
                "label": "PTR",
                "value": reverse or DASH,
                "tone": "default" if reverse else "muted",
            },
            {"label": "A", "value": _count(domain.get("a")), "tone": "default"},
            {"label": "NS", "value": _count(domain.get("ns")), "tone": "default"},
            {
                "label": "TTL",
                "value": f"{ttl}s" if ttl else DASH,
                "tone": "default" if ttl else "muted",
            },
        ],
    }


def _whois_column(whois_data: dict, location: dict) -> dict:
    whois_data = whois_data or {}
    failed = "error" in whois_data or not whois_data
    return {
        "title": "WHOIS",
        "rows": [
            {
                "label": "Status",
                "value": "unavailable" if failed else "available",
                "tone": "warning" if failed else "success",
            },
            {
                "label": "Netblock",
                "value": location.get("cidr") or DASH,
                "tone": "default",
            },
            {
                "label": "Country",
                "value": location.get("country_code") or DASH,
                "tone": "default",
            },
            {
                "label": "Updated",
                "value": str(whois_data.get("updated_date") or DASH),
                "tone": "muted" if failed else "default",
            },
        ],
    }


def _certificate_column(ssl_data: dict | None) -> dict:
    if not ssl_data:
        return {
            "title": "CERTIFICATE",
            "rows": [
                {"label": "Status", "value": "none", "tone": "muted"},
                {"label": "Issuer", "value": DASH, "tone": "muted"},
                {"label": "SAN", "value": DASH, "tone": "muted"},
                {"label": "Expires", "value": DASH, "tone": "muted"},
            ],
        }

    expires, days_left = _cert_expiry(ssl_data)
    if days_left is None:
        status, tone = DASH, "muted"
    elif days_left < 0:
        status, tone = "expired", "danger"
    elif days_left < 14:
        status, tone = f"valid · {days_left}d left", "warning"
    else:
        status, tone = f"valid · {days_left}d left", "success"

    san = ssl_data.get("subjectAltName") or ()
    return {
        "title": "CERTIFICATE",
        "rows": [
            {"label": "Status", "value": status, "tone": tone},
            {"label": "Issuer", "value": _cert_issuer(ssl_data), "tone": "default"},
            {"label": "SAN", "value": _count(san, unit="name"), "tone": "default"},
            {"label": "Expires", "value": expires, "tone": "default"},
        ],
    }


def _tags(response: dict, is_ip: bool) -> list[dict]:
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    if is_ip:
        tags = [{"text": "IPv4", "tone": "default"}]
        tags.append(
            {
                "text": "PRIVATE" if location.get("is_private") else "PUBLIC",
                "tone": "warning" if location.get("is_private") else "default",
            }
        )
        return tags

    tags = [{"text": "DOMAIN", "tone": "default"}]
    first_a = next(iter(domain.get("a") or []), None)
    if first_a:
        tags.append({"text": f"A → {first_a['ip']}", "tone": "default"})
    if response.get("ssl"):
        tags.append({"text": "TLS valid", "tone": "success"})
    return tags


def _accordions(response: dict) -> list[dict]:
    whois_data = response.get("whois") or {}
    domain = response.get("domain") or {}
    headers = response.get("headers") or {}

    if "error" in whois_data or not whois_data:
        whois_hint = "lookup failed"
    else:
        registrar = whois_data.get("registrar") or "registry data"
        created = str(whois_data.get("creation_date") or "")[:4]
        expires = str(whois_data.get("expiration_date") or "")[:4]
        span = f" · {created} → {expires}" if created and expires else ""
        whois_hint = f"{registrar}{span}"

    dns_hint = " · ".join(
        f"{label} {len(domain.get(key) or [])}"
        for label, key in (("A", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt"))
    )
    header_count = len(headers)
    return [
        {"id": "whois", "title": "WHOIS", "hint": whois_hint},
        {"id": "dns", "title": "DNS records", "hint": dns_hint},
        {
            "id": "headers",
            "title": "Your headers",
            "hint": f"{header_count} header{'s' if header_count != 1 else ''}",
        },
        {"id": "raw", "title": "Raw JSON", "hint": "full response"},
    ]


def build_view(response: dict, is_self: bool) -> dict:
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    address = response.get("address") or ""
    is_ip = _is_ip(address)

    city = (location.get("city") or {}).get("name") or ""
    subdivision = (location.get("city") or {}).get("subdivision_name") or ""
    city_line = " · ".join(part for part in (city, subdivision) if part)

    asn_parts = [
        part
        for part in (location.get("asn_cidr"), location.get("asn_name"))
        if part
    ]

    if is_ip:
        facts = [
            _network_column(location, domain, address),
            _reverse_column(location, domain),
            _whois_column(response.get("whois"), location),
        ]
    else:
        facts = [
            _network_column(location, domain, address),
            _dns_column(domain),
            _certificate_column(response.get("ssl")),
        ]

    return {
        "eyebrow": "YOUR IP ADDRESS" if is_self else "LOOKUP",
        "target": address,
        "tags": _tags(response, is_ip),
        "flag": country_flag(location.get("country_code")),
        "country_name": location.get("country_name") or "",
        "city_line": city_line,
        "asn_line": " · ".join(asn_parts),
        "distance_text": format_distance(response.get("distance_km")),
        "facts": facts,
        "accordions": _accordions(response),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_viewmodel.py -v`
Expected: all passed.

- [ ] **Step 5: Lint and commit**

```bash
poetry run ruff check viewmodel.py && poetry run ruff format viewmodel.py
git add viewmodel.py tests/test_viewmodel.py
git commit -m "feat(view): add pure view-model for hero, facts and accordions"
```

---

## Task 6: Fonts and design tokens

**Files:**
- Create: `scripts/fetch_fonts.sh`
- Create (vendored, committed): `static/fonts/InterVariable.woff2`, `static/fonts/JetBrainsMono-Regular.woff2`, `static/fonts/JetBrainsMono-Medium.woff2`, `static/fonts/JetBrainsMono-SemiBold.woff2`
- Rewrite: `static/css/whatismyip.css`
- Test: `tests/test_page.py` (append)

**Interfaces:**
- Produces: CSS custom properties on `:root` — `--bg`, `--surface`, `--surface-2`, `--border`, `--border-strong`, `--text-primary`, `--text-secondary`, `--text-muted`, `--accent`, `--accent-soft`, `--success`, `--warning`, `--danger`, `--font-sans`, `--font-mono`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_page.py`:

```python
import re
from pathlib import Path

CSS = Path("static/css/whatismyip.css")

REQUIRED_TOKENS = {
    "--bg": "#0B0D12",
    "--surface": "#151922",
    "--surface-2": "#1B2130",
    "--border": "#232A36",
    "--border-strong": "#2E3746",
    "--text-primary": "#E8ECF3",
    "--text-secondary": "#8B97AC",
    "--text-muted": "#606C82",
    "--accent": "#5B8CFF",
    "--success": "#34D399",
    "--warning": "#FBBF24",
    "--danger": "#FB7185",
}


class TestDesignTokens:
    def test_all_tokens_are_defined_with_the_spec_values(self):
        css = CSS.read_text(encoding="utf-8")
        for token, value in REQUIRED_TOKENS.items():
            assert re.search(rf"{token}:\s*{value};", css, re.IGNORECASE), token

    def test_every_font_file_referenced_by_css_exists(self):
        css = CSS.read_text(encoding="utf-8")
        sources = re.findall(r"url\(['\"]?(/static/fonts/[^'\")]+)", css)
        assert sources, "no @font-face sources found"
        for source in sources:
            assert Path(source.lstrip("/")).is_file(), source

    def test_no_light_mode_branch(self):
        assert "prefers-color-scheme" not in CSS.read_text(encoding="utf-8")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_page.py -k DesignTokens -v`
Expected: FAIL — token assertions fail against the old CSS.

- [ ] **Step 3: Write the font fetch script**

Create `scripts/fetch_fonts.sh`:

```bash
#!/usr/bin/env bash
# Vendor the two webfonts. CSP is `default-src 'self'`, so Google Fonts and any
# other CDN are blocked by design — the woff2 files must live in static/fonts/.
set -euo pipefail

INTER_VERSION="4.1"
JETBRAINS_VERSION="2.304"
DEST="static/fonts"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$DEST"

curl -fsSL -o "$TMP/inter.zip" \
  "https://github.com/rsms/inter/releases/download/v${INTER_VERSION}/Inter-${INTER_VERSION}.zip"
unzip -j -o "$TMP/inter.zip" "web/InterVariable.woff2" -d "$DEST"

curl -fsSL -o "$TMP/jetbrains.zip" \
  "https://github.com/JetBrains/JetBrainsMono/releases/download/v${JETBRAINS_VERSION}/JetBrainsMono-${JETBRAINS_VERSION}.zip"
unzip -j -o "$TMP/jetbrains.zip" \
  "fonts/webfonts/JetBrainsMono-Regular.woff2" \
  "fonts/webfonts/JetBrainsMono-Medium.woff2" \
  "fonts/webfonts/JetBrainsMono-SemiBold.woff2" -d "$DEST"

ls -la "$DEST"
```

Run:

```bash
chmod +x scripts/fetch_fonts.sh
./scripts/fetch_fonts.sh
```

Expected: four `.woff2` files in `static/fonts/`. If a path inside either zip has moved, run `unzip -l "$TMP/inter.zip"` and fix the path — do not fall back to a CDN.

- [ ] **Step 4: Rewrite the stylesheet**

Replace the whole of `static/css/whatismyip.css`:

```css
@font-face {
  font-family: "InterVariable";
  src: url("/static/fonts/InterVariable.woff2") format("woff2");
  font-weight: 100 900;
  font-display: swap;
}
@font-face {
  font-family: "JetBrains Mono";
  src: url("/static/fonts/JetBrainsMono-Regular.woff2") format("woff2");
  font-weight: 400;
  font-display: swap;
}
@font-face {
  font-family: "JetBrains Mono";
  src: url("/static/fonts/JetBrainsMono-Medium.woff2") format("woff2");
  font-weight: 500;
  font-display: swap;
}
@font-face {
  font-family: "JetBrains Mono";
  src: url("/static/fonts/JetBrainsMono-SemiBold.woff2") format("woff2");
  font-weight: 600;
  font-display: swap;
}

:root {
  --bg: #0B0D12;
  --surface: #151922;
  --surface-2: #1B2130;
  --border: #232A36;
  --border-strong: #2E3746;
  --text-primary: #E8ECF3;
  --text-secondary: #8B97AC;
  --text-muted: #606C82;
  --accent: #5B8CFF;
  --accent-soft: #5B8CFF1F;
  --success: #34D399;
  --warning: #FBBF24;
  --danger: #FB7185;
  --font-sans: "InterVariable", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, monospace;
  --radius: 12px;
  --gutter: 220px;
}

*, *::before, *::after { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text-primary);
  font-family: var(--font-sans);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}

.mono, .value, .ip, .tag, .hint, .kv-label {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

.tone-default { color: var(--text-primary); }
.tone-muted { color: var(--text-muted); }
.tone-success { color: var(--success); }
.tone-warning { color: var(--warning); }
.tone-danger { color: var(--danger); }

.shell { max-width: 1440px; margin: 0 auto; }
.inset { padding-inline: var(--gutter); }

/* Topbar */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding-block: 16px;
  border-bottom: 1px solid var(--border);
}
.wordmark { display: flex; align-items: center; gap: 9px; font-weight: 600; font-size: 14px; }
.wordmark::before {
  content: "";
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--accent);
}
.search {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 440px;
  max-width: 100%;
  height: 48px;
  padding-inline: 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  transition: border-color 0.2s ease;
}
.search:focus-within { border-color: var(--accent); }
.search input {
  flex: 1;
  min-width: 0;
  background: none;
  border: 0;
  outline: none;
  color: var(--text-primary);
  font: 500 14px/1 var(--font-mono);
}
.search input::placeholder { color: var(--text-muted); font-family: var(--font-sans); }
.search kbd {
  padding: 3px 8px;
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  background: var(--surface-2);
  color: var(--text-muted);
  font: 500 11px/1 var(--font-mono);
}

/* Hero over the map band */
.band { position: relative; height: 300px; overflow: hidden; }
.band__scrim {
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, #0B0D12FA 0%, #0B0D12E6 50%, #0B0D12A6 100%);
}
.band__fade {
  position: absolute;
  inset: auto 0 0 0;
  height: 120px;
  background: linear-gradient(180deg, #0B0D1200 0%, var(--bg) 100%);
}
.hero { position: relative; padding-top: 52px; }
.hero__label {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.eyebrow {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.6px;
  color: var(--text-secondary);
}
.copy-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 7px 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text-secondary);
  font: 500 12px/1 var(--font-sans);
  cursor: pointer;
}
.copy-btn:hover { border-color: var(--accent); color: var(--accent); }
.hero__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  margin-top: 20px;
}
.ip {
  margin: 0;
  font-size: 56px;
  font-weight: 600;
  letter-spacing: -1px;
  overflow-wrap: anywhere;
}
.tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.tag {
  padding: 4px 9px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface);
  color: var(--text-secondary);
  font-size: 11px;
  letter-spacing: 0.6px;
}
.tag.tone-success { border-color: transparent; background: #34D3991F; color: var(--success); }
.origin { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; text-align: right; }
.origin__country { display: flex; align-items: center; gap: 10px; font-size: 16px; font-weight: 500; }
.origin__flag { font-size: 22px; }
.origin__city { font-size: 13px; color: var(--text-secondary); }
.origin__asn { font-size: 12px; color: var(--text-muted); font-family: var(--font-mono); }
.origin__distance { font: 600 12px/1.4 var(--font-mono); color: var(--accent); }

/* Facts */
.facts {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0;
  padding-block: 36px;
}
.facts__col { padding-inline: 34px; }
.facts__col:first-child { padding-left: 0; }
.facts__col:last-child { padding-right: 0; }
.facts__col + .facts__col { border-left: 1px solid var(--border); }
.facts__title {
  margin: 0 0 16px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.6px;
  color: var(--text-muted);
}
.kv { display: flex; gap: 16px; margin-bottom: 10px; }
.kv-label { width: 64px; flex: none; font-size: 11px; color: var(--text-muted); letter-spacing: 0.6px; }
.kv-value { font-size: 13px; font-weight: 500; overflow-wrap: anywhere; }

/* Accordions */
.accordions { display: flex; flex-direction: column; gap: 10px; padding-bottom: 72px; }
.accordion {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.accordion__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  padding: 16px 18px;
  background: none;
  border: 0;
  color: var(--text-primary);
  font: 600 14px/1 var(--font-sans);
  text-align: left;
  cursor: pointer;
}
.accordion__header::before {
  content: "▸";
  color: var(--text-secondary);
  transition: transform 0.2s ease;
}
.accordion[open] .accordion__header::before { transform: rotate(90deg); color: var(--accent); }
.accordion__title { flex: 1; }
.hint { font-size: 12px; font-weight: 400; color: var(--text-muted); }
.accordion__body { padding: 0 18px 18px; }
.accordion[open] .accordion__body { border-top: 1px solid var(--border); padding-top: 16px; }

table.records { width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 12.5px; }
table.records th {
  padding: 10px 0;
  color: var(--text-muted);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
table.records td { padding: 11px 0; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
table.records tr:last-child td { border-bottom: 0; }
table.records td:first-child { color: var(--accent); width: 92px; }

/* Footer */
.footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding-block: 20px;
  border-top: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 12px;
}
.footer a { color: var(--text-secondary); text-decoration: none; }
.footer a:hover { color: var(--accent); }

/* Map */
.map { position: absolute; inset: 0; }
.map__tiles { position: absolute; inset: 0; }
.map__tiles img { position: absolute; width: 256px; height: 256px; }
.map__overlay { position: absolute; inset: 0; width: 100%; height: 100%; }
.map__line { fill: none; stroke: var(--accent); stroke-width: 1.5; stroke-linecap: round; }
.map__pin-halo { fill: #5B8CFF14; stroke: #5B8CFF33; }
.map__pin-ring { fill: #5B8CFF29; stroke: #5B8CFF66; }
.map__pin-dot { fill: var(--accent); }
.map__pin--origin .map__pin-halo { fill: #8B97AC14; stroke: #8B97AC40; }
.map__pin--origin .map__pin-dot { fill: var(--text-secondary); }
.map__chip {
  position: absolute;
  padding: 5px 10px;
  transform: translate(-50%, -50%);
  background: #0B0D12E6;
  border: 1px solid #5B8CFF4D;
  border-radius: 8px;
  color: var(--accent);
  font: 600 12px/1 var(--font-mono);
  white-space: nowrap;
}
.map__attribution {
  position: absolute;
  right: 8px;
  bottom: 8px;
  padding: 4px 8px;
  background: #0B0D12B3;
  border-radius: 6px;
  color: var(--text-muted);
  font-size: 10px;
}
.map__attribution a { color: inherit; }

.mobile-map { display: none; }

@media (max-width: 900px) {
  :root { --gutter: 20px; }
  .topbar { flex-direction: column; align-items: stretch; gap: 12px; }
  .search { width: 100%; height: 44px; }
  .band { height: auto; }
  .band__scrim, .band__fade, .band .map { display: none; }
  .hero { padding-top: 28px; padding-bottom: 8px; }
  .hero__row { flex-direction: column; align-items: flex-start; gap: 14px; }
  .ip { font-size: 32px; }
  .origin { align-items: flex-start; text-align: left; }
  .facts { grid-template-columns: 1fr; gap: 24px; padding-block: 24px; }
  .facts__col { padding-inline: 0; }
  .facts__col + .facts__col { border-left: 0; border-top: 1px solid var(--border); padding-top: 24px; }
  .mobile-map { display: block; padding-bottom: 24px; }
  .mobile-map__card {
    position: relative;
    height: 170px;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 14px;
    background: var(--surface);
  }
  .mobile-map__header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
  }
  .footer { flex-direction: column; align-items: flex-start; gap: 8px; }
}
```

- [ ] **Step 5: Run the tests**

Run: `poetry run pytest tests/test_page.py -k DesignTokens -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add scripts/fetch_fonts.sh static/fonts static/css/whatismyip.css tests/test_page.py
git commit -m "feat(ui): self-host Inter and JetBrains Mono, add dark design tokens"
```

---

## Task 7: Template rewrite and page interactions

**Files:**
- Rewrite: `templates/browser.html`
- Create: `static/js/app.js`
- Modify: `main.py` (both `templates.TemplateResponse` calls)
- Test: `tests/test_page.py` (append)

**Interfaces:**
- Consumes: `build_view()` (Task 5), the `map` payload (Task 4).
- Produces: template context `{"view": <view>, "json_data": <json str>, "map_data": <json str>, "nonce": <str>}`; DOM ids `#page-map` (desktop band), `#mobile-map` (mobile card), `#raw-json`, `#lookup-form`, `#lookup-input`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_page.py`:

```python
BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}


class TestBrowserPage:
    def test_server_renders_the_answer_without_javascript(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "WhatIsMyIP" in html
        assert "8.8.8.8" in html
        assert "LOOKUP" in html
        assert "NETWORK" in html
        assert "Raw JSON" in html

    def test_no_inline_event_handlers(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert "onclick=" not in html
        assert "onsubmit=" not in html

    def test_osm_attribution_and_privacy_notice_are_present(self):
        html = client.get("/8.8.8.8", headers=BROWSER_UA).text
        assert "OpenStreetMap contributors" in html
        assert "openstreetmap.org" in html

    def test_json_editor_is_not_loaded_eagerly(self):
        html = client.get("/", headers=BROWSER_UA).text
        # The tree only boots when Raw JSON is opened.
        assert 'id="raw-json"' in html
        assert "new JSONEditor(" not in html

    def test_search_form_targets_the_root_path(self):
        html = client.get("/", headers=BROWSER_UA).text
        assert 'id="lookup-form"' in html
        assert 'id="lookup-input"' in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_page.py -k BrowserPage -v`
Expected: FAIL — the old template has none of these.

- [ ] **Step 3: Rewrite the template**

Replace the whole of `templates/browser.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ view.target }} — WhatIsMyIP</title>
    <link rel="preload" href="/static/fonts/InterVariable.woff2" as="font" type="font/woff2" crossorigin>
    <link rel="stylesheet" href="/static/css/whatismyip.css">
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <link rel="shortcut icon" href="/static/favicon.ico">
    <link rel="manifest" href="/static/site.webmanifest">
</head>
<body>
<div class="shell">
    <header class="topbar inset">
        <span class="wordmark">WhatIsMyIP</span>
        <form class="search" id="lookup-form" action="/" method="get" autocomplete="off">
            <input type="text" id="lookup-input" name="q" spellcheck="false"
                   placeholder="Enter a domain or IP address"
                   aria-label="Domain or IP address to look up">
            <kbd>/</kbd>
        </form>
    </header>

    <section class="band">
        {% if view_map %}
        <div class="map" id="page-map" data-variant="desktop"></div>
        {% endif %}
        <div class="band__scrim"></div>
        <div class="band__fade"></div>
        <div class="hero inset">
            <div class="hero__label">
                <span class="eyebrow">{{ view.eyebrow }}</span>
                <button type="button" class="copy-btn" id="copy-target" data-value="{{ view.target }}">Copy</button>
            </div>
            <div class="hero__row">
                <div>
                    <h1 class="ip mono">{{ view.target }}</h1>
                    <div class="tags">
                        {% for tag in view.tags %}
                        <span class="tag tone-{{ tag.tone }}">{{ tag.text }}</span>
                        {% endfor %}
                    </div>
                </div>
                <div class="origin">
                    <div class="origin__country">
                        <span class="origin__flag">{{ view.flag }}</span>
                        <span>{{ view.country_name }}</span>
                    </div>
                    {% if view.city_line %}<span class="origin__city">{{ view.city_line }}</span>{% endif %}
                    {% if view.asn_line %}<span class="origin__asn">{{ view.asn_line }}</span>{% endif %}
                    {% if view.distance_text %}<span class="origin__distance">{{ view.distance_text }}</span>{% endif %}
                </div>
            </div>
        </div>
    </section>

    <main class="inset">
        {% if view_map %}
        <section class="mobile-map">
            <div class="mobile-map__header">
                <h2 class="facts__title">LOCATION</h2>
                <span class="hint">{{ view.distance_text or view.city_line or view.country_name }}</span>
            </div>
            <div class="mobile-map__card map" id="mobile-map" data-variant="mobile"></div>
        </section>
        {% endif %}

        <section class="facts">
            {% for column in view.facts %}
            <div class="facts__col">
                <h2 class="facts__title">{{ column.title }}</h2>
                {% for row in column.rows %}
                <div class="kv">
                    <span class="kv-label">{{ row.label }}</span>
                    <span class="kv-value mono tone-{{ row.tone }}">{{ row.value }}</span>
                </div>
                {% endfor %}
            </div>
            {% endfor %}
        </section>

        <section class="accordions">
            {% for item in view.accordions %}
            <details class="accordion" id="acc-{{ item.id }}">
                <summary class="accordion__header">
                    <span class="accordion__title">{{ item.title }}</span>
                    <span class="hint">{{ item.hint }}</span>
                </summary>
                <div class="accordion__body">
                    {% if item.id == 'raw' %}
                    <div id="raw-json"></div>
                    {% elif item.id == 'dns' %}
                    <table class="records">
                        <thead><tr><th>TYPE</th><th>NAME</th><th>VALUE</th><th>TTL</th></tr></thead>
                        <tbody>
                        {% for record in dns_rows %}
                        <tr>
                            <td>{{ record.type }}</td>
                            <td>{{ record.name }}</td>
                            <td>{{ record.value }}</td>
                            <td>{{ record.ttl }}</td>
                        </tr>
                        {% else %}
                        <tr><td colspan="4" class="tone-muted">No records</td></tr>
                        {% endfor %}
                        </tbody>
                    </table>
                    {% elif item.id == 'headers' %}
                    <table class="records">
                        <tbody>
                        {% for key, value in headers.items() %}
                        <tr><td>{{ key }}</td><td colspan="3">{{ value }}</td></tr>
                        {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <table class="records">
                        <tbody>
                        {% for key, value in whois.items() %}
                        <tr><td>{{ key }}</td><td colspan="3">{{ value }}</td></tr>
                        {% endfor %}
                        </tbody>
                    </table>
                    {% endif %}
                </div>
            </details>
            {% endfor %}
        </section>
    </main>

    <footer class="footer inset">
        <span class="mono">curl -H "Accept: application/json" {{ request.base_url }}{{ view.target }}</span>
        <span>Map tiles load directly from
            <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">openstreetmap.org</a>
            · © OpenStreetMap contributors</span>
        <a href="https://github.com/1kko/whatismyip" target="_blank" rel="noopener noreferrer">1kko/whatismyip</a>
    </footer>
</div>

<script type="application/json" id="page-data" nonce="{{ nonce }}">{{ json_data | safe }}</script>
<script type="application/json" id="map-data" nonce="{{ nonce }}">{{ map_data | safe }}</script>
<script src="/static/js/app.js" nonce="{{ nonce }}" defer></script>
<script src="/static/js/map.js" nonce="{{ nonce }}" defer></script>
</body>
</html>
```

- [ ] **Step 4: Write `static/js/app.js`**

Create `static/js/app.js`:

```javascript
// Search, copy, and lazily booting the JSON tree. CSP forbids inline handlers,
// so everything is wired with addEventListener from this file.
const pageData = JSON.parse(document.getElementById("page-data").textContent);

function normalizeLookupTarget(raw) {
  return raw
    .trim()
    .replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "")
    .split(/[/?#]/)[0];
}

const form = document.getElementById("lookup-form");
const input = document.getElementById("lookup-input");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = normalizeLookupTarget(input.value);
  if (target) {
    window.location.assign("/" + encodeURIComponent(target));
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "/" && document.activeElement !== input) {
    event.preventDefault();
    input.focus();
  }
});

const copyButton = document.getElementById("copy-target");
copyButton.addEventListener("click", async () => {
  await navigator.clipboard.writeText(copyButton.dataset.value);
  const original = copyButton.textContent;
  copyButton.textContent = "Copied";
  setTimeout(() => {
    copyButton.textContent = original;
  }, 1500);
});

// JSONEditor is 200KB+; only pay for it if Raw JSON is actually opened.
const rawAccordion = document.getElementById("acc-raw");
let rawBooted = false;

rawAccordion.addEventListener("toggle", () => {
  if (!rawAccordion.open || rawBooted) {
    return;
  }
  rawBooted = true;

  const styles = document.createElement("link");
  styles.rel = "stylesheet";
  styles.href = "/static/css/jsoneditor.css";
  document.head.appendChild(styles);

  const script = document.createElement("script");
  script.src = "/static/js/jsoneditor.min.js";
  script.addEventListener("load", () => {
    const editor = new JSONEditor(document.getElementById("raw-json"), {
      mode: "view",
      search: false,
      navigationBar: false,
      mainMenuBar: false,
      indentation: 2,
    });
    editor.set(pageData);
    editor.expandAll();
  });
  document.body.appendChild(script);
});
```

- [ ] **Step 5: Pass the view to the template**

In `main.py`, add the import:

```python
from viewmodel import build_view
```

Then add this helper next to `build_map_payload`:

```python
def render_page(request: Request, response_data: dict, is_self: bool):
    """Render browser.html from the server-side view model."""
    domain = response_data.get("domain") or {}
    dns_rows = []
    for record in domain.get("a") or []:
        dns_rows.append(
            {
                "type": "A",
                "name": response_data["address"],
                "value": record.get("ip", ""),
                "ttl": record.get("ttl", ""),
            }
        )
    for record in domain.get("mx") or []:
        dns_rows.append(
            {
                "type": "MX",
                "name": response_data["address"],
                "value": str(record.get("host", record)),
                "ttl": record.get("ttl", "") if isinstance(record, dict) else "",
            }
        )
    for record in domain.get("ns") or []:
        dns_rows.append(
            {
                "type": "NS",
                "name": response_data["address"],
                "value": str(record.get("hostname", record)),
                "ttl": record.get("ttl", "") if isinstance(record, dict) else "",
            }
        )
    for record in domain.get("txt") or []:
        dns_rows.append(
            {
                "type": "TXT",
                "name": response_data["address"],
                "value": str(record),
                "ttl": "",
            }
        )

    whois_data = response_data.get("whois") or {}
    return templates.TemplateResponse(
        request,
        "browser.html",
        {
            "view": build_view(response_data, is_self=is_self),
            "view_map": response_data.get("map") is not None,
            "dns_rows": dns_rows,
            "headers": response_data.get("headers") or {},
            "whois": {k: str(v) for k, v in whois_data.items()},
            "json_data": json.dumps(response_data, indent=2, default=str).replace(
                "</", "<\\/"
            ),
            "map_data": json.dumps(response_data.get("map"), default=str).replace(
                "</", "<\\/"
            ),
            "nonce": getattr(request.state, "csp_nonce", ""),
        },
    )
```

In `get_self_info`, replace the `if BrowserDetector.is_browser(user_agent): return templates.TemplateResponse(...)` block with:

```python
    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return render_page(request, response_data, is_self=True)
```

In `get_ip_info`, replace the same block with:

```python
    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return render_page(request, response_data, is_self=False)
```

- [ ] **Step 6: Run the tests**

Run: `poetry run pytest tests/test_page.py -v`
Expected: all passed.

- [ ] **Step 7: Lint and commit**

```bash
poetry run ruff check . && poetry run ruff format main.py
git add templates/browser.html static/js/app.js main.py tests/test_page.py
git commit -m "feat(ui): server-render the page and lazy-load the JSON tree"
```

---

## Task 8: Paint the map

**Files:**
- Create: `static/js/map.js`
- Test: browser verification (there is no JS test runner in this repo — all the math is already covered by `tests/test_mapgeom.py`, so `map.js` stays dumb enough to verify by eye)

**Interfaces:**
- Consumes: `#map-data` JSON — `{"desktop": <canvas>, "mobile": <canvas>, ...}` from Task 4; containers `#page-map` / `#mobile-map` with `data-variant`.

- [ ] **Step 1: Write `static/js/map.js`**

```javascript
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
  const group = svg("g", { class: isOrigin ? "map__pin map__pin--origin" : "map__pin" });
  const radii = isOrigin ? [24, 0, 6] : [48, 24, 7];
  group.appendChild(svg("circle", { class: "map__pin-halo", cx: x, cy: y, r: radii[0] }));
  if (radii[1]) {
    group.appendChild(svg("circle", { class: "map__pin-ring", cx: x, cy: y, r: radii[1] }));
  }
  group.appendChild(svg("circle", { class: "map__pin-dot", cx: x, cy: y, r: radii[2] }));
  return group;
}

function paint(container, canvas) {
  const tiles = document.createElement("div");
  tiles.className = "map__tiles";
  for (const tile of canvas.tiles) {
    const img = document.createElement("img");
    img.src = tile.url;
    img.alt = "";
    img.loading = "lazy";
    img.referrerPolicy = "no-referrer";
    img.style.left = `${tile.x}px`;
    img.style.top = `${tile.y}px`;
    tiles.appendChild(img);
  }
  container.appendChild(tiles);

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
      })
    );
  }
  if (canvas.origin) {
    overlay.appendChild(pin(canvas.origin.x, canvas.origin.y, true));
  }
  overlay.appendChild(pin(canvas.target.x, canvas.target.y, false));
  container.appendChild(overlay);

  const attribution = document.createElement("div");
  attribution.className = "map__attribution";
  attribution.innerHTML =
    '© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors';
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
```

- [ ] **Step 2: Serve the app**

Run: `poetry run uvicorn main:app --host 127.0.0.1 --port 8000`

- [ ] **Step 3: Verify the city mode (self lookup)**

Open `http://127.0.0.1:8000/` in a browser.
Expected: one accent pin, no line, OSM tiles visible behind the scrim on the right, attribution chip bottom-right, **zero console errors** (in particular no CSP violation for `tile.openstreetmap.org`).

- [ ] **Step 4: Verify the route mode (the antimeridian case)**

Open `http://127.0.0.1:8000/8.8.8.8`.
Expected: two pins joined by an arc that **runs across the Pacific, not backwards across Europe**; the `≈ N,NNN km from you` line appears in the hero. If the arc sweeps the wrong way, the bug is in `mapgeom.py`, not here — add a failing case to `tests/test_mapgeom.py` first.

- [ ] **Step 5: Verify mobile**

Resize to 390px wide and reload.
Expected: the band map is gone, the `LOCATION` card appears below the hero with the same pins/arc, and only the mobile tiles are requested (check the network panel: no 1440-wide tile set).

- [ ] **Step 6: Commit**

```bash
git add static/js/map.js
git commit -m "feat(map): paint OSM tiles and the great-circle arc from the server payload"
```

---

## Task 9: Clean up and document

**Files:**
- Delete: `static/css/fontawesome.css` (unused), old JSONEditor eager `<link>` (already gone with the template rewrite)
- Modify: `README.md`, `CLAUDE.md`
- Test: full suite

- [ ] **Step 1: Confirm fontawesome is unreferenced**

Run: `grep -rn "fontawesome" templates static main.py`
Expected: no matches (if there are, remove them first).

- [ ] **Step 2: Delete the dead stylesheet**

```bash
git rm static/css/fontawesome.css
```

- [ ] **Step 3: Update `CLAUDE.md`**

In the **Project Structure** section, replace the file tree with:

```
whatismyip/
├── main.py              # FastAPI app: routes, managers, security headers
├── geo.py               # Gazetteer lookup + haversine distance
├── mapgeom.py           # Web Mercator tiles, antimeridian wrap, great-circle arcs
├── viewmodel.py         # response_data -> template view (pure)
├── scripts/
│   ├── build_gazetteer.py  # regenerates static/geo/*.json from GeoNames
│   └── fetch_fonts.sh      # vendors Inter + JetBrains Mono into static/fonts/
├── templates/browser.html  # server-rendered page
├── static/
│   ├── css/whatismyip.css  # design tokens + layout
│   ├── js/app.js           # search, copy, accordions, lazy JSONEditor
│   ├── js/map.js           # paints the server's map payload
│   ├── fonts/              # self-hosted woff2 (CSP blocks font CDNs)
│   └── geo/                # cities.json, countries.json
└── tests/
```

Add a **Map** subsection under *Key Technical Details*:

```markdown
**Map (main.py + mapgeom.py)**:
- geoip2fast returns city names but latitude/longitude are ALWAYS null — coordinates
  come from `static/geo/cities.json` (GeoNames), with a country centroid fallback.
- All projection math is server-side and unit-tested (`tests/test_mapgeom.py`). The
  browser only paints tiles and an SVG polyline.
- Tiles are fetched by the browser straight from tile.openstreetmap.org (no API key).
  CSP allows exactly that one host in `img-src`. Attribution is mandatory.
- Seoul→California crosses the Pacific: the map centers on the shortest-path midpoint
  longitude and wraps tile x by 2^zoom. A naive Mercator straight line would run the
  wrong way across Europe.
```

- [ ] **Step 4: Update `README.md`**

Add a **Development setup** note after the install instructions:

```markdown
### Regenerating vendored assets

Both are committed, so this is only needed when refreshing them:

```bash
poetry run python scripts/build_gazetteer.py   # static/geo/*.json from GeoNames
./scripts/fetch_fonts.sh                       # static/fonts/*.woff2
```

The Content-Security-Policy is `default-src 'self'`, so fonts must be self-hosted and
map tiles come from the single allowlisted host `tile.openstreetmap.org`.
```

- [ ] **Step 5: Run the whole suite and the linter**

Run:

```bash
poetry run pytest tests/test_geo.py tests/test_mapgeom.py tests/test_viewmodel.py tests/test_page.py -v
poetry run ruff check .
poetry run ruff format --check .
```

Expected: all tests pass, `All checks passed!`. (`tests/test_basic.py` and `tests/test_security.py` still need a live server on port 8000 — run `poetry run uvicorn main:app --port 8000` in another shell and `poetry run pytest` to confirm nothing regressed.)

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "docs: document map subsystem, gazetteer and font vendoring"
```

---

## Self-Review

**Spec coverage**

| Spec section | Task |
|---|---|
| §3 Colors / typography tokens | Task 6 |
| §4 Layout (topbar/hero/facts/accordions/footer) | Tasks 5, 7 |
| §4 Facts 3-column mapping (IP vs domain) | Task 5 |
| §4 Certificate fields from raw `getpeercert()` | Task 5 (`_certificate_column`) |
| §4 Accordions, JSONEditor confined to Raw JSON | Task 7 (`app.js` lazy boot) |
| §4 Responsive, mobile map as its own section | Tasks 6 (CSS), 7 (template), 8 (breakpoint-aware paint) |
| §5 Gazetteer (city + country fallback) | Tasks 1, 2 |
| §5 Client-side OSM tiles, no API key, CSP one-line change | Tasks 4, 8 |
| §5 Attribution + privacy notice | Tasks 7 (footer), 8 (map chip) |
| §5 Distance + great-circle arc, antimeridian handling | Tasks 3, 4 |
| §6 Edge cases (WHOIS failure, no coords, private IP, no SSL, empty DNS) | Tasks 4, 5 (tests assert each) |
| §7 No build step, no inline handlers, self-hosted fonts | Tasks 6, 7 (test asserts no `onclick=`) |

**Type consistency**: `Gazetteer.resolve()` returns `{"lat","lon","precision"}` everywhere (Tasks 2→4); `build_canvas(target, origin, width, height)` takes those same dicts (Task 3) and is called with them in `build_map_payload` (Task 4); `build_view(response, is_self)` is called with the keyword in `render_page` (Tasks 5→7); the map payload keys `desktop`/`mobile`/`tiles`/`line`/`origin`/`target` are produced in Task 3, serialized in Task 4, and read in Task 8.

**Placeholder scan**: no TBD/TODO, every code step ships runnable code, every test step names the exact command and the expected result.
