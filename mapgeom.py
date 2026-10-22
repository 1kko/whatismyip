"""Web Mercator geometry for the OpenStreetMap band.

The browser is deliberately dumb: it paints the tiles and the polyline this
module produces. Keeping the projection here means the antimeridian handling
is covered by pytest instead of by eyeballing a map.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

TILE_SIZE = 256
TILE_URL_TEMPLATE = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
CITY_ZOOM = 10
MIN_ZOOM = 1
MAX_ZOOM = 12
LINE_SAMPLES = 48
# Keep both pins away from the canvas edges.
FIT_MARGIN = 0.8
# The direction arrowhead sits this far along the projected arc, past the apex
# (where the distance label lives) so it reads as flowing into the destination.
ARROW_POSITION = 0.70


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
    a: tuple[float, float],
    b: tuple[float, float],
    width: int,
    height: int,
    fit_ratio: float = FIT_MARGIN,
) -> int:
    """Largest integer zoom where the whole arc fits inside the canvas.

    The ARC, not just the endpoints: a Pacific great circle bulges far north
    of both cities, and fitting only the endpoints lets the curve run off the
    top of the band.
    """
    center_lon = midpoint_lon(a[1], b[1])
    points = great_circle_points(a, b)
    for zoom in range(MAX_ZOOM, MIN_ZOOM - 1, -1):
        scale = TILE_SIZE * (2**zoom)
        xs = [_unwrapped_x(lon, center_lon, scale) for _, lon in points]
        ys = [_world_y(lat) * scale for lat, _ in points]
        span_x = max(xs) - min(xs)
        span_y = max(ys) - min(ys)
        if span_x <= width * fit_ratio and span_y <= height * fit_ratio:
            return zoom
    return MIN_ZOOM


def _arrow_marker(line: list[list[float]]) -> dict | None:
    """Anchor point and screen bearing for the direction arrowhead.

    Sits ARROW_POSITION of the way along the projected polyline (which runs
    origin -> target) and points along the local tangent toward the target end.
    """
    if not line or len(line) < 2:
        return None
    last = len(line) - 1
    index = min(max(round(ARROW_POSITION * last), 1), last)
    prev = line[index - 1]
    nxt = line[min(index + 1, last)]
    angle = math.degrees(math.atan2(nxt[1] - prev[1], nxt[0] - prev[0]))
    ax, ay = line[index]
    return {"x": round(ax, 2), "y": round(ay, 2), "angle": round(angle, 2)}


def _tiles(
    zoom: int, tile_zoom_offset: int, left: float, top: float, width: int, height: int
) -> list[dict]:
    """OSM tiles covering the canvas whose top-left is (left, top) in world pixels.

    Tile x wraps around the world (a canvas over the Pacific spans the
    antimeridian); rows outside the map are dropped.
    """
    tile_zoom = max(zoom - tile_zoom_offset, 0)
    # One tile of tile_zoom covers this many canvas pixels at the current zoom.
    tile_span = TILE_SIZE * (2 ** (zoom - tile_zoom))
    tile_count = 2**tile_zoom

    tiles = []
    first_col = math.floor(left / tile_span)
    last_col = math.floor((left + width - 1) / tile_span)
    first_row = math.floor(top / tile_span)
    last_row = math.floor((top + height - 1) / tile_span)

    for col in range(first_col, last_col + 1):
        for row in range(first_row, last_row + 1):
            if row < 0 or row >= tile_count:
                continue
            tiles.append(
                {
                    "url": TILE_URL_TEMPLATE.format(
                        z=tile_zoom, x=col % tile_count, y=row
                    ),
                    "x": round(col * tile_span - left, 2),
                    "y": round(row * tile_span - top, 2),
                }
            )
    return tiles


def build_canvas(
    target: dict[str, float],
    origin: dict[str, float] | None,
    width: int,
    height: int,
    focus_x: float = 0.5,
    fit_ratio: float = FIT_MARGIN,
    tile_zoom_offset: int = 0,
) -> dict:
    """Tiles, pin positions and the projected arc for one fixed canvas.

    focus_x places the horizontal centre of what matters (the pin, or the whole
    arc) at that fraction of the canvas width. The desktop band pushes it right
    so the map does not fight the hero text on the left.

    tile_zoom_offset fetches tiles that many zoom levels out and paints them
    upscaled: 0 keeps roads and place names crisp, 1 quarters the number of tile
    requests at the cost of a soft basemap.
    """
    target_point = (target["lat"], target["lon"])

    if origin is None:
        zoom = CITY_ZOOM
        center_lon = target["lon"]
        points = [target_point]
    else:
        origin_point = (origin["lat"], origin["lon"])
        zoom = fit_zoom(target_point, origin_point, width, height, fit_ratio)
        center_lon = midpoint_lon(origin["lon"], target["lon"])
        points = great_circle_points(origin_point, target_point)

    scale = TILE_SIZE * (2**zoom)
    xs = [_unwrapped_x(lon, center_lon, scale) for _, lon in points]
    ys = [_world_y(lat) * scale for lat, _ in points]
    # Frame the whole arc, not just its endpoints.
    left = (min(xs) + max(xs)) / 2.0 - width * focus_x
    top = (min(ys) + max(ys)) / 2.0 - height / 2.0

    def project(lat: float, lon: float) -> tuple[float, float]:
        return (
            _unwrapped_x(lon, center_lon, scale) - left,
            _world_y(lat) * scale - top,
        )

    tile_zoom = max(zoom - tile_zoom_offset, 0)
    tile_span = TILE_SIZE * (2 ** (zoom - tile_zoom))
    tiles = _tiles(zoom, tile_zoom_offset, left, top, width, height)

    target_x, target_y = project(*target_point)
    canvas = {
        "width": width,
        "height": height,
        "zoom": zoom,
        "tile_size": tile_span,
        "tiles": tiles,
        "target": {"x": round(target_x, 2), "y": round(target_y, 2)},
        "origin": None,
        "line": None,
        "arrow": None,
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
        canvas["arrow"] = _arrow_marker(canvas["line"])
    return canvas


def points_center_lon(lons: Sequence[float]) -> float:
    """Centre longitude of the smallest arc holding every longitude.

    The mean of -118 and 139 is 10, the wrong side of the world. The widest
    empty gap between neighbouring longitudes (the last one wrapping to the
    first) is the part of the globe to leave out; the centre is the middle of
    what remains, so Tokyo and Los Angeles are framed across the Pacific.
    """
    # Repeats would leave a zero gap, which the modulo below reads as 360.
    lons = sorted({_wrap180(lon) for lon in lons})
    gaps = [
        (lons[(i + 1) % len(lons)] - lons[i]) % 360 or 360 for i in range(len(lons))
    ]
    widest = max(range(len(lons)), key=gaps.__getitem__)
    start = lons[(widest + 1) % len(lons)]
    return _wrap180(start + (360 - gaps[widest]) / 2)


def _core_points(
    points: Sequence[tuple[float, float, float]], fit_share: float
) -> list[tuple[float, float, float]]:
    """The heaviest points holding fit_share of the total weight (at least
    one): what a frame fits. Shared by build_points_canvas and points_frame so
    the two can never frame different points."""
    if not points:
        raise ValueError("no points to frame")
    ranked = sorted(range(len(points)), key=lambda i: -points[i][2])
    total = sum(p[2] for p in points)
    core: list[tuple[float, float, float]] = []
    held = 0.0
    for i in ranked:
        core.append(points[i])
        held += points[i][2]
        if held >= fit_share * total:
            break
    return core


def unwrap_lon(lon: float, center_lon: float) -> float:
    """lon moved by a multiple of 360 to lie within 180 of center_lon."""
    return lon + 360 * round((center_lon - lon) / 360)


def points_frame(
    points: Sequence[tuple[float, float, float]], fit_share: float = 0.9
) -> dict:
    """The degrees box around the core of many (lat, lon, weight) points, for
    a map that fits it itself. west and east are unwrapped around center_lon,
    so a box over the antimeridian has east past 180 (or west below -180)."""
    core = _core_points(points, fit_share)
    center_lon = points_center_lon([lon for _, lon, _ in core])
    lons = [unwrap_lon(lon, center_lon) for _, lon, _ in core]
    lats = [lat for lat, _, _ in core]
    return {
        "center_lon": round(center_lon, 4),
        "south": round(min(lats), 4),
        "west": round(min(lons), 4),
        "north": round(max(lats), 4),
        "east": round(max(lons), 4),
    }


def build_points_canvas(
    points: Sequence[tuple[float, float, float]],
    width: int,
    height: int,
    fit_share: float = 0.9,
    fit_ratio: float = FIT_MARGIN,
    max_zoom: int = 8,
) -> dict:
    """Tiles and projected points for many (lat, lon, weight) points.

    The frame fits the core, not everything: the heaviest points, taken until
    they hold fit_share of the total weight (at least one), so a stray light
    point on another continent does not zoom a national map out to the world.
    Points outside the frame still project (their x, y may lie off the canvas)
    and are left to the caller to clip. max_zoom keeps a single point from
    zooming past a city-sized frame. Callers pass at least one point.
    """
    core = _core_points(points, fit_share)
    center_lon = points_center_lon([lon for _, lon, _ in core])

    zoom = MIN_ZOOM
    for candidate in range(max_zoom, MIN_ZOOM - 1, -1):
        scale = TILE_SIZE * (2**candidate)
        xs = [_unwrapped_x(lon, center_lon, scale) for _, lon, _ in core]
        ys = [_world_y(lat) * scale for lat, _, _ in core]
        if (
            max(xs) - min(xs) <= width * fit_ratio
            and max(ys) - min(ys) <= height * fit_ratio
        ):
            zoom = candidate
            break

    scale = TILE_SIZE * (2**zoom)
    xs = [_unwrapped_x(lon, center_lon, scale) for _, lon, _ in core]
    ys = [_world_y(lat) * scale for lat, _, _ in core]
    left = (min(xs) + max(xs)) / 2.0 - width / 2.0
    top = (min(ys) + max(ys)) / 2.0 - height / 2.0

    return {
        "width": width,
        "height": height,
        "zoom": zoom,
        "tile_size": TILE_SIZE,
        "tiles": _tiles(zoom, 0, left, top, width, height),
        "points": [
            {
                "x": round(_unwrapped_x(lon, center_lon, scale) - left, 2),
                "y": round(_world_y(lat) * scale - top, 2),
                "weight": weight,
            }
            for lat, lon, weight in points
        ],
    }
