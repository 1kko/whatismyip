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
