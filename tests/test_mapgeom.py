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
        span = canvas["tile_size"]
        assert canvas["tiles"]
        for tile in canvas["tiles"]:
            assert tile["url"].startswith("https://tile.openstreetmap.org/")
            assert tile["url"].endswith(".png")
        # Every tile is placed so that the canvas is fully covered.
        assert min(t["x"] for t in canvas["tiles"]) <= 0
        assert max(t["x"] for t in canvas["tiles"]) + span >= DESKTOP[0]
        assert min(t["y"] for t in canvas["tiles"]) <= 0
        assert max(t["y"] for t in canvas["tiles"]) + span >= DESKTOP[1]

    def test_tiles_are_fetched_one_zoom_out_and_drawn_at_double_size(self):
        canvas = build_canvas(SEOUL, None, *DESKTOP)
        tile_zoom = int(canvas["tiles"][0]["url"].split("/")[-3])
        assert tile_zoom == canvas["zoom"] - 1
        assert canvas["tile_size"] == TILE_SIZE * 2

    def test_tile_requests_stay_cheap(self):
        # OSM's tile policy assumes low volume: one page view must not fan out
        # into a dozen tile requests.
        assert len(build_canvas(SEOUL, None, *DESKTOP)["tiles"]) <= 8
        assert len(build_canvas(MOUNTAIN_VIEW, SEOUL, *DESKTOP)["tiles"]) <= 8
        assert len(build_canvas(SEOUL, None, 350, 170)["tiles"]) <= 4

    def test_tile_x_wraps_around_the_dateline(self):
        canvas = build_canvas(MOUNTAIN_VIEW, SEOUL, *DESKTOP)
        for tile in canvas["tiles"]:
            _, tz, tx, ty = tile["url"].rsplit("/", 3)
            limit = 2 ** int(tz)
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
