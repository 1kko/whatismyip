import json
from pathlib import Path

import pytest

from geo import CITY_ZOOM, COUNTRY_ZOOM, Gazetteer, haversine_km, normalize_city

CITIES = Path("static/geo/cities.json")
COUNTRIES = Path("static/geo/countries.json")


@pytest.fixture(scope="module")
def gazetteer():
    return Gazetteer.load()


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


class TestResolve:
    def test_city_hit_wins_over_country(self, gazetteer):
        location = {"country_code": "KR", "city_name": "Seoul", "is_private": False}
        result = gazetteer.resolve(location)
        assert result["precision"] == "city"
        assert 37.0 < result["lat"] < 38.0

    def test_overlaid_coordinates_win_and_carry_accuracy(self, gazetteer):
        # GeoLite2-City overlays real lat/lon + accuracy onto the location; the
        # gazetteer must use them directly — even for a city name it has never
        # heard of — and pass the accuracy radius through.
        location = {
            "country_code": "US",
            "city_name": "Nowheresville",
            "lat": 37.751,
            "lon": -97.822,
            "accuracy_km": 20,
            "is_private": False,
        }
        result = gazetteer.resolve(location)
        assert result["precision"] == "city"
        assert (result["lat"], result["lon"]) == (37.751, -97.822)
        assert result["accuracy_km"] == 20

    def test_a_coarse_fix_keeps_country_zoom(self, gazetteer):
        # An anycast/country-centroid fix comes back with a huge accuracy radius;
        # keep the coordinates but do not pretend it is street-level.
        location = {
            "country_code": "US",
            "lat": 37.751,
            "lon": -97.822,
            "accuracy_km": 1000,
            "is_private": False,
        }
        result = gazetteer.resolve(location)
        assert result["precision"] == "country"
        assert result["accuracy_km"] == 1000

    def test_falls_back_to_country_centroid_when_city_missing(self, gazetteer):
        location = {"country_code": "US", "city_name": "", "is_private": False}
        result = gazetteer.resolve(location)
        assert result["precision"] == "country"
        assert 20.0 < result["lat"] < 55.0

    def test_unknown_city_falls_back_to_country(self, gazetteer):
        location = {
            "country_code": "KR",
            "city_name": "Nowhere-in-particular",
            "is_private": False,
        }
        assert gazetteer.resolve(location)["precision"] == "country"

    def test_private_ip_has_no_coordinates(self, gazetteer):
        location = {"country_code": "--", "city": {}, "is_private": True}
        assert gazetteer.resolve(location) is None

    def test_missing_country_has_no_coordinates(self, gazetteer):
        assert gazetteer.resolve({"city": {}}) is None

    def test_accents_and_case_are_normalized(self, gazetteer):
        location = {"country_code": "BR", "city_name": "SÃO PAULO"}
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
