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
