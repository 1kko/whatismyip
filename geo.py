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
# A trip far enough to always draw as home -> destination.
MIN_ROUTE_KM = 25.0
# Now that GeoIP resolves to city level, two *different* cities that are closer
# than MIN_ROUTE_KM still deserve the home/destination view — but not two points
# essentially on top of each other (same-city GeoIP jitter), so keep a floor.
LOCAL_ROUTE_KM = 5.0
EARTH_RADIUS_KM = 6371.0088
# Above this GeoLite2 accuracy radius the fix is really country/region level
# (anycast, country centroid), so it should not zoom to street level.
MAX_CITY_ACCURACY_KM = 200


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
        """Best-effort coordinates for a location dict.

        Prefers the precise latitude/longitude a GeoLite2-City lookup overlays
        onto the location; falls back to matching the city name against the
        local gazetteer, then to a country centroid.
        """
        if not location or location.get("is_private"):
            return None

        lat, lon = location.get("lat"), location.get("lon")
        if lat is not None and lon is not None:
            accuracy_km = location.get("accuracy_km")
            precise = accuracy_km is not None and accuracy_km <= MAX_CITY_ACCURACY_KM
            return {
                "lat": lat,
                "lon": lon,
                "precision": "city" if precise else "country",
                "accuracy_km": accuracy_km,
            }

        country = (location.get("country_code") or "").strip().upper()
        if len(country) != 2 or not country.isalpha():
            return None

        name = location.get("city_name") or ""
        if name:
            point = self.cities.get(f"{country}:{normalize_city(name)}")
            if point:
                return {"lat": point[0], "lon": point[1], "precision": "city"}

        point = self.countries.get(country)
        if point:
            return {"lat": point[0], "lon": point[1], "precision": "country"}
        return None
