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
