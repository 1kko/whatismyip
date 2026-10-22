"""asmap: sampling an AS's IPv4 space and folding the answers into city dots.
`place` is a fake, so no mmdb is read."""

import pytest

import asmap


def fake_place(ip):
    first = int(ip.split(".")[0])
    if first == 20:
        return {
            "lat": 37.57,
            "lon": 126.98,
            "accuracy_km": 10,
            "city": "Seoul",
            "country": "KR",
        }
    if first == 21:
        return {
            "lat": 37.60,
            "lon": 126.99,
            "accuracy_km": 20,
            "city": "Seoul",
            "country": "KR",
        }
    if first == 22:
        return {
            "lat": 36.5,
            "lon": 127.8,
            "accuracy_km": 500,
            "city": None,
            "country": "KR",
        }
    return None


def test_the_budget_caps_the_reads():
    prefixes = [f"30.{(2 * i) // 256}.{(2 * i) % 256}.0/24" for i in range(5000)]
    calls = []
    asmap.footprint(prefixes, lambda ip: calls.append(ip) or None, budget=2000)
    sampled = [a for a, _ in asmap.sample_addresses(prefixes, budget=2000)]
    assert len(sampled) == 2000
    # the sample reads come first; every unsampled prefix then costs one more
    assert calls[:2000] == sampled
    assert len(calls) == 2000 + 3000


def test_samples_follow_size_one_per_slash_24_at_most():
    samples = asmap.sample_addresses(["20.0.0.0/16", "21.0.0.0/24"], budget=257)
    assert len(samples) == 257
    assert sum(w for _, w in samples) == 65536 + 256
    assert sum(1 for a, _ in samples if a.startswith("21.")) == 1


def test_largest_prefixes_are_sampled_first_when_the_budget_runs_out():
    samples = asmap.sample_addresses(["21.0.0.0/24", "20.0.0.0/16"], budget=1)
    assert [a for a, _ in samples] == ["20.0.0.0"]


def test_ipv6_prefixes_are_ignored():
    assert asmap.sample_addresses(["2001:db8::/32"], budget=10) == []


def test_footprint_splits_city_country_and_unplaced_space():
    fp = asmap.footprint(
        ["20.0.0.0/24", "21.0.0.0/24", "22.0.0.0/24", "23.0.0.0/24"],
        fake_place,
        budget=4,
    )
    assert fp["samples"] == 4 and fp["sampled_share"] == 1.0
    assert fp["country_level_share"] == 0.25 and fp["unplaced_share"] == 0.25
    # 20.x and 21.x: one name in one 0.1 degree cell, no geoname_id: one dot,
    # at the weighted mean.
    assert fp["cities"] == [
        {
            "name": "Seoul",
            "country": "KR",
            "lat": 37.585,
            "lon": 126.985,
            "share": 0.5,
            "prefixes": [
                {"prefix": "20.0.0.0/24", "here": 1.0, "address": "20.0.0.1"},
                {"prefix": "21.0.0.0/24", "here": 1.0, "address": "21.0.0.1"},
            ],
        }
    ]


def test_at_most_max_dots_cities():
    def places(ip):
        return {
            "lat": int(ip.split(".")[1]),
            "lon": 0.0,
            "accuracy_km": 5,
            "city": ip,
            "country": "KR",
        }

    fp = asmap.footprint(
        [f"40.{i}.0.0/24" for i in range(50)], places, budget=50, max_dots=10
    )
    assert len(fp["cities"]) == 10


def test_nested_prefixes_are_sampled_and_weighed_once():
    samples = asmap.sample_addresses(["20.0.0.0/16", "20.0.5.0/24"], budget=300)
    assert sum(w for _, w in samples) == 65536
    fp = asmap.footprint(["20.0.0.0/16", "20.0.5.0/24"], fake_place, budget=300)
    assert fp["sampled_share"] == 1.0


def test_an_unnamed_place_is_country_level_whatever_its_radius():
    def default_record(ip):
        return {
            "lat": 37.5112,
            "lon": 126.9741,
            "accuracy_km": 200,
            "city": None,
            "country": "KR",
        }

    fp = asmap.footprint(["20.0.0.0/24"], default_record, budget=4)
    assert fp["cities"] == [] and fp["country_level_share"] == 1.0


SEOUL = {
    "lat": 37.57,
    "lon": 126.98,
    "accuracy_km": 10,
    "city": "Seoul",
    "country": "KR",
}
BUSAN = {
    "lat": 35.18,
    "lon": 129.08,
    "accuracy_km": 10,
    "city": "Busan",
    "country": "KR",
}
KR_ONLY = {"lat": 36.5, "lon": 127.8, "accuracy_km": 500, "city": None, "country": "KR"}


def split_place(ip):
    """20.0-63 Seoul, 20.64-127 Busan, 20.128-191 country level, 20.192-255 unplaced."""
    a, b = (int(x) for x in ip.split(".")[:2])
    if a != 20:
        return None
    return [SEOUL, BUSAN, KR_ONLY, None][b // 64]


def _pairs(fp, name):
    return next(c["prefixes"] for c in fp["cities"] if c["name"] == name)


# budget 4 over 20.0.0.0/8 samples 20.0.0.0, 20.64.0.0, 20.128.0.0, 20.192.0.0


def test_a_prefix_spanning_cities_appears_under_each_with_its_share():
    fp = asmap.footprint(["20.0.0.0/8"], split_place, budget=4)
    assert _pairs(fp, "Seoul") == [
        {"prefix": "20.0.0.0/8", "here": 0.25, "address": "20.0.0.1"}
    ]
    assert _pairs(fp, "Busan") == [
        {"prefix": "20.0.0.0/8", "here": 0.25, "address": "20.64.0.0"}
    ]
    # 0.25, not 0.5: the country-level and unplaced samples are in the denominator


def test_a_more_specific_is_judged_on_the_samples_inside_it():
    fp = asmap.footprint(["20.0.0.0/8", "20.64.0.0/24"], split_place, budget=4)
    assert _pairs(fp, "Busan") == [
        {
            "prefix": "20.64.0.0/24",
            "here": 1.0,
            "address": "20.64.0.1",
        },  # here desc first
        {"prefix": "20.0.0.0/8", "here": 0.25, "address": "20.64.0.0"},
    ]
    assert [p["prefix"] for p in _pairs(fp, "Seoul")] == ["20.0.0.0/8"]


def test_an_unsampled_prefix_gets_one_extra_read_and_joins_a_drawn_city():
    calls = []
    fp = asmap.footprint(
        ["20.0.0.0/8", "20.1.0.0/24"],
        lambda ip: calls.append(ip) or split_place(ip),
        budget=1,
    )
    assert calls == ["20.0.0.0", "20.1.0.1"]
    assert {"prefix": "20.1.0.0/24", "here": 1.0, "address": "20.1.0.1"} in _pairs(
        fp, "Seoul"
    )


def test_an_extra_read_outside_the_drawn_cities_attaches_nowhere():
    fp = asmap.footprint(["20.0.0.0/8", "20.65.0.0/24"], split_place, budget=1)
    assert [c["name"] for c in fp["cities"]] == ["Seoul"]  # no Busan dot is made
    assert [p["prefix"] for p in _pairs(fp, "Seoul")] == ["20.0.0.0/8"]


def test_listed_duplicates_ipv6_and_junk_are_ignored():
    fp = asmap.footprint(
        ["20.0.0.0/8", "20.0.0.0/8", "2001:db8::/32", "nonsense"], split_place, budget=4
    )
    assert [p["prefix"] for p in _pairs(fp, "Seoul")] == ["20.0.0.0/8"]


def test_reads_stay_within_budget_plus_one_per_listed_prefix():
    calls = []
    prefixes = [f"20.{i}.0.0/16" for i in range(50)]
    asmap.footprint(prefixes, lambda ip: calls.append(ip) or split_place(ip), budget=10)
    assert len(calls) <= 10 + 50


# A city's geoname_id keys its dot (GeoIpManager.place carries it): GeoLite2
# puts one city's blocks at several points, and two places can share a name.
MAPO = {"accuracy_km": 5, "city": "Mapo-gu", "country": "KR", "geoname_id": 1}
MAPO_WEST = {**MAPO, "lat": 37.54, "lon": 126.84}
MAPO_EAST = {**MAPO, "lat": 37.56, "lon": 126.96}  # across the 0.1 degree grid


def test_one_geoname_at_two_points_is_one_dot_at_their_weighted_mean():
    def place(ip):
        # 20.0-191 west, 20.192-255 east
        return MAPO_EAST if int(ip.split(".")[1]) >= 192 else MAPO_WEST

    fp = asmap.footprint(["20.0.0.0/8"], place, budget=4)
    assert len(fp["cities"]) == 1
    (dot,) = fp["cities"]
    assert (dot["name"], dot["country"], dot["share"]) == ("Mapo-gu", "KR", 1.0)
    assert dot["lat"] == pytest.approx((3 * 37.54 + 37.56) / 4, abs=1e-4)
    assert dot["lon"] == pytest.approx((3 * 126.84 + 126.96) / 4, abs=1e-4)
    assert dot["prefixes"] == [
        {"prefix": "20.0.0.0/8", "here": 1.0, "address": "20.0.0.1"}
    ]


def test_two_geonames_with_one_name_stay_two_dots():
    jung_seoul = {
        **MAPO,
        "city": "Jung-gu",
        "geoname_id": 2,
        "lat": 37.56,
        "lon": 126.99,
    }
    jung_incheon = {**jung_seoul, "geoname_id": 3}  # the same point, rounded

    def place(ip):
        return jung_incheon if int(ip.split(".")[1]) >= 128 else jung_seoul

    fp = asmap.footprint(["20.0.0.0/8"], place, budget=4)
    assert [(c["name"], c["share"]) for c in fp["cities"]] == [
        ("Jung-gu", 0.5),
        ("Jung-gu", 0.5),
    ]
    assert [c["prefixes"][0]["address"] for c in fp["cities"]] == [
        "20.0.0.1",
        "20.128.0.0",
    ]


def test_without_a_geoname_id_the_name_on_a_grid_keys_the_dot():
    west = {k: v for k, v in MAPO_WEST.items() if k != "geoname_id"}
    east = {**MAPO_EAST, "geoname_id": None}

    def place(ip):
        return east if int(ip.split(".")[1]) >= 192 else west

    fp = asmap.footprint(["20.0.0.0/8"], place, budget=4)
    assert [(c["name"], c["share"], c["lat"]) for c in fp["cities"]] == [
        ("Mapo-gu", 0.75, 37.54),
        ("Mapo-gu", 0.25, 37.56),
    ]


def test_an_extra_read_joins_its_geonames_dot_wherever_it_is_placed():
    calls = []

    def place(ip):
        calls.append(ip)
        return MAPO_EAST if ip.startswith("20.1.") else MAPO_WEST

    fp = asmap.footprint(["20.0.0.0/8", "20.1.0.0/24"], place, budget=1)
    assert calls == ["20.0.0.0", "20.1.0.1"]
    assert [p["prefix"] for p in _pairs(fp, "Mapo-gu")] == [
        "20.0.0.0/8",
        "20.1.0.0/24",
    ]
