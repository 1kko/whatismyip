"""asmap: sampling an AS's IPv4 space and folding the answers into city dots.
`place` is a fake, so no mmdb is read."""

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
    assert len(calls) == 2000


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
    # 20.x and 21.x are the same city within 0.1 degree: one dot, weighted mean.
    assert fp["cities"] == [
        {"name": "Seoul", "country": "KR", "lat": 37.585, "lon": 126.985, "share": 0.5}
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
