"""The /AS<n> page's sentence, tiles and composition bars (viewmodel, pure)."""

import pytest

import countrynames
import asinfo
import main
import mapgeom
import lookup
import viewmodel
from asinfo_fixtures import build_manager

# A minimal synthetic card: AS3786, 912 IPv4 prefixes, no country, no registry,
# CAIDA unavailable, so no first sentence and no second one.
BASE = {
    "asn": 3786,
    "country": None,
    "registry": None,
    "prefixes": {"v4": 912, "v6": 0, "v4_addresses": 8666368, "v6_48s": 0},
    "rpki": {"valid": 0, "invalid": 0, "not_found": 912},
    "upstreams": None,
    "downstreams": None,
    "peers": None,
    "unavailable": [
        {"dataset": "caida_rel", "label": "CAIDA AS relationships", "reason": "x"}
    ],
}


@pytest.fixture
def as_info(asinfo_enabled):
    return lookup.as_info_for_asn(4766, full=True, detail=True)


@pytest.fixture
def page(asinfo_enabled):
    return asinfo_enabled.page_data(4766)


@pytest.mark.parametrize(
    "n, text",
    [
        (0, "0"),
        (999, "999"),
        (1000, "1.0k"),
        (1049, "1.0k"),
        (1050, "1.1k"),
        (9949, "9.9k"),
        (9950, "10k"),
        (131072, "131k"),
        (999499, "999k"),
        (999500, "1.0M"),
        (8666368, "8.7M"),
        (29000000, "29M"),
    ],
)
def test_human_count(n, text):
    assert viewmodel.human_count(n) == text


def test_holder_and_handle():
    assert viewmodel.as_handle("LGDACOM-KR - LG DACOM Corporation") == "LGDACOM-KR"
    assert (
        viewmodel.as_holder("LGDACOM-KR - LG DACOM Corporation")
        == "LG DACOM Corporation"
    )
    assert viewmodel.as_holder("TWELVE99 Arelion Sweden AB") == "Arelion Sweden AB"
    assert viewmodel.as_holder("AS6453") == "AS6453"
    assert viewmodel.as_handle("AS6453") == "AS6453"
    assert viewmodel.as_holder(None) is None and viewmodel.as_handle("") is None


def test_country_names():
    assert countrynames.country_name("KR") == "South Korea"
    assert countrynames.country_name("ZZ") == "ZZ"
    assert countrynames.country_name(None) is None
    assert countrynames.country_name("") is None
    assert len(countrynames.COUNTRY_NAMES) == 249


def test_the_sentence_for_as4766(as_info, page):
    assert viewmodel.as_summary(as_info, page) == (
        "A network in South Korea, registered with APNIC in 1996. It buys transit from "
        "2 upstreams, serves 3 downstream networks (all in South Korea) and peers with "
        "1 network in 1 country. It announces 2 IPv4 and 1 IPv6 prefixes covering 131k "
        "IPv4 addresses (about one /15); 67% of its prefixes are RPKI-signed."
    )


def test_the_sentence_drops_what_is_unavailable(tmp_path):
    manager = build_manager(tmp_path, drop=("caida_rel", "rpki"))
    info, page = manager.for_asn(4766, full=True, detail=True), manager.page_data(4766)
    assert viewmodel.as_summary({**info, "asn_drop": None}, page) == (
        "A network in South Korea, registered with APNIC in 1996. It announces 2 IPv4 "
        "and 1 IPv6 prefixes covering 131k IPv4 addresses (about one /15)."
    )


def test_rpki_share_wording():
    def say(valid, invalid, missing):
        info = {
            **BASE,
            "rpki": {"valid": valid, "invalid": invalid, "not_found": missing},
        }
        return viewmodel.as_summary(info, None)

    assert say(1, 0, 999).endswith("; under 1% of its prefixes are RPKI-signed.")
    assert say(9, 1, 902).endswith("; 1% of its prefixes are RPKI-signed (1 invalid).")
    assert say(0, 0, 912).endswith("; 0% of its prefixes are RPKI-signed.")


def test_the_sentence_names_the_as_when_nothing_precedes_it():
    assert viewmodel.as_summary(BASE, None).startswith(
        "AS3786 announces 912 IPv4 prefixes"
    )


def test_the_sentence_with_no_prefixes():
    info = {**BASE, "prefixes": {"v4": 0, "v6": 0, "v4_addresses": 0, "v6_48s": 0}}
    assert viewmodel.as_summary(info, None) == "AS3786 announces no prefixes."


def test_tiles_for_as4766(as_info, page):
    tiles = {t["key"]: t for t in viewmodel.as_tiles(as_info, page)}
    assert list(tiles) == ["space", "prefixes", "rpki", "neighbours"]
    assert tiles["space"]["value"] == "131k"
    assert tiles["space"]["sub"] == "addresses ≈ one /15 · 1 block"
    assert tiles["prefixes"]["value"] == "2 v4 · 1 v6"
    assert tiles["prefixes"]["sub"] == "1 of the v4 are /24s"
    assert tiles["rpki"]["value"] == "67%"
    assert tiles["rpki"]["sub"] == "2 valid · 0 invalid · 1 not found"
    assert [s["label"] for s in tiles["rpki"]["segments"]] == [
        "valid",
        "invalid",
        "not found",
    ]
    assert tiles["neighbours"]["value"] == "2 · 3 · 1"
    assert tiles["neighbours"]["sub"] == "upstreams · downstreams · peers"


def test_an_unavailable_tile_says_unknown(tmp_path):
    manager = build_manager(tmp_path, drop=("caida_rel",))
    info, page = manager.for_asn(4766, full=True, detail=True), manager.page_data(4766)
    tiles = {t["key"]: t for t in viewmodel.as_tiles(info, page)}
    assert tiles["neighbours"]["value"] == "Unknown"
    assert tiles["neighbours"]["sub"].startswith("Unknown: ")
    assert tiles["neighbours"]["tone"] == "muted"
    assert tiles["space"]["value"] == "131k"


def test_glance_bars_for_as4766(as_info, page):
    glance = viewmodel.as_glance(as_info, page)
    bars = {b["key"]: b for b in glance["bars"]}
    assert list(bars) == ["rpki", "visibility", "sizes", "family"]
    assert [(s["label"], s["count"]) for s in bars["visibility"]["segments"]] == [
        ("widely seen", 3),
        ("partly", 0),
        ("narrowly", 0),
    ]
    assert [(s["label"], s["count"]) for s in bars["sizes"]["segments"]] == [
        ("/24", 1),
        ("/23", 0),
        ("/22", 0),
        ("/17–/21", 0),
        ("/16 and shorter", 1),
    ]
    assert [(s["label"], s["count"]) for s in bars["family"]["segments"]] == [
        ("IPv4", 2),
        ("IPv6", 1),
    ]
    assert bars["rpki"]["segments"][0]["pct"] == 66.67
    assert bars["rpki"]["segments"][0]["tone"] == "success"
    assert glance["note"].startswith("Routes seen by fewer than 10 RIS peers")


def test_a_truncated_list_is_said_in_the_bar_label(as_info, page):
    short = {
        **page,
        "prefixes": {
            **page["prefixes"],
            "v4": {"count": 50, "list": page["prefixes"]["v4"]["list"]},
        },
    }
    bars = {b["key"]: b for b in viewmodel.as_glance(as_info, short)["bars"]}
    assert bars["sizes"]["label"] == "Sizes (IPv4) (largest 2)"
    assert bars["visibility"]["label"] == "Visibility (largest 2 per family)"
    assert bars["rpki"]["label"] == "RPKI"


def test_a_missing_page_leaves_list_bars_unknown(as_info):
    bars = {b["key"]: b for b in viewmodel.as_glance(as_info, None)["bars"]}
    assert bars["visibility"]["empty"].startswith(("Unknown", "Not in"))
    assert bars["family"]["empty"] is None


def test_tones_are_the_codebase_vocabulary(as_info, page):
    allowed = {"default", "muted", "success", "warning", "danger"}
    tones = {t["tone"] for t in viewmodel.as_tiles(as_info, page)}
    for bar in viewmodel.as_glance(as_info, page)["bars"]:
        tones |= {s["tone"] for s in bar["segments"]}
    assert tones <= allowed


def test_a_family_without_a_median_is_left_out_of_visibility(as_info, page):
    v6 = {"prefix": "2001:db8::/32", "plen": 32, "ris_peers": 5, "rpki": None}
    lists = {**page["prefixes"], "v6": {"count": 1, "list": [v6]}}
    for median in (None, 0):
        drawn = {**page, "prefixes": lists, "medians": {"v4": 330, "v6": median}}
        bar = viewmodel.as_glance(as_info, drawn)["bars"][1]
        assert sum(s["count"] for s in bar["segments"]) == 2
        assert bar["label"] == "Visibility"


def test_visibility_is_unknown_when_no_family_has_a_median(as_info, page):
    drawn = {**page, "medians": {"v4": None, "v6": None}}
    bar = viewmodel.as_glance(as_info, drawn)["bars"][1]
    assert bar["empty"] == "Unknown" and bar["segments"] == []


N0 = {
    "asn": 1,
    "name": "N0-AS - Holder",
    "country": "US",
    "customers": 1,
    "v4_addresses": 256,
    "v4_prefixes": 1,
    "v6_prefixes": 0,
}


def test_upstream_graph_rows_and_fan(as_info, page):
    graph = viewmodel.as_upstream_graph(as_info, page, main.lookup_href)
    assert [r["asn"] for r in graph["rows"]] == [174, 701]
    assert graph["rows"][0]["href"] == "/AS174"
    assert graph["rows"][0]["handle"] == "COGENT-174"
    assert graph["height"] == 60 and graph["more"] == 0
    assert graph["fan"] == [
        "M0,15 C36,15 36,30.0 72,30.0",
        "M0,45 C36,45 36,30.0 72,30.0",
    ]


def test_more_than_twelve_upstreams_fold_into_a_more_row():
    upstreams = {
        "count": 20,
        "list": [dict(N0, asn=i + 1, customers=20 - i) for i in range(20)],
    }
    graph = viewmodel.as_upstream_graph(BASE, {"upstreams": upstreams})
    assert len(graph["rows"]) == 12 and graph["more"] == 8
    assert graph["height"] == 390


def test_map_view_draws_city_dots_and_says_what_is_left_out():
    fp = {
        "cities": [
            {
                "name": "Seoul",
                "country": "KR",
                "lat": 37.57,
                "lon": 126.98,
                "share": 0.71,
            }
        ],
        "country_level_share": 0.29,
        "unplaced_share": 0.0,
        "sampled_share": 1.0,
        "samples": 2000,
    }
    canvas = mapgeom.build_points_canvas([(37.57, 126.98, 0.71)], 560, 360)
    view = viewmodel.as_map_view(
        {**BASE, "name": "LGDACOM-KR - LG DACOM Corporation"},
        {"footprint": fp, "canvas": canvas, "fallback": None},
    )
    assert view["dots"] == [{"x": 280.0, "y": 180.0, "r": 16.0}]
    assert view["node"] == {"label": "AS3786", "sub": "LGDACOM-KR"}
    assert view["caption"] == (
        "Dots: where its IPv4 addresses geolocate (GeoLite2, by city; "
        "area = share). 29% of the space is placed only at country level "
        "and is not drawn."
    )
    assert view["credit"] == "© OpenStreetMap contributors · GeoLite2 by MaxMind"
    assert view["alt"] == "Where its IPv4 addresses geolocate: Seoul 71%"
    assert all(
        t["url"].startswith("https://tile.openstreetmap.org/") for t in view["tiles"]
    )


def test_map_view_country_fallback_caption():
    canvas = mapgeom.build_points_canvas([(36.5, 127.8, 1.0)], 560, 360, max_zoom=4)
    view = viewmodel.as_map_view(
        {**BASE, "country": "KR"},
        {"footprint": None, "canvas": canvas, "fallback": "country"},
    )
    assert view["caption"] == (
        "No city-level placement for its IPv4 addresses; "
        "the pin marks South Korea, at country level."
    )
    assert viewmodel.as_map_view(BASE, None) is None


def test_map_view_names_an_unnamed_city_and_clips_dots():
    fp = {
        "cities": [{"name": None, "country": "KR", "lat": 0, "lon": 0, "share": 0.5}],
        "country_level_share": 0,
        "unplaced_share": 0,
    }
    canvas = {
        "width": 100,
        "height": 100,
        "tile_size": 256,
        "tiles": [],
        "points": [
            {"x": -5, "y": 10, "weight": 0.5},
            {"x": 50, "y": 50, "weight": 0.5},
        ],
    }
    view = viewmodel.as_map_view(
        BASE, {"footprint": fp, "canvas": canvas, "fallback": None}
    )
    assert len(view["dots"]) == 1 and "unnamed place 50%" in view["alt"]


def test_neighbour_table_merges_relations_by_own_customers(as_info, page):
    table = viewmodel.as_neighbour_table(as_info, page, main.lookup_href)
    assert [(c["key"], c["count"]) for c in table["chips"]] == [
        ("all", 6),
        ("upstream", 2),
        ("downstream", 3),
        ("peer", 1),
    ]
    assert [(r["asn"], r["relation"]) for r in table["rows"]][:2] == [
        (174, "upstream"),
        (701, "upstream"),
    ]
    assert table["payload"]["columns"] == [
        "asn",
        "name",
        "country",
        "relation",
        "customers",
        "v4_addresses",
    ]
    assert len(table["payload"]["rows"]) == 6 and table["truncated"] == []


def test_neighbour_table_says_what_was_cut(tmp_path, monkeypatch):
    manager = build_manager(tmp_path)
    monkeypatch.setattr(asinfo, "ASINFO_PAGE_LIMIT", 1)
    table = viewmodel.as_neighbour_table(
        manager.for_asn(4766, full=True, detail=True), manager.page_data(4766)
    )
    assert table["truncated"] == [
        "Largest 1 of 2 upstreams loaded.",
        "Largest 1 of 3 downstreams loaded.",
    ]
    assert table["chips"][0]["count"] == 6


def test_prefix_table_largest_first(as_info, page):
    table = viewmodel.as_prefix_table(as_info, page)
    assert [(r["prefix"], r["size_text"], r["rpki_text"]) for r in table["rows"]] == [
        ("211.252.0.0/15", "131k", "Valid"),
        ("211.252.112.0/24", "256", "Valid"),
    ]
    assert table["counts"] == {"v4": 2, "v6": 1}
    assert table["payload"]["v6"] == [["2001:2d8::/32", 32, 120, "not-found", None]]


def test_sections_read_unknown_when_their_dataset_is_out(tmp_path):
    manager = build_manager(tmp_path, drop=("caida_rel", "ris_v4"))
    info, page = manager.for_asn(4766, full=True, detail=True), manager.page_data(4766)
    assert viewmodel.as_upstream_graph(info, page)["empty"].startswith("Unknown: ")
    assert viewmodel.as_neighbour_table(info, page)["empty"].startswith("Unknown: ")
    assert viewmodel.as_prefix_table(info, page)["empty"].startswith("Unknown: ")


def test_page_view_keeps_details_and_credits(as_info, page):
    view = viewmodel.as_page_view(as_info, main.lookup_href, page=page, as_map=None)
    labels = [row["label"] for row in view["details"]["rows"]]
    assert labels == ["Registry", "Organization", "ASN-DROP"]
    assert [t["text"] for t in view["tags"]] == ["ASN", "APNIC", "since 1996"]
    assert view["lists_payload"]["own"] == 4766 and view["map"] is None
    assert view["special"] is False and view["prefix_table"]["counts"]["v4"] == 2


def test_special_page_view_is_unchanged(asinfo_enabled):
    view = viewmodel.as_page_view(lookup.as_info_for_asn(64512))
    assert view["special"] is True
    assert [a["id"] for a in view["accordions"]] == ["as", "raw"]
