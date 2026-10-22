"""The /AS<n> page's sentence, tiles and composition bars (viewmodel, pure)."""

import pytest

import countrynames
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
    assert bars["visibility"]["label"] == "Visibility (largest 3)"
    assert bars["rpki"]["label"] == "RPKI"


def test_a_missing_page_leaves_list_bars_unknown(as_info):
    bars = {b["key"]: b for b in viewmodel.as_glance(as_info, None)["bars"]}
    assert bars["visibility"]["empty"].startswith(("Unknown", "Not in"))
    assert bars["family"]["empty"] is None
