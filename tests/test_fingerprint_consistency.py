"""The Fingerprint panel's "Clock vs address" and "Languages vs address" rows
(static/js/fingerprint.js).

A visitor on a VPN opens a "what is my IP" page to see whether the address
hides where they are. The classic tell, which browserleaks, ipleak and whoer
all show, is a browser whose clock and languages disagree with the address's
location. Both halves are already in the page: GeoIP's time_zone, country_code
and precision in #page-data, and the browser's own Intl time zone, UTC offset
and navigator.languages. fingerprint.js compares them in the page and sends
nothing anywhere (settled decision 4).

The verdict is a hint, never a detection claim: modern VPN apps leave the
clock alone, travellers and expats mismatch legitimately, and GeoLite2's zone
for a location it only knows to the country says nothing about a clock. Those
cases read "not comparable" with a reason.

The comparison is plain functions, run here in node against fingerprint.js
itself; the panel runs in node too, against a fake DOM with a tripwire on
every way a page could send or keep something. Both skip when node is missing,
as tests/test_webrtc_leak.py does, so run them where node is installed.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

FINGERPRINT_JS = Path("static/js/fingerprint.js").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")

JULY = "2026-07-01T12:00:00Z"  # Europe on summer time
JANUARY = "2026-01-15T12:00:00Z"


def _node(script, tz="Asia/Seoul"):
    """Run a fixed harness plus fingerprint.js's own source in node, with the
    process clock in `tz` (V8 reads TZ at start, as a browser reads the OS)."""
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env={**os.environ, "TZ": tz},
    )
    return json.loads(out.stdout)


def _module(call):
    return _node(
        f"const m = require({json.dumps(str(FINGERPRINT_JS))});"
        f"console.log(JSON.stringify(m.{call}));"
    )


def _zones(browser_zone, browser_offset, ip_zone, precision, now=JULY):
    return _module(
        f"compareZones({json.dumps(browser_zone)}, {json.dumps(browser_offset)}, "
        f"{json.dumps(ip_zone)}, {json.dumps(precision)}, new Date({json.dumps(now)}))"
    )


def _languages(languages, country):
    return _module(f"compareLanguages({json.dumps(languages)}, {json.dumps(country)})")


def _offset(zone, now=JULY):
    return _module(
        f"zoneOffsetMinutes({json.dumps(zone)}, new Date({json.dumps(now)}))"
    )


# --- the pure functions -----------------------------------------------------------


@needs_node
class TestZoneOffset:
    @pytest.mark.parametrize(
        "zone, now, minutes",
        [
            ("Asia/Seoul", JULY, 540),
            ("Asia/Kolkata", JULY, 330),  # a half-hour zone
            ("America/St_Johns", JANUARY, -210),  # a negative half-hour zone
            ("Pacific/Chatham", JANUARY, 825),  # a quarter-hour zone
            ("Europe/Berlin", JANUARY, 60),
            ("Europe/Berlin", JULY, 120),  # summer time: `now` decides
            ("UTC", JULY, 0),
        ],
    )
    def test_reads_the_engines_short_offset_to_the_minute(self, zone, now, minutes):
        assert _offset(zone, now) == minutes

    def test_an_unknown_zone_is_null_not_an_exception(self):
        assert _offset("Not/AZone") is None


@needs_node
class TestCompareZones:
    def test_the_same_zone_is_same(self):
        result = _zones("Asia/Seoul", 540, "Asia/Seoul", "city")
        assert result["verdict"] == "same"
        assert result["reason"] is None

    @pytest.mark.parametrize(
        "ip_zone, verdict",
        [("Atlantic/Reykjavik", "same"), ("Europe/Berlin", "differs")],
    )
    def test_reykjavik_is_compared_like_any_other_zone(self, ip_zone, verdict):
        """Atlantic/Reykjavik gets no rule of its own: against an address in
        Iceland it is the same zone, against one elsewhere it differs."""
        result = _zones("Atlantic/Reykjavik", 0, ip_zone, "city")
        assert result["verdict"] == verdict

    def test_different_zones_differ_by_their_current_offsets(self):
        """Seoul against Berlin: 7 h in summer, 8 h in winter. The sign says
        which way: positive when the clock runs ahead of the address."""
        summer = _zones("Asia/Seoul", 540, "Europe/Berlin", "city", JULY)
        winter = _zones("Asia/Seoul", 540, "Europe/Berlin", "city", JANUARY)
        assert summer["verdict"] == "differs"
        assert (summer["ip_offset_min"], summer["diff_min"]) == (120, 420)
        assert (winter["ip_offset_min"], winter["diff_min"]) == (60, 480)

    def test_a_half_hour_zone_is_counted_in_minutes(self):
        result = _zones("Asia/Kolkata", 330, "Asia/Seoul", "city")
        assert result["verdict"] == "differs"
        assert result["diff_min"] == -210

    @pytest.mark.parametrize(
        "browser_zone, browser_offset, ip_zone",
        [
            ("Asia/Calcutta", 330, "Asia/Kolkata"),
            ("Europe/Kiev", 180, "Europe/Kyiv"),
            ("Asia/Saigon", 420, "Asia/Ho_Chi_Minh"),
        ],
    )
    def test_two_spellings_of_one_zone_are_the_same_zone(
        self, browser_zone, browser_offset, ip_zone
    ):
        """V8 reports a browser in India, Ukraine or Vietnam under the zone's
        old name; GeoLite2 writes the current one. Without canonicalising
        both names, every visitor there would read "differs" with the same
        offset on both sides."""
        result = _zones(browser_zone, browser_offset, ip_zone, "city")
        assert result["verdict"] == "same"

    def test_different_zones_with_one_offset_still_differ(self):
        """Detroit and New York keep the same clock; the zones are not the
        same place. Reported as differs with a difference of 0, which the row
        words as "the same UTC offset"."""
        result = _zones("America/Detroit", -240, "America/New_York", "city")
        assert result["verdict"] == "differs"
        assert result["diff_min"] == 0

    @pytest.mark.parametrize(
        "browser_zone, browser_offset, ip_zone, precision, reason",
        [
            ("Asia/Seoul", 540, None, "city", "no time zone for this address"),
            ("Asia/Seoul", 540, "America/Chicago", "country", "country-level location"),
            ("Asia/Seoul", 540, "America/Chicago", None, "country-level location"),
            ("UTC", 0, "Europe/London", "city", "browser reports UTC"),
            ("Etc/UTC", 0, "Europe/London", "city", "browser reports UTC"),
            (
                "Asia/Seoul",
                540,
                "Not/AZone",
                "city",
                "time zone not recognised by this browser",
            ),
            (None, None, "Asia/Seoul", "city", "no browser time zone"),
        ],
    )
    def test_what_cannot_be_compared_says_why(
        self, browser_zone, browser_offset, ip_zone, precision, reason
    ):
        """A country-level location is the big one: GeoLite2 gives 8.8.8.8 a
        1000 km centroid in America/Chicago, and a clock set against that
        would read "differs" for most of the United States. A browser that
        reports UTC has no clock of its own to compare."""
        result = _zones(browser_zone, browser_offset, ip_zone, precision)
        assert result["verdict"] == "not_comparable"
        assert result["reason"] == reason

    def test_a_missing_browser_offset_still_compares_the_names(self):
        result = _zones("Asia/Seoul", None, "Europe/Berlin", "city")
        assert result["verdict"] == "differs"
        assert result["diff_min"] is None


@needs_node
class TestCompareLanguages:
    def test_a_language_naming_the_addresss_country_is_same(self):
        result = _languages(["ko-KR", "ko"], "KR")
        assert result["verdict"] == "same"
        assert result["match"] == "ko-KR"

    def test_any_listed_language_may_match(self):
        """English first, Korean second, in Korea: the device is where the
        address is. Judging the preferred language alone would be a false
        alarm for everyone who reads the web in English."""
        assert _languages(["en-US", "ko-KR"], "KR")["verdict"] == "same"

    def test_languages_naming_only_other_countries_differ(self):
        result = _languages(["en-US", "fr-FR", "en-US"], "KR")
        assert result["verdict"] == "differs"
        assert result["regions"] == ["US", "FR"]

    def test_a_script_subtag_does_not_hide_the_region(self):
        assert _languages(["zh-Hant-TW"], "TW")["verdict"] == "same"

    def test_case_does_not_matter(self):
        assert _languages(["ko-kr"], "kr")["verdict"] == "same"

    def test_a_bare_navigator_language_string_is_accepted(self):
        assert _languages("ko-KR", "KR")["verdict"] == "same"

    @pytest.mark.parametrize(
        "languages, country, reason",
        [
            (["en"], "KR", "no country in your languages"),
            (["es-419"], "MX", "no country in your languages"),  # a UN M.49 area
            ([], "KR", "no country in your languages"),
            (["ko-KR"], "--", "no country for this address"),  # managers.NO_COUNTRY
            (["ko-KR"], None, "no country for this address"),
        ],
    )
    def test_what_cannot_be_compared_says_why(self, languages, country, reason):
        result = _languages(languages, country)
        assert result["verdict"] == "not_comparable"
        assert result["reason"] == reason
