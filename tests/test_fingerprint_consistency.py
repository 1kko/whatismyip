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


# --- the panel, in a fake browser -------------------------------------------------

# Just enough of a browser for fingerprint.js: the elements it looks up by id
# (left out for a lookup page), a document that counts what it creates, a
# navigator with scripted languages, an Intl that can be made to lack
# "shortOffset", and a tripwire on every way a page could send something to a
# server or keep something between visits.
HARNESS = r"""
if (!SHORT_OFFSET) {
  // An engine without timeZoneName "shortOffset" (Safari before 15.4)
  // throws a RangeError for it.
  const RealFormat = Intl.DateTimeFormat;
  Intl.DateTimeFormat = function (locales, options) {
    if (options && options.timeZoneName === "shortOffset") {
      throw new RangeError("Value shortOffset out of range for timeZoneName");
    }
    return new RealFormat(locales, options);
  };
}
const calls = { created: 0, sent: [], stored: [] };
function el(tag, id) {
  const node = {
    tag, id: id || "", className: "", children: [], dataset: {}, disabled: false,
    colSpan: 1, style: {}, offsetWidth: 0, offsetHeight: 0, _text: "",
    append(...nodes) { this.children.push(...nodes); },
    appendChild(child) { this.children.push(child); return child; },
    removeChild() {},
    addEventListener() {},
    getContext() { return null; },
    classList: { add() {}, remove() {} },
  };
  // In a browser, textContent = "" removes every child; the fake does too.
  Object.defineProperty(node, "textContent", {
    get() { return this._text; },
    set(value) { this._text = String(value); this.children = []; },
  });
  return node;
}
const ids = SELF_PAGE
  ? ["acc-fingerprint", "fp-signals", "fp-hash", "fp-bits", "fp-unique",
     "fp-acc-hint", "fp-copy"]
  : [];
const elements = Object.fromEntries(ids.map((id) => [id, el("div", id)]));
// Open, as a visitor who expanded the panel has it: the UNIQUE ID, the bit
// estimate and the hint's signal count are what these tests compare, and a
// script may hold that measurement until the panel is opened.
if (elements["acc-fingerprint"]) elements["acc-fingerprint"].open = true;
if (PAGE_DATA !== null) {
  elements["page-data"] = el("script", "page-data");
  elements["page-data"].textContent = JSON.stringify(PAGE_DATA).replace(/<\//g, "<\\/");
}
global.window = global;
global.document = {
  getElementById: (id) => elements[id] || null,
  createElement: (tag) => { calls.created += 1; return el(tag); },
  body: el("body"),
};
// Node has a navigator of its own; a plain assignment does not replace it.
Object.defineProperty(global, "navigator", {
  configurable: true,
  value: {
    languages: LANGUAGES,
    language: LANGUAGES[0],
    sendBeacon: () => calls.sent.push("beacon"),
  },
});
global.fetch = (...a) => calls.sent.push("fetch");
global.XMLHttpRequest = function () { calls.sent.push("xhr"); };
global.WebSocket = function () { calls.sent.push("websocket"); };
global.EventSource = function () { calls.sent.push("eventsource"); };
global.Image = function () { calls.sent.push("image"); };
for (const name of ["localStorage", "sessionStorage", "indexedDB"]) {
  Object.defineProperty(global, name, {
    configurable: true,
    get() { calls.stored.push(name); return {}; },
  });
}
require(FINGERPRINT_JS);
const text = (id) => (elements[id] ? elements[id].textContent : null);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
(async () => {
  // The measurement ends by writing the UNIQUE ID (a dash when it fails), so
  // wait for that rather than for a fixed time; a lookup page has no ID.
  for (let i = 0; i < 80 && elements["fp-hash"] && !text("fp-hash"); i++) {
    await wait(25);
  }
  const table = elements["fp-signals"];
  const rows = table
    ? table.children.map((tr) => [
        tr.children[0].textContent,
        tr.children[1].textContent,
        tr.children[1].className,
      ])
    : null;
  console.log(JSON.stringify({
    created: calls.created, sent: calls.sent, stored: calls.stored, rows,
    hint: text("fp-acc-hint"), hash: text("fp-hash"), bits: text("fp-bits"),
  }));
})();
"""


def _load(
    self_page=True,
    location=None,
    page_data=True,
    tz="Asia/Seoul",
    languages=("ko-KR", "ko"),
    short_offset=True,
):
    """Load fingerprint.js into the fake browser and let both phases run.

    `self_page` False leaves out the panel's elements, as a lookup page does;
    `page_data` False leaves out #page-data itself; `location` is what the
    server put under "location", None for a #page-data without one;
    `short_offset` False is an engine that has no timeZoneName "shortOffset"."""
    data = None
    if page_data:
        data = {"address": "203.0.113.10", "whois": {"pending": True}}
        if location is not None:
            data["location"] = location
    script = (
        HARNESS.replace("FINGERPRINT_JS", json.dumps(str(FINGERPRINT_JS)))
        .replace("SELF_PAGE", json.dumps(self_page))
        .replace("PAGE_DATA", json.dumps(data))
        .replace("LANGUAGES", json.dumps(list(languages)))
        .replace("SHORT_OFFSET", json.dumps(short_offset))
    )
    return _node(script, tz=tz)


BERLIN = {"time_zone": "Europe/Berlin", "country_code": "DE", "precision": "city"}
SEOUL = {"time_zone": "Asia/Seoul", "country_code": "KR", "precision": "city"}
LONDON = {"time_zone": "Europe/London", "country_code": "GB", "precision": "city"}


def _rows(run):
    """The two comparison rows, by label: {label: (text, class)}."""
    return {label: (text, tone) for label, text, tone in run["rows"][:2]}


@needs_node
class TestThePanel:
    def test_a_lookup_page_gets_nothing(self):
        """fingerprint.js is loaded on the self page alone, while #page-data
        is on every page: without the panel the script stops at its first
        line and touches nothing."""
        run = _load(self_page=False, location=BERLIN)
        assert run["rows"] is None
        assert run["created"] == 0
        assert run["sent"] == [] and run["stored"] == []

    def test_the_two_rows_come_first(self):
        labels = [label for label, _, _ in _load(location=BERLIN)["rows"][:3]]
        assert labels == ["Clock vs address", "Languages vs address", "Languages"]

    def test_a_different_zone_and_language_are_hints_not_verdicts(self):
        """TZ=Asia/Seoul and ko-KR against an address in Berlin: both rows
        warn, name both sides, and never claim to have detected anything.
        The panel compares the clocks at new Date(), so Berlin's summer time
        decides between UTC+2 (7 h) and UTC+1 (8 h)."""
        rows = _rows(_load(location=BERLIN))
        clock, clock_tone = rows["Clock vs address"]
        assert clock_tone == "tone-warning"
        assert clock.startswith("differs: your clock is on Asia/Seoul (UTC+9), ")
        assert (
            "the address is on Europe/Berlin (UTC+2), 7 h ahead of the address" in clock
            or "the address is on Europe/Berlin (UTC+1), 8 h ahead of the address"
            in clock
        )
        assert (
            "a VPN, proxy or travelling device, and any site can notice it too" in clock
        )
        languages, languages_tone = rows["Languages vs address"]
        assert languages_tone == "tone-warning"
        assert languages.startswith("differs: ")
        assert "KR" in languages and "DE" in languages
        assert "detected" not in (clock + languages).lower()

    def test_a_matching_zone_and_language_are_same(self):
        rows = _rows(_load(location=SEOUL))
        assert rows["Clock vs address"] == (
            "same: your clock and the address are both on Asia/Seoul",
            "tone-success",
        )
        assert rows["Languages vs address"] == (
            "same: ko-KR names KR, where the address is",
            "tone-success",
        )

    def test_no_time_zone_and_no_country_are_not_comparable(self):
        """What a fresh volume shows until GeoLite2-City is downloaded, and
        any address no database places (country_code "--")."""
        rows = _rows(_load(location={"country_code": "--"}))
        assert rows["Clock vs address"] == (
            "not comparable: no time zone for this address",
            "tone-muted",
        )
        assert rows["Languages vs address"] == (
            "not comparable: no country for this address",
            "tone-muted",
        )

    def test_a_country_level_location_is_not_compared_with_the_clock(self):
        rows = _rows(_load(location={**BERLIN, "precision": "country"}))
        assert rows["Clock vs address"] == (
            "not comparable: country-level location",
            "tone-muted",
        )
        # The country itself is still known, so the languages are compared.
        assert rows["Languages vs address"][1] == "tone-warning"

    def test_a_browser_reporting_utc_is_not_compared(self):
        rows = _rows(_load(location=LONDON, tz="UTC", languages=("en-GB", "en")))
        assert rows["Clock vs address"] == (
            "not comparable: browser reports UTC",
            "tone-muted",
        )
        assert rows["Languages vs address"][1] == "tone-success"

    def test_a_half_hour_difference_is_written_out(self):
        """Neither Kolkata nor Seoul keeps summer time, so this is exact all
        year: a clock behind the address says so, minutes included."""
        rows = _rows(_load(location=SEOUL, tz="Asia/Kolkata", languages=("hi-IN",)))
        clock, clock_tone = rows["Clock vs address"]
        assert clock_tone == "tone-warning"
        assert "(UTC+5:30)" in clock and "Asia/Seoul (UTC+9)" in clock
        assert "3 h 30 min behind the address" in clock

    def test_an_engine_without_short_offsets_still_draws_the_table(self):
        """Safari before 15.4 throws a RangeError for timeZoneName
        "shortOffset", which node 22 cannot show on its own. The clock row
        falls back to not comparable, and the language row and every signal
        are still drawn: an exception in phase 1 would leave the whole table
        on "Reading…"."""
        run = _load(location=BERLIN, short_offset=False)
        rows = _rows(run)
        assert rows["Clock vs address"] == (
            "not comparable: time zone not recognised by this browser",
            "tone-muted",
        )
        assert rows["Languages vs address"][1] == "tone-warning"
        assert [label for label, _, _ in run["rows"][2:4]] == ["Languages", "Time zone"]
        assert run["hash"]

    def test_a_page_without_page_data_degrades_to_not_comparable(self):
        rows = _rows(_load(page_data=False))
        assert rows["Clock vs address"][1] == "tone-muted"
        assert rows["Languages vs address"][1] == "tone-muted"

    def test_the_rows_are_not_signals(self):
        """They change with the network, so they stay out of the UNIQUE ID
        (which must survive a reload), the bit estimate and the signal count."""
        berlin = _load(location=BERLIN)
        seoul = _load(location=SEOUL)
        assert berlin["hash"] == seoul["hash"]
        assert berlin["bits"] == seoul["bits"]
        counted = int(berlin["hint"].split(" ")[0])
        assert counted == len(berlin["rows"]) - 2

    @pytest.mark.parametrize("location", [BERLIN, SEOUL, {"country_code": "--"}])
    def test_nothing_is_sent_or_stored(self, location):
        """Settled decision 4, checked in the harness: the CSP would allow a
        same-origin request, so this is what keeps one out."""
        run = _load(location=location)
        assert run["sent"] == []
        assert run["stored"] == []
