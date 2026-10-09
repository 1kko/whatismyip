"""The subdomain panel: a way to the whole list, a filter, and an honest wait.

The panel loads up to 5,000 names and draws 100 of them. It used to end on
"The full list is in the JSON response", which was only true for
?subdomains=include, and the Raw JSON viewer is not where anyone would look.
It now links to /{domain}?subdomains=only, which always answers JSON, and lets
the visitor filter and copy every loaded name. It also says how old the list is
and whether crt.sh's answer was cut short, and the 3-20 second crt.sh wait
shows a running counter instead of a bare "Loading…".

The server-rendered half (?subdomains=include, the no-JavaScript path) is
checked through TestClient. The pure helpers in static/js/app.js run in node,
as test_error_pages.py does for isLocalAddress(). The DOM wiring has no runtime
here; the source-text checks below cover what can be pinned without one.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app, client=("118.235.14.201", 41234))

BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    ),
}
# What Chrome sends on a top-level navigation, i.e. on following a link.
NAVIGATION = {
    **BROWSER_UA,
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
}

GATHERED = {
    "address": "example.com",
    "domain": {
        "a": [{"ip": "93.184.216.34", "ttl": 300}],
        "mx": [],
        "ns": [],
        "txt": [],
    },
    "location": {"country_code": "US", "country_name": "United States"},
    "whois": {"registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}

APP_JS = Path("static/js/app.js")
DEAD_END = "The full list is in the JSON response"


def _subdomains(n, count=None, **extra):
    return {
        "names": [f"h{i}.example.com" for i in range(n)],
        "count": n if count is None else count,
        "truncated": False,
        "source": "crt.sh",
        "fetched_at": "2026-09-29T00:00:00+00:00",
        "stale": False,
        "error": None,
        **extra,
    }


def _panel(data):
    """The subdomain accordion's body, server-rendered with `data`."""
    with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
        with patch("main.get_subdomains", new_callable=AsyncMock, return_value=data):
            html = client.get("/example.com?subdomains=include", headers=BROWSER_UA)
    assert html.status_code == 200
    body = html.text.split('id="acc-subdomains"')[1]
    return body.split("</details>")[0]


# --- The server-rendered panel (?subdomains=include, works without JS) --------


class TestServerRenderedPanel:
    def test_a_capped_list_links_to_the_full_list(self):
        panel = _panel(_subdomains(500))
        assert 'href="/example.com?subdomains=only"' in panel
        assert "Showing 100 of 500." in panel

    def test_the_dead_end_sentence_is_gone(self):
        assert DEAD_END not in _panel(_subdomains(500))
        assert DEAD_END not in APP_JS.read_text(encoding="utf-8")
        assert DEAD_END not in Path("templates/browser.html").read_text("utf-8")

    def test_a_list_that_fits_needs_no_link(self):
        panel = _panel(_subdomains(3))
        assert "?subdomains=only" not in panel
        assert "Showing" not in panel

    def test_the_link_answers_json_to_a_browser_that_follows_it(self):
        """The link is an ordinary navigation, Accept: text/html and all, and
        must still land on the list rather than on another HTML page."""
        with patch(
            "main.get_subdomains",
            new_callable=AsyncMock,
            return_value=_subdomains(500),
        ):
            response = client.get("/example.com?subdomains=only", headers=NAVIGATION)
        assert response.headers["content-type"].startswith("application/json")
        assert len(response.json()["subdomains"]["names"]) == 500

    def test_fetched_at_is_shown_as_a_time_element(self):
        """UTC as text for a reader without JavaScript; app.js rewrites it in
        the visitor's locale from the datetime attribute."""
        panel = _panel(_subdomains(3))
        assert (
            'as of <time datetime="2026-09-29T00:00:00+00:00">'
            "2026-09-29 00:00 UTC</time>"
        ) in panel

    def test_no_fetched_at_no_as_of(self):
        panel = _panel(_subdomains(3, fetched_at=None))
        assert "as of" not in panel
        assert "<time" not in panel

    def test_a_truncated_list_says_where_it_was_cut(self):
        panel = _panel(_subdomains(5000, count=9123, truncated=True))
        assert "truncated at 5,000" in panel
        assert "Showing 100 of 9,123." in panel

    def test_an_untruncated_list_does_not_claim_to_be(self):
        assert "truncated" not in _panel(_subdomains(500))

    def test_refreshing_joins_the_same_line(self):
        panel = _panel(_subdomains(3, stale=True, truncated=True))
        assert re.search(r"</time>\s*·\s*refreshing\s*·\s*truncated at 3", panel)

    def test_the_panel_is_marked_for_app_js_to_rebuild(self):
        """app.js rebuilds this markup from #page-data, which carries every
        loaded name, so the filter and Copy all see the whole list."""
        panel = _panel(_subdomains(500))
        assert 'id="subdomains-rendered"' in panel
        assert 'data-target="example.com"' in panel

    def test_the_hint_groups_its_count_like_the_panel(self):
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            with patch(
                "main.get_subdomains",
                new_callable=AsyncMock,
                return_value=_subdomains(5000, count=6002, truncated=True),
            ):
                html = client.get(
                    "/example.com?subdomains=include", headers=BROWSER_UA
                ).text
        assert '<span class="hint" id="hint-subdomains">6,002 subdomains found' in html

    def test_an_error_is_still_an_error(self):
        panel = _panel(_subdomains(0, error="crt.sh timed out"))
        assert "Lookup failed: crt.sh timed out" in panel
        assert 'id="subdomains-rendered"' not in panel


# --- static/js/app.js helpers, run in node -------------------------------------

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")


def _js(expression, *names):
    """Evaluate `expression` in node, with app.js's named top-level functions
    and constants in scope, and return its JSON-decoded value."""
    source = APP_JS.read_text(encoding="utf-8")
    parts = []
    for name in names:
        match = re.search(
            rf"^(?:const {name} = .*?;|(?:async )?function {name}\(.*?^\}})$",
            source,
            re.M | re.S,
        )
        assert match, f"{name} not found in app.js"
        parts.append(match.group(0))
    script = "\n".join(parts) + f"\nconsole.log(JSON.stringify({expression}));"
    # The script is app.js's own source plus a fixed expression from this file.
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


NAMES = ["api.example.com", "www.example.com", "api-v2.example.com", "mx.example.com"]


@needs_node
class TestFilter:
    def _filter(self, names, query):
        return _js(
            f"filterSubdomains({json.dumps(names)}, {json.dumps(query)})",
            "filterSubdomains",
        )

    def test_substring_match_keeps_order(self):
        assert self._filter(NAMES, "api") == ["api.example.com", "api-v2.example.com"]

    def test_case_and_surrounding_space_are_ignored(self):
        assert self._filter(NAMES, "  API ") == [
            "api.example.com",
            "api-v2.example.com",
        ]

    def test_an_empty_filter_keeps_everything(self):
        assert self._filter(NAMES, "") == NAMES
        assert self._filter(NAMES, "   ") == NAMES

    def test_no_match_is_an_empty_list(self):
        assert self._filter(NAMES, "zzz") == []

    def test_it_searches_every_loaded_name_not_just_the_rendered_hundred(self):
        names = [f"h{i}.example.com" for i in range(5000)]
        matches = self._filter(names, "h1")
        # h1, h10-h19, h100-h199, h1000-h1999
        assert len(matches) == 1 + 10 + 100 + 1000
        assert matches[-1] == "h1999.example.com"


@needs_node
class TestNotes:
    def _notes(self, data, locale="en-US", time_zone="UTC"):
        return _js(
            f"subdomainNotes({json.dumps(data)}, {json.dumps(locale)}, "
            f"{json.dumps(time_zone)})",
            "formatCount",
            "subdomainNotes",
        )

    def test_as_of_is_in_the_given_locale(self):
        [note] = self._notes(_subdomains(3))
        assert note.startswith("as of Sep 29, 2026, 12:00")

    def test_as_of_is_in_the_visitors_time_zone_not_utc(self):
        """20:00 UTC is already the next morning in Seoul."""
        data = _subdomains(3, fetched_at="2026-09-29T20:00:00+00:00")
        [note] = self._notes(data, locale="ko-KR", time_zone="Asia/Seoul")
        assert note.startswith("as of 2026. 9. 30.")

    def test_a_missing_or_unparseable_time_is_left_out(self):
        assert self._notes(_subdomains(3, fetched_at=None)) == []
        assert self._notes(_subdomains(3, fetched_at="yesterday")) == []

    def test_truncated_says_where_it_was_cut(self):
        notes = self._notes(_subdomains(5000, count=9123, truncated=True))
        assert notes[-1] == "truncated at 5,000"

    def test_order_matches_the_server_line(self):
        notes = self._notes(_subdomains(3, stale=True, truncated=True))
        assert [n.split(" ")[0] for n in notes] == ["as", "refreshing", "truncated"]


@needs_node
class TestCountLine:
    def _text(self, shown, matched, total, filtering):
        return _js(
            f"subdomainCountText({shown}, {matched}, {total}, {json.dumps(filtering)})",
            "formatCount",
            "subdomainCountText",
        )

    def test_unfiltered(self):
        assert self._text(100, 2585, 2585, False) == "Showing 100 of 2,585."
        assert self._text(57, 57, 57, False) == "Showing 57 of 57."
        # Truncated: 5,000 loaded of 9,123 seen, and the line counts what crt.sh saw.
        assert self._text(100, 5000, 9123, False) == "Showing 100 of 9,123."

    def test_none_found_is_said_not_left_blank(self):
        assert self._text(0, 0, 0, False) == "No subdomains found."

    def test_filtered(self):
        assert self._text(12, 12, 2585, True) == "Showing 12 of 12 matches."
        assert self._text(1, 1, 2585, True) == "Showing 1 of 1 match."
        assert self._text(100, 1111, 2585, True) == "Showing 100 of 1,111 matches."

    def test_a_filter_that_matches_nothing_says_so(self):
        assert self._text(0, 0, 2585, True) == "No names match the filter."

    def test_the_summary_hint_groups_its_count_like_the_line_below_it(self):
        """The hint sits a few lines above "Showing 100 of 6,002."; one panel
        should not write the same number two ways. viewmodel.py renders the
        same wording on the server path."""
        hints = _js(
            "[6002, 1, 0].map(subdomainHintText)", "formatCount", "subdomainHintText"
        )
        assert hints == [
            "6,002 subdomains found",
            "1 subdomain found",
            "0 subdomains found",
        ]


@needs_node
def test_the_counter_reads_whole_seconds():
    assert _js("[0, 999, 1000, 3500, 19999].map(elapsedLabel)", "elapsedLabel") == [
        "0s",
        "0s",
        "1s",
        "3s",
        "19s",
    ]


@needs_node
def test_the_full_list_link_is_the_json_route():
    assert _js("['example.com', 'a/b?c'].map(fullListHref)", "fullListHref") == [
        "/example.com?subdomains=only",
        "/a%2Fb%3Fc?subdomains=only",
    ]


# --- app.js wiring, by source text ---------------------------------------------


def _function(name):
    source = APP_JS.read_text(encoding="utf-8")
    return re.search(
        rf"^(?:async )?function {name}\(.*?^\}}$", source, re.M | re.S
    ).group(0)


def test_names_never_reach_innerhtml():
    """They come from third-party certificates; textContent only."""
    source = APP_JS.read_text(encoding="utf-8")
    assert not re.search(r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML", source)


def test_loading_is_no_longer_a_bare_loading_string():
    assert '"Loading…"' not in APP_JS.read_text(encoding="utf-8")


def test_the_status_line_is_a_polite_live_region():
    line = _function("subdomainStatusLine")
    assert '"role", "status"' in line
    assert '"aria-live", "polite"' in line


def test_the_wait_is_marked_busy_and_the_timer_always_stops():
    """The interval is cleared in a finally, so success, an error response, a
    network failure and an aborted fetch all stop it; the busy flag comes off
    on the same path."""
    source = APP_JS.read_text(encoding="utf-8")
    handler = source.split('subdomainAccordion.addEventListener("toggle"')[1]
    assert '"aria-busy", "true"' in handler
    final = handler.split("} finally {")[1].split("}")[0]
    assert "clearInterval(" in final
    assert "aria-busy" in final


def test_the_counter_is_hidden_from_the_live_region():
    """A twenty-second wait is one announcement, not twenty."""
    source = APP_JS.read_text(encoding="utf-8")
    handler = source.split('subdomainAccordion.addEventListener("toggle"')[1]
    assert 'elapsed.setAttribute("aria-hidden", "true")' in handler


def test_copy_all_copies_the_matches_not_the_rendered_rows():
    panel = _function("renderSubdomainPanel")
    assert "copyWithFeedback(copy, filterSubdomains(names, filter.value)" in panel
    assert "SUBDOMAIN_RENDER_CAP" in panel


def test_the_slash_shortcut_leaves_the_filter_alone():
    """ "/" focuses the search box from anywhere, which must not include the
    middle of typing into another text field."""
    source = APP_JS.read_text(encoding="utf-8")
    shortcut = source.split('event.key === "/"')[1].split("\n")[0]
    assert "input, textarea" in shortcut
