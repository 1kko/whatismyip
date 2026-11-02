"""The contents list marks the section in view (static/js/contents.js).

The pure part, which section the view is in, runs in node. The observer
wiring only runs in a page.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")
CONTENTS_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "contents.js"

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

SECTIONS = [
    {"id": "a", "top": 100, "bottom": 400},
    {"id": "b", "top": 400, "bottom": 900},
    {"id": "c", "top": 900, "bottom": 1200},
]


def _current(sections, view_top, at_bottom=None):
    script = (
        f"const m = require({json.dumps(str(CONTENTS_JS))});"
        f"console.log(JSON.stringify(m.currentSection("
        f"{json.dumps(sections)}, {json.dumps(view_top)}"
        f"{'' if at_bottom is None else ', ' + json.dumps(at_bottom)})));"
    )
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def test_first_section_before_scrolling():
    assert _current(SECTIONS, 0) == "a"


def test_section_under_the_top():
    assert _current(SECTIONS, 450) == "b"
    assert _current(SECTIONS, 898) == "b"
    assert _current(SECTIONS, 900) == "c"


def test_last_section_at_the_bottom():
    assert _current(SECTIONS, 1100) == "c"


def test_no_sections_is_null():
    assert _current([], 0) is None


def test_never_scrolls_the_page():
    assert "scrollIntoView" not in CONTENTS_JS.read_text()  # no call, no mention


def test_at_bottom_marks_the_last_section():
    assert _current(SECTIONS, 450, True) == "c"
    assert _current(SECTIONS, 450, False) == "b"


def test_at_bottom_without_sections_is_null():
    assert _current([], 0, True) is None


def _at_bottom(*args):
    script = (
        f"const m = require({json.dumps(str(CONTENTS_JS))});"
        f"console.log(JSON.stringify(m.isAtBottom(...{json.dumps(args)})));"
    )
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


def test_a_page_that_does_not_scroll_is_never_at_bottom():
    assert _at_bottom(0, 900, 700) is False
    assert _at_bottom(0, 900, 900) is False


def test_scrolled_to_the_end_is_at_bottom():
    assert _at_bottom(1100, 900, 2000) is True
    assert _at_bottom(1098, 900, 2000) is True


def test_mid_page_is_not_at_bottom():
    assert _at_bottom(500, 900, 2000) is False
