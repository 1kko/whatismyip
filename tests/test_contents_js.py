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


def _current(sections, view_top):
    script = (
        f"const m = require({json.dumps(str(CONTENTS_JS))});"
        f"console.log(JSON.stringify(m.currentSection("
        f"{json.dumps(sections)}, {json.dumps(view_top)})));"
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
