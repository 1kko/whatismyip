"""Slicing the lookup page (templates/browser.html) for the page tests.

Not a test module. The page is one summary, a row of status cards, a contents
list and a run of `<section class="report-section" id="sec-…">`, each a heading
and its blocks (templates/_blocks.html). A test that asks what one section or
one card says reads it through these, so it does not depend on what comes
before or after it.
"""


def section(html: str, sid: str) -> str:
    """The text between `id="sec-{sid}"` and the next `</section>`: the
    section's heading, hint and blocks. A section never holds another one
    (tests/test_sections.py), so the next `</section>` is its own."""
    marker = f'id="sec-{sid}"'
    assert marker in html, f"no section {sid!r} on the page"
    return html.split(marker, 1)[1].split("</section>", 1)[0]


def card(html: str, cid: str) -> str:
    """The inner HTML of the status card `#card-{cid}`: its dot, label, value
    and sub line."""
    marker = f'id="card-{cid}"'
    assert marker in html, f"no card {cid!r} on the page"
    return html.split(marker, 1)[1].split(">", 1)[1].split("</a>", 1)[0]
