"""The fingerprint's active probes (static/js/fingerprint.js) wait for the
"Measure" button in the self page's "Your browser" section.

Phase 1, the passive signals (languages, time zone, screen, navigator values,
the GPU name), is read as the page loads. Phase 2 is different in kind: a
canvas drawn and read back with toDataURL, an OfflineAudioContext rendered,
the WebGL parameters, and forty fonts measured. Firefox with
resistFingerprinting, and so Tor Browser, asks before a page reads a canvas,
but only while it is handling a click or a key
(UserActivation::IsHandlingUserInput); a read at any other time is declined
unasked and flagged with the canvas icon in the address bar, to exactly the
visitors this page is for. So phase 2 runs on a press of #fp-measure, the way
the WebRTC test runs on its button, and the press's click handler reads the
canvas itself, before its first await.

fingerprint.js runs here in node against a fake DOM: the #sec-browser section,
the #fp-measure button whose click listener the harness fires, the two hints
(the contents entry's and the heading's) and the two dots of that section, a
canvas that records toDataURL, an OfflineAudioContext that records its
construction, a <body> that records the span the font probe appends, and a
tripwire on every way a page could send something to a server (settled
decision 4: nothing leaves the browser). What the template renders around it
is checked in tests/test_page.py.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

FINGERPRINT_JS = Path("static/js/fingerprint.js").resolve()
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node")

# A fake browser: just enough DOM for fingerprint.js, recorders on the three
# probes that touch the document (canvas, audio, fonts), and a tripwire on
# every way a page could send something to a server.
HARNESS = r"""
const calls = { probes: [], sent: [] };
const listeners = {};
const writes = [];
function el(id) {
  const classes = new Set();
  const node = {
    id, className: "", hidden: false, disabled: false, dataset: {}, style: {},
    children: [], colSpan: 1, title: "",
    append(...nodes) { this.children.push(...nodes); },
    appendChild(child) { this.children.push(child); return child; },
    removeChild(child) {
      this.children = this.children.filter((c) => c !== child);
      return child;
    },
    addEventListener(type, fn) { listeners[id + ":" + type] = fn; },
    classList: {
      add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
      contains: (name) => classes.has(name),
      list: () => [...classes],
    },
  };
  let text = "";
  Object.defineProperty(node, "textContent", {
    get: () => text,
    set: (value) => {
      text = String(value);
      node.children = [];
      writes.push([id, text]);
    },
  });
  return node;
}
// A canvas whose 2d context draws nothing and whose WebGL contexts are
// missing; reading it back is the canvas probe.
function canvas() {
  const node = el("canvas");
  node.getContext = (kind) => (kind === "2d" ? { fillRect() {}, fillText() {} } : null);
  node.toDataURL = () => {
    if (CANVAS_THROWS) throw new Error("canvas blocked");
    calls.probes.push("canvas");
    return "data:image/png;base64,AAAA";
  };
  return node;
}
const ids = [
  "sec-browser", "fp-measure", "fp-signals", "fp-hash", "fp-copy", "fp-bits",
  "fp-unique",
];
const elements = Object.fromEntries(ids.map((id) => [id, el(id)]));
// The section's hint in the contents list and in its heading, both
// [data-hint="browser"], and its two dots, which start "on request".
const hints = [el("toc-hint"), el("heading-hint")];
const dots = [el("toc-dot"), el("heading-dot")];
for (const dot of dots) dot.classList.add("dot", "dot--request");
const queries = {
  '[data-hint="browser"]': hints,
  '.toc__item[data-section="browser"] .dot, #h-browser .dot': dots,
};
// What the template ships: an enabled Measure button, a disabled copy
// button, "…" for the ID, and the hint that says nothing was measured yet.
elements["fp-copy"].disabled = true;
elements["fp-hash"].textContent = "…";
for (const hint of hints) {
  hint.textContent = "not measured yet";
  hint.title = "not measured yet";
}
writes.length = 0;
const body = el("body");
body.appendChild = (child) => { calls.probes.push("fonts"); return child; };
global.window = global;
global.document = {
  body,
  getElementById: (id) => elements[id] || null,
  querySelectorAll: (selector) => queries[selector] || [],
  createElement: (tag) => (tag === "canvas" ? canvas() : el(tag)),
};
global.OfflineAudioContext = class {
  constructor() { calls.probes.push("audio"); this.destination = {}; }
  createOscillator() { return { frequency: {}, connect() {}, start() {} }; }
  createDynamicsCompressor() {
    return {
      threshold: {}, knee: {}, ratio: {}, attack: {}, release: {}, connect() {},
    };
  }
  async startRendering() { return { getChannelData: () => new Float32Array(6000) }; }
};
global.fetch = () => calls.sent.push("fetch");
global.XMLHttpRequest = function () { calls.sent.push("xhr"); };
global.WebSocket = function () { calls.sent.push("websocket"); };
global.EventSource = function () { calls.sent.push("eventsource"); };
global.Image = function () { calls.sent.push("image"); };
// node's own navigator is a read-only getter: a plain assignment is ignored.
Object.defineProperty(globalThis, "navigator", {
  value: {
    languages: ["en-US"], userAgent: "harness",
    sendBeacon: () => calls.sent.push("beacon"),
  },
  configurable: true,
});
require(FINGERPRINT_JS);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const hint = () => hints[1].textContent;
const dotStates = () =>
  dots.map((dot) => dot.classList.list().filter((c) => c !== "dot"));
async function settled() {
  for (let i = 0; i < 80 && hint() === "measuring…"; i++) await wait(25);
}
(async () => {
  await wait(50); // longer than a setTimeout(cb, 1) idle fallback takes to fire
  await settled();
  const onLoad = {
    probes: [...calls.probes], hint: hint(), hash: elements["fp-hash"].textContent,
    rows: elements["fp-signals"].children.length, dots: dotStates(),
    buttonDisabled: elements["fp-measure"].disabled,
  };
  const click = listeners["fp-measure:click"];
  // A visitor's press: clickProbes holds what each click's listener read
  // before it returned, which is what Firefox counts as the visitor's action.
  const clickProbes = [];
  const disabledAfter = [];
  for (let i = 0; i < CLICKS; i++) {
    const before = calls.probes.length;
    if (click) click();
    clickProbes.push(calls.probes.slice(before));
    disabledAfter.push(elements["fp-measure"].disabled);
    await settled();
  }
  console.log(JSON.stringify({
    onLoad, clickProbes, disabledAfter, probes: calls.probes, hint: hint(),
    hints: hints.map((h) => [h.textContent, h.title]),
    dots: dotStates(),
    listened: Object.keys(listeners),
    hash: elements["fp-hash"].textContent, bits: elements["fp-bits"].textContent,
    labels: elements["fp-signals"].children.map((tr) => tr.children[0].textContent),
    copyDisabled: elements["fp-copy"].disabled,
    copyValue: elements["fp-copy"].dataset.value || "",
    hintWrites: writes.filter(([id]) => id === "heading-hint").map(([, text]) => text),
    sent: calls.sent,
  }));
})();
"""

PROBES = ["canvas", "audio", "fonts"]


def _sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


# What the UNIQUE ID hashes in this harness (TZ=UTC): the stable signals'
# label=value pairs in page order, then the font list. Nothing in node answers
# screen, CPU, memory or WebGL, so those read "—", and the canvas and audio
# values are the first 16 hex digits of their own hashes. The fingerprint.js
# of 7abcdb9, which ran the probes at load, hashes exactly this too.
HARNESS_MATERIAL = "|".join(
    [
        "Languages=en-US",
        "Time zone=UTC",
        "Resolution=—",
        "Color depth=—",
        "Touch points=—",
        "Platform=—",
        "CPU cores=—",
        "Device memory=—",
        "GPU=—",
        "WebGL2=no",
        "User agent=harness",
        "Cookies enabled=no",
        "Do Not Track=unset",
        "Global Privacy Control=unset",
        "PDF viewer=—",
        "Canvas=" + _sha256("data:image/png;base64,AAAA")[:16],
        "Audio=" + _sha256("0")[:16],
        "WebGL params=—",
        "Fonts=—",
        "fonts=",
    ]
)


def _load(canvas_throws=False, clicks=0):
    """Load fingerprint.js into the fake browser (TZ=UTC), wait longer than an
    idle fallback would take, then press Measure `clicks` times, waiting for
    each measurement."""
    script = (
        HARNESS.replace("FINGERPRINT_JS", json.dumps(str(FINGERPRINT_JS)))
        .replace("CANVAS_THROWS", json.dumps(canvas_throws))
        .replace("CLICKS", json.dumps(clicks))
    )
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env={**os.environ, "TZ": "UTC"},
    )
    return json.loads(out.stdout)


@needs_node
class TestBeforeThePress:
    def test_no_active_probe_runs_on_load(self):
        """The acceptance test: until Measure is pressed, toDataURL, the
        OfflineAudioContext and the font probe never run."""
        run = _load()
        assert run["onLoad"]["probes"] == []
        assert run["probes"] == []

    def test_the_passive_signals_are_painted_on_load(self):
        run = _load()
        assert run["onLoad"]["rows"] > 0
        assert "Languages" in run["labels"]
        assert "Canvas" not in run["labels"]

    def test_the_hint_says_nothing_was_measured(self):
        run = _load()
        assert run["onLoad"]["hint"] == "not measured yet"
        assert run["hash"] == "…"
        assert run["copyDisabled"]
        assert not run["onLoad"]["buttonDisabled"]

    def test_the_section_stays_on_request(self):
        """The contents entry's dot and the heading's stay "on request" until
        a measurement has run."""
        assert _load()["dots"] == [["dot--request"], ["dot--request"]]

    def test_only_the_button_is_listened_to(self):
        """No toggle or header listener is left from the accordion: the
        section is always open, so only a press may start the probes."""
        assert _load()["listened"] == ["fp-measure:click"]


@needs_node
class TestOnThePress:
    def test_the_press_runs_every_probe_once(self):
        run = _load(clicks=1)
        assert run["probes"] == PROBES
        assert run["labels"][-4:] == ["Canvas", "Audio", "WebGL params", "Fonts"]
        assert len(run["labels"]) == run["onLoad"]["rows"] + 4

    def test_the_id_and_the_estimate_are_filled_in(self):
        run = _load(clicks=1)
        assert re.fullmatch(r"[0-9a-f]{32}", run["hash"])
        assert run["copyValue"].startswith(run["hash"])
        assert not run["copyDisabled"]
        assert re.fullmatch(r"≈ \d+ bits", run["bits"])
        assert re.fullmatch(r"\d+ signals · ≈ \d+ bits", run["hint"])

    def test_the_id_is_the_one_the_page_computed_before(self):
        """A browser's UNIQUE ID does not change with the button: the hash
        material (the stable signals in page order, then the fonts) is what
        the fingerprint.js of 7abcdb9 hashed."""
        assert _load(clicks=1)["copyValue"] == _sha256(HARNESS_MATERIAL)

    def test_the_hints_show_the_measurement_in_progress(self):
        """Both hints, the contents entry's and the heading's, get the same
        text and the same title, which carries it when a narrow screen cuts
        the text with an ellipsis."""
        run = _load(clicks=1)
        assert run["hintWrites"][0] == "measuring…"
        assert run["hintWrites"][-1] == run["hint"]
        assert run["hints"] == [[run["hint"], run["hint"]]] * 2

    def test_the_button_is_disabled_once_pressed(self):
        assert _load(clicks=1)["disabledAfter"] == [True]

    def test_a_second_press_measures_nothing_more(self):
        run = _load(clicks=3)
        assert run["clickProbes"][1:] == [[], []]
        assert run["probes"] == PROBES
        assert re.fullmatch(r"\d+ signals · ≈ \d+ bits", run["hint"])

    def test_the_dots_turn_to_info_when_measured(self):
        assert _load(clicks=1)["dots"] == [["dot--info"], ["dot--info"]]

    def test_nothing_is_sent_anywhere(self):
        """Settled decision 4. The CSP would allow a same-origin request, so
        this is the check that keeps it out."""
        assert _load()["sent"] == []
        assert _load(clicks=1)["sent"] == []

    def test_a_probe_that_throws_does_not_leave_the_hint_measuring(self):
        """A canvas-blocking extension makes toDataURL throw. The ID stays
        blank and the copy button disabled, and the hint falls back to the
        signal count rather than staying on "measuring…"."""
        run = _load(clicks=1, canvas_throws=True)
        assert run["hash"] == "—"
        assert run["copyDisabled"]
        assert re.fullmatch(r"\d+ signals", run["hint"])
        assert run["dots"] == [["dot--info"], ["dot--info"]]


@needs_node
class TestOnAClick:
    """Firefox (resistFingerprinting, Tor Browser) asks before a canvas read
    only while a click or a key is being handled, so the button's click
    listener has to read the canvas itself, before it returns."""

    def test_the_canvas_is_read_inside_the_click(self):
        run = _load(clicks=1)
        assert "canvas" in run["clickProbes"][0]
        assert run["probes"] == PROBES
