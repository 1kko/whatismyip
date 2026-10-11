// Client-side browser fingerprint for the self page. Everything is computed
// here and shown here — nothing is sent to the server, and the page and
// /privacy both promise so. Only this file keeps that promise: the CSP's
// default-src 'self' would allow a same-origin fetch, so do not add one.
// No dependencies, no storage. Mirrors the map.js pattern: server renders empty
// placeholders, this paints them. Two phases: the passive signals on load, the
// active probes only once the visitor opens the panel.
//
// The first two rows of the signal table compare this browser's clock and
// languages with the address the page was served to, whose GeoIP record is in
// #page-data. The comparison is plain functions, run in node by
// tests/test_fingerprint_consistency.py; the DOM wiring after them only runs
// in a page.
(function () {
  // ---- Clock and languages against the address (pure) --------------------

  // The engine's own name for `zone`, so that two spellings of one zone are
  // equal: V8 answers "Asia/Calcutta" for the clock of a browser in India,
  // while GeoLite2 writes "Asia/Kolkata", and "Etc/UTC" and "GMT" both become
  // "UTC". null when the engine does not know the zone.
  function canonicalZone(zone) {
    if (typeof zone !== "string" || !zone) return null;
    try {
      return new Intl.DateTimeFormat("en-US", { timeZone: zone }).resolvedOptions().timeZone;
    } catch (_e) {
      return null;
    }
  }

  // Minutes east of UTC that `zone` keeps at `now`, from the engine's tables:
  // "GMT+5:30" is 330, "GMT-2:30" is -150, "GMT" alone is 0. null when the
  // engine does not know the zone or cannot write a short offset.
  function zoneOffsetMinutes(zone, now) {
    let text;
    try {
      const parts = new Intl.DateTimeFormat("en-US", {
        timeZone: zone,
        timeZoneName: "shortOffset",
      }).formatToParts(now);
      const part = parts.find((p) => p.type === "timeZoneName");
      text = part ? part.value : "";
    } catch (_e) {
      return null;
    }
    if (text === "GMT" || text === "UTC") return 0;
    const match = /^(?:GMT|UTC)([+-])(\d{1,2})(?::(\d{2}))?$/.exec(text);
    if (!match) return null;
    const minutes = Number(match[2]) * 60 + Number(match[3] || 0);
    return match[1] === "-" ? -minutes : minutes;
  }

  // `browserZone` and `browserOffsetMin` (minutes east of UTC) are what this
  // browser reports; `ipZone` and `precision` are the address's GeoIP record.
  // "same" when both clocks are in one zone, "differs" with the difference
  // (`diff_min`, positive when the clock runs ahead of the address), and
  // "not_comparable" with a reason when a comparison would mislead: no zone
  // for the address, a location only known to the country (GeoLite2's zone
  // for a 1000 km centroid says nothing about a clock), a browser that
  // reports UTC, or a zone this engine does not know.
  function compareZones(browserZone, browserOffsetMin, ipZone, precision, now) {
    const result = {
      verdict: "not_comparable",
      reason: null,
      browser_zone: browserZone || null,
      ip_zone: ipZone || null,
      browser_offset_min: Number.isFinite(browserOffsetMin) ? browserOffsetMin : null,
      ip_offset_min: null,
      diff_min: null,
    };
    if (!browserZone) return { ...result, reason: "no browser time zone" };
    if (!ipZone) return { ...result, reason: "no time zone for this address" };
    if (precision !== "city") return { ...result, reason: "country-level location" };
    const browser = canonicalZone(browserZone);
    if (browser === "UTC") return { ...result, reason: "browser reports UTC" };
    const ip = canonicalZone(ipZone);
    const ipOffset = zoneOffsetMinutes(ipZone, now);
    if (ip === null || ipOffset === null) {
      return { ...result, reason: "time zone not recognised by this browser" };
    }
    result.ip_offset_min = ipOffset;
    if (browser !== null && browser === ip) return { ...result, verdict: "same" };
    const diff = result.browser_offset_min === null ? null : result.browser_offset_min - ipOffset;
    return { ...result, verdict: "differs", diff_min: diff };
  }

  // The region subtag of a BCP 47 tag: "ko-KR" and "zh-Hant-TW" name a
  // country, "en" and "es-419" (a UN M.49 area, never an ISO code) do not.
  const REGION = /^[a-z]{2,8}(?:-[a-z]{4})?-([a-z]{2})(?:-|$)/i;

  // `languages` is navigator.languages (or navigator.language); `countryCode`
  // the address's ISO code. "same" when any listed language names that
  // country, "differs" when the languages name only other countries, and
  // "not_comparable" when no language names a country at all or the address
  // has none ("--" is managers.NO_COUNTRY).
  function compareLanguages(languages, countryCode) {
    const tags = Array.isArray(languages) ? languages : languages ? [languages] : [];
    const regions = [];
    const named = [];
    for (const tag of tags) {
      const match = REGION.exec(String(tag || "").trim());
      if (match) {
        regions.push(match[1].toUpperCase());
        named.push(String(tag).trim());
      }
    }
    const country = typeof countryCode === "string" ? countryCode.trim().toUpperCase() : "";
    const result = {
      verdict: "not_comparable",
      reason: null,
      regions: [...new Set(regions)],
      country_code: /^[A-Z]{2}$/.test(country) ? country : null,
      match: null,
    };
    if (result.country_code === null) return { ...result, reason: "no country for this address" };
    if (!regions.length) return { ...result, reason: "no country in your languages" };
    const index = regions.indexOf(country);
    if (index !== -1) return { ...result, verdict: "same", match: named[index] };
    return { ...result, verdict: "differs" };
  }

  if (typeof module === "object" && module.exports) {
    module.exports = { canonicalZone, zoneOffsetMinutes, compareZones, compareLanguages };
  }
  if (typeof document === "undefined") {
    return;
  }

  const panel = document.getElementById("acc-fingerprint");
  if (!panel) return; // lookup page, or not the self view — do nothing.

  const DASH = "—";
  const tbody = document.getElementById("fp-signals");
  // The wording of the two comparison rows is a hint, not a verdict: a clock
  // or a language that does not match the address is what a VPN or a proxy
  // looks like, and also what a traveller, an expat or a deliberate
  // English-and-UTC setup looks like. Declared before phase 1, which renders
  // the rows: a const below it would still be in its temporal dead zone.
  const CLOCK_NOTICE = "a VPN, proxy or travelling device, and any site can notice it too";
  const LANGUAGE_NOTICE =
    "a VPN, proxy or travelling device, or a language chosen on purpose, and any site can notice it too";
  const TONES = { same: "success", differs: "warning" };

  // {label, value, bits}. bits count only when the signal was actually read,
  // so a browser that blocks canvas/WebGL honestly scores lower.
  const signals = [];
  const add = (label, value, bits, stable = true) => {
    const has = value !== null && value !== undefined && value !== "";
    signals.push({ label, value: has ? String(value) : DASH, bits: has ? bits : 0, stable });
  };
  const safe = (fn) => {
    try {
      const v = fn();
      return v === undefined ? null : v;
    } catch (_e) {
      return null;
    }
  };
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text || DASH;
  };
  // The accordion hint is one line with an ellipsis on a narrow screen (.hint
  // in whatismyip.css), so its title carries the full text too.
  const setHint = (id, text) => {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = text;
      el.title = text;
    }
  };

  // ---- Phase 1: passive signals (synchronous) ----------------------------
  const nav = navigator;

  const languages = safe(() => nav.languages || [nav.language]);
  add("Languages", languages ? languages.join(", ") : null, 3);
  const browserZone = safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  add("Time zone", browserZone, 3);
  const offset = safe(() => -new Date().getTimezoneOffset());
  add("UTC offset", offset != null ? (offset >= 0 ? "+" : "") + offset + " min" : null, 0, false);

  // The address's side: the GeoIP record this page was rendered from, which
  // render_page embeds as #page-data. Compared here and shown here. These two
  // rows are not signals: they change with the network, so they stay out of
  // `signals`, and so out of the UNIQUE ID, the bit count and the signal count.
  const location = safe(() => JSON.parse(document.getElementById("page-data").textContent).location) || {};
  const consistency = [
    zoneRow(safe(() => compareZones(browserZone, offset, location.time_zone, location.precision, new Date()))),
    languageRow(safe(() => compareLanguages(languages, location.country_code))),
  ];

  add("Resolution", safe(() => screen.width + "×" + screen.height), 4);
  add("Available", safe(() => screen.availWidth + "×" + screen.availHeight), 0, false);
  add("Color depth", safe(() => screen.colorDepth), 1);
  add("Pixel ratio", safe(() => window.devicePixelRatio), 1, false);
  add("Orientation", safe(() => screen.orientation && screen.orientation.type), 0, false);
  add("Touch points", safe(() => nav.maxTouchPoints), 1);

  add("Platform", safe(() => (nav.userAgentData && nav.userAgentData.platform) || nav.platform), 2);
  add("CPU cores", safe(() => nav.hardwareConcurrency), 2);
  add("Device memory", safe(() => (nav.deviceMemory != null ? nav.deviceMemory + " GB" : null)), 2);
  add("Pointer", safe(() =>
    matchMedia("(pointer: fine)").matches ? "fine"
      : matchMedia("(pointer: coarse)").matches ? "coarse" : "none"), 0, false);
  add("Hover", safe(() => (matchMedia("(hover: hover)").matches ? "yes" : "no")), 0, false);

  // GPU via WebGL. This context is reused in phase 2 for the parameter hash.
  const gl = safe(() => {
    const c = document.createElement("canvas");
    return c.getContext("webgl") || c.getContext("experimental-webgl");
  });
  let gpu = null;
  if (gl) {
    const dbg = safe(() => gl.getExtension("WEBGL_debug_renderer_info"));
    if (dbg) {
      gpu = safe(() => gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
      add("GPU vendor", safe(() => gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)), 2);
    }
    add("Max texture", safe(() => gl.getParameter(gl.MAX_TEXTURE_SIZE)), 1);
  }
  add("GPU", gpu, 7);
  add("WebGL2", safe(() =>
    (document.createElement("canvas").getContext("webgl2") ? "yes" : "no")), 0);

  add("User agent", safe(() => nav.userAgent), 10);
  add("Cookies enabled", safe(() => (nav.cookieEnabled ? "yes" : "no")), 0);
  add("Do Not Track", safe(() => nav.doNotTrack || window.doNotTrack || "unset"), 0);
  add("Global Privacy Control",
    safe(() => (nav.globalPrivacyControl != null ? String(nav.globalPrivacyControl) : "unset")), 0);
  add("PDF viewer",
    safe(() => (nav.pdfViewerEnabled != null ? (nav.pdfViewerEnabled ? "yes" : "no") : null)), 0);

  // The full signal list lives in the Fingerprint accordion table.
  renderSignals();

  // ---- Phase 2: active entropy, run once the visitor opens the panel ------
  // Canvas, audio, WebGL parameters and the font probe are the active probes.
  // Firefox with resistFingerprinting, and so Tor Browser, asks before a page
  // reads a canvas, but only while it is handling a click or a key: a read at
  // any other time, such as right after load, is declined unasked and flagged
  // with the canvas icon in the address bar, to exactly the visitors this page
  // is for. So the probes wait for the panel to be opened, the way the WebRTC
  // test waits for its button and Raw JSON for its first opening. A click on
  // the header (Enter or Space on it fires one too) starts them inside that
  // click, before the browser opens the panel; the toggle event comes after,
  // in a task of its own, too late to count as the visitor's action, and is
  // left to an opening without a click (find in page, a script). The passive
  // signals above stay on load.
  let measured = false;
  const measureOnOpen = () => {
    if (!panel.open || measured) return;
    measured = true;
    measure();
  };
  const header = safe(() => panel.querySelector("summary"));
  if (header) {
    header.addEventListener("click", () => {
      if (panel.open || measured) return; // closing it, or measured already
      measured = true;
      measure();
    });
  }
  panel.addEventListener("toggle", measureOnOpen);
  measureOnOpen(); // a panel already open (restored or scripted) sends no toggle

  // The canvas read stays the first thing measure() does, before any await, so
  // that it happens inside the click that called it.
  async function measure() {
    setHint("fp-acc-hint", "measuring…");
    try {
      const canvasHash = await hashString(canvasFingerprint());
      add("Canvas", canvasHash ? canvasHash.slice(0, 16) : null, 8);
      const audioHash = await hashString(await audioFingerprint());
      add("Audio", audioHash ? audioHash.slice(0, 16) : null, 5);
      const glHash = await hashString(webglParams(gl));
      add("WebGL params", glHash ? glHash.slice(0, 16) : null, 3);
      const fonts = detectFonts();
      add("Fonts", fonts.length ? fonts.length + " detected" : null, 6);
      renderSignals();

      const material =
        signals.filter((s) => s.stable).map((s) => s.label + "=" + s.value).join("|") +
        "|fonts=" + fonts.join(",");
      const id = await hashString(material);
      const bits = signals.reduce((total, s) => total + s.bits, 0);

      setText("fp-hash", id ? id.slice(0, 32) : DASH);
      const copyBtn = document.getElementById("fp-copy");
      if (copyBtn && id) {
        copyBtn.dataset.value = id;
        copyBtn.disabled = false;
        copyBtn.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(id);
            copyBtn.classList.add("is-copied");
            setTimeout(() => copyBtn.classList.remove("is-copied"), 1200);
          } catch (_e) {}
        });
      }
      setText("fp-bits", "≈ " + bits + " bits");
      setText("fp-unique", "≈ 1 in " + formatCount(Math.pow(2, bits)) + " browsers");
      setHint("fp-acc-hint", signals.length + " signals · ≈ " + bits + " bits");
    } catch (_e) {
      // Phase 1 already painted; a failed measurement leaves the ID blank and
      // the hint without an estimate, never stuck on "measuring…".
      setText("fp-hash", DASH);
      setHint("fp-acc-hint", signals.length + " signals");
    }
  }

  // ---- helpers -----------------------------------------------------------
  function renderSignals() {
    if (!tbody) return;
    tbody.textContent = "";
    for (const c of consistency) tbody.append(row(c.label, c.value, c.tone));
    for (const s of signals) tbody.append(row(s.label, s.value, null));
  }

  function row(label, text, tone) {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = label;
    const value = document.createElement("td");
    value.colSpan = 3;
    if (tone) value.className = "tone-" + tone;
    value.textContent = text;
    tr.append(name, value);
    return tr;
  }

  function zoneRow(r) {
    if (!r) return { label: "Clock vs address", value: "not comparable: could not read the clock", tone: "muted" };
    let text;
    if (r.verdict === "same") {
      text = "same: your clock and the address are both on " + r.ip_zone;
    } else if (r.verdict === "differs") {
      text =
        "differs: your clock is on " + r.browser_zone + " (" + utcLabel(r.browser_offset_min) + "), " +
        "the address is on " + r.ip_zone + " (" + utcLabel(r.ip_offset_min) + "), " +
        aheadOrBehind(r.diff_min) + " — " + CLOCK_NOTICE;
    } else {
      text = "not comparable: " + r.reason;
    }
    return { label: "Clock vs address", value: text, tone: TONES[r.verdict] || "muted" };
  }

  function languageRow(r) {
    if (!r) return { label: "Languages vs address", value: "not comparable: could not read the languages", tone: "muted" };
    let text;
    if (r.verdict === "same") {
      text = "same: " + r.match + " names " + r.country_code + ", where the address is";
    } else if (r.verdict === "differs") {
      text =
        "differs: your languages name " + r.regions.join(", ") + ", the address is in " +
        r.country_code + " — " + LANGUAGE_NOTICE;
    } else {
      text = "not comparable: " + r.reason;
    }
    return { label: "Languages vs address", value: text, tone: TONES[r.verdict] || "muted" };
  }

  function utcLabel(minutes) {
    if (minutes === null || minutes === undefined) return "UTC offset unknown";
    const sign = minutes < 0 ? "-" : "+";
    const hours = Math.floor(Math.abs(minutes) / 60);
    const rest = Math.abs(minutes) % 60;
    return "UTC" + sign + hours + (rest ? ":" + String(rest).padStart(2, "0") : "");
  }

  function aheadOrBehind(diff) {
    if (diff === null || diff === undefined) return "offset difference unknown";
    if (diff === 0) return "the same UTC offset";
    const hours = Math.floor(Math.abs(diff) / 60);
    const rest = Math.abs(diff) % 60;
    const span = (hours ? hours + " h" : "") + (hours && rest ? " " : "") + (rest ? rest + " min" : "");
    return span + (diff > 0 ? " ahead of" : " behind") + " the address";
  }

  function canvasFingerprint() {
    const canvas = document.createElement("canvas");
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "";
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("WhatIsMyIP \u{1F310} fp", 2, 15);
    ctx.fillStyle = "rgba(102, 200, 0, 0.7)";
    ctx.fillText("WhatIsMyIP \u{1F310} fp", 4, 17);
    return canvas.toDataURL();
  }

  async function audioFingerprint() {
    const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OAC) return "";
    try {
      const ctx = new OAC(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50;
      comp.knee.value = 40;
      comp.ratio.value = 12;
      comp.attack.value = 0;
      comp.release.value = 0.25;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      const buffer = await ctx.startRendering();
      const data = buffer.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      return String(sum);
    } catch (_e) {
      return "";
    }
  }

  function webglParams(context) {
    if (!context) return "";
    const names = [
      "RED_BITS", "GREEN_BITS", "BLUE_BITS", "ALPHA_BITS", "DEPTH_BITS",
      "STENCIL_BITS", "MAX_RENDERBUFFER_SIZE", "MAX_TEXTURE_SIZE",
      "MAX_VERTEX_ATTRIBS", "MAX_VERTEX_UNIFORM_VECTORS", "MAX_VARYING_VECTORS",
      "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_TEXTURE_IMAGE_UNITS",
      "MAX_FRAGMENT_UNIFORM_VECTORS", "SHADING_LANGUAGE_VERSION", "VERSION",
    ];
    const values = names.map((name) => {
      try {
        return context.getParameter(context[name]);
      } catch (_e) {
        return "?";
      }
    });
    let exts = "";
    try {
      exts = (context.getSupportedExtensions() || []).sort().join(",");
    } catch (_e) {
      exts = "";
    }
    return values.join("|") + "|" + exts;
  }

  function detectFonts() {
    const baseFonts = ["monospace", "sans-serif", "serif"];
    const probe = "mmmmmmmmmmlli";
    const candidates = [
      "Arial", "Arial Black", "Arial Narrow", "Calibri", "Cambria",
      "Comic Sans MS", "Consolas", "Courier", "Courier New", "Georgia",
      "Helvetica", "Helvetica Neue", "Impact", "Lucida Console", "Lucida Grande",
      "Menlo", "Monaco", "Palatino", "Segoe UI", "Tahoma", "Times",
      "Times New Roman", "Trebuchet MS", "Verdana", "Andale Mono", "Geneva",
      "Gill Sans", "Optima", "Futura", "Baskerville", "American Typewriter",
      "Papyrus", "Noto Sans", "Roboto", "Ubuntu", "Cantarell", "DejaVu Sans",
      "Liberation Sans", "Droid Sans", "Fira Sans",
    ];
    const span = document.createElement("span");
    span.style.position = "absolute";
    span.style.left = "-9999px";
    span.style.top = "-9999px";
    span.style.fontSize = "72px";
    span.style.lineHeight = "normal";
    span.textContent = probe;
    document.body.appendChild(span);
    const baseline = {};
    for (const base of baseFonts) {
      span.style.fontFamily = base;
      baseline[base] = { w: span.offsetWidth, h: span.offsetHeight };
    }
    const detected = [];
    for (const font of candidates) {
      let matched = false;
      for (const base of baseFonts) {
        span.style.fontFamily = "'" + font + "'," + base;
        if (span.offsetWidth !== baseline[base].w || span.offsetHeight !== baseline[base].h) {
          matched = true;
          break;
        }
      }
      if (matched) detected.push(font);
    }
    document.body.removeChild(span);
    return detected;
  }

  async function hashString(str) {
    if (!str) return "";
    try {
      if (window.crypto && crypto.subtle) {
        const bytes = new TextEncoder().encode(str);
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
      }
    } catch (_e) {
      // fall through to the pure-JS hash
    }
    return cyrb53(str).toString(16);
  }

  // Non-cryptographic fallback for non-secure contexts (plain-HTTP LAN access),
  // where crypto.subtle is unavailable.
  function cyrb53(str, seed = 0) {
    let h1 = 0xdeadbeef ^ seed;
    let h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
  }

  function formatCount(n) {
    if (!isFinite(n)) return "∞";
    const units = [
      [1e18, "quintillion"], [1e15, "quadrillion"], [1e12, "trillion"],
      [1e9, "billion"], [1e6, "million"], [1e3, "thousand"],
    ];
    for (const [size, name] of units) {
      if (n >= size) return (n / size).toFixed(1).replace(/\.0$/, "") + " " + name;
    }
    return String(Math.round(n));
  }
})();
