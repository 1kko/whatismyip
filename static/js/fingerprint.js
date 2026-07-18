// Client-side browser fingerprint for the self page. Everything is computed
// here and shown here — nothing is sent to the server (CSP forbids it anyway).
// No dependencies, no storage. Mirrors the map.js pattern: server renders empty
// placeholders, this paints them. Two phases so the first frame is never blocked.
(function () {
  const panel = document.getElementById("acc-fingerprint");
  if (!panel) return; // lookup page, or not the self view — do nothing.

  const DASH = "—";
  const tbody = document.getElementById("fp-signals");

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

  // ---- Phase 1: passive signals (synchronous) ----------------------------
  const nav = navigator;

  add("Languages", safe(() => (nav.languages || [nav.language]).join(", ")), 3);
  add("Time zone", safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone), 3);
  const offset = safe(() => -new Date().getTimezoneOffset());
  add("UTC offset", offset != null ? (offset >= 0 ? "+" : "") + offset + " min" : null, 0, false);

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

  // ---- Phase 2: active entropy (deferred, never blocks first paint) ------
  const idle = window.requestIdleCallback || ((cb) => setTimeout(cb, 1));
  idle(async () => {
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
      setText("fp-acc-hint", signals.length + " signals · ≈ " + bits + " bits");
    } catch (_e) {
      // Phase 1 already painted; a phase-2 failure just leaves the ID blank.
      setText("fp-hash", DASH);
    }
  });

  // ---- helpers -----------------------------------------------------------
  function renderSignals() {
    if (!tbody) return;
    tbody.textContent = "";
    for (const s of signals) {
      const tr = document.createElement("tr");
      const label = document.createElement("td");
      label.textContent = s.label;
      const value = document.createElement("td");
      value.colSpan = 3;
      value.textContent = s.value;
      tr.append(label, value);
      tbody.append(tr);
    }
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
