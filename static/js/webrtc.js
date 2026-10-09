// The WebRTC leak test in the self page's Fingerprint panel. On a click, and
// only then, it asks one STUN server which public address this browser's
// WebRTC traffic leaves from, and compares that with the address the page was
// served to. Both are already in this page and the comparison stays in it:
// nothing here sends anything to this site's server. That is this file's
// rule, not the CSP's (default-src 'self' would allow a same-origin fetch).
//
// The comparison is plain functions, run in node by tests/test_webrtc_leak.py;
// the DOM wiring after them only runs in a page.
(function () {
  "use strict";

  const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

  // One ICE candidate, as RTCIceCandidate.candidate or an SDP "a=" line:
  //   candidate:<foundation> <component> <transport> <priority> <address> <port> typ <type> ...
  // Read from the text because RTCIceCandidate's own .address and .type are
  // missing from older browsers.
  function parseCandidate(line) {
    const fields = String(line || "").replace(/^a=/, "").trim().split(/\s+/);
    if (fields.length < 8 || !fields[0].startsWith("candidate:") || fields[6] !== "typ") {
      return null;
    }
    return { address: fields[4], type: fields[7] };
  }

  // {family, key} for an IP literal, where every spelling of one address has
  // the same key ("2001:DB8::7" and "2001:db8:0:0:0:0:0:7"); null for anything
  // else, such as the mDNS name a browser puts in a host candidate.
  function canonicalAddress(text) {
    const value = String(text || "").trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
    const octets = value.match(IPV4);
    if (octets) {
      const parts = octets.slice(1).map(Number);
      return parts.every((n) => n <= 255) ? { family: 4, key: parts.join(".") } : null;
    }
    // A dual-stack socket reports an IPv4 client as ::ffff:a.b.c.d.
    const mapped = value.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) {
      return canonicalAddress(mapped[1]);
    }
    if (!/^[0-9a-f:]+$/.test(value)) {
      return null;
    }
    const halves = value.split("::");
    if (halves.length > 2) {
      return null;
    }
    const head = halves[0] ? halves[0].split(":") : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const gap = 8 - head.length - tail.length;
    if (halves.length === 2 ? gap < 1 : gap !== 0) {
      return null;
    }
    const groups = [...head, ...Array(halves.length === 2 ? gap : 0).fill("0"), ...tail];
    if (!groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) {
      return null;
    }
    return { family: 6, key: groups.map((group) => parseInt(group, 16).toString(16)).join(":") };
  }

  // `observed` is the address this page was served to; `lines` every
  // candidate the browser gathered. Only server-reflexive (srflx) candidates
  // count: each is the address the STUN server saw, which is what any site
  // can learn this way. Host candidates are mDNS names in current browsers, or
  // a LAN address, and with no TURN server configured there are no relays.
  //
  // Each address family is judged on its own. A dual-stack visitor reaches
  // the page over one family while WebRTC shows both, and the other family's
  // address has nothing to be compared with: "unverifiable", not a leak.
  function compare(observed, lines) {
    const page = canonicalAddress(observed);
    const exposed = { 4: new Map(), 6: new Map() };
    for (const line of lines) {
      const candidate = parseCandidate(line);
      if (!candidate || candidate.type !== "srflx") {
        continue;
      }
      const address = canonicalAddress(candidate.address);
      if (address && !exposed[address.family].has(address.key)) {
        exposed[address.family].set(address.key, candidate.address);
      }
    }
    const families = [4, 6].map((family) => {
      const seen = page && page.family === family ? page : null;
      const keys = [...exposed[family].keys()];
      let verdict = "none";
      if (keys.length && !seen) {
        verdict = "unverifiable";
      } else if (keys.length) {
        verdict = keys.every((key) => key === seen.key) ? "same" : "different";
      }
      return {
        family,
        page: seen ? observed : null,
        webrtc: [...exposed[family].values()],
        verdict,
      };
    });
    return { overall: overall(families.map((f) => f.verdict)), families };
  }

  // "nothing" is "could not check", never "no leak": a WebRTC-blocking
  // extension and a network that drops UDP look the same from here.
  function overall(verdicts) {
    if (verdicts.includes("different")) {
      return "leak";
    }
    if (verdicts.every((verdict) => verdict === "none")) {
      return "nothing";
    }
    if (!verdicts.includes("same")) {
      return "uncompared";
    }
    return verdicts.includes("unverifiable") ? "partial" : "clean";
  }

  if (typeof module === "object" && module.exports) {
    module.exports = { parseCandidate, canonicalAddress, compare };
  }
  if (typeof document === "undefined") {
    return;
  }

  const root = document.getElementById("webrtc");
  const button = document.getElementById("webrtc-run");
  const verdict = document.getElementById("webrtc-verdict");
  const results = document.getElementById("webrtc-results");
  const rows = document.getElementById("webrtc-rows");
  if (!root || !button) {
    return; // a lookup page, or the test is turned off
  }

  // A STUN answer takes one round trip. A server that has not answered in
  // this long is treated as not answering, and whatever came back is judged.
  const GATHER_TIMEOUT_MS = 5000;
  // The end of gathering cannot be waited for: Chrome 153 on macOS, measured,
  // had its srflx after ~100 ms and still had not finished 15 s later, because
  // the STUN request on a socket with no route out is retried for that long.
  // Every interface asks at the same moment, so once one answer is in, the
  // others are a round trip behind it at most.
  const SETTLE_MS = 1500;

  button.addEventListener("click", run);

  async function run() {
    button.disabled = true;
    results.hidden = true;
    say("Asking the STUN server…", "muted");
    try {
      const PeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      if (!PeerConnection) {
        say("This browser has no WebRTC, so no address can leak through it.", "success");
        return;
      }
      show(compare(root.dataset.observed, await gather(PeerConnection, root.dataset.stun)));
    } catch (err) {
      say(`The test could not run: ${(err && err.message) || err}.`, "warning");
    } finally {
      button.disabled = false;
      button.textContent = "Run again";
    }
  }

  // Every candidate line the browser produces for a local offer, until
  // gathering completes, the first srflx has had SETTLE_MS for company, or
  // the timeout passes. The offer goes nowhere: there is no peer, and the
  // connection is closed as soon as gathering stops.
  function gather(PeerConnection, stunUrl) {
    return new Promise((resolve, reject) => {
      const pc = new PeerConnection({ iceServers: [{ urls: stunUrl }] });
      const lines = [];
      let finished = false;
      let settle = null;
      const finish = (error) => {
        if (finished) {
          return;
        }
        finished = true;
        clearTimeout(timer);
        clearTimeout(settle);
        // Some browsers list a candidate only in the final SDP.
        const sdp = (pc.localDescription && pc.localDescription.sdp) || "";
        lines.push(...sdp.split(/\r?\n/).filter((line) => line.startsWith("a=candidate:")));
        pc.close();
        if (error) {
          reject(error);
        } else {
          resolve(lines);
        }
      };
      const timer = setTimeout(() => finish(), GATHER_TIMEOUT_MS);
      pc.addEventListener("icecandidate", (event) => {
        if (!event.candidate) {
          finish(); // gathering is complete
        } else if (event.candidate.candidate) {
          lines.push(event.candidate.candidate);
          const candidate = parseCandidate(event.candidate.candidate);
          if (!settle && candidate && candidate.type === "srflx") {
            settle = setTimeout(() => finish(), SETTLE_MS);
          }
        }
      });
      pc.addEventListener("icegatheringstatechange", () => {
        if (pc.iceGatheringState === "complete") {
          finish();
        }
      });
      pc.createDataChannel("webrtc-leak-test");
      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(finish);
    });
  }

  function show(result) {
    const observed = root.dataset.observed;
    const page = canonicalAddress(observed);
    const pageFamily = page && page.family;
    const otherFamily = pageFamily === 6 ? 4 : 6;
    const table = [row("This page saw", observed, "default")];
    for (const family of result.families) {
      const label = `WebRTC IPv${family.family}`;
      if (!family.webrtc.length) {
        table.push(row(label, "none came back", "muted"));
      }
      for (const address of family.webrtc) {
        if (family.verdict === "unverifiable") {
          const why = pageFamily ? `this page saw you over IPv${pageFamily}` : "nothing to compare";
          table.push(row(label, `${address} — not compared: ${why}`, "warning"));
        } else if (canonicalAddress(address).key === page.key) {
          table.push(row(label, `${address} — same as this page`, "success"));
        } else {
          table.push(row(label, `${address} — not the address this page saw`, "danger"));
        }
      }
    }
    rows.replaceChildren(...table);
    results.hidden = false;

    const check = `On a VPN, make sure that address is the VPN's.`;
    switch (result.overall) {
      case "leak":
        say(
          "Leak: WebRTC reveals an address this page did not see, and any site can read it the same way.",
          "danger",
        );
        break;
      case "clean":
        say("No leak: WebRTC shows only the address this page saw.", "success");
        break;
      case "partial":
        say(
          `No leak over IPv${pageFamily}. WebRTC also shows an IPv${otherFamily} address, ` +
            `which this page cannot check: it reached you over IPv${pageFamily} only. ${check}`,
          "warning",
        );
        break;
      case "uncompared":
        say(
          pageFamily
            ? `Not compared: WebRTC shows only an IPv${otherFamily} address, and this page ` +
                `reached you over IPv${pageFamily}. ${check}`
            : `Not compared: this page has no address of yours to compare with. ${check}`,
          "warning",
        );
        break;
      default:
        say(
          "No public address came back from the STUN server. WebRTC may be blocked by the " +
            "browser, an extension or the network, and this test cannot tell which.",
          "muted",
        );
    }
  }

  function row(label, text, tone) {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = label;
    const value = document.createElement("td");
    value.colSpan = 3;
    value.className = `tone-${tone}`;
    value.textContent = text;
    tr.append(name, value);
    return tr;
  }

  function say(text, tone) {
    verdict.textContent = text;
    verdict.className = `webrtc__verdict tone-${tone}`;
  }
})();
