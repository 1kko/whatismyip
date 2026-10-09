// Search, copy, and lazily booting the JSON tree. CSP forbids inline handlers,
// so everything is wired with addEventListener from this file. The error page
// loads it too, for its search box, and has none of the rest.

function normalizeLookupTarget(raw) {
  const target = raw
    .trim()
    .replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "")
    .split(/[/?#]/)[0];
  // A URL writes an IPv6 host in brackets, with any port after them.
  const bracketed = target.match(/^\[([^\]]*)\](?::\d*)?$/);
  return bracketed ? bracketed[1] : target;
}

const form = document.getElementById("lookup-form");
const input = document.getElementById("lookup-input");
const error = document.getElementById("lookup-error");
const status = document.getElementById("lookup-status");
const progress = document.getElementById("progress");

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

// The server bans a request whose path matches a probe pattern and whose target
// has no public suffix, so the search box must not navigate to one. DOMAIN below
// is happy with "admin.php" — one label, a dot, three letters — and submitting
// it would earn the visitor a 24 hour ban from this page's own form. These are
// the extensions in the server's detector that also pass DOMAIN; the rest of it
// (dotfiles, /wp-, nested paths) can't be produced by a single-segment target.
const PROBE_SUFFIX = /\.(php|aspx?|json|xml|sql|bak|conf|config|ini|log)$/i;

// An IPv6 address as the URL parser writes it (lower case, the longest run of
// zero groups as "::"), or null when `value` is not one. The parser accepts
// the same forms the server's ipaddress does; the character check in front
// keeps it to a bare address, so "x]@[::1" is not the "::1" inside it, and a
// zone ("fe80::1%eth0") names an interface on this machine, not an address.
function ipv6Host(value) {
  if (!value.includes(":") || !/^[0-9a-f:.]+$/i.test(value)) {
    return null;
  }
  try {
    return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

function isLookupTarget(value) {
  const octets = value.match(IPV4);
  if (octets) {
    return octets.slice(1).every((part) => Number(part) <= 255);
  }
  if (ipv6Host(value) !== null) {
    return true;
  }
  return DOMAIN.test(value) && !PROBE_SUFFIX.test(value);
}

// A router's address is the commonest thing typed in here, and the server
// refuses it with a 400. These are the ranges a home router, an office
// network, a VPN or this machine answers on: RFC 1918, loopback, link-local
// and CGNAT (100.64.0.0/10, carriers and Tailscale), and IPv6's loopback,
// link-local and unique local (fc00::/7). _LOCAL_NETWORKS in main.py is the
// same list, behind the error page's own explanation.
function isLocalAddress(value) {
  const host = ipv6Host(value);
  if (host !== null) {
    // The parser writes the first group out unless the address starts "::".
    const first = host.startsWith(":") ? 0 : parseInt(host, 16);
    return (
      host === "::1" ||
      (first & 0xffc0) === 0xfe80 ||
      (first & 0xfe00) === 0xfc00
    );
  }
  const octets = value.match(IPV4);
  if (!octets) {
    return false;
  }
  const [a, b] = octets.slice(1, 3).map(Number);
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function showError(message) {
  error.textContent = message;
  error.hidden = false;
  form.classList.add("is-invalid");
}

function clearError() {
  error.hidden = true;
  form.classList.remove("is-invalid");
}

// Answered here rather than by asking the server, which would only say no.
// The target is what the visitor typed, so it goes in as text, never markup.
function showLocalHint(target) {
  showError(
    `${target} is a local network address. On the internet you appear as your public IP: `,
  );
  const link = document.createElement("a");
  link.href = "/";
  link.textContent = "show it";
  error.appendChild(link);
}

// The lookup is a full page navigation and the server needs a second or two for
// WHOIS and DNS. Without this the page just sits there and looks broken.
function showPending(target) {
  form.classList.add("is-loading");
  input.readOnly = true;
  status.textContent = `Looking up ${target}…`;
  status.hidden = false;
  progress.classList.add("is-active");
}

function resetPending() {
  form.classList.remove("is-loading");
  input.readOnly = false;
  status.hidden = true;
  progress.classList.remove("is-active");
}

input.addEventListener("input", clearError);

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = normalizeLookupTarget(input.value);
  if (!target) {
    showError("Enter a domain or an IP address.");
    return;
  }
  if (!isLookupTarget(target)) {
    showError(`"${target}" is not a domain or an IP address.`);
    return;
  }
  if (isLocalAddress(target)) {
    showLocalHint(target);
    return;
  }
  clearError();
  showPending(target);
  window.location.assign("/" + encodeURIComponent(target));
});

// Coming back via the bfcache restores the DOM as it was — including the
// spinner — so the page would look like it is still loading.
window.addEventListener("pageshow", resetPending);

// Not from inside another text field (the subdomain filter), where "/" is
// something being typed.
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !event.target.closest?.("input, textarea")) {
    event.preventDefault();
    input.focus();
  }
});

// The resting label is read once, into data-label: a second click inside the
// 1.5 s window would otherwise capture "Copied" as the label to restore.
async function copyWithFeedback(button, text) {
  button.dataset.label ??= button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch (err) {
    button.textContent = "Copy failed";
  }
  setTimeout(() => {
    button.textContent = button.dataset.label;
  }, 1500);
}

for (const button of document.querySelectorAll(".copy-btn[data-value]")) {
  button.addEventListener("click", () => copyWithFeedback(button, button.dataset.value));
}

// JSONEditor is 200KB+; only pay for it if Raw JSON is actually opened.
const rawAccordion = document.getElementById("acc-raw");
let rawBooted = false;

rawAccordion?.addEventListener("toggle", () => {
  if (!rawAccordion.open || rawBooted) {
    return;
  }
  rawBooted = true;

  const styles = document.createElement("link");
  styles.rel = "stylesheet";
  styles.href = "/static/css/jsoneditor.css";
  document.head.appendChild(styles);

  const script = document.createElement("script");
  script.src = "/static/js/jsoneditor.min.js";
  script.addEventListener("load", () => {
    const editor = new JSONEditor(document.getElementById("raw-json"), {
      mode: "view",
      search: false,
      navigationBar: false,
      mainMenuBar: false,
      indentation: 2,
    });
    editor.set(JSON.parse(document.getElementById("page-data").textContent));
    editor.expandAll();
  });
  document.body.appendChild(script);
});

// Opening the accordion is the opt-in: nothing is requested until then, so an
// ordinary lookup never causes an outbound crt.sh fetch.
const subdomainAccordion = document.getElementById("acc-subdomains");
const subdomainSlot = document.getElementById("subdomains-slot");
const subdomainHint = document.getElementById("hint-subdomains");
let subdomainsBooted = false;

// The summary's hint starts as "click to lookup" and becomes the result once
// the fetch lands, so the lazy path ends up reading the same as the
// server-rendered one (see _accordions in viewmodel.py). A failed lookup must
// say so there too: leaving "click to lookup" next to an error would invite
// the reader to try again forever.
function setSubdomainHint(text) {
  if (subdomainHint) {
    subdomainHint.textContent = text;
  }
}

// The lookup loads up to 5,000 names (SUBDOMAIN_MAX_NAMES), far more links
// than anyone scrolls through, so at most this many are drawn. The filter and
// Copy all work on every loaded name, and the full list is a link away.
const SUBDOMAIN_RENDER_CAP = 100;

function filterSubdomains(names, query) {
  const needle = query.trim().toLowerCase();
  return needle ? names.filter((name) => name.includes(needle)) : names;
}

// Counts are grouped the English way to match the rest of the page's text,
// whatever the visitor's locale.
function formatCount(n) {
  return n.toLocaleString("en-US");
}

// fetched_at is UTC ISO 8601. "As of" means the visitor's own clock, so it is
// shown in their locale and time zone: undefined for both picks the browser's,
// and the tests pass fixed ones.
function subdomainNotes(data, locale, timeZone) {
  const notes = [];
  const fetched = data.fetched_at ? new Date(data.fetched_at) : null;
  if (fetched && !Number.isNaN(fetched.getTime())) {
    const when = fetched.toLocaleString(locale, {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone,
    });
    notes.push(`as of ${when}`);
  }
  if (data.stale) {
    notes.push("refreshing");
  }
  // names is crt.sh's answer cut at SUBDOMAIN_MAX_NAMES; count is how many
  // there were before the cut.
  if (data.truncated) {
    notes.push(`truncated at ${formatCount((data.names || []).length)}`);
  }
  return notes;
}

// Never empty, unlike the server's line, which only appears for a capped list:
// this is the live region's text, and the finished lookup is announced through
// it, so a list that fits still says "Showing 57 of 57." Unfiltered, the total
// is what crt.sh saw (data.count), which for a truncated list is more than was
// loaded; the notes line says where it was cut.
function subdomainCountText(shown, matched, total, filtering) {
  if (filtering) {
    if (!matched) {
      return "No names match the filter.";
    }
    const unit = matched === 1 ? "match" : "matches";
    return `Showing ${formatCount(shown)} of ${formatCount(matched)} ${unit}.`;
  }
  if (!total) {
    return "No subdomains found.";
  }
  return `Showing ${formatCount(shown)} of ${formatCount(total)}.`;
}

// The same wording _accordions in viewmodel.py renders on the server path.
function subdomainHintText(count) {
  return `${formatCount(count)} subdomain${count === 1 ? "" : "s"} found`;
}

function elapsedLabel(ms) {
  return `${Math.max(0, Math.floor(ms / 1000))}s`;
}

// ?subdomains=only answers JSON even to a browser navigation, so this opens
// the whole loaded list in the browser's own JSON viewer.
function fullListHref(target) {
  return `/${encodeURIComponent(target)}?subdomains=only`;
}

// The panel's live region: it announces the wait, the result, and each filter
// change. It must be in the document before anything is written to it; screen
// readers often skip a region that arrives already filled.
function subdomainStatusLine() {
  const line = document.createElement("p");
  line.className = "subdomains__meta";
  const status = document.createElement("span");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  line.appendChild(status);
  return line;
}

// Fills `body` with the notes, the filter, Copy all and the list, and keeps
// `line` (from subdomainStatusLine) saying how much of it is shown.
function renderSubdomainPanel(body, line, data, target) {
  const names = data.names || [];
  const status = line.querySelector('[role="status"]');
  body.textContent = "";

  const notes = subdomainNotes(data);
  if (notes.length) {
    const meta = document.createElement("p");
    meta.className = "subdomains__meta";
    meta.textContent = notes.join(" · ");
    body.appendChild(meta);
  }

  const filter = document.createElement("input");
  if (names.length) {
    const tools = document.createElement("div");
    tools.className = "subdomains__tools";
    filter.type = "search";
    filter.className = "subdomains__filter";
    filter.placeholder = "Filter";
    filter.spellcheck = false;
    filter.autocomplete = "off";
    filter.setAttribute("aria-label", "Filter subdomains");
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy-btn";
    copy.textContent = "Copy all";
    copy.title = "Copy every name that matches the filter, not only those shown";
    // Every loaded name that matches, one per line -- not the rendered rows,
    // which stop at SUBDOMAIN_RENDER_CAP.
    copy.addEventListener("click", () =>
      copyWithFeedback(copy, filterSubdomains(names, filter.value).join("\n")),
    );
    tools.append(filter, copy);
    body.appendChild(tools);
  }

  const list = document.createElement("ul");
  list.className = "subdomains__list";
  body.appendChild(list);

  if (names.length > SUBDOMAIN_RENDER_CAP) {
    const link = document.createElement("a");
    link.href = fullListHref(target);
    link.textContent = "Full list as JSON";
    line.append(" ", link);
  }

  const draw = () => {
    const matches = filterSubdomains(names, filter.value);
    const shown = matches.slice(0, SUBDOMAIN_RENDER_CAP);
    list.textContent = "";
    // textContent, never innerHTML: these names come from third-party
    // certificates and are not ours to trust as markup. The href is built
    // with encodeURIComponent for the same reason -- normalization already
    // restricts names to [a-z0-9._-], but nothing here should depend on
    // that rule staying narrow.
    for (const name of shown) {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = `/${encodeURIComponent(name)}`;
      link.textContent = name;
      item.appendChild(link);
      list.appendChild(item);
    }
    status.textContent = subdomainCountText(
      shown.length,
      matches.length,
      data.count ?? names.length,
      filter.value.trim() !== "",
    );
  };
  filter.addEventListener("input", draw);
  draw();
}

function subdomainFailed(line, message) {
  line.querySelector('[role="status"]').textContent = message;
  line.classList.add("subdomains__error");
  setSubdomainHint("lookup failed");
}

// ?subdomains=include draws the panel on the server, so it works without
// JavaScript. With it, the panel is rebuilt from the page's own data, which
// holds every loaded name, so it gets the same filter and Copy all as the lazy
// path below.
const renderedSubdomains = document.getElementById("subdomains-rendered");
const pageDataScript = document.getElementById("page-data");
if (renderedSubdomains && pageDataScript) {
  const data = JSON.parse(pageDataScript.textContent).subdomains;
  if (data && Array.isArray(data.names)) {
    const line = subdomainStatusLine();
    renderedSubdomains.after(line);
    renderSubdomainPanel(renderedSubdomains, line, data, renderedSubdomains.dataset.target);
  }
}

if (subdomainAccordion && subdomainSlot) {
  // Both made now, while the panel is still closed, so the live region exists
  // well before the lookup writes to it.
  const subdomainBody = document.createElement("div");
  const subdomainLine = subdomainStatusLine();
  subdomainSlot.append(subdomainBody, subdomainLine);

  subdomainAccordion.addEventListener("toggle", async () => {
    if (!subdomainAccordion.open || subdomainsBooted) {
      return;
    }
    subdomainsBooted = true;

    // crt.sh takes anywhere from 3 to 20 seconds, and a static loading line
    // looks hung by about the fifth. The counter is aria-hidden so the live
    // region announces the wait once, not once a second.
    const elapsed = document.createElement("span");
    elapsed.className = "subdomains__elapsed";
    elapsed.setAttribute("aria-hidden", "true");
    subdomainLine.querySelector('[role="status"]').textContent = "Querying crt.sh…";
    subdomainLine.appendChild(elapsed);
    subdomainBody.setAttribute("aria-busy", "true");
    setSubdomainHint("searching…");
    const started = Date.now();
    const tick = () => {
      elapsed.textContent = elapsedLabel(Date.now() - started);
    };
    tick();
    const timer = setInterval(tick, 1000);

    try {
      const target = subdomainSlot.dataset.target;
      const response = await fetch(
        `/${encodeURIComponent(target)}?subdomains=only`,
        { headers: { Accept: "application/json" } },
      );
      // A non-200 (429 rate limit, 403 ban, 400 when the feature is
      // disabled) must never be read as "no subdomains" -- and a payload
      // with no `subdomains` object is the same confident-falsehood risk,
      // so both bail out with an explicit failure rather than falling
      // through to an empty {} that renders "undefined found".
      if (!response.ok) {
        subdomainFailed(subdomainLine, "Lookup failed.");
        return;
      }
      const payload = await response.json();
      const data = payload.subdomains;
      if (!data) {
        subdomainFailed(subdomainLine, "Lookup failed.");
        return;
      }

      if (data.error) {
        subdomainFailed(subdomainLine, `Lookup failed: ${data.error}`);
        return;
      }

      setSubdomainHint(subdomainHintText(data.count));
      renderSubdomainPanel(subdomainBody, subdomainLine, data, target);
    } catch (err) {
      subdomainFailed(subdomainLine, "Lookup failed.");
    } finally {
      // Every way out -- a result, an error response, a network failure, an
      // aborted fetch -- stops the counter and lifts the busy state.
      clearInterval(timer);
      elapsed.remove();
      subdomainBody.removeAttribute("aria-busy");
    }
  });
}
