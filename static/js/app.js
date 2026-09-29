// Search, copy, and lazily booting the JSON tree. CSP forbids inline handlers,
// so everything is wired with addEventListener from this file.
const pageData = JSON.parse(document.getElementById("page-data").textContent);

function normalizeLookupTarget(raw) {
  return raw
    .trim()
    .replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "")
    .split(/[/?#]/)[0];
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

function isLookupTarget(value) {
  const octets = value.match(IPV4);
  if (octets) {
    return octets.slice(1).every((part) => Number(part) <= 255);
  }
  return DOMAIN.test(value) && !PROBE_SUFFIX.test(value);
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
  clearError();
  showPending(target);
  window.location.assign("/" + encodeURIComponent(target));
});

// Coming back via the bfcache restores the DOM as it was — including the
// spinner — so the page would look like it is still loading.
window.addEventListener("pageshow", resetPending);

document.addEventListener("keydown", (event) => {
  if (event.key === "/" && document.activeElement !== input) {
    event.preventDefault();
    input.focus();
  }
});

for (const button of document.querySelectorAll(".copy-btn[data-value]")) {
  button.addEventListener("click", async () => {
    await navigator.clipboard.writeText(button.dataset.value);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = original;
    }, 1500);
  });
}

// JSONEditor is 200KB+; only pay for it if Raw JSON is actually opened.
const rawAccordion = document.getElementById("acc-raw");
let rawBooted = false;

rawAccordion.addEventListener("toggle", () => {
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
    editor.set(pageData);
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

function subdomainFailed(message) {
  subdomainSlot.textContent = message;
  setSubdomainHint("lookup failed");
}

if (subdomainAccordion && subdomainSlot) {
  subdomainAccordion.addEventListener("toggle", async () => {
    if (!subdomainAccordion.open || subdomainsBooted) {
      return;
    }
    subdomainsBooted = true;
    subdomainSlot.textContent = "Loading…";

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
        subdomainFailed("Lookup failed.");
        return;
      }
      const payload = await response.json();
      const data = payload.subdomains;
      if (!data) {
        subdomainFailed("Lookup failed.");
        return;
      }

      if (data.error) {
        subdomainFailed(`Lookup failed: ${data.error}`);
        return;
      }

      const names = data.names || [];
      const shown = names.slice(0, 100);
      subdomainSlot.textContent = "";
      setSubdomainHint(
        `${data.count} subdomain${data.count === 1 ? "" : "s"} found`,
      );

      // The count lives in the summary hint (set above), so this line carries
      // only what the hint cannot -- currently just the refreshing state.
      if (data.stale) {
        const meta = document.createElement("p");
        meta.className = "subdomains__meta";
        meta.textContent = "refreshing";
        subdomainSlot.appendChild(meta);
      }

      const list = document.createElement("ul");
      list.className = "subdomains__list";
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
      subdomainSlot.appendChild(list);

      if (names.length > shown.length) {
        const more = document.createElement("p");
        more.className = "subdomains__meta";
        more.textContent =
          `Showing ${shown.length} of ${data.count}. The full list is in the JSON response.`;
        subdomainSlot.appendChild(more);
      }
    } catch (err) {
      subdomainFailed("Lookup failed.");
    }
  });
}
