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

function isLookupTarget(value) {
  const octets = value.match(IPV4);
  if (octets) {
    return octets.slice(1).every((part) => Number(part) <= 255);
  }
  return DOMAIN.test(value);
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
