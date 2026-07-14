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

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = normalizeLookupTarget(input.value);
  if (target) {
    window.location.assign("/" + encodeURIComponent(target));
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "/" && document.activeElement !== input) {
    event.preventDefault();
    input.focus();
  }
});

const copyButton = document.getElementById("copy-target");
copyButton.addEventListener("click", async () => {
  await navigator.clipboard.writeText(copyButton.dataset.value);
  const original = copyButton.textContent;
  copyButton.textContent = "Copied";
  setTimeout(() => {
    copyButton.textContent = original;
  }, 1500);
});

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
