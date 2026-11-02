// The contents list on a lookup page: marks the section in view with
// aria-current="true". Sections are read from the DOM and compared by
// position; nothing here fetches or sends anything.
//
// currentSection is a plain function, run in node by tests/test_contents_js.py;
// the DOM wiring after it only runs in a page.
(function () {
  "use strict";

  // The last section whose top is at or above the line one pixel under the
  // view's top; before any section has reached it, the first section whose
  // bottom is still below the view; null when there is none.
  function currentSection(sections, viewTop) {
    let current = null;
    for (const s of sections) {
      if (s.top <= viewTop + 1) {
        current = s.id;
      }
    }
    if (current !== null) {
      return current;
    }
    for (const s of sections) {
      if (s.bottom > viewTop) {
        return s.id;
      }
    }
    return null;
  }

  if (typeof module === "object" && module.exports) {
    module.exports = { currentSection };
  }
  if (typeof document === "undefined") {
    return;
  }

  const toc = document.querySelector(".toc");
  const sections = Array.from(document.querySelectorAll(".report-section"));
  if (!toc || sections.length === 0) {
    return;
  }
  const items = Array.from(toc.querySelectorAll(".toc__item[data-section]"));
  // Under 900px the sticky chip row covers the top of the page.
  const LINE = 80;
  let shown = null;

  function update() {
    const rects = sections.map((el) => {
      const r = el.getBoundingClientRect();
      return { id: el.id.replace(/^sec-/, ""), top: r.top, bottom: r.bottom };
    });
    const id = currentSection(rects, LINE);
    if (id === shown) {
      return;
    }
    shown = id;
    let active = null;
    for (const item of items) {
      if (item.dataset.section === id) {
        item.setAttribute("aria-current", "true");
        active = item;
      } else {
        item.removeAttribute("aria-current");
      }
    }
    // Only the chip row scrolls sideways; never the page-scrolling call, which would
    // move the page. In the desktop column this is a no-op (nothing overflows).
    if (active && toc.scrollWidth > toc.clientWidth) {
      const left = active.offsetLeft - toc.offsetLeft;
      const right = left + active.offsetWidth;
      if (left < toc.scrollLeft) {
        toc.scrollLeft = left - 20;
      } else if (right > toc.scrollLeft + toc.clientWidth) {
        toc.scrollLeft = right - toc.clientWidth + 20;
      }
    }
  }

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(update, { threshold: [0, 1] });
    sections.forEach((el) => observer.observe(el));
  }
  window.addEventListener("scroll", update, { passive: true });
  window.addEventListener("resize", update);
  update();
})();
