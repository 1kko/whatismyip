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
  // bottom is still below the view; null when there is none. At the end of the
  // page a short last section never reaches the line, so it is the last one.
  function currentSection(sections, viewTop, atBottom = false) {
    if (atBottom && sections.length > 0) {
      return sections[sections.length - 1].id;
    }
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

  // True at the end of a page that can scroll; a page that fits the window
  // has no end to reach, so the first-section rule applies there.
  function isAtBottom(scrollY, innerHeight, scrollHeight) {
    return scrollHeight > innerHeight && scrollY + innerHeight >= scrollHeight - 2;
  }

  if (typeof module === "object" && module.exports) {
    module.exports = { currentSection, isAtBottom };
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
    const atBottom = isAtBottom(
      window.scrollY,
      window.innerHeight,
      document.documentElement.scrollHeight,
    );
    const id = currentSection(rects, LINE, atBottom);
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
