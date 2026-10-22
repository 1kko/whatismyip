/* The /AS<n> page's controls: relation chips, filters, "Show all" and the
 * prefix table's family switch and /8 grouping.
 *
 * The server already draws the first rows and every control (each `hidden`),
 * so the page reads without this file. This reveals the controls and redraws
 * the two tables from #as-lists, the compact copy of everything the server
 * loaded. A row drawn here must equal the one viewmodel.as_neighbour_table /
 * as_prefix_table gives the template, cell for cell (tests/test_as_page_js.py
 * compares them), so the formulas below repeat the server's.
 *
 * Text goes in with textContent and nodes with createElement only: an AS name
 * is third-party text and the CSP allows no inline script.
 */
"use strict";

var ROWS_SHOWN = 10;

/* ---- pure helpers (exported for node) ---------------------------------- */

/* viewmodel.human_count: 999, 1.0k, 131k, 8.7M, 29M. */
function humanCount(n) {
  if (n < 1000) return String(n);
  var t;
  if (n < 999500) {
    t = Math.floor((n + 50) / 100);
    return t < 100
      ? Math.floor(t / 10) + "." + (t % 10) + "k"
      : Math.floor((n + 500) / 1000) + "k";
  }
  t = Math.floor((n + 50000) / 100000);
  return t < 100
    ? Math.floor(t / 10) + "." + (t % 10) + "M"
    : Math.floor((n + 500000) / 1000000) + "M";
}

/* viewmodel.as_holder: RIPE's "HANDLE - Holder" or "HANDLE Holder"; a single
 * word is its own holder; "" for no name. */
function holderOf(name) {
  name = (name || "").trim();
  if (!name) return "";
  var handle, holder, at;
  if ((at = name.indexOf(" - ")) !== -1) {
    handle = name.slice(0, at);
    holder = name.slice(at + 3);
  } else if ((at = name.indexOf(" ")) !== -1) {
    handle = name.slice(0, at);
    holder = name.slice(at + 1);
  } else {
    return name;
  }
  return holder.trim() || handle.trim();
}

/* viewmodel.country_flag: two regional-indicator letters, or "". */
function countryFlag(code) {
  code = (code || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return String.fromCodePoint(
    0x1f1e6 + code.charCodeAt(0) - 65,
    0x1f1e6 + code.charCodeAt(1) - 65
  );
}

function thousands(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/* neighbour rows are [asn, name, country, relation, customers, v4_addresses]. */
function filterNeighbours(rows, relation, needle) {
  needle = (needle || "").trim().toLowerCase();
  return rows.filter(function (row) {
    if (relation && relation !== "all" && row[3] !== relation) return false;
    if (!needle) return true;
    return [
      "as" + row[0],
      String(row[0]),
      String(row[1] || "").toLowerCase(),
      String(row[2] || "").toLowerCase(),
    ].some(function (text) {
      return text.indexOf(needle) !== -1;
    });
  });
}

/* An address as a BigInt and its family, or null. */
function parseAddress(text) {
  text = (text || "").trim();
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (m) {
    var value = 0n;
    for (var i = 1; i <= 4; i++) {
      if (Number(m[i]) > 255) return null;
      value = (value << 8n) | BigInt(m[i]);
    }
    return { family: 4, value: value };
  }
  if (text.indexOf(":") === -1 || !/^[0-9a-fA-F:]+$/.test(text)) return null;
  var halves = text.split("::");
  if (halves.length > 2) return null;
  var head = halves[0] ? halves[0].split(":") : [];
  var tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  var groups;
  if (halves.length === 2) {
    var gap = 8 - head.length - tail.length;
    if (gap < 1) return null;
    groups = head.concat(new Array(gap).fill("0"), tail);
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  var v6 = 0n;
  for (var j = 0; j < 8; j++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[j])) return null;
    v6 = (v6 << 16n) | BigInt("0x" + groups[j]);
  }
  return { family: 6, value: v6 };
}

/* [start, end] of a CIDR prefix as BigInts, with its family, or null. */
function prefixRange(prefix) {
  var parts = String(prefix).split("/");
  var base = parseAddress(parts[0]);
  if (!base || parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) return null;
  var bits = base.family === 4 ? 32 : 128;
  var plen = Number(parts[1]);
  if (plen > bits) return null;
  var span = (1n << BigInt(bits - plen)) - 1n;
  var start = base.value & ~span;
  return { family: base.family, start: start, end: start | span };
}

function containsAddress(prefix, needle) {
  var range = prefixRange(prefix);
  var address = parseAddress(needle);
  if (!range || !address || range.family !== address.family) return false;
  return address.value >= range.start && address.value <= range.end;
}

/* prefix rows are [prefix, plen, ris_peers, state, reason]. */
function filterPrefixes(rows, needle) {
  needle = (needle || "").trim().toLowerCase();
  if (!needle) return rows.slice();
  return rows.filter(function (row) {
    return row[0].toLowerCase().indexOf(needle) !== -1 || containsAddress(row[0], needle);
  });
}

function slash8Of(prefix) {
  return Number(String(prefix).split(".")[0]);
}

/* One entry per /8 of the IPv4 rows, ascending. `addresses` counts every
 * address once: a prefix inside one already counted adds nothing. `signed` is
 * valid plus invalid, as the server's RPKI share. */
function groupBySlash8(rows) {
  var groups = {};
  rows.forEach(function (row) {
    var octet = slash8Of(row[0]);
    (groups[octet] = groups[octet] || []).push(row);
  });
  return Object.keys(groups)
    .map(Number)
    .sort(function (a, b) {
      return a - b;
    })
    .map(function (octet) {
      var members = groups[octet]
        .map(function (row) {
          return { range: prefixRange(row[0]), row: row };
        })
        .sort(function (a, b) {
          return a.range.start < b.range.start ? -1 : a.range.start > b.range.start ? 1 : 0;
        });
      var addresses = 0;
      var lastEnd = -1n;
      var signed = 0;
      members.forEach(function (member) {
        if (member.row[3] === "valid" || member.row[3] === "invalid") signed += 1;
        if (member.range.start <= lastEnd) return;
        addresses += Number(member.range.end - member.range.start + 1n);
        lastEnd = member.range.end;
      });
      return { slash8: octet + ".0.0.0/8", count: members.length, addresses: addresses, signed: signed };
    });
}

function visibleRows(rows, showAll, limit) {
  return showAll ? rows : rows.slice(0, limit === undefined ? ROWS_SHOWN : limit);
}

/* ---- rows: the server's markup, built node by node --------------------- */

function el(tag, className, text) {
  var node = document.createElement(tag);
  if (className) node.setAttribute("class", className);
  if (text !== undefined) node.textContent = text;
  return node;
}

function barCell(pct, text) {
  var cell = el("td");
  var wrap = el("span", "size-cell");
  var bar = el("span", "size-bar");
  bar.setAttribute("aria-hidden", "true");
  var fill = el("i");
  fill.setAttribute("style", "width:" + pct + "%");
  bar.appendChild(fill);
  wrap.appendChild(bar);
  wrap.appendChild(el("span", "mono", text));
  cell.appendChild(wrap);
  return cell;
}

function asLink(asn) {
  var link = el("a", "lookup-link", "AS" + asn);
  link.setAttribute("href", "/AS" + asn);
  link.setAttribute("rel", "nofollow");
  return link;
}

function neighbourRow(row, maxCustomers) {
  var customers = row[4];
  var space = row[5];
  var tr = el("tr");
  var asn = el("td", "mono");
  asn.appendChild(asLink(row[0]));
  tr.appendChild(asn);
  tr.appendChild(el("td", "as-table__holder", holderOf(row[1])));
  var country = el("td", "as-table__country");
  var flag = countryFlag(row[2]);
  if (flag) {
    var badge = el("span", "as-flag", flag);
    badge.setAttribute("title", row[2]);
    country.appendChild(badge);
    country.appendChild(document.createTextNode(" "));
  }
  country.appendChild(el("span", "as-cc", row[2] || "—"));
  tr.appendChild(country);
  var relation = el("td");
  relation.appendChild(el("span", "relation relation--" + row[3], row[3]));
  tr.appendChild(relation);
  var pct = maxCustomers
    ? (
        Math.round(
          (100 * Math.log10((customers || 0) + 1) * 10) / Math.log10(maxCustomers + 1)
        ) / 10
      ).toFixed(1)
    : "0"; // the server's int 0 when nobody has customers
  tr.appendChild(
    barCell(pct, customers !== null && customers !== undefined ? thousands(customers) : "—")
  );
  tr.appendChild(
    el(
      "td",
      "as-col-space mono",
      space !== null && space !== undefined ? humanCount(space) : "—"
    )
  );
  return tr;
}

var RPKI_TEXT = { valid: "Valid", invalid: "Invalid", "not-found": "Not found", not_found: "Not found" };
var RPKI_TONE = { valid: "success", invalid: "warning" };

/* log2 of a prefix's size: addresses for IPv4, /48s for IPv6 (0 past /48). */
function exponentOf(plen, family) {
  return Math.max((family === "v4" ? 32 : 48) - (plen || 0), 0);
}

function sizeText(plen, family) {
  var exponent = exponentOf(plen, family);
  if (family === "v4") return humanCount(Math.pow(2, exponent));
  if ((plen || 0) > 48) return "under a /48";
  return humanCount(Math.pow(2, exponent)) + " /48s";
}

/* The widest prefix in `rows`, the 100% of the size bars. */
function topSize(rows, family) {
  var top = 1;
  rows.forEach(function (row) {
    top = Math.max(top, Math.pow(2, exponentOf(row[1], family)));
  });
  return top;
}

function prefixRow(row, family, top) {
  var state = row[3];
  var text = Object.prototype.hasOwnProperty.call(RPKI_TEXT, state) ? RPKI_TEXT[state] : "Unknown";
  if (state === "invalid" && row[4]) text += ": " + row[4];
  var tone = Object.prototype.hasOwnProperty.call(RPKI_TONE, state)
    ? RPKI_TONE[state]
    : state
      ? "default"
      : "muted";
  var size = Math.pow(2, exponentOf(row[1], family));
  var pct = (Math.round((100 * Math.log2(size + 1) * 10) / Math.log2(top + 1)) / 10).toFixed(1);
  var tr = el("tr");
  tr.appendChild(el("td", "mono", row[0]));
  tr.appendChild(barCell(pct, sizeText(row[1], family)));
  tr.appendChild(
    el("td", "mono", typeof row[2] === "number" ? thousands(row[2]) : "—")
  );
  tr.appendChild(el("td", "tone-" + tone, text));
  return tr;
}

function messageRow(columns, text) {
  var tr = el("tr");
  var td = el("td", "tone-muted", text);
  td.setAttribute("colspan", String(columns));
  tr.appendChild(td);
  return tr;
}

/* ---- the page ---------------------------------------------------------- */

function replaceChildren(node, children) {
  while (node.firstChild) node.removeChild(node.firstChild);
  children.forEach(function (child) {
    node.appendChild(child);
  });
}

function reveal(nodes) {
  Array.prototype.forEach.call(nodes, function (node) {
    node.hidden = false;
  });
}

function setPressed(buttons, isPressed) {
  Array.prototype.forEach.call(buttons, function (button) {
    button.setAttribute("aria-pressed", isPressed(button) ? "true" : "false");
  });
}

/* "Show all N" appears only past the first rows; N counts what matches. */
function syncMore(button, total, expanded, noun) {
  button.hidden = total <= ROWS_SHOWN;
  button.textContent = expanded ? "Show fewer" : "Show all " + thousands(total) + " " + noun;
}

function wireNeighbours(lists) {
  var tbody = document.getElementById("neighbour-rows");
  var more = document.getElementById("neighbours-more");
  var filter = document.getElementById("neighbour-filter");
  var chips = document.querySelectorAll("button.chip[data-relation]");
  if (!tbody || !more || !filter || !lists.neighbours) return;
  var data = lists.neighbours;
  var state = { relation: "all", showAll: false };

  function draw() {
    var matching = filterNeighbours(data.rows, state.relation, filter.value);
    var rows = visibleRows(matching, state.showAll).map(function (row) {
      return neighbourRow(row, data.max_customers);
    });
    if (!rows.length) rows = [messageRow(6, "No neighbours match the filter.")];
    replaceChildren(tbody, rows);
    syncMore(more, matching.length, state.showAll, "neighbours");
  }

  function select(relation) {
    state.relation = relation;
    state.showAll = false;
    setPressed(chips, function (chip) {
      return chip.getAttribute("data-relation") === relation;
    });
    draw();
  }

  reveal(chips);
  filter.hidden = false;
  Array.prototype.forEach.call(chips, function (chip) {
    chip.addEventListener("click", function () {
      select(chip.getAttribute("data-relation"));
    });
  });
  filter.addEventListener("input", function () {
    state.showAll = false;
    draw();
  });
  more.addEventListener("click", function () {
    state.showAll = !state.showAll;
    draw();
  });
  syncMore(more, data.rows.length, false, "neighbours");

  // The graph's "+N more" is a plain anchor to the table; it also picks the
  // chip, since the graph shows only upstreams.
  var jump = document.querySelector("a.as-graph__more[data-relation]");
  if (jump) {
    jump.addEventListener("click", function () {
      select(jump.getAttribute("data-relation"));
    });
  }
}

function groupDetails(group, rows, family, top, biggest) {
  var details = el("details", "as-group");
  var summary = el("summary", "as-group__summary");
  summary.appendChild(el("span", "mono", group.slash8));
  summary.appendChild(el("span", "tone-muted", group.count + (group.count === 1 ? " prefix" : " prefixes")));
  var bar = el("span", "size-bar");
  bar.setAttribute("aria-hidden", "true");
  var fill = el("i");
  var pct = (Math.round((100 * Math.log2(group.addresses + 1) * 10) / Math.log2(biggest + 1)) / 10).toFixed(1);
  fill.setAttribute("style", "width:" + pct + "%");
  bar.appendChild(fill);
  summary.appendChild(bar);
  summary.appendChild(el("span", "mono", humanCount(group.addresses)));
  summary.appendChild(el("span", "tone-muted", thousands(group.signed) + " signed"));
  details.appendChild(summary);
  var table = el("table", "as-table as-table--prefixes");
  var body = el("tbody");
  replaceChildren(
    body,
    rows
      .filter(function (row) {
        return group.slash8 === slash8Of(row[0]) + ".0.0.0/8";
      })
      .map(function (row) {
        return prefixRow(row, family, top);
      })
  );
  table.appendChild(body);
  details.appendChild(table);
  return details;
}

function wirePrefixes(lists) {
  var tbody = document.getElementById("prefix-rows");
  var more = document.getElementById("prefixes-more");
  var filter = document.getElementById("prefix-filter");
  var families = document.querySelectorAll("button.chip[data-family]");
  var group = document.getElementById("prefix-group");
  if (!tbody || !more || !filter || !group || !lists.prefixes) return;
  var data = lists.prefixes;
  var pressed = document.querySelector('button.chip[data-family][aria-pressed="true"]');
  var state = { family: pressed ? pressed.getAttribute("data-family") : "v4", showAll: false, grouped: false };

  function draw() {
    var all = data[state.family] || [];
    var matching = filterPrefixes(all, filter.value);
    var top = topSize(all, state.family);
    if (state.grouped) {
      var groups = groupBySlash8(matching);
      var biggest = Math.max.apply(null, groups.map(function (g) { return g.addresses; }).concat([1]));
      var cells = groups.map(function (g) {
        var tr = el("tr");
        var td = el("td");
        td.setAttribute("colspan", "4");
        td.appendChild(groupDetails(g, matching, state.family, top, biggest));
        tr.appendChild(td);
        return tr;
      });
      replaceChildren(tbody, cells.length ? cells : [messageRow(4, "No prefixes match the filter.")]);
      more.hidden = true;
      return;
    }
    var rows = visibleRows(matching, state.showAll).map(function (row) {
      return prefixRow(row, state.family, top);
    });
    replaceChildren(tbody, rows.length ? rows : [messageRow(4, "No prefixes match the filter.")]);
    syncMore(more, matching.length, state.showAll, "prefixes");
  }

  function syncGroup() {
    // Grouping is by IPv4 /8; an IPv6 table has no such thing.
    group.disabled = state.family !== "v4";
    if (group.disabled) state.grouped = false;
    group.setAttribute("aria-pressed", state.grouped ? "true" : "false");
  }

  reveal(families);
  group.hidden = false;
  filter.hidden = false;
  syncGroup();
  Array.prototype.forEach.call(families, function (button) {
    button.addEventListener("click", function () {
      state.family = button.getAttribute("data-family");
      state.showAll = false;
      setPressed(families, function (chip) {
        return chip === button;
      });
      syncGroup();
      draw();
    });
  });
  group.addEventListener("click", function () {
    if (group.disabled) return;
    state.grouped = !state.grouped;
    state.showAll = false;
    syncGroup();
    draw();
  });
  filter.addEventListener("input", function () {
    state.showAll = false;
    draw();
  });
  more.addEventListener("click", function () {
    state.showAll = !state.showAll;
    draw();
  });
  syncMore(more, (data[state.family] || []).length, false, "prefixes");
}

function init() {
  var script = document.getElementById("as-lists");
  if (!script) return;
  var lists;
  try {
    lists = JSON.parse(script.textContent);
  } catch (error) {
    return;
  }
  wireNeighbours(lists);
  wirePrefixes(lists);
}

if (typeof module === "object" && module.exports) {
  module.exports = {
    humanCount: humanCount,
    holderOf: holderOf,
    countryFlag: countryFlag,
    filterNeighbours: filterNeighbours,
    containsAddress: containsAddress,
    filterPrefixes: filterPrefixes,
    groupBySlash8: groupBySlash8,
    visibleRows: visibleRows,
    neighbourRow: neighbourRow,
    prefixRow: prefixRow,
    topSize: topSize,
  };
}
if (typeof document !== "undefined") init();
