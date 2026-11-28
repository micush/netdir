"use strict";
// MCP Network Director web GUI: the devices page.

// Devices  (MCP: list_devices, device_facts, …; API: /api/devices, /api/devices/query)
// The inventory, and a form that asks the devices a target picks for one thing at once.  Every device answers on its own row:
// what it said, or why not, and how long it took.  Nothing is polled: a device is asked only when Ask is pressed.
VIEWS.devices = (() => {
  let tiles, inv, bar, list, filter, count, sizeSel, pager, pageIn, pages, first, prev, next, last;
  let lastAt = 0, page = 0, size = 50, cur = { all: [], below: {}, hl: () => ({}) };
  const STATE = { ok: ["answering", "ok tiny"], warn: ["refusing", "warn tiny"], bad: ["unreachable", "bad tiny"], paused: ["disabled", "tiny"] };
  // the table: the devices that hold every word typed in the filter box (any column, the state and the tags too), one page of them
  function draw() {
    const { all, below, hl } = cur;
    bar.classList.toggle("hidden", !all.length);
    if (!all.length) { clear(list).append(h("div", { class: "empty" }, "No devices yet. Add them under Configure ▸ Devices.")); return; }
    const flt = parseFilter(filter.value), words = { length: flt.empty ? 0 : 1 };
    const hay = (x) => [x.name, (STATE[hl(x).status] || ["not checked"])[0], platformName(x.platform), x.address + (x.port ? ":" + x.port : ""), (x.via || []).join(" "), (x.tags || []).join(" "), x.unattached ? "no gateway" : x.disabled ? "disabled" : ""].join(" ").toLowerCase();
    const vis = words.length ? all.filter((x) => { const t = hay(x); return flt.match((w) => t.includes(w)); }) : all;
    const n = Math.max(1, Math.ceil(vis.length / size));
    page = Math.min(Math.max(page, 0), n - 1);
    const from = page * size, shown = vis.slice(from, from + size);
    count.textContent = vis.length ? `${from + 1}\u2013${from + shown.length} of ${vis.length}${words.length ? ` (filtered from ${all.length})` : ""}` : (words.length ? `0 of ${all.length}` : "0 rows");
    pager.hidden = n < 2;
    pageIn.value = String(page + 1);
    pageIn.max = String(n);
    pages.textContent = "of " + n;
    first.disabled = prev.disabled = page === 0;
    next.disabled = last.disabled = page >= n - 1;
    clear(list).append(shown.length ? h("div", { class: "scroll" }, h("table", { class: "tight", onmouseover: cutTip },
      h("thead", {}, h("tr", {}, ["Device", "State", "Platform", "Address", "Via", "Tags", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, shown.map((x) => h("tr", { class: x.disabled ? "muted" : "", tabindex: "0", title: "Right-click for the network tools",
        oncontextmenu: rowMenu(toolItems(x.address, x.remote ? "" : x.name)) },
        h("td", { class: "nname" }, x.name), h("td", { title: [hl(x).detail || "not checked yet", hl(x).by ? "Checked by " + hl(x).by : "", below[x.name] ? "Below it: " + below[x.name] : ""].filter(Boolean).join(". ") },
          pill(...(STATE[hl(x).status] || ["not checked", "tiny"]))),
        h("td", {}, platformName(x.platform)), h("td", { class: "mono" }, x.address + (x.port ? ":" + x.port : "")),
        h("td", {}, (x.via || []).join(" \u25b8 ")),
        h("td", {}, (x.tags || []).map((t) => [pill(t, "info tiny"), " "])), h("td", {}, x.unattached ? pill("no gateway") : x.disabled ? pill("disabled") : ""))))))
      : h("div", { class: "empty" }, "No devices match the filter."));
  }
  async function load() {
    const d = (await api("GET", "/api/devices")).data;
    lastAt = Date.now();
    // the devices below the Network Directors that are devices here come with their own health (Via: the directors between)
    const all = d.devices.concat((d.remote || []).map((r) => Object.assign({}, r, { remote: true })));
    const hl = (x) => (x.remote ? { status: x.status, detail: x.detail } : (d.health || {})[x.name] || {});
    const st = (x) => (x.disabled ? "paused" : hl(x).status || "");
    const n = (k) => all.filter((x) => st(x) === k).length;
    const tile = (cls, label, value, sub) => h("div", { class: "qtile " + cls }, h("div", { class: "qv" }, value), h("div", { class: "qs" }, sub || "\u00a0"), h("div", { class: "ql" }, label));
    const plats = new Set(all.map((x) => x.platform));
    clear(tiles).append(
      tile("t1", "Devices", String(all.length), plats.size + (plats.size === 1 ? " platform" : " platforms")),
      tile("t3", "Answering", String(n("ok")), "asked and answered"),
      tile("t5", "Refusing", String(n("warn")), "answered with an error"),
      tile("t6", "Unreachable", String(n("bad")), "no answer"),
      tile("t2", "Disabled", String(n("paused")), "never contacted"));
    cur = { all, below: d.remote_errors || {}, hl };
    draw();   // only the table: the filter box keeps what was typed and the focus
  }
  return {
    mount(main) {
      page = 0;
      size = 50;
      tiles = h("div", { class: "qtiles" });
      // the filter box and the pager are those of the tables under Configure ▸ Devices
      filter = h("input", { type: "text", class: "policy-filter", placeholder: "Filter devices", "aria-label": "Filter devices", autocomplete: "off", spellcheck: "false" });
      count = h("span", { class: "policy-count muted" }, "");
      sizeSel = h("select", { "aria-label": "Rows per page" }, [25, 50, 100, 250, 500].map((n) => h("option", { value: String(n) }, n + " per page")));
      sizeSel.value = String(size);
      const mkBtn = (label, title) => h("button", { type: "button", class: "btn small", title, "aria-label": title }, label);
      first = mkBtn("\u00ab", "First page"); prev = mkBtn("\u2039", "Previous page"); next = mkBtn("\u203a", "Next page"); last = mkBtn("\u00bb", "Last page");
      pageIn = h("input", { type: "number", min: "1", class: "policy-page", "aria-label": "Page number" });
      pages = h("span", { class: "muted" }, "");
      pager = h("span", { class: "policy-pager" }, first, prev, pageIn, pages, next, last);
      bar = h("div", { class: "policy-bar" }, filter, count, h("span", { class: "grow" }), pager, sizeSel);
      filter.addEventListener("input", () => { page = 0; draw(); });
      filter.addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
      sizeSel.addEventListener("change", () => { size = +sizeSel.value || 50; page = 0; draw(); });
      first.addEventListener("click", () => { page = 0; draw(); });
      prev.addEventListener("click", () => { page--; draw(); });
      next.addEventListener("click", () => { page++; draw(); });
      last.addEventListener("click", () => { page = 1e9; draw(); });
      pageIn.addEventListener("change", () => { page = (parseInt(pageIn.value, 10) || 1) - 1; draw(); });
      pageIn.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); pageIn.blur(); } });
      list = h("div", {}, "Loading\u2026");
      inv = h("div", { class: "body" }, bar, list);
      bar.classList.add("hidden");   // until the devices are known
      main.append(tiles, h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, "Devices")), inv));
      load().catch((e) => { if (e.message !== "unauthenticated") clear(list).append(h("p", { class: "bad-text" }, e.message)); });
    },
    async poll() { if (Date.now() - lastAt >= 10000) await load(); },   // the tiles and the table follow the devices, as the Node page follows the machine
    refresh: () => load(),   // now, not in 10 s (a recheck just changed a device's state)
  };
})();

// A table cell whose text is cut by its box (an ellipsis) shows the whole text as a tooltip when the pointer reaches it; a cell with a tooltip of its own keeps it.
function cutTip(e) {
  const td = e.target.closest && e.target.closest("td");
  if (td && !td.title && td.scrollWidth > td.clientWidth) td.title = td.textContent.trim();
}
