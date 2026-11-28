"use strict";
// MCP Network Director web GUI: the mcpusage page.

// ── MCP, Monitor  (API: GET /api/mcpusage) ──────────────────────────────────────
// What the MCP endpoint is used for on the picked node, laid out like Monitor ▸ Node: a time range, tiles, charts per hour, and cards
// with calls by key, by source address, by tool and by device, then the newest calls.  Counted by the daemon (mcpusage.go);
// nothing a caller sent or was answered is kept.
VIEWS.mcpusage = (() => {
  const SVGNS = "http://www.w3.org/2000/svg";
  const sv = (tag, attrs, ...kids) => {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null && v !== false) el.setAttribute(k, v);
    for (const kid of kids.flat(Infinity)) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return el;
  };
  const RANGES = [["1h", "Last Hour"], ["24h", "Last Day"], ["7d", "Last Week"]];
  const REFRESH_MS = 5000;
  const kept = { win: "24h" };
  let status, bar, tiles, charts, tables, recent, foot, rangeBtns, win = kept.win, seq = 0, lastAt = 0, last = "";
  const size = (n) => (n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(2) + " GB");
  const at = (u) => (u ? new Date(u * 1000).toLocaleString() : "–");
  const num = (n) => n.toLocaleString();
  const hm = (u, long) => new Date(u * 1000).toLocaleString([], long ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false } : { hour: "2-digit", minute: "2-digit", hour12: false });
  // csv: the rows of the card's download, or null when it has none to give
  const card = (title, csv, ...kids) => h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc(title)), h("span", { class: "grow" }), csv ? csvButton(title, csv) : null), h("div", { class: "body flush" }, ...kids));
  const sumCsv = (first, rows) => () => [[first, "Calls", "Errors", "Refused", "Changes", "Data (bytes)", "Avg ms", "Last (UTC)"],
    ...rows.map((r) => [r.name, r.calls, r.errors, r.refused, r.writes, r.bytes, r.avg_ms, r.last ? csvIso(r.last) : ""])];
  const COLS = [["Calls", (r) => num(r.calls), true], ["Errors", (r) => (r.errors ? num(r.errors) : "–"), true], ["Refused", (r) => (r.refused ? num(r.refused) : "–"), true],
    ["Changes", (r) => (r.writes ? num(r.writes) : "–"), true], ["Data", (r) => size(r.bytes), true], ["Avg ms", (r) => num(r.avg_ms), true], ["Last", (r) => at(r.last), false]];
  function sumCard(title, first, rows) {
    return card(title, rows.length ? sumCsv(first, rows) : null, rows.length
      ? h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, first), COLS.map((c) => h("th", { class: c[2] ? "num" : "" }, c[0])))),
        h("tbody", {}, rows.map((r) => h("tr", {}, h("td", { class: "mono" }, r.name), COLS.map((c) => h("td", { class: c[2] ? "num" : "" }, c[1](r))))))))
      : h("div", { class: "empty" }, "No calls in this time range."));
  }
  // bars per hour; red is the part that failed
  function bars(title, hours, cls, pick, fail2, text, csv) {
    const W = 620, H = 230, L = 12, R = 12, T = 12, B = 28, n = hours.length, max = Math.max(1, ...hours.map(pick));
    const pw = W - L - R, ph = H - T - B, bw = pw / Math.max(1, n);
    const svg = sv("svg", { class: "qchart", viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": title });
    for (let g = 0; g <= 4; g++) svg.append(sv("line", { class: "qgrid", x1: L, x2: W - R, y1: T + ph - (ph * g) / 4, y2: T + ph - (ph * g) / 4 }));
    hours.forEach((x, i) => {
      const v = pick(x), hh = Math.round((v / max) * ph), eh = fail2 ? Math.round((fail2(x) / max) * ph) : 0;
      svg.append(sv("g", {}, sv("title", {}, hm(x.t, true) + ": " + text(x)),
        sv("rect", { class: "ubar " + cls, x: (L + i * bw + 0.5).toFixed(1), y: T + ph - hh, width: Math.max(1, bw - 1).toFixed(1), height: hh }),
        eh ? sv("rect", { class: "uerr t3", x: (L + i * bw + 0.5).toFixed(1), y: T + ph - eh, width: Math.max(1, bw - 1).toFixed(1), height: eh }) : null));
    });
    svg.append(sv("text", { class: "qax", x: L, y: H - 8 }, hm(hours[0].t, n > 24)), sv("text", { class: "qax", x: W - R, y: H - 8, "text-anchor": "end" }, hm(hours[n - 1].t, n > 24)),
      sv("text", { class: "qax", x: W - R, y: T + 10, "text-anchor": "end" }, "most " + max.toLocaleString()));
    return h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc(title)), h("span", { class: "grow" }), csvButton(title, csv)), h("div", { class: "body" }, svg));
  }
  function draw(r) {
    const sig = JSON.stringify(r);
    if (sig === last) return;
    last = sig;
    const t = r.totals;
    const tile = (cls, label, value, sub) => h("div", { class: "qtile " + cls }, h("div", { class: "qv" }, value), h("div", { class: "qs" }, sub || "\u00a0"), h("div", { class: "ql" }, label));
    const per = r.window_hours ? t.calls / r.window_hours : 0;
    clear(tiles).append(
      tile("t1", "Calls", num(t.calls), per ? (per < 10 ? per.toFixed(1) : Math.round(per)) + " an hour" : ""),
      tile("t3", "Errors", num(t.errors), t.calls ? Math.round((t.errors * 100) / t.calls) + "% of calls" : ""),
      tile("t2", "Refused", num(t.refused), "read-only callers asking to change"),
      tile("t4", "Changes", num(t.writes), "that went through"),
      tile("t5", "Data returned", size(t.bytes), "after privacy masking"),
      tile("t6", "Average time", num(t.avg_ms) + " ms", "per call on this node"));
    clear(charts).append(
      bars("Calls per hour", r.hours, "t1", (x) => x.calls, (x) => x.errors, (x) => x.calls + " call" + (x.calls === 1 ? "" : "s") + (x.errors ? ", " + x.errors + " failed" : ""),
        () => [["Hour (UTC)", "Calls", "Errors"], ...r.hours.map((x) => [csvIso(x.t), x.calls, x.errors])]),
      bars("Data returned per hour", r.hours, "t5", (x) => x.bytes, null, (x) => size(x.bytes),
        () => [["Hour (UTC)", "Data (bytes)"], ...r.hours.map((x) => [csvIso(x.t), x.bytes])]));
    clear(tables).append(sumCard("By key", "Key", r.by_key), sumCard("By source address", "Address", r.by_source), sumCard("By tool", "Tool", r.by_tool), sumCard("By device", "Device, tag or target", r.by_target));
    clear(recent).append(card("Newest calls", r.recent.length ? () => [["Time (UTC)", "Key", "Address", "Tool", "Target", "Result", "Change", "Ms", "Data (bytes)"],
      ...r.recent.map((c) => [new Date(c.time).toISOString(), c.caller, c.addr, c.tool, c.target || "", c.result, c.write ? "yes" : "no", c.ms, c.bytes])] : null, r.recent.length
      ? h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Time", "Key", "Address", "Tool", "Target", "Result", "Ms", "Data"].map((x, i) => h("th", { class: i >= 6 ? "num" : "" }, x)))),
        h("tbody", {}, r.recent.map((c) => h("tr", {}, h("td", {}, new Date(c.time).toLocaleTimeString([], { hour12: false })), h("td", { class: "mono" }, c.caller), h("td", { class: "mono" }, c.addr),
          h("td", { class: "mono" }, c.tool), h("td", { class: "mono" }, c.target || ""), h("td", { class: c.result === "ok" ? "" : "bad" }, c.result + (c.write && c.result === "ok" ? " (change)" : "")),
          h("td", { class: "num" }, String(c.ms)), h("td", { class: "num" }, size(c.bytes)))))))
      : h("div", { class: "empty" }, "No calls since the daemon started.")));
    foot.textContent = r.note;
  }
  async function load() {
    const my = ++seq;
    try {
      const r = await api("GET", "/api/mcpusage?window=" + win);   // the answer is the report itself, not wrapped in {ok, data}
      if (my !== seq) return;
      lastAt = Date.now();
      clear(status);
      draw(r);
    } catch (e) { fail(status)(e); }
  }
  function setRange(id) {
    win = kept.win = id; last = "";
    for (const [k, b] of rangeBtns) b.setAttribute("aria-pressed", k === id ? "true" : "false");
    load();
  }
  return {
    mount(main) {
      last = ""; win = kept.win;
      status = h("div", { "aria-live": "polite" });
      rangeBtns = new Map(RANGES.map(([id, label]) => [id, h("button", { type: "button", class: "seg", "aria-pressed": id === win ? "true" : "false", onclick: () => setRange(id) }, label)]));
      bar = h("div", { class: "toolbar qbar" }, h("span", { class: "segs", role: "group", "aria-label": "Time range" }, [...rangeBtns.values()]));
      tiles = h("div", { class: "qtiles" }); charts = h("div", { class: "hostcharts" }); tables = h("div", { class: "hosttables" }); recent = h("div", {}); foot = h("p", { class: "hint" });
      main.append(status, bar, tiles, charts, tables, recent, foot);
      load();
    },
    async poll() { if (Date.now() - lastAt >= REFRESH_MS) await load(); },
  };
})();
