"use strict";
// MCP Network Director web GUI: the host page.

// Width (in chart units) the y-axis labels need: the chart's left margin grows with the longest label so big
// numbers are never cut off.  ~6.6 units a character at the 11px axis font, plus the gap and a little edge room.
const axisMargin = (labels, min) => Math.max(min, Math.ceil(Math.max(0, ...labels.map((t) => String(t).length)) * 6.6) + 14);

// ── shared helpers for the management pages ───────────────────────────────
// Nothing is said when every node answered (the Node menu says "Cluster"); when one could not, which and why, since the
// numbers are then missing its share
const clusterNote = (c) => {
  const lost = c && c.nodes ? c.nodes.filter((n) => !n.ok) : [];
  if (!lost.length) return [];
  return [h("div", { class: "notice bad", role: "alert" }, "Not included in these numbers: " + lost.map((n) => n.name + " (" + n.error + ")").join(", "))];
};
const csvNum = (v) => (typeof v === "number" && isFinite(v) ? Math.round(v * 1000) / 1000 : "");

// ── Node, Monitor  (CLI: --host) ─────────────────────────────────────────────
// CPU, memory, disk and network use of the machine, sampled every 10 s by the daemon and
// kept in memory for 30 days.  The picked node (top-bar Node menu) is the one shown.
VIEWS.host = (() => {
  const SVGNS = "http://www.w3.org/2000/svg";
  const sv = (tag, attrs, ...kids) => {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return el;
  };
  const RANGES = [["1h", "Last Hour"], ["1d", "Last Day"], ["7d", "Last Week"], ["30d", "Last Month"], ["custom", "Custom"]];
  const REFRESH_MS = 10000;
  const pc = (v) => (v == null || v < 0 ? "–" : v.toFixed(v < 10 ? 1 : 0) + "%");
  const bits = (v) => (v == null || v < 0 ? "–" : v >= 1e9 ? (v / 1e9).toFixed(2) + " Gb/s" : v >= 1e6 ? (v / 1e6).toFixed(v >= 1e8 ? 0 : 2) + " Mb/s" : v >= 1e3 ? (v / 1e3).toFixed(v >= 1e5 ? 0 : 1) + " kb/s" : Math.round(v) + " b/s");
  const bytes = (v) => { let f = Number(v) || 0; for (const u of ["B", "KiB", "MiB", "GiB", "TiB"]) { if (f < 1024 || u === "TiB") return (u === "B" ? f : f.toFixed(1)) + " " + u; f /= 1024; } return ""; };
  const niceMax = (v, floor) => {
    if (v <= floor) return floor;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  };
  const stamp = (sec, step, long) => {
    const d = new Date(sec * 1000);
    const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
    return step >= 3600 || long ? d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm : hm;
  };

  let status, bar, cnote, tiles, charts, tables, neigh, foot, rangeBtns, fromIn, toIn, customRow;
  let range = "1h", lastAt = 0, seq = 0;

  // One line chart: series = [{ label, cls, values, text(i) }]; values below 0 are gaps.
  function lineChart(title, d, series, o) {
    const n = d.cpu.length;
    const peak = Math.max(0, ...series.flatMap((s) => s.values));
    const max = o.fixedMax || niceMax(peak, o.floor || 10);
    const W = 620, H = 230, L = axisMargin([0, 1, 2, 3, 4].map((g) => o.axis((max * g) / 4)), 62), R = 12, T = 12, B = 28, pw = W - L - R, ph = H - T - B;
    const x = (i) => L + (n <= 1 ? pw / 2 : (pw * i) / (n - 1));
    const y = (v) => T + ph - (ph * Math.min(v, max)) / max;
    const svg = sv("svg", { class: "qchart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title + " over time" });
    for (let g = 0; g <= 4; g++) {
      const v = (max * g) / 4;
      svg.append(sv("line", { class: "qgrid", x1: L, x2: W - R, y1: y(v), y2: y(v) }), sv("text", { class: "qax", x: L - 6, y: y(v) + 4, "text-anchor": "end" }, o.axis(v)));
    }
    const ticks = Math.min(8, n);
    const long = d.step >= 600 && d.to - d.from > 20 * 3600;
    for (let k = 0; k < ticks; k++) {
      const i = ticks === 1 ? 0 : Math.round((k * (n - 1)) / (ticks - 1));
      svg.append(sv("text", { class: "qax", x: x(i), y: H - 8, "text-anchor": k === 0 ? "start" : k === ticks - 1 ? "end" : "middle" }, stamp(d.start + i * d.step, d.step, long)));
    }
    for (const s of series) {
      let path = "", pen = false;
      s.values.forEach((v, i) => { if (v < 0) { pen = false; return; } path += (pen ? "L" : "M") + x(i).toFixed(1) + "," + y(v).toFixed(1); pen = true; });
      if (path) svg.append(sv("path", { class: "qline " + s.cls, d: path }));
    }
    const cross = sv("line", { class: "qcross hidden", y1: T, y2: T + ph });
    const dots = series.map((s) => sv("circle", { class: "qdot hidden " + s.cls, r: 4, cx: 0, cy: 0 }));
    const tip = sv("g", { class: "qtip hidden" });
    const tipBg = sv("rect", { class: "qtipbg", rx: 6, width: 250, height: 20 + 18 * (series.length + 1) });
    const tipHead = sv("text", { class: "qtiph", x: 10, y: 17 });
    const tipRows = series.map((s, k) => sv("g", { transform: `translate(10 ${36 + 18 * k})` }, sv("rect", { class: s.cls + " sw", width: 10, height: 10, y: -9, rx: 2 }), sv("text", { class: "qtipt", x: 16, y: 0 }, "")));
    tip.append(tipBg, tipHead, ...tipRows);
    const hit = sv("rect", { class: "qhit", x: L, y: T, width: pw, height: ph,
      onmousemove: (e) => {
        const r = svg.getBoundingClientRect();
        const px = ((e.clientX - r.left) / r.width) * W;
        const i = Math.max(0, Math.min(n - 1, Math.round(((px - L) / pw) * (n - 1))));
        cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.classList.remove("hidden");
        series.forEach((s, k) => { const v = s.values[i]; dots[k].classList.toggle("hidden", v < 0); dots[k].setAttribute("cx", x(i)); dots[k].setAttribute("cy", v < 0 ? 0 : y(v)); });
        tipHead.textContent = new Date((d.start + i * d.step) * 1000).toLocaleString();
        series.forEach((s, k) => { tipRows[k].lastChild.textContent = s.label + ": " + (s.values[i] < 0 ? "no data" : s.text(i)); });
        const tx = x(i) > W / 2 ? x(i) - 260 : x(i) + 12;
        tip.setAttribute("transform", `translate(${tx} ${T + 6})`); tip.classList.remove("hidden");
      },
      onmouseleave: () => { cross.classList.add("hidden"); tip.classList.add("hidden"); dots.forEach((c) => c.classList.add("hidden")); } });
    svg.append(cross, ...dots, hit, tip);
    const legend = series.length > 1 || o.legend ? h("div", { class: "qlegend" }, series.map((s) => h("span", { class: "qchip " + s.cls }, h("span", { class: "sw" }), s.label))) : null;
    // the chart's numbers: one row per sample, the busiest sample of the interval beside the average where there is one; a gap is an empty cell
    const sampleRows = () => {
      const cell = (v) => (v < 0 ? "" : csvNum(v));
      return [["Time (UTC)", ...series.flatMap((s) => [s.label + " (" + o.unit + ")", ...(s.peaks ? [s.label + " peak (" + o.unit + ")"] : [])])],
        ...Array.from({ length: n }, (_, i) => [csvIso(d.start + i * d.step), ...series.flatMap((s) => [cell(s.values[i]), ...(s.peaks ? [cell(s.peaks[i])] : [])])])];
    };
    return h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc(title)), h("span", { class: "grow" }), csvButton(title, sampleRows)), h("div", { class: "body" }, legend, svg));
  }

  function draw(d) {
    const n = d.now;
    clear(status);
    if (!n.at) { clear(tiles); clear(charts).append(h("div", { class: "empty" }, "No sample yet: the daemon has only just started.")); clear(tables); return; }
    const tile = (cls, label, value, sub) => h("div", { class: "qtile " + cls }, h("div", { class: "qv" }, value), h("div", { class: "qs" }, sub || "\u00a0"), h("div", { class: "ql" }, label));
    // the fullest real disk; tiny system mounts (under 1 GiB) only count when nothing bigger exists
    const big = (n.fs || []).filter((f) => f.total >= 1 << 30);
    const topFS = (big.length ? big : n.fs || []).reduce((a, f) => (!a || f.pct > a.pct ? f : a), null);
    clear(tiles).append(
      tile("t1", "CPU", pc(n.cpu_pct), n.cores + (n.cores === 1 ? " core" : " cores") + " · load " + n.load[0].toFixed(2)),
      tile("t3", "Memory", pc(n.mem_pct), bytes(n.mem_used) + " of " + bytes(n.mem_total)),
      tile("t4", "Disk space", topFS ? pc(topFS.pct) : "–", topFS ? topFS.mount + " · " + bytes(topFS.used) + " of " + bytes(topFS.total) : ""),
      tile("t2", "Disk I/O", pc(n.io_pct), "busiest disk, time busy"),
      tile("t5", "Network in", bits(n.rx_bps), n.net_util_pct >= 0 ? "busiest link " + pc(n.net_util_pct) : "link speed unknown"),
      tile("t6", "Network out", bits(n.tx_bps), ""));
    const cpuT = (i) => pc(d.cpu[i]) + " (peak " + pc(d.cpu_max[i]) + ")";
    const fsCls = ["t4", "t5", "t6", "t7", "t8", "t-other"];
    const ioT = (i) => pc(d.io[i]) + " (peak " + pc(d.io_max[i]) + ")";
    const diskSeries = [{ label: "I/O busy", cls: "t2", values: d.io, peaks: d.io_max, text: ioT }].concat((d.fs || []).map((f, k) => ({ label: f.mount + " used", cls: fsCls[k % fsCls.length], values: f.pct, text: (i) => pc(f.pct[i]) })));
    clear(charts).append(
      lineChart("CPU utilization", d, [{ label: "CPU", cls: "t1", values: d.cpu, peaks: d.cpu_max, text: cpuT }], { unit: "%", floor: 10, axis: (v) => (Number.isInteger(v) ? v : v.toFixed(1)) + "%" }),
      lineChart("Memory utilization", d, [{ label: "Memory", cls: "t3", values: d.mem, text: (i) => pc(d.mem[i]) }], { unit: "%", floor: 10, axis: (v) => (Number.isInteger(v) ? v : v.toFixed(1)) + "%" }),
      lineChart("Disk utilization", d, diskSeries, { unit: "%", fixedMax: 100, axis: (v) => (Number.isInteger(v) ? v : v.toFixed(1)) + "%", legend: true }),
      lineChart("Network utilization", d, [
        { label: "In", cls: "t5", values: d.rx, peaks: d.rx_max, text: (i) => bits(d.rx[i]) + " (peak " + bits(d.rx_max[i]) + ")" },
        { label: "Out", cls: "t6", values: d.tx, peaks: d.tx_max, text: (i) => bits(d.tx[i]) + " (peak " + bits(d.tx_max[i]) + ")" }], { unit: "bits/s", floor: 1000, axis: (v) => bits(v) }));
    const fsRows = (n.fs || []).map((f) => h("tr", {}, h("td", { class: "mono" }, f.mount), h("td", {}, f.device + " · " + f.type), h("td", { class: "num" }, bytes(f.used) + " of " + bytes(f.total)), h("td", { class: "num" }, pc(f.pct))));
    const ifList = (n.ifaces || []).filter((i) => !/(^| )lo$/.test(i.name));   // "lo", or "node lo" in the cluster view
    const ifRows = ifList.map((i) => h("tr", { class: i.counted ? null : "muted" }, h("td", { class: "mono" }, i.name), h("td", { title: i.counted ? null : "Not in the totals" }, i.up ? "up" : "down", i.counted ? "" : " *"),
      h("td", { class: "num" }, i.speed ? i.speed + " Mb/s" : "–"), h("td", { class: "num" }, bits(i.rx_bps)), h("td", { class: "num" }, bits(i.tx_bps)), h("td", { class: "num" }, i.util_pct >= 0 ? pc(i.util_pct) : "–")));
    fill(tables, 
      h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc("Filesystems")), h("span", { class: "grow" }), fsRows.length ? csvButton("Filesystems", () => [["Mount", "Device", "Type", "Used (bytes)", "Total (bytes)", "Use (%)"],
        ...(n.fs || []).map((f) => [f.mount, f.device, f.type, f.used, f.total, csvNum(f.pct)])]) : null), h("div", { class: "body flush" }, fsRows.length
        ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Mount"), h("th", {}, "Device"), h("th", { class: "num" }, "Used"), h("th", { class: "num" }, "Use"))), h("tbody", {}, fsRows))
        : h("div", { class: "empty" }, "No disk filesystems found."))),
      h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc("Network interfaces")), h("span", { class: "grow" }), ifRows.length ? csvButton("Network interfaces", () => [["Interface", "State", "Counted in totals", "Speed (Mb/s)", "In (bits/s)", "Out (bits/s)", "Link use (%)"],
        ...ifList.map((i) => [i.name, i.up ? "up" : "down", i.counted ? "yes" : "no", i.speed || "", csvNum(i.rx_bps), csvNum(i.tx_bps), i.util_pct >= 0 ? csvNum(i.util_pct) : ""])]) : null), h("div", { class: "body flush" }, ifRows.length
        ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Interface"), h("th", {}, "State"), h("th", { class: "num" }, "Speed"), h("th", { class: "num" }, "In"), h("th", { class: "num" }, "Out"), h("th", { class: "num" }, "Link use"))), h("tbody", {}, ifRows)))
        : h("div", { class: "empty" }, "No interfaces found."))));
    clear(cnote).append(...clusterNote(d.cluster));   // which nodes are added together, when the Node menu says Cluster
    foot.hidden = true;
  }

  async function load() {
    const my = ++seq;
    try {
      let from = range, to = "";
      if (range === "custom") {
        const a = new Date(fromIn.value), b = new Date(toIn.value);
        if (isNaN(a) || isNaN(b) || a >= b) throw new Error("Pick a start that is before the end.");
        from = String(Math.floor(a / 1000)); to = String(Math.floor(b / 1000));
      }
      const r = await api("GET", "/api/host?from=" + encodeURIComponent(from) + (to ? "&to=" + encodeURIComponent(to) : ""));
      if (my !== seq) return;
      lastAt = Date.now();
      draw(r.data);
    } catch (e) { fail(status)(e); }
    loadNeighbors(my);
  }

  // LLDP neighbors of the picked node: the switch and port each interface is plugged into.  Not for the cluster as one
  // (that is a sum), and not while LLDP is off and lldpd is not running.
  async function loadNeighbors(my) {
    if (state.target === CLUSTER) { clear(neigh); return; }
    let st;
    try { st = (await api("GET", "/api/lldp")).data; } catch (e) { if (e.message === "unauthenticated") throw e; clear(neigh); return; }
    if (my !== seq) return;
    if (!st.enabled && !st.running) { clear(neigh); return; }
    const ns = st.neighbors || [];
    const rows = ns.map((n) => h("tr", {},
      h("td", { class: "mono" }, n.interface),
      h("td", { title: n.system_descr || null }, n.system_name || n.chassis_id || "–"),
      h("td", { title: n.port_descr && n.port_descr !== n.port_id ? n.port_id : null }, n.port_descr || n.port_id || "–"),
      h("td", {}, (n.vlans || []).join(", ") || "–"),
      h("td", { class: "mono" }, (n.mgmt_ips || []).join(", ") || "–"),
      h("td", { class: "num" }, n.age || "–")));
    const body = st.error ? h("div", { class: "empty bad-text" }, st.error)
      : !st.running ? h("div", { class: "empty" }, lldpWords(st))
      : rows.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Interface", "Switch", "Port", "VLAN", "Management", "Seen"].map((t, i) => h("th", { class: i === 5 ? "num" : null }, t)))), h("tbody", {}, rows)))
      : h("div", { class: "empty" }, "None seen yet.");
    const dl = !st.error && st.running && ns.length ? csvButton("LLDP neighbors", () => [["Interface", "Switch", "Port", "VLAN", "Management", "Seen"],
      ...ns.map((n) => [n.interface, n.system_name || n.chassis_id || "", n.port_descr || n.port_id || "", (n.vlans || []).join("; "), (n.mgmt_ips || []).join("; "), n.age || ""])]) : null;
    clear(neigh).append(h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc("LLDP neighbors")), h("span", { class: "grow" }), dl), h("div", { class: "body flush" }, body)));
  }

  function setRange(r) {
    range = r;
    for (const [id, b] of rangeBtns) b.setAttribute("aria-pressed", id === r ? "true" : "false");
    customRow.classList.toggle("hidden", r !== "custom");
    if (r === "custom" && !fromIn.value) {
      const f = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
      toIn.value = f(new Date()); fromIn.value = f(new Date(Date.now() - 6 * 3600 * 1000));
    }
    if (r !== "custom") load();
  }

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      rangeBtns = new Map(RANGES.map(([id, label]) => [id, h("button", { type: "button", class: "seg", "aria-pressed": id === range ? "true" : "false", onclick: () => setRange(id) }, label)]));
      fromIn = h("input", { type: "datetime-local", "aria-label": "From" });
      toIn = h("input", { type: "datetime-local", "aria-label": "To" });
      customRow = h("span", { class: "qcustom hidden" }, fromIn, " to ", toIn,
        h("button", { class: "btn", type: "button", onclick: load }, "Apply"), h("span", { class: "muted small" }, " only the last 30 days exist"));
      bar = h("div", { class: "toolbar qbar" }, h("span", { class: "segs", role: "group", "aria-label": "Time range" }, [...rangeBtns.values()]), customRow);
      tiles = h("div", { class: "qtiles" });
      charts = h("div", { class: "hostcharts" });
      tables = h("div", { class: "hosttables" });
      neigh = h("div", {});
      foot = h("p", { class: "hint" });
      cnote = h("div", {});
      main.append(status, bar, cnote, tiles, charts, tables, neigh, foot);
      setRange(range);
    },
    async poll() {
      if (range === "custom") return;
      if (Date.now() - lastAt >= REFRESH_MS) await load();
    },
  };
})();
