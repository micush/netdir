"use strict";
// MCP Network Director web GUI: the capture page.

const pickedGw = () => (isGw() ? (state.gws || []).find((g) => String(g.group_id) === state.target.slice(GW.length)) || null : null);
const many = () => state.target === CLUSTER || isGw();   // a page about several nodes: every node, or a gateway's own

// ── Capture, Monitor  (CLI: --capture, --capture-interfaces) ────────────────────
// One node: a tcpdump-like capture on the node picked in the Node menu, shown live and downloadable as a .tgz (one .pcap in it).
// Cluster: the same capture on every node at once for a chosen time, one .pcap per node in a .tgz.
VIEWS.capture = (() => {
  let keptFilter = "";   // the filter text survives a change of node (the page is built again for each)
  let status, iface, filter, info, box, startBtn, dlBtn, ifs = null, cursor = 0, shown = 0, last = null, running = false;
  let job = null, jobBox, durSel, goBtn, dlJob;
  const ROWS = 1500;
  const cluster = many;
  const sizeText = (n) => (n < 1024 ? n + " bytes" : n < 1048576 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB");

  const ifaceSelect = () => h("select", { "aria-label": "Interface", class: "capif" });
  async function loadIfaces() {
    const r = (await api("GET", "/api/capture/interfaces")).data;
    ifs = r;
    const gw = new Set(r.gateway || []);
    const keep = iface.value;
    clear(iface).append(...r.interfaces.map((i) => h("option", { value: i.name }, i.name + (gw.has(i.name) ? " (gateway)" : "") + (i.up ? "" : " (down)"))));
    const pick = [keep, last && last.iface, ...(r.gateway || []), (r.interfaces.find((i) => i.up && i.name !== "lo") || {}).name, (r.interfaces[0] || {}).name].find((n) => n && r.interfaces.some((i) => i.name === n));
    if (pick) iface.value = pick;
  }
  function addRows(pk) {
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    if (box.firstChild && box.firstChild.classList && box.firstChild.classList.contains("empty")) clear(box);
    for (const p of pk) {
      const arp = /^(ARP|ICMPv6 .*neighbor)/.test(p.summary) || p.summary.startsWith("ARP");
      box.append(h("div", { class: "capline" + (arp ? " arp" : ""), title: p.len + " bytes" },
        h("span", { class: "ct" }, p.time), h("span", { class: "cs" }, p.summary)));
    }
    shown += pk.length;
    while (box.childNodes.length > ROWS) { box.removeChild(box.firstChild); }
    if (stick) box.scrollTop = box.scrollHeight;
  }
  function empty(text) { clear(box).append(h("div", { class: "empty" }, text)); shown = 0; }
  function setButtons() {
    startBtn.textContent = running ? "Stop" : "Start";   // one button: it starts a capture, and stops a running one
    dlBtn.disabled = !(last && last.count > 0);
  }
  async function refresh(full) {
    const q = full ? 0 : cursor;
    const st = (await api("GET", "/api/capture/packets?since=" + q)).data;
    if (st.cursor < cursor || (last && st.iface !== last.iface && !full)) return refresh(true); // another capture began, or this one was reset
    if (full) { clear(box); shown = 0; }
    if (st.packets.length) addRows(st.packets);
    cursor = st.cursor;
    last = st;
    running = st.running;
    if (!shown && !box.firstChild) empty(st.iface ? "Waiting for packets on " + st.iface + (st.filter ? " matching: " + st.filter : "") + "…" : "Not capturing. Choose an interface and press Start.");
    clear(info).append(!st.iface ? "" :
      (st.running ? "Capturing on " : "Stopped on ") + st.iface + (st.filter ? " · filter: " + st.filter : "") + " · " + st.count + " packet" + (st.count === 1 ? "" : "s") + " kept" +
      (st.seen > st.matched ? " (" + st.seen + " seen, the filter turned away " + (st.seen - st.matched) + ")" : "") +
      " · " + sizeText(st.bytes) + " in the buffer, the newest 5000 or 32 MB");
    setButtons();
  }
  async function start() {
    if (running) return;   // Start is greyed out while capturing; Enter in the filter box does nothing either
    try {
      await api("POST", "/api/capture/start", { iface: iface.value, filter: filter.value.trim() });
      say(status, "ok"); cursor = 0; last = null; empty("Waiting for packets…");
      await refresh(true);
    } catch (e) { fail(status)(e); }
  }
  async function stop() { try { await api("POST", "/api/capture/stop", {}); await refresh(false); } catch (e) { fail(status)(e); } }
  async function clearAll() { try { await api("POST", "/api/capture/clear", {}); empty(running ? "Waiting for packets…" : "Cleared."); await refresh(false); } catch (e) { fail(status)(e); } }

  // ── every node ──
  function drawJob() {
    clear(jobBox);
    if (!job || job.none) return;
    // Nothing to say when it went well (the table does): only while it runs, and when a node could not capture
    const failed = (job.nodes || []).filter((n) => n.status !== "done").length;
    if (job.done && job.error) jobBox.append(h("div", { class: "notice bad", role: "alert" }, job.error));
    else if (job.done && failed) jobBox.append(h("div", { class: "notice bad", role: "alert" }, failed + " of " + job.nodes.length + " nodes could not capture (see the list); the others are in the download."));
    if (job.nodes && job.nodes.length) {
      jobBox.append(h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Node", "Interface", "Result", "Packets kept", "Seen", "Size", "Why not"].map((t, i) => h("th", { class: i >= 3 && i <= 5 ? "num" : "" }, t)))),
        h("tbody", {}, job.nodes.map((n) => h("tr", {},
          h("td", {}, n.name, n.self ? " ★" : ""), h("td", { class: "mono" }, n.iface),
          h("td", {}, pill(n.status, n.status === "done" ? "ok" : n.status === "error" ? "bad" : "")),
          h("td", { class: "num" }, n.status === "done" ? String(n.kept) : "–"), h("td", { class: "num" }, n.status === "done" ? String(n.seen) : "–"),
          h("td", { class: "num" }, n.status === "done" ? sizeText(n.bytes) : "–"),
          h("td", {}, n.error || "")))))));
    }
    dlJob.disabled = !(job.done && job.ready);
    goBtn.disabled = !job.done;
  }
  async function pollJob() {
    const r = (await api("GET", "/api/clustercapture/status")).data;
    job = r.none ? null : r;
    drawJob();
  }
  async function goAll() {
    try {
      const gw = pickedGw();
      await api("POST", "/api/clustercapture/start", gw ? { gw: String(gw.group_id), filter: filter.value.trim(), seconds: Number(durSel.value) } : { iface: iface.value, filter: filter.value.trim(), seconds: Number(durSel.value) });
      say(status, "ok");
      await pollJob();
    } catch (e) { fail(status)(e); }
  }

  return {
    async mount(main) {
      cursor = 0; shown = 0; last = null; running = false; job = null; ifs = null;
      status = h("div", { "aria-live": "polite" });
      iface = ifaceSelect();
      filter = h("input", { type: "text", class: "grow", placeholder: "Filter, e.g. host 10.20.0.205 and port 123", "aria-label": "Capture filter", spellcheck: "false", autocomplete: "off", maxlength: "300",
        onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); (cluster() ? goAll : start)(); } } });
      filter.value = keptFilter;
      if (state.prefill.capture) { filter.value = state.prefill.capture; state.prefill.capture = null; }   // sent here from a server's menu: only Start is left
      keptFilter = filter.value;
      filter.addEventListener("input", () => { keptFilter = filter.value; });
      if (cluster()) {
        durSel = h("select", { "aria-label": "How long" }, [["5", "5 seconds"], ["10", "10 seconds"], ["30", "30 seconds"], ["60", "60 seconds"]].map(([v, t]) => h("option", { value: v }, t)));
        durSel.value = "10";
        goBtn = h("button", { class: "btn primary", type: "button", onclick: goAll }, "Capture on all nodes");
        dlJob = h("button", { class: "btn", type: "button", disabled: true, onclick: () => apiDownload("/api/clustercapture/download", "netdir-cluster-capture.tgz").catch(fail(status)) }, "Download .tgz");
        jobBox = h("div", {});
        const gw = pickedGw();
        if (gw) goBtn.textContent = "Capture on its nodes";
        main.append(status, section(gw ? "Capture on gateway " + gwTitle(gw) : "Capture on every node",
          h("div", { class: "toolbar tight logbar" }, gw ? h("span", { class: "mono small" }, gw.interface) : iface, filter, durSel, goBtn, dlJob), jobBox));
        if (!gw) await loadIfaces().catch(fail(status));
        await pollJob().catch(fail(status));
        return;
      }
      startBtn = h("button", { class: "btn primary", type: "button", onclick: () => (running ? stop() : start()) }, "Start");
      dlBtn = h("button", { class: "btn", type: "button", disabled: true, onclick: () => apiDownload("/api/capture/download", "netdir-capture.tgz").catch(fail(status)) }, "Download .tgz");
      info = h("div", { class: "hint nomargin" });
      box = h("div", { class: "logbox capbox", tabindex: "0", role: "log", "aria-label": "Captured packets" });
      main.append(status, section("Packet capture",
        h("div", { class: "toolbar tight logbar" }, iface, filter, startBtn,
          h("button", { class: "btn", type: "button", onclick: clearAll }, "Clear"), dlBtn),
        box, info));
      empty("Not capturing. Choose an interface and press Start.");
      try { await loadIfaces(); await refresh(true); } catch (e) { fail(status)(e); }
    },
    async poll() {
      if (cluster()) { if (job && !job.done) await pollJob(); return; }
      if (running || (last && !last.iface)) await refresh(false);
    },
    poll_ms: 1000,
  };
})();
