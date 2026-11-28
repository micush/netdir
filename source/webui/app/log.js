"use strict";
// MCP Network Director web GUI: the log page.

// ── Log, Monitor  (CLI: --log) ───────────────────────────────────────────────
VIEWS.log = (() => {
  let status, level, span, count, search, live, info, box, first, timer, tsBtn, tsHold = 0, seq = 0, shown = [];
  // the filters survive a change of node (and of page): the view is built again each time, from these
  const kept = { level: "", span: "1h", count: "1000", q: "", live: true };
  const sel = (label, opts, val, onchange) => {
    const el = h("select", { "aria-label": label, onchange }, opts.map(([v, t]) => h("option", { value: v }, t)));
    el.value = val;
    return el;
  };
  const stamp = (t) => {
    const d = new Date(t);
    if (isNaN(d)) return t || "";
    const day = d.toDateString() === new Date().toDateString() ? "" : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " ";
    return day + d.toLocaleTimeString([], { hour12: false });
  };
  const words = () => search.value.trim().split(/\s+/).filter(Boolean);
  // the message with the search words marked
  const marked = (msg) => {
    const w = words();
    if (!w.length) return msg;
    const re = new RegExp("(" + w.map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")", "ig");
    return msg.split(re).map((part, i) => (i % 2 ? h("mark", {}, part) : part));
  };
  function draw(r) {
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40; // at the bottom: follow new lines
    shown = r.lines;
    clear(box);
    if (!r.lines.length) box.append(h("div", { class: "empty" }, r.scanned ? "No log line matches these filters." : "The log is empty."));
    for (const l of r.lines) {
      box.append(h("div", { class: "logline lv-" + l.level.toLowerCase() },
        h("span", { class: "lt" }, stamp(l.time)), h("span", { class: "ll" }, l.level), h("span", { class: "lm" }, marked(l.msg))));
    }
    if (stick || first) box.scrollTop = box.scrollHeight;
    clear(info).append(r.matched + " matching line" + (r.matched === 1 ? "" : "s") + " of " + r.scanned + " on disk" +
      (r.truncated ? "; showing the newest " + r.lines.length + " (older ones are cut: narrow the filters or raise the line count)" : "") +
      (r.oldest ? ". The log reaches back to " + when(r.oldest) + "." : "."));
  }
  async function load() {
    const my = ++seq;
    const q = new URLSearchParams({ level: level.value, q: search.value.trim(), since: span.value, n: count.value });
    try {
      const r = (await api("GET", "/api/log?" + q.toString())).data;
      if (my !== seq) return; // a newer request is on its way
      if (Date.now() > tsHold) clear(status);   // not while the troubleshooting bundle is saying something
      draw(r);
      first = false;
    } catch (e) { fail(status)(e); }
  }
  // the troubleshooting bundle: every node's logs, configuration and state in one .tgz, asked of the node signed in to
  async function tshoot() {
    tsBtn.disabled = true; tsHold = Infinity;
    say(status, "info", "Collecting from every node… this takes up to a minute.");
    try {
      await apiDownload("/api/tshoot/download?capture=1", "netdir-tshoot.tgz");
      say(status, "info", "Downloaded. Passwords, the gateway key, tokens and join codes are removed; README.txt in it lists what it holds.");
    } catch (e) { fail(status)(e); }
    tsBtn.disabled = false; tsHold = Date.now() + 20000;
  }
  function download() {
    const text = shown.map((l) => l.raw).join("\n") + "\n";
    const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "text/plain" })), download: "netdir-log.txt" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  return {
    mount(main) {
      first = true;
      status = h("div", { "aria-live": "polite" });
      level = sel("Level", [["", "All levels"], ["info", "Info and above"], ["warn", "Warnings and errors"], ["error", "Errors only"]], kept.level, () => { kept.level = level.value; load(); });
      span = sel("Time range", [["15m", "Last 15 minutes"], ["1h", "Last hour"], ["6h", "Last 6 hours"], ["1d", "Last 24 hours"], ["7d", "Last 7 days"], ["all", "All of it"]], kept.span, () => { kept.span = span.value; load(); });
      count = sel("Lines", [["200", "200 lines"], ["1000", "1000 lines"], ["5000", "5000 lines"]], kept.count, () => { kept.count = count.value; load(); });
      search = h("input", { type: "search", placeholder: "Filter words (AND, OR, !not)…", "aria-label": "Filter text", spellcheck: "false", class: "grow",
        oninput: () => { kept.q = search.value; clearTimeout(timer); timer = setTimeout(load, 300); } });
      if (state.prefill.log != null) { kept.q = state.prefill.log; state.prefill.log = null; }   // sent here from a server's menu
      search.value = kept.q;
      live = h("input", { type: "checkbox", checked: kept.live, onchange: () => { kept.live = live.checked; } });
      tsBtn = h("button", { class: "btn", type: "button", onclick: tshoot }, "tshoot");
      info = h("div", { class: "hint nomargin" });
      box = h("div", { class: "logbox", tabindex: "0", role: "log", "aria-label": "Log lines" });
      main.append(status, section("Log",
        h("div", { class: "toolbar tight logbar" }, search, level, span, count,
          h("label", { class: "opt" }, live, " Live")),
        h("div", { class: "toolbar tight" },
          h("button", { class: "btn", type: "button", onclick: load }, "Refresh"),
          h("button", { class: "btn", type: "button", onclick: download }, "Download"),
          tsBtn),
        box, info));
    },
    async poll() {
      if (first || live.checked) await load();
    },
    poll_ms: 3000,
  };
})();
