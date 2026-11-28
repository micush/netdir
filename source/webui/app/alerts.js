"use strict";
// MCP Network Director web GUI: the alerts page.

// Configure ▸ Settings, Gateways, MCP, Devices, Web GUI, Monitoring, Alerts and Backup: one page each, all made from the one form
// (every page shows its own panel and saves through the same call).
// Configure ▸ Alerts: where alerts are sent, and the rules.  The rules come from the node (its catalog), the settings go back
// in the settings.alerts block; only a rule that was touched is written out in full, so the others keep following the defaults.
const ALERT_FIX = {};

// ── Scheduler  (CLI: --schedule, --schedule-history, --schedule-set, --schedule-del, --schedule-run) ──
// ── Monitor ▸ Alerts  (CLI: none yet) ───────────────────────────────────────
VIEWS.alerts = (() => {
  let status, box, note, last = "", showClosed = false;
  const SEV = { critical: "bad", warning: "warn", info: "info" };
  const at = (u) => (u ? new Date(u * 1000).toLocaleString() : "–");
  const dur = (s) => { s = Math.max(0, Math.round(s)); const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? d + "d " + hh + "h" : hh ? hh + "h " + m + "m" : m ? m + "m" : s + "s"; };
  const say2 = (t) => { note.textContent = t; setTimeout(() => { if (note.textContent === t) note.textContent = ""; }, 6000); };
  async function call(path, body, done) {
    try { const r = await api("POST", "/api/alerts/" + path, body); if (r.data && r.data.message) say2(r.data.message); clear(status); await VIEWS.alerts.poll(true); refreshAlertMark(); if (done) done(); } catch (e) { fail(status)(e); }
  }
  const copy = async (text) => { try { await navigator.clipboard.writeText(text); } catch (_) { /* no permission */ } };
  function draw(v) {
    const sig = JSON.stringify([v, showClosed]);
    if (sig === last) return;
    last = sig;
    const rules = Object.fromEntries(v.rules.map((r) => [r.id, r]));
    const real = box; box = h("div", {});
    try {
      const list = v.alerts.filter((a) => showClosed || !a.closed);
      const open = v.alerts.filter((a) => !a.closed);
      const text = (a) => "[" + a.severity + "] " + a.title + (a.subject ? " (" + a.subject + ")" : "") + ": " + a.message;
      const menu = (a) => {
        const d = rules[a.rule] || {};
        const more = [];
        if (!a.closed) for (const f of d.fix || []) more.push([ALERT_FIX[f] || f, () => call("fix", { id: a.id, action: f })]);
        if (d.go) more.push(["Go to " + (TABS.find((t) => t[0] === d.go) || [0, d.go])[1], () => selectTab(d.go)]);
        more.push(["Edit rule", () => { state.alertRule = a.rule; selectTab("cfg_alerts"); }]);
        const items = a.closed ? [["Copy", () => copy(text(a))], "-", ["More", more]] : [
          a.acked ? ["Unacknowledge", () => call("ack", { id: a.id, ack: false })] : ["Acknowledge", () => call("ack", { id: a.id, ack: true })],
          ["Silence", [["15 minutes", 15], ["1 hour", 60], ["4 hours", 240], ["1 day", 1440], ["7 days", 10080]].map(([l, m]) => [l, () => call("silence", { id: a.id, minutes: m })])],
          a.silenced_until ? ["Unsilence", () => call("silence", { id: a.id, minutes: 0 })] : null,
          ["Mark resolved", () => call("resolve", { id: a.id })],
          ["Copy", () => copy(text(a))], "-", ["More", more]].filter(Boolean);
        return rowMenu(items);
      };
      const stateCell = (a) => {
        if (a.closed) return [pill("closed", "ok"), " ", h("span", { class: "small muted" }, ({ cleared: "cleared by itself", manual: "marked resolved" + (a.resolved_by ? " by " + a.resolved_by : ""), "rule off": "rule turned off" })[a.resolution] || a.resolution)];
        const out = [];
        if (a.silenced_until) out.push(pill("silenced", ""), " ", h("span", { class: "small muted" }, "until " + at(a.silenced_until)));
        else if (a.acked) out.push(pill("acknowledged", "info"), " ", h("span", { class: "small muted" }, a.acked_by ? "by " + a.acked_by : ""));
        else if (a.recovering) out.push(pill("recovering", "warn"));
        else out.push(pill("open", SEV[a.severity] || ""));
        return out;
      };
      const row = (a) => h("tr", { tabindex: "0", class: a.closed ? "paused" : "", oncontextmenu: menu(a) },
        h("td", {}, pill(a.severity, SEV[a.severity] || "")),
        h("td", {}, a.title, a.subject ? h("div", { class: "mono small muted" }, a.subject) : null),
        h("td", { class: "wrap" }, a.message),
        h("td", { title: a.closed ? "closed " + at(a.closed) : "" }, at(a.opened), h("div", { class: "small muted" }, a.closed ? "lasted " + dur(a.closed - a.opened) : "for " + dur(v.now - a.opened))),
        h("td", {}, stateCell(a)),
        h("td", { class: "num" }, a.count > 1 ? "×" + a.count : ""));
      const closedBox = h("input", { type: "checkbox", checked: showClosed });
      closedBox.addEventListener("change", () => { showClosed = closedBox.checked; draw(v); });
      const crit = open.filter((a) => a.severity === "critical" && !a.silenced_until && !a.acked).length;
      box.append(section("Alerts of " + v.node,
        h("div", { class: "toolbar" }, h("label", { class: "nt-opt" }, closedBox, " Show closed"),
          h("span", { class: "muted small" }, open.length ? open.length + " open" + (crit ? ", " + crit + " critical" : "") : "Nothing is open.")),
        h("div", { class: "scroll" }, h("table", { class: "tight alerts" },
          h("thead", {}, h("tr", {}, ["Severity", "Alert", "What is wrong", "Since", "State", ""].map((x) => h("th", {}, x)))),
          h("tbody", {}, list.length ? list.map(row) : h("tr", {}, h("td", { colspan: 6, class: "empty" }, showClosed ? "No alerts yet." : "No open alerts.")))))));
      if (v.silences.length) box.append(section("Silences",
        h("div", { class: "scroll" }, h("table", { class: "tight" },
          h("thead", {}, h("tr", {}, ["Alert", "Subject", "Until", "By"].map((x) => h("th", {}, x)))),
          h("tbody", {}, v.silences.map((s) => h("tr", {}, h("td", {}, (rules[s.rule] || { title: s.rule || "any" }).title), h("td", { class: "mono" }, s.subject || "any"), h("td", {}, at(s.until)), h("td", {}, s.by || ""))))))));
    } finally { morph(real, box); box = real; }
  }
  return {
    async mount(main) {
      status = h("div", { "aria-live": "polite" }); note = h("div", { class: "hint", "aria-live": "polite" }); box = h("div", {}); last = "";
      main.append(status, note, box);
      try { draw((await api("GET", "/api/alerts")).data); } catch (e) { fail(status)(e); }
    },
    async poll(force) { if (force) last = ""; draw((await api("GET", "/api/alerts")).data); },
    poll_ms: 5000,
  };
})();
