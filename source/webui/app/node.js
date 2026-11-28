"use strict";
// MCP Network Director web GUI: the node page.

// ── Node, Operate  (CLI: --assert-agc, --node-pause/-resume/-status, --power) ──
VIEWS.node = (() => {
  let status, pending, act, whenSel, mins, clock, takeBtn, npBtn, npPaused = false;
  const radio = (name, value, label, checked, ...extra) => {
    const r = h("input", { type: "radio", name, value, checked: !!checked });
    return h("label", { class: "opt" }, r, " ", label, ...extra);
  };
  const val = (name) => { const r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : ""; };

  const showNodePause = () => {
    npBtn.textContent = npPaused ? "Resume this node" : "Pause this node";
    npBtn.className = npPaused ? "btn primary" : "btn danger";
  };
  async function takeOver() {
    if (!confirm("Make this node the gateway controller for all groups?\n\nThe node that currently answers for the shared address is asked to step down once this node has taken the role.")) return;
    takeBtn.disabled = true;
    try {
      const r = await api("POST", "/api/assert-agc", {});
      if (!r.ok) say(status, "bad", r.error || "Could not take over as the gateway controller");
      else say(status, "info", "Asked to take over: " + (r.messages || []).join(" · "));   // what happened, per group and address family
    } catch (e) { fail(status)(e); }
    finally { takeBtn.disabled = false; }
  }
  async function toggleNodePause() {
    const want = !npPaused;
    if (want && !confirm("Pause this node?\n\nAll of its gateways stop serving and the other nodes take over. Clients are not interrupted as long as another node is serving. Resume it when you are done.")) return;
    try {
      await api("POST", "/api/nodepause", { paused: want });
      npPaused = want; showNodePause();
    } catch (e) { fail(status)(e); }
  }

  async function go(req) {
    const verb = req.action === "restart" ? "restart" : "shut down";
    const whenText = req.when === "now" ? "now" : req.when === "in" ? "in " + req.minutes + " minute(s)" : "at " + req.time;
    if (!confirm(verb.charAt(0).toUpperCase() + verb.slice(1) + " the whole host " + whenText + "?\n\n" +
      (req.action === "restart" ? "The host reboots and you lose access to this page until it is back." : "The host powers off and stays off until it is powered on again.") +
      (req.when === "now" ? "" : "\n\nThe gateway is not checked for cover at the scheduled time; make sure another member is serving by then."))) return;
    try {
      const r = (await api("POST", "/api/power", req)).data;
      say(status, "info", "Host " + (req.action === "restart" ? "restart" : "shutdown") + " " + r.when + ".");
      await VIEWS.node.poll();
    } catch (e) {
      // a gateway would lose its last serving member: say so and let the admin decide
      if (/^not safe to /.test(e.message || "") && confirm(e.message.replace(/ \(to go ahead anyway.*$/, "") + "\n\nGo ahead anyway? Clients of that gateway will be interrupted.")) {
        try { const r = (await api("POST", "/api/power", { ...req, force: true })).data; say(status, "info", "Host " + (req.action === "restart" ? "restart" : "shutdown") + " " + r.when + "."); await VIEWS.node.poll(); } catch (e2) { fail(status)(e2); }
        return;
      }
      fail(status)(e);
    }
  }

  function execute() {
    const req = { action: val("power-act") || "restart", when: val("power-when") || "now" };
    if (req.when === "in") {
      req.minutes = parseInt(mins.value, 10);
      if (!(req.minutes >= 1 && req.minutes <= 10080)) { say(status, "bad", "Enter a number of minutes between 1 and 10080."); return; }
    } else if (req.when === "at") {
      req.time = clock.value;
      if (!/^\d{2}:\d{2}$/.test(req.time)) { say(status, "bad", "Choose a time of day."); return; }
    }
    go(req);
  }

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      pending = h("div", {});
      mins = h("input", { type: "number", min: "1", max: "10080", value: "5", class: "narrow", "aria-label": "Minutes", onfocus: () => { document.querySelector('input[name="power-when"][value="in"]').checked = true; } });
      clock = h("input", { type: "time", "aria-label": "Time of day", onfocus: () => { document.querySelector('input[name="power-when"][value="at"]').checked = true; } });
      takeBtn = h("button", { class: "btn warn", type: "button", onclick: takeOver }, "Make this node the gateway controller");
      npBtn = h("button", { class: "btn", type: "button", onclick: toggleNodePause }, "…");
      main.append(status,
        section("Gateway controller", h("div", { class: "toolbar" }, takeBtn)),
        section("Maintenance", h("div", { class: "toolbar" }, npBtn)),
        section("Host",
          h("fieldset", { class: "radios" }, h("legend", {}, "Action"),
            radio("power-act", "restart", "Restart host", true), radio("power-act", "shutdown", "Shut down host", false)),
          h("fieldset", { class: "radios" }, h("legend", {}, "When"),
            radio("power-when", "now", "Now", true),
            radio("power-when", "in", "In ", false, mins, " minutes"),
            radio("power-when", "at", "At ", false, clock, " (24-hour)"),
            pending),   // the scheduled-action line and Cancel it sit in this box
          h("div", { class: "toolbar" },
            h("button", { class: "btn danger", type: "button", onclick: execute }, "Execute"))));
    },
    async poll() {
      try { npPaused = !!(await api("GET", "/api/nodepause")).data.paused; showNodePause(); } catch (_) { /* keep the last state */ }
      const p = (await api("GET", "/api/power")).data;
      clear(pending);
      if (p.scheduled) {
        pending.append(h("div", { class: "muted" },
          "A " + p.action + " is scheduled for " + when(p.at) + ". ",
          h("button", { class: "linkbtn", type: "button", onclick: async () => {
            try { await api("POST", "/api/power", { action: "cancel" }); say(status, "info", "The scheduled " + p.action + " is cancelled."); await VIEWS.node.poll(); } catch (e) { fail(status)(e); }
          } }, "Cancel it")));
      }
    },
    poll_ms: 5000,
  };
})();
