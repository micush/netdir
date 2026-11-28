"use strict";
// MCP Network Director web GUI: the gateways page.

// Gateways  (CLI: --show-gateways, --show-neighbors)
VIEWS.gateways = (() => {
  let body;
  return {
    mount(main) {
      body = h("div", {});
      main.append(body, h("p", { class: "hint" }, "★ marks this node"));
    },
    async poll() {
      const r = await api("GET", "/api/gateways");
      const out = h("div", {});   // built aside, then patched into the page (see morph)
      if (!r.data.length) {
        out.append(h("div", { class: "card" }, h("div", { class: "empty" }, "No gateway groups running.")));
        morph(body, out);
        return;
      }
      for (const g of r.data) {
        const rows = g.members.map((m) => h("tr", { class: m.local ? "local" : "" },
          h("td", { class: "nname", title: m.name || null }, m.name || "–", m.local ? " ★" : ""),
          h("td", { class: "mono" }, m.ip),
          h("td", { class: "num" }, m.priority),
          h("td", { class: "num" }, m.slot || "–"),
          h("td", { class: "num" }, m.weight),
          h("td", {}, pill(m.role, m.role === "AGC" ? "ok" : m.role === "AFN" ? "info" : "")),
          h("td", {}, pill(m.state.toUpperCase(), m.state === "expired" ? "bad" : m.state === "active" || m.state === "forward" ? "ok" : "warn"),
            m.preempt ? " " : null, m.preempt ? pill("preempt") : null),
          h("td", { class: "num", title: "average gap between this node's hellos / the largest gap in the last 30 to 60 seconds, counting a silence in progress" }, m.local || !m.hello_avg_ms ? "–" : m.hello_avg_ms + " / " + m.hello_max_ms),
          h("td", { class: "mono" }, m.vmac || "–"),
          h("td", {}, pill(m.service_up ? "answering" : "not answering", m.service_up ? "ok" : "warn"))));
        out.append(h("div", { class: "card" },
          h("header", { class: "bar" }, h("h2", {}, g.name ? g.name + " · Group " + g.group_id : "Group " + g.group_id),
            h("span", { class: "muted gw-vip" }, "VIP ", h("span", { class: "mono" }, g.vip)),
            g.agc ? h("span", { class: "muted" }, "AGC ", h("span", { class: "mono" }, g.agc)) : null,
            h("span", { class: "grow" }),
            g.members.some((m) => m.local && m.real_macs) ? null
              : h("button", { class: "btn hdr", type: "button", title: "Check that replies addressed to this gateway's virtual MAC reach this node", onclick: () => vmacTestPopup(g.group_id, g.name || "Group " + g.group_id) }, "Test")),
          h("div", { class: "scroll" }, h("table", { class: "tight" },
            h("thead", {}, h("tr", {}, ["Node name", "Node IP", "Pri", "Slot", "Weight", "Role", "State", "Hello avg / max (ms)", "vMAC", "Service"].map((t, i) => h("th", { class: [2, 3, 4, 7].includes(i) ? "num" : "" }, t)))),
            h("tbody", {}, rows)))));
      }
      morph(body, out);
    },
  };
})();
// Asks this node to check that replies addressed to a virtual MAC reach it, and shows what it found.  Nothing changes unless
// the person presses "Use real MAC addresses" (offered only when the test says they are not delivered).
function vmacTestPopup(gid, label) {
  const out = h("div", { class: "vmac-out", "aria-live": "polite" }, h("p", {}, "Testing… this takes a few seconds."));
  const useReal = h("button", { class: "btn primary", type: "button", hidden: true, onclick: async () => {
    useReal.disabled = true;
    try {
      const r = await api("GET", "/api/config");
      const g = (r.config.groups || []).find((x) => x.group_id === gid);
      if (!g) throw new Error("the gateway is not in the saved configuration");
      g.real_macs = true;
      await api("PUT", "/api/config", { config: r.config, note: "Use real MAC addresses", base: r.base });
      useReal.textContent = "Real MAC addresses are on";
    } catch (e) { if (e.message !== "unauthenticated") { useReal.disabled = false; useReal.textContent = "Could not save: " + e.message; } }
  } }, "Use real MAC addresses");
  const d = h("dialog", { class: "cv-dialog nt-dialog", "aria-label": "Virtual MACs: " + label });
  const close = () => { try { d.close(); } catch (_) { /* closed */ } d.remove(); };
  d.addEventListener("close", () => d.remove());
  d.append(h("h2", {}, "Virtual MACs: " + label), out,
    h("div", { class: "toolbar vmac-bar" }, useReal, h("button", { class: "btn", type: "button", onclick: close }, "Close")));
  root.append(d);
  d.showModal();
  (async () => {
    try {
      const r = await api("POST", "/api/vmactest", { group: gid });
      const x = (r.data || [])[0];
      if (!x) throw new Error("no result");
      // real MAC addresses on: just say so (the daemon's words, capitalised); otherwise the verdict, then a line per address family
      const lines = x.verdict === "off" ? [x.detail.charAt(0).toUpperCase() + x.detail.slice(1)] : [vmacLine(x), ...(x.families || []).map((f) => f.af + ": " + f.detail)];
      clear(out).append(...lines.map((t) => h("p", {}, t)));
      useReal.hidden = x.verdict !== "not-delivered";
    } catch (e) { if (e.message !== "unauthenticated") clear(out).append(h("p", {}, "The test could not run: " + e.message)); }
  })();
}
