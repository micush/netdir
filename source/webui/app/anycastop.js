"use strict";
// MCP Network Director web GUI: the anycastop page.

// ── Anycast, Operate  (CLI: --bgp-disable/-enable, --bgp-neighbor-disable/-enable, --ospf-disable/-enable, --ospf-interface-disable/-enable) ──
VIEWS.anycastop = (() => {
  let status, boxB, boxO;

  async function call(path, body) {
    try { await api("POST", path, body); clear(status); await refresh(); }
    catch (e) { fail(status)(e); }
  }
  const both = async () => { const [a, b] = await Promise.all([api("GET", "/api/bgp"), api("GET", "/api/ospf")]); return [a.data, b.data]; };
  async function refresh() { draw(...(await both())); }

  function draw(st, os) {
    for (const [real, fn] of [[boxB, buildBGP], [boxO, buildOSPF]]) {
      const tmp = h("div", {});
      try { fn(tmp, st, os); } finally { morph(real, tmp); }
    }
  }
  // built into a detached copy and morphed in: the page keeps its elements (and so its scroll boxes) from one poll to the next
  function buildBGP(box, st) {
    const c = st.config;
    if (st.blocked) { box.append(section("BGP", h("div", { class: "muted" }, BOTH_BLOCKED))); return; }
    if (!c.asn) { box.append(section("BGP", h("div", { class: "muted" }, "BGP is off on this node: set it up under Configure → Anycast → BGP."))); return; }
    const live = new Map(st.peers.map((p) => [p.peer, p]));
    const stateOf = (n) => {
      const p = live.get(n.peer);
      if (n.disabled) return pill("disabled", "");
      if (c.disabled) return pill("–", "");
      return p ? pill(p.state, p.state === "Established" ? "ok" : p.state === "Active" || p.state === "Connect" || p.state === "OpenSent" || p.state === "OpenConfirm" ? "warn" : "bad") : pill(st.running ? "not known yet" : "–", "");
    };
    const toggleBGP = h("button", { class: c.disabled ? "btn primary" : "btn danger", type: "button", onclick: () => {
      if (!c.disabled && !confirm("Disable BGP on this node?\n\nIts sessions go down and the anycast addresses are no longer announced from this node by BGP. The settings are kept.")) return;
      call("/api/bgp/operate", { enabled: !!c.disabled });
    } }, c.disabled ? "Enable BGP" : "Disable BGP");
    const row = (n) => h("tr", { tabindex: "0", oncontextmenu: rowMenu([[n.disabled ? "Enable" : "Disable", () => {
        if (c.disabled) return;
        if (!n.disabled && !confirm("Disable neighbor " + n.peer + "?\n\nThe session is shut down and nothing is announced to it. The neighbor is kept.")) return;
        call("/api/bgp/operate", { peer: n.peer, enabled: !!n.disabled });
      }]]) }, h("td", { class: "mono" }, n.peer), h("td", {}, String(n.remote_as)), h("td", {}, n.description || ""), h("td", {}, stateOf(n)));
    box.append(section("BGP",
      kv([["Local AS", String(c.asn)], ["State", c.disabled ? pill("disabled", "") : pill("enabled", "ok")]]),
      h("div", { class: "toolbar" }, toggleBGP)));
    box.append(section("Neighbors", h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Neighbor", "AS", "Description", "BGP"].map((t) => h("th", {}, t)))),
      h("tbody", {}, c.neighbors.length ? c.neighbors.map(row) : h("tr", {}, h("td", { colspan: 5, class: "empty" }, "No neighbors yet: add one under Configure → Anycast → BGP.")))))));
  }
  function buildOSPF(box, st, os) {
    const oc = os.config;
    if (os.blocked) { box.append(section("OSPF", h("div", { class: "muted" }, BOTH_BLOCKED))); return; }
    if (!oc.interfaces.length) { box.append(section("OSPF", h("div", { class: "muted" }, "OSPF is off on this node: set it up under Configure → Anycast → OSPF."))); return; }
    const full = (f) => os.peers.some((p) => p.interface === f.name && p.state === "Full");
    const stateOf = (f) => f.disabled ? pill("disabled", "") : oc.disabled ? pill("–", "") : os.running ? (full(f) ? pill("Full", "ok") : pill("no neighbor", "bad")) : pill("–", "");
    const toggleOSPF = h("button", { class: oc.disabled ? "btn primary" : "btn danger", type: "button", onclick: () => {
      if (!oc.disabled && !confirm("Disable OSPF on this node?\n\nIts neighbors go down and the anycast addresses are no longer announced from this node by OSPF. ospfd and ospf6d are stopped. The settings are kept.")) return;
      call("/api/ospf/operate", { enabled: !!oc.disabled });
    } }, oc.disabled ? "Enable OSPF" : "Disable OSPF");
    const row = (f) => h("tr", { tabindex: "0", oncontextmenu: rowMenu([[f.disabled ? "Enable" : "Disable", () => {
        if (oc.disabled) return;
        if (!f.disabled && !confirm("Disable OSPF on " + f.name + "?\n\nNo hellos are sent and its neighbors go down. The interface is kept.")) return;
        call("/api/ospf/operate", { interface: f.name, enabled: !!f.disabled });
      }]]) }, h("td", { class: "mono" }, f.name), h("td", {}, f.area), h("td", {}, f.network || "default"), h("td", {}, stateOf(f)));
    box.append(section("OSPF",
      kv([["Router ID", oc.router_id], ["State", oc.disabled ? pill("disabled", "") : pill("enabled", "ok")]]),
      h("div", { class: "toolbar" }, toggleOSPF)));
    box.append(section("Interfaces", h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Interface", "Area", "Link type", "OSPF"].map((t) => h("th", {}, t)))),
      h("tbody", {}, oc.interfaces.map(row))))));
  }

  return {
    async mount(main) {
      status = h("div", { "aria-live": "polite" }); boxB = h("div", {}); boxO = h("div", {});
      const panes = [h("div", { role: "tabpanel" }, boxB), h("div", { role: "tabpanel" }, boxO)];
      main.append(status, anycastTabs("anycastOpTab", "Anycast routing", panes), ...panes);
      try { await refresh(); } catch (e) { fail(status)(e); }
    },
    async poll() { await refresh(); },
    poll_ms: 5000,
  };
})();
