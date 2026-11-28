"use strict";
// MCP Network Director web GUI: the anycaststatus page.

// ── Anycast, Monitor  (CLI: --bgp, --ospf) ──────────────────────────────────────────────
VIEWS.anycaststatus = (() => {
  let boxB, boxO;
  const stateKind = (st) => (st === "Established" ? "ok" : st === "Active" || st === "Connect" || st === "OpenSent" || st === "OpenConfirm" ? "warn" : "bad");
  const ospfKind = (st) => (st === "Full" ? "ok" : st === "Down" || st === "Attempt" ? "bad" : "warn");
  const bfdKind = (st) => (st === "up" ? "ok" : st === "init" ? "warn" : st === "down" ? "bad" : "");
  // the time beside a BFD pill: how long the router takes to drop this node once it goes silent
  const bfdTip = (t) => "The router drops this node after " + t.detect_ms + " ms without a BFD packet (" + t.mult + " × " + Math.round(t.detect_ms / t.mult) + " ms)." +
    (t.peer_detect_ms ? " This node drops the router after " + t.peer_detect_ms + " ms." : "");
  const applied = (a) => ["Last apply", h("span", {}, pill(a.ok ? "ok" : "failed", a.ok ? "ok" : "bad"), ...(a.ok ? [] : [" ", a.detail || "–"]))];

  function draw(st, os) {
    for (const [which, fn] of [["B", buildBGP], ["O", buildOSPF]]) {
      const real = which === "B" ? boxB : boxO, tmp = h("div", {});
      try { fn(tmp, st, os); } finally { morph(real, tmp); }
    }
  }
  function addresses(box, st) {
    box.append(section("Anycast addresses", h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Address", "State", "Why"].map((t) => h("th", {}, t)))),
      h("tbody", {}, st.addresses.length ? st.addresses.map((a) => h("tr", {},
        h("td", { class: "mono" }, a.addr),
        h("td", {}, a.up ? pill("announced", "ok") : pill("withdrawn", "")),
        h("td", {}, a.up ? "" : a.reason || "")))
        : h("tr", {}, h("td", { colspan: 3, class: "empty" }, "None: add an anycast address to a gateway on the Topology page.")))))));
  }
  // built into a detached copy and morphed in: the page keeps its elements (and so its scroll boxes) from one poll to the next
  function buildBGP(box, st) {
    const c = st.config;
    if (st.blocked) { box.append(section("BGP", h("div", { class: "muted" }, BOTH_BLOCKED))); return; }
    if (!c.asn) { box.append(section("BGP", h("div", { class: "muted" }, "BGP is off on this node."))); return; }
    if (c.disabled) { box.append(section("BGP", h("div", { class: "muted" }, "BGP is disabled on this node (AS " + c.asn + ")."))); return; }
    box.append(section("Status", kv([
      ["Local AS", String(c.asn) + (c.router_id ? " · router id " + c.router_id : "")],
      ["FRR", st.installed ? pill("installed", "ok") : pill("not installed", "bad")],
      st.installed ? ["bgpd", st.running ? pill("answering", "ok") : pill("not answering", "bad")] : null,
      applied(st.applied),
    ]), ...(st.notes || []).map((n) => h("div", { class: "muted" }, n))));
    const live = new Map(st.peers.map((p) => [p.peer, p]));
    const row = (n) => {
      const p = live.get(n.peer);
      return h("tr", {}, h("td", { class: "mono" }, n.peer), h("td", {}, String(n.remote_as)), h("td", {}, n.description || ""),
        h("td", {}, n.disabled ? pill("disabled", "") : p ? pill(p.state, stateKind(p.state)) : pill(st.running ? "not known yet" : "–", "")),
        h("td", {}, p && p.bfd ? pill(p.bfd, bfdKind(p.bfd)) : "–", p && p.bfd_timers ? h("span", { class: "hint", title: bfdTip(p.bfd_timers) }, " " + p.bfd_timers.detect_ms + " ms") : null),
        h("td", {}, p && p.state === "Established" ? p.uptime : "–"),
        h("td", {}, p && p.state === "Established" ? String(p.sent) : "–"));
    };
    box.append(section("Neighbors", h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Neighbor", "AS", "Description", "BGP", "BFD", "Up for", "Prefixes sent"].map((t) => h("th", {}, t)))),
      h("tbody", {}, c.neighbors.length ? c.neighbors.map(row) : h("tr", {}, h("td", { colspan: 7, class: "empty" }, "No neighbors yet: add one under Configure → Anycast → BGP.")))))));
    addresses(box, st);
  }
  function buildOSPF(box, st, os) {
    const oc = os.config;
    if (os.blocked) { box.append(section("OSPF", h("div", { class: "muted" }, BOTH_BLOCKED))); return; }
    if (!oc.interfaces.length) { box.append(section("OSPF", h("div", { class: "muted" }, "OSPF is off on this node."))); return; }
    if (oc.disabled) { box.append(section("OSPF", h("div", { class: "muted" }, "OSPF is disabled on this node."))); return; }
    box.append(section("Status", kv([
      ["Router ID", oc.router_id],
      ["FRR", os.installed ? pill("installed", "ok") : pill("not installed", "bad")],
      os.installed ? ["ospfd / ospf6d", os.running ? pill("answering", "ok") : pill("not answering", "bad")] : null,
      applied(os.applied),
    ]), ...(os.notes || []).filter((n) => !/^Nothing is announced/.test(n)).map((n) => h("div", { class: "muted" }, n))));
    const rows = [];
    for (const f of oc.interfaces) {
      const ps = os.peers.filter((p) => p.interface === f.name);
      if (f.disabled || !ps.length) {
        rows.push(h("tr", {}, h("td", { class: "mono" }, f.name), h("td", {}, f.area), h("td", {}, "–"), h("td", {}, "–"),
          h("td", {}, f.disabled ? pill("disabled", "") : pill(os.running ? "no neighbor" : "–", os.running ? "bad" : "")), h("td", {}, "–"), h("td", {}, "–")));
        continue;
      }
      for (const p of ps) {
        rows.push(h("tr", {}, h("td", { class: "mono" }, f.name), h("td", {}, f.area), h("td", { class: "mono" }, p.neighbor), h("td", {}, p.af === "ipv6" ? "OSPFv3" : "OSPFv2"),
          h("td", {}, pill(p.state, ospfKind(p.state))), h("td", {}, p.bfd ? pill(p.bfd, bfdKind(p.bfd)) : "–"), h("td", {}, p.state === "Full" && p.uptime ? p.uptime : "–")));
      }
    }
    box.append(section("Neighbors", h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Interface", "Area", "Neighbor", "Protocol", "State", "BFD", "Up for"].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows)))));
    addresses(box, st);
  }

  const both = async () => { const [a, b] = await Promise.all([api("GET", "/api/bgp"), api("GET", "/api/ospf")]); return [a.data, b.data]; };
  return {
    async mount(main) {
      boxB = h("div", {}); boxO = h("div", {});
      const panes = [h("div", { role: "tabpanel" }, boxB), h("div", { role: "tabpanel" }, boxO)];
      main.append(anycastTabs("anycastMonTab", "Anycast routing", panes), ...panes);
      draw(...(await both()));
    },
    async poll() { draw(...(await both())); },
    poll_ms: 5000,
  };
})();
