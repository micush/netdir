"use strict";
// MCP Network Director web GUI: the anycast page.

// ── Anycast, Configure  (CLI: --asn, --router-id, --bgp-neighbor-add/-del) ──────
VIEWS.anycast = (() => {
  let status, settings, nbrs, cfg = null, sel = null, draft = null, rows = new Map(), chain = Promise.resolve();
  const clone = (o) => JSON.parse(JSON.stringify(o));

  function save(next, keepForm) {
    chain = chain.then(async () => {
      try { const st = (await api("PUT", "/api/bgp", next)).data; say(status, "ok"); cfg = st.config; return true; }
      catch (e) { fail(status)(e); if (!keepForm) await load(); return false; }
    });
    return chain;
  }

  function select(key) {
    sel = key;
    for (const [k, tr] of rows) tr.classList.toggle("sel", k === key);
  }

  // a password box with an eye beside it: click to see what is typed, click again to hide it
  function withEye(input) {
    const btn = h("button", { class: "pweye", type: "button", title: "Show password", "aria-label": "Show password", "aria-pressed": "false", onclick: () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", String(show));
      btn.title = show ? "Hide password" : "Show password"; btn.setAttribute("aria-label", btn.title);
      btn.classList.toggle("on", show);
    } }, "\u{1F441}");
    return h("div", { class: "pwwrap" }, input, btn);
  }

  function neighborRow(n, idx) {
    const as = h("input", { class: "as", type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", value: String(n.remote_as), "aria-label": "AS of " + n.peer });
    const desc = h("input", { type: "text", value: n.description || "", maxlength: "60", "aria-label": "Description of " + n.peer });
    const pw = h("input", { type: "password", value: n.password || "", autocomplete: "new-password", "aria-label": "Password for " + n.peer });
    const mh = h("input", { class: "as", type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", value: n.multihop > 1 ? String(n.multihop) : "", placeholder: "off", "aria-label": "Multihop of " + n.peer });
    // the address can be changed like the rest of the row; "was" tells the server it is the same neighbor
    const peer = h("input", { class: "mono", type: "text", value: n.peer, spellcheck: "false", autocomplete: "off", "aria-label": "Address of " + n.peer });
    const commit = async () => {
      const addr = peer.value.trim() || n.peer;
      const next = clone(cfg);
      next.neighbors[idx] = { peer: addr, remote_as: Number(as.value) || 0, description: desc.value.trim(), password: pw.value, multihop: Number(mh.value) || 0 };
      if (addr === n.peer) { peer.value = n.peer; save(next); return; }
      next.neighbors[idx].was = n.peer;
      if (await save(next)) { if (sel === n.peer) sel = addr; drawNeighbors(); }
    };
    for (const el of [peer, as, desc, pw, mh]) el.addEventListener("change", commit);
    // on/off for this one neighbor (the same as Operate ▸ Anycast): off shuts the session down and keeps the neighbor
    const on = h("input", { type: "checkbox", checked: !n.disabled, disabled: !!cfg.disabled, title: cfg.disabled ? "BGP is switched off on this node" : "Off: the session is shut down and nothing is announced to this neighbor", "aria-label": "Neighbor " + n.peer + " enabled" });
    on.addEventListener("change", () => {
      if (!on.checked && !confirm("Disable neighbor " + n.peer + "?\n\nThe session is shut down and nothing is announced to it. The neighbor is kept.")) { on.checked = true; return; }
      on.disabled = true;
      chain = chain.then(async () => {
        try { await api("POST", "/api/bgp/operate", { peer: n.peer, enabled: on.checked }); say(status, "ok"); } catch (e) { fail(status)(e); }
        await load();
      });
    });
    return h("tr", { "data-peer": n.peer }, h("td", {}, peer), h("td", {}, as), h("td", {}, desc), h("td", {}, withEye(pw)), h("td", {}, mh), h("td", {}, on));
  }

  // the new row: becomes a neighbor once it has an address and an AS
  function draftRow() {
    const peer = h("input", { type: "text", placeholder: "192.0.2.1 or 2001:db8::1", spellcheck: "false", "aria-label": "New neighbor address" });
    const as = h("input", { class: "as", type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", placeholder: "AS", "aria-label": "New neighbor AS" });
    const desc = h("input", { type: "text", maxlength: "60", placeholder: "optional", "aria-label": "New neighbor description" });
    const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "optional", "aria-label": "New neighbor password" });
    const mh = h("input", { class: "as", type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", placeholder: "off", "aria-label": "New neighbor multihop" });
    const commit = async () => {
      if (!peer.value.trim() || !(Number(as.value) > 0)) return; // not complete yet
      const next = clone(cfg);
      next.neighbors.push({ peer: peer.value.trim(), remote_as: Number(as.value), description: desc.value.trim(), password: pw.value, multihop: Number(mh.value) || 0 });
      if (await save(next, true)) { draft = null; sel = peer.value.trim(); drawNeighbors(); }
    };
    for (const el of [peer, as, desc, pw, mh]) el.addEventListener("change", commit);
    draft = { peer, focus: () => peer.focus() };
    return h("tr", { "data-peer": "" }, h("td", {}, peer), h("td", {}, as), h("td", {}, desc), h("td", {}, withEye(pw)), h("td", {}, mh), h("td", {}));
  }

  function drawNeighbors() {
    rows = new Map();
    const add = h("button", { class: "btn small", type: "button", "aria-label": "Add a neighbor", title: "Add a neighbor", onclick: () => {
      if (draft) { draft.focus(); return; }
      const tr = draftRow(); body.append(tr); rows.set("", tr); select(""); draft.focus();
      const e = body.querySelector(".empty"); if (e) e.closest("tr").remove();
    } }, "+");
    const del = h("button", { class: "btn small", type: "button", "aria-label": "Remove the selected neighbor", title: "Remove the selected neighbor", onclick: () => {
      if (sel === null) { say(status, "bad", "Click a neighbor first, then remove it."); return; }
      if (sel === "") { draft = null; drawNeighbors(); return; }
      if (!confirm("Remove neighbor " + sel + "?")) return;
      const next = clone(cfg); next.neighbors = next.neighbors.filter((x) => x.peer !== sel);
      sel = null; save(next).then(drawNeighbors);
    } }, "−");
    const body = h("tbody", {});
    cfg.neighbors.forEach((n, i) => { const tr = neighborRow(n, i); body.append(tr); rows.set(n.peer, tr); });
    draft = null;
    if (!cfg.neighbors.length) body.append(h("tr", {}, h("td", { colspan: 6, class: "empty" }, "No neighbors yet. Press + to add one.")));
    for (const [k, tr] of rows) { const pick = () => select(k); tr.addEventListener("click", pick); tr.addEventListener("focusin", pick); }
    if (sel !== null && !rows.has(sel)) sel = null;
    clear(nbrs).append(section("Neighbors",
      h("div", { class: "toolbar tight" }, add, del),
      h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Neighbor", "AS", "Description", "Password", "Multihop", "Enabled"].map((t) => h("th", {}, t)))), body))));
    select(sel);
  }

  function drawSettings() {
    const asn = h("input", { type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", value: cfg.asn ? String(cfg.asn) : "", placeholder: "64512" });
    const rid = h("input", { type: "text", value: cfg.router_id || "", placeholder: "192.0.2.1 (optional)", spellcheck: "false" });
    const secs = (v, d, label) => h("input", { class: "narrow", type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", value: String(v || d), "aria-label": label });
    const ka = secs(cfg.keepalive, 3, "Keepalive"), hold = secs(cfg.hold, 9, "Hold time");
    const prepNow = Number(cfg.as_prepend_count) || (cfg.as_prepend ? 3 : 0);   // an older config: on was 3
    const prep = h("select", { "aria-label": "AS Prepend" }, Array.from({ length: 9 }, (_, n) => h("option", { value: String(n), selected: n === prepNow }, n ? String(n) : "0 (off)")));
    const bfd = h("select", { "aria-label": "BFD" }, h("option", { value: "yes", selected: !cfg.bfd_off }, "Yes"), h("option", { value: "no", selected: !!cfg.bfd_off }, "No"));
    const needAS = () => { rid.disabled = !(Number(asn.value) > 0); };   // a router ID means nothing without an AS
    needAS();
    const commit = () => {
      if (!(Number(asn.value) > 0)) rid.value = "";   // clearing the AS clears the router ID with it
      needAS();
      const next = clone(cfg);
      next.asn = Number(asn.value) || 0; next.router_id = rid.value.trim();
      next.keepalive = Number(ka.value) || 0; next.hold = Number(hold.value) || 0;
      delete next.as_prepend;
      if (Number(prep.value) > 0) next.as_prepend_count = Number(prep.value); else delete next.as_prepend_count;
      if (bfd.value === "no") next.bfd_off = true; else delete next.bfd_off;
      save(next);
    };
    asn.addEventListener("input", needAS);
    for (const el of [asn, rid, ka, hold, prep, bfd]) el.addEventListener("change", commit);
    clear(settings).append(section("BGP",
      h("div", { class: "bgprow" },
        h("label", { class: "f" }, h("span", {}, "Local AS number"), asn),
        h("label", { class: "f" }, h("span", {}, "Router ID"), rid),
        h("label", { class: "f" }, h("span", {}, "Keepalive"), ka),
        h("label", { class: "f" }, h("span", {}, "Hold time"), hold),
        h("label", { class: "f" }, h("span", {}, "AS Prepend"), prep),
        h("label", { class: "f" }, h("span", {}, "BFD"), bfd))));
  }

  async function load() {
    const st = (await api("GET", "/api/bgp")).data;
    cfg = st.config;
    if (st.blocked) {
      clear(nbrs);
      clear(settings).append(section("BGP", h("div", { class: "muted" }, "BGP is unavailable: AnyName is installed on this host.")));
      return;
    }
    drawSettings(); drawNeighbors();
  }

  // ── OSPF tab ──
  let ocfg = null, ohost = [], osettings, oifs, osel = null, odraft = null, orows = new Map(), orid = null;

  function osave(next, keepForm) {
    chain = chain.then(async () => {
      try { const st = (await api("PUT", "/api/ospf", next)).data; say(status, "ok"); ocfg = st.config; ohost = st.host_interfaces || ohost; return true; }
      catch (e) { fail(status)(e); if (!keepForm) await oload(); return false; }
    });
    return chain;
  }

  function oselect(key) {
    osel = key;
    for (const [k, tr] of orows) tr.classList.toggle("sel", k === key);
  }

  const LINKS = [["", "Default"], ["point-to-point", "Point-to-point"], ["broadcast", "Broadcast"]];
  const linkSelect = (value, label) => h("select", { "aria-label": label }, ...LINKS.map(([v, t]) => h("option", { value: v, selected: v === (value || "") }, t)));
  const areaInput = (value, label) => h("input", { class: "as", type: "text", autocomplete: "off", value: value && value !== "0.0.0.0" ? value : "", placeholder: "0", spellcheck: "false", "aria-label": label });

  function interfaceRow(f, idx) {
    const area = areaInput(f.area, "Area of " + f.name);
    const link = linkSelect(f.network, "Link type of " + f.name);
    const key = h("input", { type: "password", value: f.password || "", autocomplete: "new-password", maxlength: "16", "aria-label": "Key for " + f.name });
    const commit = () => {
      const next = clone(ocfg);
      next.interfaces[idx] = { name: f.name, area: area.value.trim(), network: link.value, password: key.value };
      osave(next);
    };
    for (const el of [area, link, key]) el.addEventListener("change", commit);
    // on/off for this one interface (the same as Operate ▸ Anycast): off makes it passive, no neighbors, and keeps it
    const on = h("input", { type: "checkbox", checked: !f.disabled, disabled: !!ocfg.disabled, title: ocfg.disabled ? "OSPF is switched off on this node" : "Off: no hellos are sent and no neighbors are formed on this interface", "aria-label": "Interface " + f.name + " enabled" });
    on.addEventListener("change", () => {
      if (!on.checked && !confirm("Disable OSPF on " + f.name + "?\n\nNo hellos are sent and its neighbors go down. The interface is kept.")) { on.checked = true; return; }
      on.disabled = true;
      chain = chain.then(async () => {
        try { await api("POST", "/api/ospf/operate", { interface: f.name, enabled: on.checked }); say(status, "ok"); } catch (e) { fail(status)(e); }
        await oload();
      });
    });
    return h("tr", { "data-iface": f.name }, h("td", { class: "mono" }, f.name), h("td", {}, area), h("td", {}, link), h("td", {}, withEye(key)), h("td", {}, on));
  }

  // the new row: becomes an interface once it has a name
  function draftInterfaceRow() {
    const list = "ospf-host-ifs";
    const name = h("input", { type: "text", list, placeholder: "eth0", spellcheck: "false", autocomplete: "off", "aria-label": "New interface name" });
    const dl = h("datalist", { id: list }, ...ohost.filter((n) => !ocfg.interfaces.some((f) => f.name === n)).map((n) => h("option", { value: n })));
    const area = areaInput("", "New interface area");
    const link = linkSelect("", "New interface link type");
    const key = h("input", { type: "password", autocomplete: "new-password", placeholder: "optional", maxlength: "16", "aria-label": "New interface key" });
    const commit = async () => {
      if (!name.value.trim()) return; // not complete yet
      const rid = orid.value.trim();
      if (!rid) { say(status, "bad", "Enter the router ID first (an IPv4 address that is unique among your routers), then add the interface."); orid.focus(); return; }
      const next = clone(ocfg);
      next.router_id = rid;
      next.interfaces.push({ name: name.value.trim(), area: area.value.trim(), network: link.value, password: key.value });
      if (await osave(next, true)) { odraft = null; osel = name.value.trim(); drawOSPF(); }
    };
    for (const el of [name, area, link, key]) el.addEventListener("change", commit);
    odraft = { name, focus: () => name.focus() };
    return h("tr", { "data-iface": "" }, h("td", {}, name, dl), h("td", {}, area), h("td", {}, link), h("td", {}, withEye(key)), h("td", {}));
  }

  function drawOSPF() {
    // settings
    const rid = h("input", { type: "text", value: ocfg.router_id || "", placeholder: "192.0.2.10", spellcheck: "false", "aria-label": "OSPF router ID" });
    orid = rid;
    const num = (v, d, label) => h("input", { class: "narrow", type: "text", inputmode: "numeric", pattern: "[0-9]*", autocomplete: "off", value: String(v || d), "aria-label": label });
    const hello = num(ocfg.hello, 10, "Hello interval"), dead = num(ocfg.dead, 40, "Dead interval"), metric = num(ocfg.metric, 20, "Metric");
    const commit = () => {
      if (!ocfg.interfaces.length) return; // saved with the first interface (the router ID means nothing without one)
      const next = clone(ocfg);
      next.router_id = rid.value.trim();
      next.hello = Number(hello.value) || 0; next.dead = Number(dead.value) || 0; next.metric = Number(metric.value) || 0;
      if (next.hello === 10) next.hello = 0;
      if (next.dead === 40) next.dead = 0;
      if (next.metric === 20) next.metric = 0;
      osave(next);
    };
    for (const el of [rid, hello, dead, metric]) el.addEventListener("change", commit);
    clear(osettings).append(section("OSPF",
      h("div", { class: "bgprow" },
        h("label", { class: "f" }, h("span", {}, "Router ID"), rid),
        h("label", { class: "f" }, h("span", {}, "Hello interval"), hello),
        h("label", { class: "f" }, h("span", {}, "Dead interval"), dead),
        h("label", { class: "f" }, h("span", {}, "Metric"), metric))));

    // interfaces
    orows = new Map();
    const add = h("button", { class: "btn small", type: "button", "aria-label": "Add an interface", title: "Add an interface", onclick: () => {
      if (odraft) { odraft.focus(); return; }
      const tr = draftInterfaceRow(); body.append(tr); orows.set("", tr); oselect(""); odraft.focus();
      const e = body.querySelector(".empty"); if (e) e.closest("tr").remove();
    } }, "+");
    const del = h("button", { class: "btn small", type: "button", "aria-label": "Remove the selected interface", title: "Remove the selected interface", onclick: () => {
      if (osel === null) { say(status, "bad", "Click an interface first, then remove it."); return; }
      if (osel === "") { odraft = null; drawOSPF(); return; }
      if (!confirm("Remove interface " + osel + " from OSPF?")) return;
      const next = clone(ocfg); next.interfaces = next.interfaces.filter((x) => x.name !== osel);
      osel = null; osave(next).then(drawOSPF);
    } }, "−");
    const body = h("tbody", {});
    ocfg.interfaces.forEach((f, i) => { const tr = interfaceRow(f, i); body.append(tr); orows.set(f.name, tr); });
    odraft = null;
    if (!ocfg.interfaces.length) body.append(h("tr", {}, h("td", { colspan: 5, class: "empty" }, "No interfaces yet. Enter a router ID, then press + to add one.")));
    for (const [k, tr] of orows) { const pick = () => oselect(k); tr.addEventListener("click", pick); tr.addEventListener("focusin", pick); }
    if (osel !== null && !orows.has(osel)) osel = null;
    clear(oifs).append(section("Interfaces",
      h("div", { class: "toolbar tight" }, add, del),
      h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Interface", "Area", "Link type", "Key (OSPFv2)", "Enabled"].map((t) => h("th", {}, t)))), body))));
    oselect(osel);
  }

  async function oload() {
    const st = (await api("GET", "/api/ospf")).data;
    ocfg = st.config; ohost = st.host_interfaces || [];
    if (st.blocked) { clear(osettings).append(section("OSPF", h("div", { class: "muted" }, "OSPF is not available here: " + st.blocked + "."))); clear(oifs); return; }
    drawOSPF();
  }

  return {
    async mount(main) {
      status = h("div", { "aria-live": "polite" }); settings = h("div", {}); nbrs = h("div", {});
      osettings = h("div", {}); oifs = h("div", {});
      sel = null; draft = null; osel = null; odraft = null;
      // two tabs: BGP and OSPF.  Both stay in the page; the hidden one is just not shown.
      const TABS = [["BGP", h("div", {}, settings, nbrs)], ["OSPF", h("div", {}, osettings, oifs)]];
      const panes = TABS.map(([, el]) => h("div", { role: "tabpanel" }, el));
      const buttons = TABS.map(([name], i) => h("button", { type: "button", role: "tab", class: "dtab", onclick: () => show(i) }, name));
      function show(i, focus) {
        state.anycastTab = i;
        refreshHelp();
        panes.forEach((p, j) => { p.hidden = j !== i; });
        buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
        if (focus) buttons[i].focus();
      }
      const strip = h("div", { class: "dtabs", role: "tablist", "aria-label": "Anycast routing" }, buttons);
      strip.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        show((state.anycastTab + d + TABS.length) % TABS.length, true);
      });
      show(state.anycastTab >= 0 && state.anycastTab < TABS.length ? state.anycastTab : 0);
      main.append(status, strip, ...panes);
      try { await load(); } catch (e) { fail(status)(e); }
      try { await oload(); } catch (e) { fail(status)(e); }
    },
  };
})();
