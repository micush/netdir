"use strict";
// MCP Network Director web GUI: the settings page.

const LB = ["roundrobin", "weighted", "hostpinned", "failover"];
const GROUP_FIELDS = [
  { shared: true, k: "name", l: "Name", t: "text", hint: "Optional label." },
  { shared: true, k: "group_id", l: "Group ID", t: "int", min: 1, max: 255, def: 1 },
  { k: "interface", l: "Interface", t: "text" },
  { shared: true, k: "fqdn", l: "VIP FQDN", t: "text", hint: "Optional, e.g. vip.example.com." },
  { shared: true, k: "anycast_fqdn", l: "Anycast FQDN", t: "text", hint: "Optional, e.g. any.example.com." },
  { shared: true, k: "vip4", l: "IPv4 VIP/prefix", t: "text", hint: "e.g. 10.0.0.1/24 — empty to disable" },
  { shared: true, k: "vip6", l: "IPv6 VIP/prefix", t: "text", hint: "e.g. 2001:db8::1/64 — empty to disable" },
  { shared: true, k: "more_vip4", l: "More IPv4 addresses", t: "rows", rows: "morevip4", wide: true, hint: "Same subnet, one per row." },
  { shared: true, k: "more_vip6", l: "More IPv6 addresses", t: "rows", rows: "morevip6", wide: true, hint: "Same subnet, one per row." },
  { k: "priority", l: "Priority", t: "int", min: 0, max: 255, def: 100 },
  { shared: true, k: "lb_method", l: "LB method", t: "select", options: LB },
  { k: "weight", l: "Weight", t: "int", min: 0, max: 255, def: 100 },
  { shared: true, k: "hello_ms", l: "Hello interval (ms)", t: "int", min: 1, max: 65535, def: 150 },
  { shared: true, k: "hold_ms", l: "Hold time (ms)", t: "int", min: 1, max: 65535, def: 750 },
  { shared: true, k: "max_afns", l: "Max forwarders", t: "int", min: 1, max: 255, def: 128 },
  { shared: true, k: "key", l: "HMAC shared key", t: "text", weakKey: true },
  { k: "preempt", l: "Preemption", t: "bool" },
  { shared: true, k: "real_macs", l: "Use real MAC addresses (no virtual MACs)", t: "bool" },
  { shared: true, k: "neighbors", l: "Neighbors (unicast mode)", t: "rows", rows: "neighbors", wide: true, hint: "Empty: multicast." },
];
const SSO_FIELDS = [
  { shared: true, k: "sso_base_url", brk: true, l: "Address of this console", t: "text" },
  { shared: true, k: "sso_google_client_id", brk: true, l: "Google client ID", t: "text" },
  { shared: true, k: "sso_google_client_secret", l: "Google client secret", t: "secret" },
  { shared: true, k: "sso_entra_tenant", brk: true, l: "Microsoft tenant ID", t: "text" },
  { shared: true, k: "sso_entra_client_id", l: "Microsoft client ID", t: "text" },
  { shared: true, k: "sso_entra_client_secret", l: "Microsoft client secret", t: "secret" },
  { shared: true, k: "sso_oidc_name", brk: true, l: "OpenID Connect button name", t: "text" },
  { shared: true, k: "sso_oidc_issuer", l: "OpenID Connect issuer", t: "text" },
  { shared: true, k: "sso_oidc_client_id", l: "OpenID Connect client ID", t: "text" },
  { shared: true, k: "sso_oidc_client_secret", l: "OpenID Connect client secret", t: "secret" },
  { shared: true, k: "sso_oidc_skip_verify", l: "Do not check the provider's certificate", t: "bool" },
  { shared: true, k: "sso_mcp", l: "SSO sign-in for MCP", t: "bool" },
  { shared: true, k: "sso_users", l: "Users", t: "rows", rows: "ssousers", wide: true },
];

// Configure ▸ Users ▸ SSO: a tab for the settings every provider shares (the console's address, who may sign in) and one for each provider
const SSO_TABS = [
  ["General", ["sso_base_url", "sso_mcp", "sso_users"]],
  ["Google", ["sso_google_client_id", "sso_google_client_secret"]],
  ["Microsoft", ["sso_entra_tenant", "sso_entra_client_id", "sso_entra_client_secret"]],
  ["OpenID Connect", ["sso_oidc_name", "sso_oidc_issuer", "sso_oidc_client_id", "sso_oidc_client_secret", "sso_oidc_skip_verify"]],
];
function ssoTabs(obj) {
  const sets = SSO_TABS.map(([, keys]) => fieldset(SSO_FIELDS.filter((f) => keys.includes(f.k)).map((f) => ({ ...f, brk: false })), obj));
  const panes = sets.map((fs) => h("div", { role: "tabpanel" }, fs.el));
  const buttons = SSO_TABS.map(([name], i) => h("button", { type: "button", role: "tab", class: "dtab sub", onclick: () => show(i) }, name));
  function show(i, focus) {
    state.ssoTab = i;
    refreshHelp();
    panes.forEach((pn, j) => { pn.hidden = j !== i; });
    buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
    if (focus) buttons[i].focus();
  }
  const strip = h("div", { class: "dtabs sub", role: "tablist", "aria-label": "Single sign-on" }, buttons);
  strip.addEventListener("keydown", (e) => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    show((state.ssoTab + d + SSO_TABS.length) % SSO_TABS.length, true);
  });
  show(state.ssoTab >= 0 && state.ssoTab < SSO_TABS.length ? state.ssoTab : 0);
  return { el: h("div", {}, strip, ...panes), get: () => Object.assign({}, ...sets.map((fs) => fs.get())) };
}

// Configure ▸ Users ▸ LDAP: sign-in with a directory (Active Directory, Samba 4), and a Test button that says what happens
const LDAP_FIELDS = [
  { shared: true, k: "ldap_servers", l: "LDAP servers", t: "rows", rows: "ldapservers", wide: true },
  { shared: true, k: "ldap_skip_verify", l: "Do not check the server's certificate", t: "bool" },
  { shared: true, k: "ldap_bind_dn", l: "Bind account", t: "text" },
  { shared: true, k: "ldap_bind_password", l: "Bind password", t: "secret" },
  { shared: true, k: "ldap_base_dn", l: "Search base", t: "text" },
  { shared: true, k: "ldap_rw_group", l: "Full-access group", t: "text" },
  { shared: true, k: "ldap_ro_group", l: "Read-only group", t: "text" },
];
function ldapTab(obj) {
  const fs = fieldset(LDAP_FIELDS, obj);
  // two lines: bind account, bind password and search base; then the full-access and the read-only group
  fs.el.classList.add("ldap6");
  [...fs.el.querySelectorAll(":scope > label.f:not(.check)")].forEach((el, i) => el.classList.add(i < 3 ? "span2" : "span3"));
  const user = h("input", { type: "text", autocomplete: "off", spellcheck: "false", "aria-label": "User name to test", placeholder: "alice" });
  const pass = h("input", { type: "password", autocomplete: "new-password", "aria-label": "Password to test", placeholder: "optional" });
  const out = h("pre", { class: "ldap-out hidden", role: "status", "aria-live": "polite" });
  const btn = h("button", { type: "button", class: "btn" }, "Test");
  const run = async () => {
    btn.disabled = true;
    out.classList.remove("hidden");
    out.textContent = "Trying…";
    try {
      const d = (await api("POST", "/api/ldap/test", { username: user.value.trim(), password: pass.value }, true)).data;
      out.textContent = (d.ok ? "OK" + (d.read_only ? " (read-only access)" : "") : "Not accepted") + "\n" + d.steps.map((x) => "  " + x).join("\n");
    } catch (e) { out.textContent = "Could not test: " + (e.message || e); }
    btn.disabled = false;
  };
  btn.addEventListener("click", run);
  for (const i of [user, pass]) i.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); run(); } });
  const test = h("div", { class: "ldap-test" },
    h("h3", {}, "Test"),
    h("div", { class: "ldap-test-row" },
      h("label", { class: "f" }, "User name", user), h("label", { class: "f" }, "Password", pass), btn),
    out);
  test.addEventListener("change", (e) => e.stopPropagation());   // the test boxes are not settings
  return { el: h("div", {}, fs.el, test), get: fs.get };
}

const WEB_FIELDS = [
  { k: "listen", l: "Listen address", t: "port", def: "22161", hint: "Port, or address:port." },
  { shared: true, k: "group", l: "Login groups", t: "text", hint: "Separated by commas." },
  { shared: true, k: "read_group", l: "Read-only groups", t: "text", hint: "Same form. Empty: nobody." },
  { k: "pam_service", l: "PAM service", t: "text" },
  { k: "session_idle_minutes", l: "Session idle timeout (min)", t: "int", min: 1, def: 30 },
  { shared: true, k: "max_failed_logins", l: "Failed logins before lockout", t: "int", min: 1, max: 1000, def: 3 },
  { shared: true, k: "failed_login_window_minutes", l: "…within this many minutes", t: "int", min: 1, max: 10080, def: 1 },
  { shared: true, k: "lockout_minutes", l: "Lockout lasts (minutes)", t: "int", min: 1, max: 10080, def: 15 },
  { shared: true, k: "min_password_length", l: "Minimum password length", t: "int", min: 0, max: 128, def: 8, zeroDef: true },
];
const SNMP_FIELDS = [
  { k: "location", l: "Location", t: "text" },
  { shared: true, k: "snmp_contact", l: "Contact", t: "text" },
  { shared: true, k: "snmp_communities", l: "Community strings", t: "rows", rows: "community", wide: true },
  { shared: true, k: "snmp_acl", l: "Allowed sources", t: "rows", rows: "snmpacl", wide: true },
];
const PROM_FIELDS = [
  { shared: true, k: "metrics_acl", l: "Allowed sources", t: "rows", rows: "metricsacl", wide: true },
];
// Configure ▸ Settings ▸ General ▸ Neighbor discovery (lldp.go)
// Configure ▸ Settings ▸ General ▸ Topology (settings.topology_squares_above): how many devices a gateway may have before the drawing turns each into a small square
const TOPO_FIELDS = [
  { shared: true, k: "topology_squares_above", l: "Small square limit", unit: "devices", t: "int", min: 1, max: 5000, def: 36, hint: "Above this many, devices become squares." },
];
const LLDP_FIELDS = [
  { shared: true, k: "lldp", l: "Run LLDP on every node", t: "bool" },
];
// Configure ▸ Devices (devices.go): the inventory and the logins, shared by the cluster
const DEVICE_FIELDS = [
  { shared: true, k: "devices", l: "Devices", t: "rows", rows: "devices", wide: true, hint: "Tags: tag:site=dc1." },
];
const DEVCHECK_FIELDS = [
  { shared: true, k: "device_live_check_s", unit: "s", l: "Active checks", t: "int", min: 10, max: 600, def: 30 },
  { shared: true, k: "device_live_facts_min", unit: "min", l: "Active facts", t: "int", min: 1, max: 60, def: 5 },
  { shared: true, k: "device_check_s", unit: "s", l: "Idle checks", t: "int", min: 30, max: 3600, def: 180 },
  { shared: true, k: "device_facts_min", unit: "min", l: "Idle facts", t: "int", min: 5, max: 1440, def: 360 },
];
const DEVCRED_FIELDS = [
  { shared: true, k: "device_credentials", l: "Logins", t: "rows", rows: "devcreds", wide: true, hint: "Password or API token." },
];
const MCP_FIELDS = [
  { shared: true, k: "mcp_port", l: "Port", t: "int", min: 1, max: 65535, def: 443 },
  { shared: true, k: "mcp_max_result_mb", l: "Largest answer (MB)", t: "int", min: 1, max: 8, def: 1 },
  { shared: true, k: "mcp_log", l: "Log all MCP requests and replies", t: "bool" },
  { shared: true, k: "mcp_log_mb", unit: "MB", l: "Log size limit", t: "int", min: 1, max: 1000, def: 50 },
  { shared: true, k: "mcp_log_entry_kb", unit: "KB", l: "Entry size limit", t: "int", min: 1, max: 8192, def: 256 },
  { shared: true, k: "mcp_acl", l: "Allowed sources", t: "rows", rows: "mcpacl", wide: true },
  { shared: true, k: "mcp_keys", l: "Keys", t: "mcpkeys", wide: true },
];
const CLUSTER_FIELDS = [
  { k: "listen", l: "Binding address", t: "port", def: "22162", hint: "Port, or address:port." },
  { k: "self", l: "Advertised address", t: "text" },
  { k: "sync_interval_sec", l: "Sync interval (s)", t: "int", min: 1, max: 3600, def: 5 },
];
// Configure ▸ Settings ▸ Logs: where this node sends its log (per node, never replicated)
const SYSLOG_FIELDS = [
  { k: "enabled", l: "Send the log to a syslog server", t: "bool", hint: "" },
  { k: "protocol", l: "Protocol", t: "select", options: ["tcp", "udp", "tls"] },
  { k: "server", l: "Server", t: "text", hint: "Host or host:port." },
  { k: "facility", l: "Facility", t: "select", options: ["daemon", "user", "auth", "authpriv", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"] },
  { k: "format", l: "Message format", t: "select", options: ["rfc5424", "rfc3164"] },
  { k: "ca_file", l: "CA certificate file (tls)", t: "text", hint: "PEM file. Empty: system CAs." },
  { k: "tls_insecure", l: "Do not check the server's certificate (tls)", t: "bool" },
];
// Configure ▸ Settings ▸ DNS: this node puts its own addresses into DNS (per node, never replicated)
const DNSREG_FIELDS = [
  { k: "enabled", l: "Register this node's addresses in DNS", t: "bool" },
  { k: "key", l: "TSIG key", t: "secret", hint: "NAME:SECRET[:ALG], or a key file path." },
  { k: "domain", l: "Domain", t: "text", hint: "Empty: the resolver's search domain." },
  { k: "server", l: "Server", t: "text", hint: "Empty: the zone's primary (from the SOA)." },
  { k: "interval_sec", l: "Check every (s)", t: "int", min: 30, max: 86400, def: 300 },
  { k: "ttl", l: "TTL (s)", t: "int", min: 1, max: 604800, def: 900 },
  { k: "skip_interfaces", l: "Leave out interfaces", t: "text", hint: "Names or patterns, e.g. docker*, veth*" },
];
const LOG_FIELDS = [{ k: "log_level", l: "Log level", t: "select", options: ["debug", "info", "warning", "error"] }];
// the short lists (a handful of rows) have no filter box and no paging; the long ones (clients, domains, users) do
const SMALL_TABLES = new Set(["ldapservers", "neighbors", "morevip4", "morevip6", "community", "snmpacl", "metricsacl", "mcpacl"]);
// The devices a key or an allowed source may use: a pill for each device name or tag:TAG, and the two special ones, all (no pills) and none.
// The choices are the devices of the inventory and their tags; any other name can be typed (a device added later).
let devChoices = { names: [], tags: [], gateways: [] };   // gateways: [{id, name}]
const gwPillLabel = (x) => { const m = /^gateway:(\d+)$/.exec(x); if (!m) return x; const g = devChoices.gateways.find((y) => String(y.id) === m[1]); return "gateway:" + (g && g.name ? g.name : m[1]); };
let devPickSeq = 0;
function devicePicker(list, onChange) {
  let items = (list || []).filter(Boolean);
  const ENTRY = /^(tag:[^\s,"]{1,80}|gateway:\d{1,9}|[A-Za-z0-9._-]{1,80})$/;
  const el = h("div", { class: "devpick", role: "group", "aria-label": "Devices" });
  const dl = h("datalist", { id: "devpick-" + (++devPickSeq) });
  const input = h("input", { type: "text", list: dl.id, autocomplete: "off", spellcheck: "false", placeholder: "add device or tag", "aria-label": "Add a device or tag",
    title: "A device name, tag:TAG (every device with the tag, now and later), all or none. Pick from the list or type, then Enter." });
  function draw() {
    const have = new Set(items.map((x) => x.toLowerCase()));
    dl.replaceChildren(...["all", "none", ...devChoices.names, ...devChoices.tags.map((t) => "tag:" + t), ...devChoices.gateways.map((g) => "gateway:" + g.id)].filter((o) => !have.has(o.toLowerCase())).map((o) => h("option", { value: o, label: gwPillLabel(o) })));
    clear(el).append(...(items.length ? items : ["all"]).map((x) => {
      const special = !items.length || x === "none";
      const p = h("span", { class: "pill " + (special ? "special" : x.startsWith("tag:") ? "warn" : x.startsWith("gateway:") ? "ok" : "info"), title: x.startsWith("gateway:") ? "The gateway and every device on it, now and later" : "" }, gwPillLabel(x));
      if (items.length) p.append(h("button", { type: "button", "aria-label": "Remove " + x, title: "Remove " + x, onclick: () => set(items.filter((y) => y !== x)) }, "\u00d7"));
      return p;
    }), input, dl);
  }
  function set(next) {
    items = next;
    draw();
    onChange(items);
    el.dispatchEvent(new Event("change", { bubbles: true }));
    input.focus();
  }
  function add() {
    let v = input.value.trim(), low = v.toLowerCase();
    if (!v) return;
    const gn = low.startsWith("gateway:") ? low.slice(8) : low;   // a gateway typed by its name (or by its number)
    const gw = devChoices.gateways.find((g) => (g.name && g.name.toLowerCase() === gn) || String(g.id) === gn && low.startsWith("gateway:"));
    if (gw && !devChoices.names.some((n) => n.toLowerCase() === low)) { v = "gateway:" + gw.id; low = v; }
    if (low === "all") { input.value = ""; return set([]); }
    if (low === "none") { input.value = ""; return set(["none"]); }
    if (!ENTRY.test(v)) { input.classList.add("bad"); return; }
    input.value = "";
    if (items.some((x) => x.toLowerCase() === low)) return;
    set([...items.filter((x) => x !== "none"), v]);
  }
  input.addEventListener("input", (e) => { input.classList.remove("bad"); if (!e.inputType || e.inputType === "insertReplacementText") add(); });   // a choice from the list
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === ",") { e.preventDefault(); e.stopPropagation(); add(); }
    else if (e.key === "Backspace" && !input.value && items.length) set(items.slice(0, -1));
  });
  input.addEventListener("change", (e) => { e.stopPropagation(); add(); });
  draw();
  return el;
}

// A field of a table whose text does not fit its box shows the whole text as a tooltip.  It is checked when the pointer arrives, the box gets
// the focus or its text changes, so a box that is wide enough has none.  A secret is never put in a tooltip.
const tipCtx = document.createElement("canvas").getContext("2d");
function tipWhenCut(el, text) {
  const set = () => {
    const t = text();
    let cut = false;
    if (t && el.tagName === "SELECT") {   // a select's text is not scrollable: measure it against the room inside the box (less the arrow)
      const cs = getComputedStyle(el);
      tipCtx.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
      cut = tipCtx.measureText(t).width > el.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - 24;
    } else if (t) cut = el.scrollWidth > el.clientWidth;
    if (cut) el.title = t; else el.removeAttribute("title");
  };
  for (const ev of ["mouseenter", "focus", "input", "change"]) el.addEventListener(ev, set);
}

// Configure ▸ Devices ▸ Tags: one row to each tag in the Tags column of the devices table, built the same way as the other tables
// (filter, pages, right-click).  Changing a tag's text renames it on every device that has it; Remove takes it off every device.
// devTable() is the devices table, col its Tags column, showDevices() brings its tab forward.
function tagTable(devTable, col, showDevices) {
  let page = 0, size = 50;
  const tbody = h("tbody", {});
  const tbl = h("table", { class: "policy zones rows tagtable" }, h("thead", {}, h("tr", {}, h("th", { "aria-label": "Row number" }, "#"), h("th", {}, "Tag"), h("th", { class: "num" }, "Devices"))), tbody);
  const empty = h("div", { class: "policy-empty" }, "");
  const wrap = h("div", { class: "policy-wrap" }, tbl, empty);
  const filter = h("input", { type: "text", class: "policy-filter", placeholder: "Filter tags", "aria-label": "Filter tags", autocomplete: "off", spellcheck: "false" });
  const count = h("span", { class: "policy-count muted" }, "");
  const sizeSel = h("select", { "aria-label": "Rows per page" }, [25, 50, 100, 250, 500].map((n) => h("option", { value: String(n) }, n + " per page")));
  sizeSel.value = String(size);
  const mkBtn = (label, title) => h("button", { type: "button", class: "btn small", title, "aria-label": title }, label);
  const first = mkBtn("«", "First page"), prev = mkBtn("‹", "Previous page"), next = mkBtn("›", "Next page"), last = mkBtn("»", "Last page");
  const pageIn = h("input", { type: "number", min: "1", class: "policy-page", "aria-label": "Page number" });
  const pages = h("span", { class: "muted" }, "");
  const pager = h("span", { class: "policy-pager" }, first, prev, pageIn, pages, next, last);
  const bar = h("div", { class: "policy-bar" }, filter, count, h("span", { class: "grow" }), pager, sizeSel);
  const box = h("div", { class: "policy-box rows wide" }, bar, wrap);
  bar.addEventListener("change", (e) => e.stopPropagation());   // the filter and paging controls are not settings
  const tally = () => { const m = new Map(); for (const w of devTable().words(col)) m.set(w, (m.get(w) || 0) + 1); return m; };
  const rename = (t, n, k) => {
    n = n.trim().replace(/[\s,]+/g, "");
    if (!n || n === t) return false;
    if (tally().has(n) && !confirm("There is a tag " + n + " already. Merge " + t + " into it?")) return false;
    devTable().mapWords(col, (w) => (w === t ? n : w));
    return true;
  };
  const remove = (t, k) => { if (confirm("Remove the tag " + t + " from " + k + " device" + (k === 1 ? "" : "s") + "?")) devTable().mapWords(col, (w) => (w === t ? "" : w)); };
  const menuFor = (t, k, inp) => [
    ["Rename", () => { inp.focus(); inp.select(); }],
    ["Copy", () => { try { navigator.clipboard.writeText(t); } catch (e) { /* no clipboard */ } }],
    ["Show the devices with this tag", () => { devTable().setFilter(t); showDevices(); }],
    ["Remove from every device", () => remove(t, k), "danger"],
  ];
  function render() {
    const all = [...tally()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true, sensitivity: "base" }));
    const flt = parseFilter(filter.value), q = !flt.empty, vis = q ? all.filter(([t]) => flt.match((w) => t.toLowerCase().includes(w))) : all;
    const n = Math.max(1, Math.ceil(vis.length / size));
    page = Math.min(Math.max(page, 0), n - 1);
    const from = page * size, shown = vis.slice(from, from + size);
    clear(tbody).append(...shown.map(([t, k], i) => {
      const inp = h("input", { type: "text", value: t, "aria-label": "Tag " + t, autocomplete: "off", spellcheck: "false" });
      inp.addEventListener("change", () => { if (!rename(t, inp.value, k)) inp.value = t; });
      inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); inp.blur(); } else if (e.key === "Escape") { inp.value = t; inp.blur(); } });
      const tr = h("tr", {}, h("td", { class: "grip" }, h("span", { class: "rownum" }, String(from + i + 1))), h("td", {}, inp), h("td", { class: "num" }, String(k)));
      tr.addEventListener("contextmenu", (e) => rowMenu(menuFor(t, k, inp))(e));
      return tr;
    }));
    const filtered = vis.length !== all.length;
    count.textContent = vis.length ? `${from + 1}–${Math.min(from + size, vis.length)} of ${vis.length}${filtered ? ` (filtered from ${all.length})` : ""}` : (filtered ? `0 of ${all.length}` : "0 tags");
    pager.hidden = n < 2;
    pageIn.value = String(page + 1); pageIn.max = String(n); pages.textContent = "of " + n;
    first.disabled = prev.disabled = page === 0; next.disabled = last.disabled = page >= n - 1;
    empty.hidden = vis.length > 0;
    empty.textContent = all.length ? "No tags match the filter." : "No tags yet. Type tags (site=dc1 role=core) in the Tags column of the Devices tab.";
  }
  filter.addEventListener("input", () => { page = 0; render(); });
  filter.addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
  sizeSel.addEventListener("change", () => { size = +sizeSel.value || 50; page = 0; render(); });
  first.addEventListener("click", () => { page = 0; render(); });
  prev.addEventListener("click", () => { page--; render(); });
  next.addEventListener("click", () => { page++; render(); });
  last.addEventListener("click", () => { page = 1e9; render(); });
  pageIn.addEventListener("change", () => { page = (parseInt(pageIn.value, 10) || 1) - 1; render(); });
  pageIn.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); pageIn.blur(); } });
  render();
  return { el: box, refresh: render };
}

function rowTable(spec, lines) {
  const N = spec.cols.length;
  const small = SMALL_TABLES.has(spec.key);
  const data = (lines || []).map((l) => { const v = spec.parse(l); return { v, off: !!(spec.isOff && spec.isOff(l)), ...(spec.track ? { orig: String(v[0] || "").trim() } : {}) }; });
  let page = 0, size = small ? 1e9 : 50, dragging = null;
  const tbody = h("tbody", {});
  const tbl = h("table", { class: "policy zones rows t-" + spec.key + (N === 1 ? " one" : "") },
    h("thead", {}, h("tr", {}, h("th", { "aria-label": "Row number and order" }, "#"), ...spec.cols.map((c) => h("th", {}, c.name)))), tbody);
  const empty = h("div", { class: "policy-empty" }, "");
  const wrap = h("div", { class: "policy-wrap" }, tbl, empty);
  const filter = h("input", { type: "text", class: "policy-filter", placeholder: "Filter rows", "aria-label": "Filter rows", autocomplete: "off", spellcheck: "false" });
  const count = h("span", { class: "policy-count muted" }, "");
  const sizeSel = h("select", { "aria-label": "Rows per page" }, [25, 50, 100, 250, 500].map((n) => h("option", { value: String(n) }, n + " per page")));
  sizeSel.value = String(size);
  const mkBtn = (label, title) => h("button", { type: "button", class: "btn small", title, "aria-label": title }, label);
  const first = mkBtn("«", "First page"), prev = mkBtn("‹", "Previous page"), next = mkBtn("›", "Next page"), last = mkBtn("»", "Last page");
  const pageIn = h("input", { type: "number", min: "1", class: "policy-page", "aria-label": "Page number" });
  const pages = h("span", { class: "muted" }, "");
  const pager = h("span", { class: "policy-pager" }, first, prev, pageIn, pages, next, last);
  const bar = h("div", { class: "policy-bar" }, filter, count, h("span", { class: "grow" }), pager, sizeSel);
  const box = h("div", { class: "policy-box rows" + (spec.wide ? " wide" : "") }, ...(small ? [] : [bar]), wrap);
  bar.addEventListener("change", (e) => e.stopPropagation());   // the filter and paging controls are not settings
  const changed = () => tbl.dispatchEvent(new Event("change", { bubbles: true }));
  const plain = spec.cols.map((c) => !c.secret);   // the filter never looks into a password or a token
  const visible = () => { const flt = parseFilter(filter.value); return flt.empty ? data : data.filter((r) => flt.match((w) => r.v.some((x, i) => plain[i] && (x.toLowerCase().includes(w) || (spec.cols[i].opts === PLATFORMS && platformName(x.trim()).toLowerCase().includes(w)))))); };
  const clearMarks = () => tbody.querySelectorAll(".drop-above, .drop-below").forEach((x) => x.classList.remove("drop-above", "drop-below"));
  const trOf = (row) => [...tbody.children].find((t) => t._row === row);
  const cells = (row) => row.v.map((x) => x.trim());
  const names = () => { const n = {}; for (const r of data) { const x = r.v[0].trim(); if (x) n[x] = (n[x] || 0) + 1; } return n; };   // how many rows carry each first-cell name
  const mark = (tr, row) => { tr.classList.toggle("incomplete", !!spec.mark(cells(row))); };

  function render(follow) {
    const vis = visible();
    const n = Math.max(1, Math.ceil(vis.length / size));
    if (follow) { const i = vis.indexOf(follow); if (i >= 0) page = Math.floor(i / size); }
    page = Math.min(Math.max(page, 0), n - 1);
    const from = page * size;
    tbody.replaceChildren(...vis.slice(from, from + size).map(mk));
    const filtered = vis.length !== data.length;
    count.textContent = vis.length
      ? `${from + 1}–${Math.min(from + size, vis.length)} of ${vis.length}${filtered ? ` (filtered from ${data.length})` : ""}`
      : (filtered ? `0 of ${data.length}` : "0 rows");
    pager.hidden = n < 2;
    pageIn.value = String(page + 1);
    pageIn.max = String(n);
    pages.textContent = "of " + n;
    first.disabled = prev.disabled = page === 0;
    next.disabled = last.disabled = page >= n - 1;
    empty.hidden = vis.length > 0;
    empty.textContent = data.length ? "No rows match the filter." : (spec.empty || "No rows.") + " Right-click here ▸ Add row.";
  }
  function moveTo(row, target, after) {
    if (row === target) return;
    data.splice(data.indexOf(row), 1);
    const j = data.indexOf(target);
    data.splice(after ? j + 1 : j, 0, row);
    render(row);
    changed();
  }
  function mk(row) {
    const tr = h("tr", { class: row.off ? "off" : "" });
    tr._row = row;
    const grip = h("span", { class: "grip-h", draggable: "true", title: "Drag to reorder", "aria-hidden": "true" }, "⋮⋮");
    tr.append(h("td", { class: "grip" }, h("span", { class: "rownum" }, String(data.indexOf(row) + 1)), grip));
    spec.cols.forEach((c, i) => {
      let inp;
      if (c.opts) {
        const opts = c.opts.includes(row.v[i]) || !row.v[i] ? c.opts : [...c.opts, row.v[i]];   // a value this list does not know is kept
        inp = h("select", { "aria-label": c.name }, opts.map((o) => h("option", { value: o }, PLATFORM_LABEL[o] || o)));
        if (!row.v[i]) row.v[i] = c.opts[0];
        inp.value = row.v[i];
        inp.addEventListener("change", () => { row.v[i] = inp.value; mark(tr, row); });
      } else if (c.pills) {
        inp = devicePicker(row.v[i] ? row.v[i].split(",") : [], (l) => { row.v[i] = l.join(","); mark(tr, row); });
      } else if (c.tags) {
        inp = tagPicker((row.v[i] || "").split(/[\s,]+/), (l) => { row.v[i] = l.join(" "); mark(tr, row); }, () => (spec.tagsNow ? spec.tagsNow() : []), c.name);
      } else {
        inp = h("input", { type: c.secret ? "password" : "text", autocomplete: c.secret ? "new-password" : "off", spellcheck: "false", "aria-label": c.name, placeholder: c.ph || "" });
        if (!row.v[i] && c.def) row.v[i] = c.def;   // the default shown as the value, not left empty
        inp.value = row.v[i] || "";
        inp.addEventListener("input", () => { row.v[i] = inp.value; mark(tr, row); });
        if (c.list) {   // a column that offers a list of names while typing (the datalist is filled when the box gets the focus: the names may be unsaved)
          inp.setAttribute("list", c.list);
          inp.addEventListener("focus", () => { if (spec.onList) spec.onList(c.list); });
        }
      }
      if (!c.pills && !c.tags && !c.secret) tipWhenCut(inp, () => (inp.tagName === "SELECT" ? (inp.selectedOptions[0] ? inp.selectedOptions[0].textContent : "") : inp.value));
      tr.append(h("td", {}, inp));
    });
    grip.addEventListener("dragstart", (e) => {
      dragging = row;
      e.dataTransfer.effectAllowed = "move";
      try { e.dataTransfer.setData("text/plain", "row"); e.dataTransfer.setDragImage(tr, 0, 0); } catch (x) { /* a browser without drag images */ }
      tr.classList.add("dragging");
    });
    grip.addEventListener("dragend", () => { dragging = null; tr.classList.remove("dragging"); clearMarks(); });
    tr.addEventListener("dragover", (e) => {
      if (!dragging || dragging === row) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      const r = tr.getBoundingClientRect();
      clearMarks();
      tr.classList.add(e.clientY > r.top + r.height / 2 ? "drop-below" : "drop-above");
    });
    tr.addEventListener("drop", (e) => {
      if (!dragging || dragging === row) return;
      e.preventDefault();
      const below = tr.classList.contains("drop-below");
      clearMarks();
      const d = dragging;
      dragging = null;
      moveTo(d, row, below);
    });
    tr.addEventListener("contextmenu", (e) => rowMenu(menuFor(row))(e));
    tr.addEventListener("keydown", (e) => { if (e.key === "Escape" && row.fresh && isBlank(row)) { e.stopPropagation(); if (document.activeElement) document.activeElement.blur(); dropBlank(row); } });
    tr.addEventListener("focusout", () => setTimeout(() => { if (!tr.contains(document.activeElement)) dropBlank(row); }, 0));
    mark(tr, row);
    return tr;
  }
  // a row added with Add and left empty (Esc, or a click elsewhere) goes away again; a select counts as empty while it shows its first choice
  const isBlank = (row) => row.v.every((x, i) => (spec.cols[i].opts ? x === spec.cols[i].opts[0] : !x.trim() || x === spec.cols[i].def));
  function dropBlank(row) {
    if (!row.fresh || !data.includes(row) || !isBlank(row)) return false;
    const ae = document.activeElement, atr = ae && ae.closest ? ae.closest("tr") : null;
    const keep = atr && atr._row && atr._row !== row && tbody.contains(atr) ? { row: atr._row, col: [...atr.querySelectorAll("input, select")].indexOf(ae), a: ae.selectionStart, b: ae.selectionEnd } : null;
    data.splice(data.indexOf(row), 1);
    render();
    if (keep) { focusRow(keep.row, keep.col); const el = (trOf(keep.row) || {}).querySelectorAll ? trOf(keep.row).querySelectorAll("input, select")[keep.col] : null; try { if (el && keep.a != null) el.setSelectionRange(keep.a, keep.b); } catch (x) { /* a select */ } }
    return true;
  }
  function insert(vals, after) {
    for (const r of data.filter((x) => x.fresh && isBlank(x))) data.splice(data.indexOf(r), 1);
    if (after && !data.includes(after)) after = null;
    const row = { v: Array.from({ length: N }, (_, i) => vals[i] || ""), fresh: !vals.some((x) => x) };
    data.splice(after ? data.indexOf(after) + 1 : data.length, 0, row);
    filter.value = "";
    render(row);
    return row;
  }
  const focusRow = (row, col) => { const t = trOf(row); const el = t && t.querySelectorAll("input, select")[col || 0]; if (el) el.focus(); };
  // pasted rows: the cells separated by tabs, one row to a line (the lines of a spreadsheet), or one line of the list's own form
  const parseText = (txt) => txt.split(/\r?\n/).filter((l) => l.trim()).map((l) => (l.includes("\t") ? l.split("\t").map((x) => x.trim()) : spec.parse(l.trim())));
  async function paste(after) {
    let list = rowClips[spec.key] ? [rowClips[spec.key]] : [];
    if (!list.length) { try { list = parseText(await navigator.clipboard.readText()); } catch (e) { /* no permission: nothing to paste */ } }
    if (!list.length) return;
    let at = after;
    for (const v of list) at = insert(v, at);
    changed();
  }
  function menuFor(row) {
    const vis = visible(), i = vis.indexOf(row), di = data.indexOf(row);
    return [
      ["Edit", () => focusRow(row, 0)],
      ["Copy", () => { rowClips[spec.key] = cells(row).map((x, i) => (spec.cols[i].secret ? "" : x)); try { navigator.clipboard.writeText(rowClips[spec.key].join("\t")); } catch (e) { /* the row stays in the page's own clipboard */ } }],
      ["Paste", () => paste(row)],
      ["Add", () => focusRow(insert([], row), 0)],
      ...(spec.isOff ? [[row.off ? "Enable" : "Disable", () => { row.off = !row.off; render(); changed(); }]] : []),
      ...(i > 0 ? [["Move up", () => moveTo(row, vis[i - 1], false)]] : []),
      ...(i >= 0 && i < vis.length - 1 ? [["Move down", () => moveTo(row, vis[i + 1], true)]] : []),
      ...(di > 0 ? [["Move to top", () => moveTo(row, data[0], false)]] : []),
      ...(di < data.length - 1 ? [["Move to bottom", () => moveTo(row, data[data.length - 1], true)]] : []),
      ["Delete", () => { data.splice(data.indexOf(row), 1); render(); changed(); }, "danger"],
    ];
  }
  wrap.addEventListener("contextmenu", rowMenu([
    ["Add", () => focusRow(insert([], null), 0)],
    ["Paste", () => paste(data[data.length - 1])],
  ]));
  filter.addEventListener("input", () => { page = 0; render(); });
  sizeSel.addEventListener("change", () => { size = +sizeSel.value || 50; page = 0; render(); });
  first.addEventListener("click", () => { page = 0; render(); });
  prev.addEventListener("click", () => { page--; render(); });
  next.addEventListener("click", () => { page++; render(); });
  last.addEventListener("click", () => { page = 1e9; render(); });
  pageIn.addEventListener("change", () => { page = (parseInt(pageIn.value, 10) || 1) - 1; render(); });
  pageIn.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); pageIn.blur(); } });
  filter.addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
  render();
  return {
    el: box,
    // a tracked table (spec.track): the rows that had one name and now have another (original -> now); a new, deleted, unnamed or doubly named row has none
    renames: () => { const n = names(); return new Map(data.filter((r) => r.orig && r.v[0].trim() && r.v[0].trim() !== r.orig && n[r.v[0].trim()] === 1).map((r) => [r.orig, r.v[0].trim()])); },
    // what each row is called now is what it was called: renames start again from here
    commit: () => { const n = names(); for (const r of data) if (r.v[0].trim() && n[r.v[0].trim()] === 1) r.orig = r.v[0].trim(); },
    // a column's values that are keys of the map take the map's value (the Login column follows a renamed login)
    retarget: (col, map) => { let k = 0; for (const r of data) { const x = (r.v[col] || "").trim(); if (map.has(x)) { r.v[col] = map.get(x); k++; } } if (k) render(); return k; },
    setFilter: (t) => { filter.value = t; page = 0; render(); },   // the filter box, as if typed
    // the words of a column of words (the Tags column): every word in use, and a way to rename or remove one in every row (fn gives the new word, or "" to drop it)
    words: (col) => data.flatMap((r) => (r.v[col] || "").split(/[\s,]+/).filter(Boolean)),
    mapWords: (col, fn) => { let k = 0; for (const r of data) { const w = (r.v[col] || "").split(/[\s,]+/).filter(Boolean), n = [...new Set(w.map(fn).filter(Boolean))]; if (n.join(" ") !== w.join(" ")) { r.v[col] = n.join(" "); k++; } } if (k) { render(); changed(); } return k; },
    get: () => (spec.obj ? data.filter((r) => !(spec.drop || spec.mark)(cells(r))).map((r) => spec.obj(cells(r)))
      : data.flatMap((r) => ((spec.drop || spec.mark)(cells(r)) ? [] : spec.format(cells(r)).map((x) => (r.off ? x + " disabled" : x))))),
  };
}

// one value to a row, one row to a list entry (a row with several, separated by commas or spaces, is saved as several entries)
const oneCol = (key, name, ph, empty) => ({
  key, empty, cols: [{ name, ph }],
  parse: (line) => [String(line).trim()],
  format: (c) => c[0].split(/[\s,]+/).filter(Boolean),
  mark: (c) => !c[0],
});
const ROW_TABLES = {
  snmpacl: oneCol("snmpacl", "Address or network", "10.1.0.0/24, 192.0.2.5, 2001:db8::/32", "Nobody may ask."),
  metricsacl: oneCol("metricsacl", "Address or network", "10.1.0.0/24, 192.0.2.5, 2001:db8::/32", "Nobody may read /metrics."),
  // MCP access: "10.1.0.0/24" (read-only), "10.1.1.50 rw", "10.1.0.0/24 strict" (an address or network, ro or rw, a privacy level)
  mcpacl: {
    key: "mcpacl", wide: true, empty: "No sources allowed without a key.",
    cols: [{ name: "Address or network", ph: "10.1.1.50, 10.1.0.0/24" }, { name: "Access", opts: ["ro", "rw"] }, { name: "Privacy", opts: ["default", "none", "standard", "strict"] }, { name: "Devices", pills: true }, { name: "Expires (UTC)", ph: "never, 2026-12-31 or 2026-12-31 17:00" }, { name: "Notes", ph: "what this source is for", note: true }],
    parse: (line) => {
      const [body, ...nt] = String(line).split("#");   // "10.1.1.50 rw # laptop": what it says, and its note
      const w = body.trim().split(/\s+/), f = w.map((x) => x.toLowerCase());
      const lv = f.slice(1).find((x) => ["none", "standard", "strict"].includes(x));
      const dv = w.slice(1).find((x) => x.toLowerCase().startsWith("devices="));
      const un = w.slice(1).find((x) => x.toLowerCase().startsWith("until="));
      return [w[0] || "", f.slice(1).includes("rw") ? "rw" : "ro", lv || "default", dv ? dv.slice(8) : "", un ? un.slice(6).replace("T", " ").replace(/Z$/, "") : "", nt.join("#").trim()];
    },
    format: (c) => c[0].split(/[\s,]+/).filter(Boolean).map((a) => a + (c[1] === "rw" ? " rw" : "") + (c[2] && c[2] !== "default" ? " " + c[2] : "") + (c[3] ? " devices=" + c[3] : "") + (c[4] && c[4].trim() ? " until=" + c[4].trim().replace(/\s+/, "T") : "") + ((c[5] || "").replace(/[#\r\n]/g, " ").trim() ? " # " + c[5].replace(/[#\r\n]/g, " ").trim() : "")),
    mark: (c) => !c[0],
    isOff: (l) => /\sdisabled\s*$/i.test(String(l).split("#")[0]),   // a row switched off with right-click ▸ Disable stays in the list but allows nothing
  },
  neighbors: oneCol("neighbors", "Neighbor IP address", "10.0.0.2", "No neighbors: multicast."),
  morevip4: oneCol("morevip4", "IPv4 address", "10.0.0.11", "No more IPv4 addresses."),
  morevip6: oneCol("morevip6", "IPv6 address", "2001:db8::11", "No more IPv6 addresses."),
  // a community string may contain commas: one string to a row, never split
  community: { ...oneCol("community", "Community string", "", "No community strings: SNMP is off."), format: (c) => [c[0]] },
  // Configure ▸ Devices: one device to a row.  What the table has no column for (options, ca_pem, disabled) is kept from the saved
  // device of the same name (devExtra, filled in when the page is drawn).
  devices: {
    key: "devices", empty: "No devices.", wide: true,
    cols: [{ name: "Name", ph: "core-sw1" }, { name: "Platform", opts: PLATFORMS }, { name: "Address", ph: "10.0.0.2" }, { name: "Port", ph: "443", def: "443" },
      { name: "Login", ph: "a login's name", list: "device-logins" }, { name: "Tags", ph: "site=dc1 role=core", tags: true }, { name: "Certificate", opts: ["skip check", "check"] }, { name: "Options", ph: "serial=Q2XX-XXXX-XXXX" }],
    parse: (d) => {
      if (typeof d === "string") { const f = d.split(/\s+/); return [f[0] || "", f[1] || PLATFORMS[0], f[2] || "", f[3] || "", f[4] || "", "", "skip check", ""]; }
      return [d.name || "", d.platform || PLATFORMS[0], d.address || "", d.port ? String(d.port) : portDef(d.platform), d.credential || "", (d.tags || []).join(" "), d.insecure || !d.ca_pem ? "skip check" : "check", Object.entries(d.options || {}).map(([a, b]) => a + "=" + b).join(" ")];
    },
    format: (c) => {
      const x = { ...(devExtra[c[0]] || {}), name: c[0], platform: c[1], address: c[2], credential: c[4] };
      if (c[3].trim() && c[3].trim() !== portDef(c[1])) x.port = Number(c[3]); else delete x.port;   // 443 is the default and is not written
      const tags = c[5].split(/[\s,]+/).filter(Boolean);
      if (tags.length) x.tags = tags; else delete x.tags;
      if (c[6] === "skip check") { x.insecure = true; delete x.ca_pem; } else delete x.insecure;
      const opts = {};
      for (const p of (c[7] || "").split(/[\s,]+/).filter(Boolean)) { const m = /^([a-z_]{1,32})=(\S{1,100})$/.exec(p); if (m) opts[m[1]] = m[2]; }
      if (Object.keys(opts).length) x.options = opts; else delete x.options;
      return [x];
    },
    mark: (c) => !c[0] || (!c[2] && !SERVICE_ADDR[c[1]]) || !c[4],
    drop: (c) => !c[0] || (!c[2] && !SERVICE_ADDR[c[1]]),   // a device with no login is marked, but it is saved (an imported one has none yet)
  },
  // the logins the devices use: a user name and password, or an API token (FortiOS, PAN-OS, Technitium, Observium, IP Fabric, Centreon)
  devcreds: {
    key: "devcreds", empty: "No logins.", wide: true, track: true,   // track: a renamed login is followed by the devices that use it (see devicesOut)
    cols: [{ name: "Name", ph: "lab" }, { name: "User name", ph: "netdir" }, { name: "Password", secret: true }, { name: "Token", secret: true, ph: "FortiOS, PAN-OS, Meraki, MCP key" }],
    parse: (c) => (typeof c === "string" ? [c.split(/\s+/)[0] || "", "", "", ""] : [c.name || "", c.username || "", c.password || "", c.token || ""]),
    format: (c) => [{ name: c[0], ...(c[1] ? { username: c[1] } : {}), ...(c[2] ? { password: c[2] } : {}), ...(c[3] ? { token: c[3] } : {}) }],
    mark: (c) => !c[0] || (!c[2] && !c[3]),
  },
  // single sign-on users: "alice@example.com rw"
  ldapservers: oneCol("ldapservers", "Server", "ldaps://dc1.example.lan:636", "No directory servers yet."),
  ssousers: {
    key: "ssousers", empty: "Nobody may sign in with single sign-on yet.",
    cols: [{ name: "E-mail address", ph: "alice@example.com" }, { name: "Access", opts: ["ro", "rw"] }, { name: "Provider", opts: ["any", "google", "microsoft", "oidc"] }],
    parse: (line) => {
      const f = line.trim().split(/\s+/);
      let level = "ro", prov = "any";
      for (const t of f.slice(1).map((x) => x.toLowerCase())) {
        if (["rw", "read-write", "readwrite", "admin"].includes(t)) level = "rw";
        else if (["ro", "read-only", "readonly", "read"].includes(t)) level = "ro";
        else if (t === "google") prov = "google";
        else if (["microsoft", "entra", "azure", "ms"].includes(t)) prov = "microsoft";
        else if (["oidc", "openid", "generic"].includes(t)) prov = "oidc";
        else if (["any", "both"].includes(t)) prov = "any";
      }
      return [f[0] || "", level, prov];
    },
    format: (c) => [c[0] + " " + (c[1] || "ro") + (c[2] && c[2] !== "any" ? " " + c[2] : "")],
    mark: (c) => !c[0],
  },
};

// the parts of each saved device the Devices table has no column for, by name (see ROW_TABLES.devices)
let devExtra = {};
// Build inputs for one object; returns {el, get()} where get() reads values back with types.
// With asCards, every {section} spec starts a card of its own (title in the header, optional note above the fields).
// the gateway keys everybody knows, and the shortest key not called short (keep in step with gkey.go)
const WELL_KNOWN_KEYS = ["", "dnsdir", "ntpdir", "netdir", "logdir", "flowdir", "dgw", "ddgw", "change-me", "changeme", "secret", "password", "key", "test", "default"];
const isWeakKey = (k) => k.length < 12 || WELL_KNOWN_KEYS.includes(k.trim().toLowerCase());
const mcpURL = () => (mcpBaseURL || location.origin) + "/mcp";
const MCP_NAME_RE = /^[A-Za-z0-9._-]{1,40}$/;
function dialog(title, body) {
  const d = h("dialog", { class: "cv-dialog", "aria-label": title });
  const close = () => { try { d.close(); } catch (_) { /* closed */ } d.remove(); };
  d.addEventListener("close", () => d.remove());
  d.append(h("h2", {}, title), ...body(close));
  root.append(d);
  d.showModal();
  return d;
}
// Configure ▸ Privacy: what an MCP caller is not told (mcpprivacy.go).  The default level, and what the standard and the
// strict level each hide.  Only what differs from the built-in rules is saved, so an untouched page leaves nothing in the file.
const PRIV_STD = { public_ips: true, private_ips: false, ip_keep: 0, public_asns: true, private_asns: false, serials: "tail", macs: "show", emails: true, contacts: true, words: [] };
const PRIV_STRICT = { public_ips: true, private_ips: true, ip_keep: 0, public_asns: true, private_asns: true, serials: "hide", macs: "hide", emails: true, contacts: true, words: [] };
function privacyForm(cur) {
  cur = cur || {};
  const section = (title, ...kids) => h("div", { class: "card" }, h("header", {}, h("h2", {}, tc(title))), h("div", { class: "body" }, ...kids));
  const defSel = h("select", { "aria-label": "Default privacy level" }, [["standard", "standard"], ["none", "none — nothing is hidden"], ["strict", "strict"]].map(([v, l]) => h("option", { value: v }, l)));
  defSel.value = cur.default || "standard";
  const card = (title, base, saved) => {
    const r = { ...base, ...(saved || {}), words: (saved && saved.words) || [] };
    const box = (k, label) => { const i = h("input", { type: "checkbox", checked: !!r[k] }); i.addEventListener("change", () => { r[k] = i.checked; }); return h("label", { class: "f check" }, i, label); };
    const sel = (k, label, opts, hint) => {
      const i = h("select", { "aria-label": label }, opts.map(([v, l]) => h("option", { value: String(v) }, l)));
      i.value = String(r[k]);
      i.addEventListener("change", () => { r[k] = typeof base[k] === "number" ? Number(i.value) : i.value; });
      return h("label", { class: "f" }, h("span", {}, label), i, hint ? h("span", { class: "hint" }, hint) : null);
    };
    const words = h("textarea", { rows: 4, spellcheck: "false", autocomplete: "off", "aria-label": "Words always hidden", placeholder: "one per line, e.g. your company or site names" });
    words.value = r.words.join("\n");
    words.addEventListener("change", () => { r.words = words.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean); });
    const el = section(title,
      h("div", { class: "grid" },
        box("public_ips", "Public IP addresses"), box("private_ips", "Private IP addresses (10.x, 172.16-31.x, 192.168.x, fc00::/7 …)"),
        box("public_asns", "Public AS numbers"), box("private_asns", "Private AS numbers"),
        box("emails", "E-mail addresses"), box("contacts", "SNMP contact and location")),
      h("div", { class: "grid gap-top" },
        sel("ip_keep", "IP addresses", [[0, "hidden (x.x.x.x)"], [1, "first 1 (203.x.x.x)"], [2, "first 2 (203.0.x.x)"], [3, "first 3 (203.0.114.x)"], [-1, "last 1 (x.x.x.7)"], [-2, "last 2 (x.x.114.7)"], [-3, "last 3 (x.0.114.7)"]]),
        sel("serials", "Serial numbers", [["show", "shown"], ["tail", "last four characters (****1234)"], ["hide", "hidden"]]),
        sel("macs", "MAC addresses", [["show", "shown"], ["oui", "OUI part shown (00:1a:2b:xx:xx:xx)"], ["nic", "NIC part shown (xx:xx:xx:3c:4d:5e)"], ["hide", "hidden"]])),
      h("label", { class: "f wide gap-top" }, h("span", {}, "Words always hidden"), words));
    return { el, get: () => ({ ...r, words: r.words.slice() }) };
  };
  const std = card("Standard level hides", PRIV_STD, cur.standard), strict = card("Strict level hides", PRIV_STRICT, cur.strict);
  const same = (a, b) => JSON.stringify(Object.keys(b).sort().map((k) => [k, a[k]])) === JSON.stringify(Object.keys(b).sort().map((k) => [k, b[k]]));
  // words that mark a secret, for every filter and every level (device/secretwords.go): a key name, a line or a path that holds one is hidden or refused
  const secretBox = h("textarea", { rows: 4, spellcheck: "false", autocomplete: "off", "aria-label": "Secret words", placeholder: "one per line, e.g. passkey, vault, token-id" });
  secretBox.value = (cur.secret_words || []).join("\n");
  const secrets = section("Secret words", h("label", { class: "f wide" }, h("span", {}, "Words that mark a secret"), secretBox, h("span", { class: "hint" }, "On top of the built-in ones; at every level, none included.")));
  const intro = section("Default level", h("label", { class: "f" }, h("span", {}, "Level for a source or key that has none of its own"), defSel));
  return {
    el: h("div", {}, intro, std.el, strict.el, secrets),
    get() {
      const o = {};
      if (defSel.value !== "standard") o.default = defSel.value;
      if (!same(std.get(), PRIV_STD)) o.standard = std.get();
      if (!same(strict.get(), PRIV_STRICT)) o.strict = strict.get();
      const sw = secretBox.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      if (sw.length) o.secret_words = sw;
      return Object.keys(o).length ? o : undefined;
    },
  };
}
// The MCP keys (Configure ▸ MCP): a name, ro or rw, and the key (kept, so Show can display it again; an old key has
// only its hash).  Add key makes a random key here, shows it, and sends it with the next save.  A change is a "change" event,
// so the page saves it like any other field.
function mcpKeysEditor(list) {
  const keys = (list || []).map((k) => ({ ...k }));
  const el = h("div", { class: "mcpkeys" });
  const changed = () => { draw(); el.dispatchEvent(new Event("change", { bubbles: true })); };
  const NAME_RE = MCP_NAME_RE;
  const day = (t) => (t ? new Date(t * 1000).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" }) : "");
  const when = (t) => (t ? new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") : "");   // UTC
  const expired = (k) => !!k.expires && k.expires * 1000 <= Date.now();
  // "2026-12-31" is the end of that day, "2026-12-31 17:00" that minute; all UTC; "" is never; null is not a time
  const readWhen = (s) => {
    s = s.trim();
    if (!s || /^never$/i.test(s)) return 0;
    const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}))?Z?$/.exec(s);
    if (!m) return null;
    const t = m[4] ? Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5]) : Date.UTC(+m[1], m[2] - 1, +m[3], 23, 59);
    return Number.isNaN(t) ? null : Math.floor(t / 1000);
  };
  const shown = (k) => !!k.key && k.key !== "(hidden)";   // a key made before keys were kept has a hash only; a read-only account is not given it
  // a new key under the same name and access: whatever used the old one is refused from the next save
  function replaceKey(k) {
    if (!confirm("Replace the key " + k.name + "?\n\nWhatever uses the old key can no longer connect to /mcp.")) return;
    const key = randomKey();
    k.key = key; delete k.hash; k.created = Math.floor(Date.now() / 1000);
    changed();
  }
  // the same look as the address list above (rowTable): a numbered table, edited in place, right-click for the rest
  function draw() {
    const tbody = h("tbody", {}, keys.map((k, i) => {
      const name = h("input", { type: "text", autocomplete: "off", spellcheck: "false", maxlength: "40", "aria-label": "Name", value: k.name,
        title: "Who or what holds the key; renaming it does not change the key" });
      name.addEventListener("change", (ev) => {
        const n = name.value.trim();
        if (!NAME_RE.test(n) || keys.some((x) => x !== k && x.name.toLowerCase() === n.toLowerCase())) { ev.stopPropagation(); name.value = k.name; return; }   // not saved: the old name comes back
        k.name = n;
      });
      const acc = h("select", { "aria-label": "Access of " + k.name }, ["ro", "rw"].map((a) => h("option", { value: a }, a)));
      acc.value = k.access || "ro";
      acc.addEventListener("change", () => { k.access = acc.value; });
      const priv = h("select", { "aria-label": "Privacy of " + k.name }, ["default", "none", "standard", "strict"].map((a) => h("option", { value: a }, a)));
      priv.value = k.privacy || "default";
      priv.addEventListener("change", () => { if (priv.value === "default") delete k.privacy; else k.privacy = priv.value; });
      // the key in a password box like every other secret (the eye is added to it like to the others); an old key has none to show
      const keyIn = h("input", { type: shown(k) ? "password" : "text", readonly: true, autocomplete: "off", spellcheck: "false", "aria-label": "Key of " + k.name, class: "mono",
        value: shown(k) ? k.key : k.key || "", placeholder: "not kept: Replace key" });
      const exp = h("input", { type: "text", autocomplete: "off", spellcheck: "false", maxlength: "20", "aria-label": "Expires (UTC) of " + k.name, value: when(k.expires), placeholder: "never",
        title: "UTC. Empty: never. 2026-12-31 is the end of that day; 2026-12-31 17:00 that minute. After it the key is refused; the row stays." });
      exp.addEventListener("change", (ev) => {
        const t = readWhen(exp.value);
        if (t === null) { ev.stopPropagation(); exp.value = when(k.expires); return; }   // not a time: the old one comes back
        if (t) k.expires = t; else delete k.expires;
        changed();
      });
      const notes = h("input", { type: "text", autocomplete: "off", spellcheck: "false", maxlength: "200", "aria-label": "Notes for " + k.name, value: k.notes || "", placeholder: "what this key is for",
        title: "A note for yourself: what the key is for. It changes nothing." });
      notes.addEventListener("input", () => { const n = notes.value.replace(/[\r\n]+/g, " ").trim(); if (n) k.notes = n; else delete k.notes; });
      const devs = devicePicker(k.devices, (l) => { if (l.length) k.devices = l; else delete k.devices; });
      const tr = h("tr", { class: k.disabled || expired(k) ? "off" : "", title: expired(k) ? "Expired " + when(k.expires) + " UTC: refused" : "" },
        h("td", { class: "grip" }, h("span", { class: "rownum" }, String(i + 1))),
        h("td", {}, name),
        h("td", {}, acc),
        h("td", {}, priv),
        h("td", {}, devs),
        h("td", { class: "ctext" }, day(k.created)),
        h("td", {}, exp),
        h("td", {}, notes),
        h("td", {}, keyIn));
      tr.addEventListener("contextmenu", rowMenu([
        ["Add key", addKey],
        ["Copy key", () => { try { navigator.clipboard.writeText(k.key); } catch (_) { /* nothing to copy to */ } }, "", null, shown(k) ? "" : "No key is kept for this row: Replace key"],
        ["Replace key", () => replaceKey(k)],
        [k.disabled ? "Enable" : "Disable", () => { if (k.disabled) delete k.disabled; else k.disabled = true; changed(); }],
        ["Delete", () => { if (confirm("Delete the key " + k.name + "?\n\nWhatever uses it can no longer connect to /mcp.")) { keys.splice(keys.indexOf(k), 1); changed(); } }, "danger"],
      ]));
      return tr;
    }));
    const tbl = h("table", { class: "policy zones rows mcpkeytab" },
      h("thead", {}, h("tr", {}, h("th", { "aria-label": "Row number" }, "#"), h("th", {}, "Name"), h("th", {}, "Access"), h("th", {}, "Privacy"), h("th", {}, "Devices"), h("th", {}, "Added"), h("th", {}, "Expires (UTC)"), h("th", {}, "Notes"), h("th", {}, "Key"))), tbody);
    const empty = h("div", { class: "policy-empty" }, "No keys: only the sources above may use /mcp. Right-click here ▸ Add key.");
    empty.hidden = keys.length > 0;
    const wrap = h("div", { class: "policy-wrap" }, tbl, empty);
    wrap.addEventListener("contextmenu", (e) => { if (!e.target.closest("tbody tr")) rowMenu([["Add key", addKey]])(e); });
    clear(el).append(h("div", { class: "policy-box rows wide" }, wrap));
  }
  function addKey() {
    const name = h("input", { type: "text", autocomplete: "off", spellcheck: "false", maxlength: "40", placeholder: "e.g. laptop, claude-ops", "aria-label": "Name" });
    const access = h("select", { "aria-label": "Access" }, h("option", { value: "ro" }, "ro — read only"), h("option", { value: "rw" }, "rw — read and change"));
    const err = h("div", { "aria-live": "polite" });
    dialog("Add an MCP key", (close) => [h("form", { onsubmit: (ev) => {
      ev.preventDefault();
      const n = name.value.trim();
      if (!NAME_RE.test(n)) { errorBox(err, "Give it a name of up to 40 letters, digits, dots, dashes and underscores: who or what will hold it."); return; }
      if (keys.some((k) => k.name.toLowerCase() === n.toLowerCase())) { errorBox(err, "There is already a key named " + n + "."); return; }
      const key = randomKey();
      const entry = { name: n, access: access.value, key, created: Math.floor(Date.now() / 1000) };
      keys.push(entry);
      close();
      changed();
    } },
    h("label", { class: "f wide" }, "Name", name, h("span", { class: "hint" }, "Who or what holds the key. Its changes are logged and kept in the configuration history as mcp:NAME@ADDRESS.")),
    h("label", { class: "f wide" }, "Access", access),
    err,
    h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "submit" }, "Create key"), h("button", { class: "btn", type: "button", onclick: close }, "Cancel")))]);
    name.focus();
  }
  draw();
  return { el, get: () => keys.map((k) => ({ name: k.name, access: k.access || "ro", ...(k.privacy ? { privacy: k.privacy } : {}), ...(k.devices && k.devices.length ? { devices: k.devices } : {}), ...(k.disabled ? { disabled: true } : {}), ...(k.expires ? { expires: k.expires } : {}), ...(k.notes ? { notes: k.notes } : {}), ...(k.key ? { key: k.key } : { hash: k.hash }), created: k.created })) };
}

// the range under a number field, with its default, on one line: "10 to 600 s. Default 30."
function rangeText(f) {
  if (f.t !== "int" && f.t !== "float") return "";
  const u = f.unit ? " " + f.unit : "";
  const r = f.range ? f.range : f.min != null && f.max != null ? f.min + " to " + f.max + u : f.min != null ? f.min + " or more" + u : f.max != null ? "up to " + f.max + u : "";
  const d = f.def != null ? "Default " + f.def + "." : "";
  return [r ? r + "." : "", d].filter(Boolean).join(" ");
}
function fieldset(specs, obj, asCards) {
  const getters = {}, tables = {};
  let grid = h("div", { class: "grid" });
  const wrap = asCards ? h("div", {}) : grid;
  for (const f of specs) {
    if (f.section) {
      if (!asCards) { // a heading inside the one grid
        grid.append(h("div", { class: "fsec" }, h("h3", {}, tc(f.section)), f.note ? h("p", { class: "hint nomargin" }, f.note) : null));
        continue;
      }
      grid = h("div", { class: f.cols === 3 ? "grid c3" : "grid" });
      wrap.append(h("div", { class: "card" }, h("header", {}, h("h2", {}, tc(f.section))),
        h("div", { class: "body" }, f.note ? h("p", { class: "hint" }, f.note) : null, grid)));
      continue;
    }
    const v = obj[f.k];
    let input, get;
    if (f.t === "bool") {
      input = h("input", { type: "checkbox", checked: !!v });
      get = () => input.checked;
      grid.append(h("label", { class: "f check" }, input, f.l, sharedTag(f)));
      getters[f.k] = get;
      continue;
    }
    if (f.t === "mcpkeys") {
      const mk = mcpKeysEditor(v || []);
      getters[f.k] = mk.get;
      grid.append(h("div", { class: "f wide" }, h("span", {}, f.l, sharedTag(f)), mk.el));   // what keys are and do is in the help, like the address list above
      continue;
    }
    if (f.t === "rows") {
      const rt = rowTable(ROW_TABLES[f.rows], v || []);
      getters[f.k] = rt.get;
      tables[f.k] = rt;
      grid.append(h("div", { class: "f wide" }, h("span", {}, f.l, sharedTag(f)), rt.el, f.hint ? h("span", { class: "hint" }, f.hint) : null));
      continue;
    }
    if (f.t === "select") {
      input = h("select", {}, f.options.map((o) => h("option", { value: o, selected: o === v }, o)));
      get = () => input.value;
    } else if (f.t === "list") {
      input = h("textarea", { rows: 3, spellcheck: "false" });
      input.value = (v || []).join("\n");
      get = () => input.value.split("\n").map((s) => s.trim()).filter(Boolean);
    } else if (f.t === "port") {
      // a listen address kept as ":22161" in the file is shown as the port alone; one with a host in front is shown as it is
      input = h("input", { type: "text", inputmode: "numeric", autocomplete: "off", spellcheck: "false" });
      input.value = v == null || v === "" ? (f.def || "") : String(v).replace(/^:(\d+)$/, "$1");
      get = () => { const t = input.value.trim(); return /^\d+$/.test(t) ? ":" + t : t; };
    } else if (f.t === "secret") {
      input = h("input", { type: "password", autocomplete: "new-password", spellcheck: "false" });
      input.value = v == null ? "" : v;
      get = () => input.value.trim();
    } else if (f.t === "int" || f.t === "float") {
      input = h("input", { type: "number", step: f.t === "float" ? "any" : "1", min: f.min, max: f.max });
      input.value = v == null || v === "" || (v === 0 && f.def != null && (f.min > 0 || f.zeroDef)) ? (f.def == null ? "" : f.def) : v;   // empty or "the default" is shown as the default itself
      get = () => (input.value === "" ? 0 : Number(input.value));
    } else {
      input = h("input", { type: "text", autocomplete: "off", spellcheck: "false" });
      input.value = v == null ? "" : v;
      get = () => (f.raw ? input.value : input.value.trim());   // raw: kept exactly as typed
    }
    getters[f.k] = get;
    // a well-known or short gateway key: a few words of red text beside the field, no more (it follows what is typed)
    const weak = f.weakKey ? h("span", { class: "hint weak-key" }) : null;
    if (weak) {
      const upd = () => { weak.textContent = isWeakKey(input.value) ? "Well known or short: anyone on the network can take over this gateway." : ""; };
      input.addEventListener("input", upd); upd();
    }
    grid.append(h("label", { class: "f" + (f.wide ? " wide" : "") + (f.brk ? " brk" : "") }, h("span", {}, f.l, sharedTag(f)), input, (f.hint || rangeText(f)) ? h("span", { class: "hint" }, [f.hint, rangeText(f)].filter(Boolean).join(" ")) : null, weak));
  }
  return { el: wrap, table: (k) => tables[k], get: () => Object.fromEntries(Object.entries(getters).map(([k, g]) => [k, g()])) };
}
const alertsForm = (acfg) => {
  acfg = acfg || {};
  const saved = acfg.rules || {}, dirty = new Set(), rows = {};
  const webhook = h("input", { type: "text", value: acfg.webhook || "", placeholder: "https://hooks.example.com/…", spellcheck: "false", autocomplete: "off", "aria-label": "Webhook address" });
  const repeat = h("input", { type: "number", min: "0", max: "720", value: String(acfg.repeat_hours || 0), "aria-label": "Repeat every (hours)" });
  const testOut = h("span", { class: "hint" });
  const test = h("button", { type: "button", class: "btn", onclick: async () => {
    testOut.textContent = "Sending…";
    try { await api("POST", "/api/alerts/test", {}); testOut.textContent = "The webhook took the message."; } catch (e) { testOut.textContent = "Not sent: " + e.message; }
  } }, "Send test");
  const rulesBox = h("div", {});
  const num = (v, max) => h("input", { type: "number", min: "0", max: String(max || 100000), step: "any", value: String(v), class: "arule-n" });
  const sel = (opts, v) => h("select", {}, opts.map(([k, l]) => h("option", { value: k, selected: k === v }, l)));
  async function fill() {
    let rules;
    try { rules = (await api("GET", "/api/alerts")).data.rules; } catch (e) { clear(rulesBox).append(h("div", { class: "hint" }, "The rules could not be read from this node: " + e.message)); return; }
    const tbody = h("tbody", {});
    const GROUPS = [["gateways", "Gateways"], ["devices", "Devices"], ["cfg", "Certificates and backups"], ["host", "Host"]];
    const groupOf = (r) => (r.go === "cfg_web" || r.go === "cfg_backup" ? "cfg" : r.go || "host");
    const unitSpan = (t) => h("span", { class: "arule-u" }, t);
    const cell = (...k) => h("td", {}, h("div", { class: "arule-c" }, ...k));
    const dash = () => h("td", {}, h("span", { class: "muted", "aria-label": "Not used" }, "–"));
    for (const [gk, gname] of GROUPS) {
      const list = rules.filter((r) => groupOf(r) === gk);
      if (!list.length) continue;
      tbody.append(h("tr", { class: "agroup" }, h("th", { colspan: "7", scope: "colgroup" }, gname)));
      for (const r of list) {
        const c = { en: h("input", { type: "checkbox", checked: r.enabled, "aria-label": "On: " + r.title }), sev: sel([["info", "Info"], ["warning", "Warning"], ["critical", "Critical"]], r.severity_now),
          clearMode: sel([["checks", "checks"], ["minutes", "min"]], r.clear_mode), clear: num(r.clear) };
        c.sev.setAttribute("aria-label", "Severity: " + r.title); c.clear.setAttribute("aria-label", "Clear after: " + r.title);
        c.clearMode.setAttribute("aria-label", "Clear after, counted in: " + r.title);
        c.sev.className = "arule-sev";
        const sevSync = () => { c.sev.dataset.sev = c.sev.value; };
        c.sev.addEventListener("change", sevSync); sevSync();
        let when, thr, forc;
        if (r.kind === "updown") {
          c.mode = sel([["in_a_row", "Checks in a row"], ["minutes", "Minutes down"], ["m_of_n", "Checks of last"]], r.mode);
          c.mode.setAttribute("aria-label", "Alert when: " + r.title);
          c.after = num(r.after); c.of = num(r.of, 100);
          c.after.setAttribute("aria-label", "Threshold: " + r.title); c.of.setAttribute("aria-label", "Of the last checks: " + r.title);
          const ofBox = h("span", { class: "arule-c" }, unitSpan("of"), c.of);
          const unit = unitSpan("");
          const sync = () => { ofBox.hidden = c.mode.value !== "m_of_n"; unit.textContent = c.mode.value === "minutes" ? "min" : "checks"; };
          c.mode.addEventListener("change", sync); sync();
          when = cell(c.mode); thr = cell(c.after, ofBox, unit); forc = dash();
        } else {
          c.thr = num(r.threshold_now); c.forMin = num(r.for_minutes_now, 10080);
          c.thr.setAttribute("aria-label", "Threshold: " + r.title); c.forMin.setAttribute("aria-label", "For minutes: " + r.title);
          when = h("td", {}, h("span", { class: "arule-dir" }, r.below ? "Value below" : "Value above")); thr = cell(c.thr, unitSpan(r.unit)); forc = cell(c.forMin, unitSpan("min"));
        }
        const tr = h("tr", { "data-rule": r.id }, h("td", { class: "arule-on" }, c.en),
          h("td", {}, h("div", { class: "arule-t" }, r.title), h("div", { class: "muted small" }, r.subject ? "One alert per " + r.subject : "This node")),
          h("td", {}, c.sev), when, thr, forc, cell(c.clear, c.clearMode));
        const offSync = () => tr.classList.toggle("off", !c.en.checked);
        c.en.addEventListener("change", offSync); offSync();
        tr.addEventListener("change", () => dirty.add(r.id));
        rows[r.id] = { r, c };
        tbody.append(tr);
      }
    }
    const cols = ["2.4rem", "", "8.6rem", "10.5rem", "12.5rem", "6rem", "11rem"];
    clear(rulesBox).append(h("div", { class: "scroll" }, h("table", { class: "arules" },
      h("colgroup", {}, cols.map((w) => h("col", w ? { class: "w-" + w.replace(".", "_") } : {}))),
      h("thead", {}, h("tr", {}, ["On", "Rule", "Severity", "Alert when", "Threshold", "For", "Clear after"].map((x) => h("th", {}, x)))), tbody)));
    if (state.alertRule && rows[state.alertRule]) {
      const tr = rulesBox.querySelector('tr[data-rule="' + state.alertRule + '"]');
      if (tr) { tr.classList.add("flash"); tr.scrollIntoView({ block: "center" }); }
    }
    state.alertRule = null;
  }
  fill();
  const ruleOf = (id) => {
    const { r, c } = rows[id];
    const o = { enabled: c.en.checked, severity: c.sev.value, clear_mode: c.clearMode.value, clear: Number(c.clear.value) };
    if (r.kind === "updown") { o.mode = c.mode.value; o.after = Number(c.after.value); if (o.mode === "m_of_n") o.of = Number(c.of.value); }
    else { o.threshold = Number(c.thr.value); o.for_minutes = Number(c.forMin.value); }
    return o;
  };
  return {
    el: h("div", {},
      h("div", { class: "grid" }, h("label", { class: "f wide" }, "Webhook address", webhook), h("label", { class: "f" }, "Repeat every (hours)", repeat)),
      h("div", { class: "toolbar" }, test, testOut), rulesBox),
    get() {
      const rules = {};
      for (const [id, old] of Object.entries(saved)) if (!dirty.has(id)) rules[id] = old;
      for (const id of dirty) if (rows[id]) rules[id] = ruleOf(id);
      const a = {};
      if (webhook.value.trim()) a.webhook = webhook.value.trim();
      if (Number(repeat.value) > 0) a.repeat_hours = Number(repeat.value);
      if (Object.keys(rules).length) a.rules = rules;
      return Object.keys(a).length ? a : undefined;
    },
  };
};

// Configure ▸ Backup: three cards.  The servers are the shared settings (the settings.backup block); when backups run is a
// Scheduler task (action "backup"), shown and created from the first card.  There is no archive password (since v188):
// an old one in the settings is kept as it is, to open the archives it made.  The status and the restore
// are those of the node picked in the top bar.  Every explanation is in the help.
// the task the "Schedule daily backups" button adds (02:30 UTC; each node at its own time within five minutes)
const BACKUP_TASK = { id: "backup", name: "Back up every node", action: "backup", freq: "daily", at: "02:30", until: "02:35" };
// the columns of the table of backup servers (the server entries are part of the same shared block)
const BACKUP_COLS = [
  ["name", "Name", "text", "Backup 1"], ["host", "Server", "text", "backup.example.com"], ["port", "Port", "int", "22"],
  ["user", "User", "text", "netdir"], ["dir", "Directory", "text", "backups/netdir"], ["keep", "Keep", "int", "14"],
];
// setSchedule(list) tells the config page the Scheduler's task list changed, so its next save carries the new one
const backupForm = (bcfg, setSchedule) => {
  bcfg = bcfg || {};
  const notSetting = (el) => { el.addEventListener("change", (e) => e.stopPropagation()); return el; };
  const at = (u) => (u ? new Date(u * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "never");
  const bytes = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " kB");
  let last = null;   // the last /api/backup answer

  // ── Schedule: when this node last backed up and will next; the buttons under it ──
  const lastEl = h("dd", {}, "");
  const nextEl = h("dd", {}, "");
  const runBtn = h("button", { type: "button", class: "btn" }, "Back up now");
  const runErr = h("span", { class: "bad-text small" });
  runBtn.addEventListener("click", async () => {
    runBtn.disabled = true; runErr.textContent = "";
    try { await api("POST", "/api/backup/run", {}); start(); show(); } catch (e) { runBtn.disabled = false; runErr.textContent = e.message; }
  });
  const toSched = h("button", { type: "button", class: "btn" }, "Open Scheduler");
  toSched.addEventListener("click", () => selectTab("scheduler"));
  const addTask = h("button", { type: "button", class: "btn", hidden: true }, "Schedule daily backups");
  addTask.addEventListener("click", async () => {
    addTask.disabled = true; addTask.textContent = "Scheduling…"; runErr.textContent = "";
    try {
      await api("POST", "/api/schedule/task", { task: BACKUP_TASK });
      try { const c = await api("GET", "/api/config"); if (setSchedule) setSchedule(c.config.dns.schedule); } catch (_) { /* the next load reads it */ }
      show();
    } catch (e) { runErr.textContent = e.message; }
    finally { addTask.disabled = false; addTask.textContent = "Schedule daily backups"; }
  });
  async function showWhen() {
    let tasks;
    try { tasks = ((await api("GET", "/api/schedule")).data.tasks || []).filter((t) => t.action === "backup"); } catch (_) { return; }
    const on = tasks.filter((t) => !t.disabled && t.applies);
    const next = on.map((t) => t.next_run).filter(Boolean).sort((a, b) => a - b)[0];
    clear(nextEl).append(on.length ? at(next) + " · " + on.map((t) => t.describe).join("; ")
      : h("span", { class: "bad-text" }, tasks.length ? "Not scheduled (the task is off)" : "Not scheduled"));
    addTask.hidden = tasks.length > 0;
  }
  const schedule = section("Schedule",
    h("dl", { class: "kv" }, h("dt", {}, "Last backup"), lastEl, h("dt", {}, "Next backup"), nextEl),
    h("div", { class: "toolbar nomargin" }, runBtn, addTask, toSched, runErr));
  // ── Servers: one row per server with its status under it; click a row to pick it, the toolbar acts on that one ──
  const initial = (bcfg.targets || []).slice();
  if (bcfg.host || bcfg.user || bcfg.dir) initial.unshift({ host: bcfg.host, port: bcfg.port, user: bcfg.user, dir: bcfg.dir, keep: bcfg.keep });   // the single server of older versions
  const tbody = h("tbody", {});
  const rows = () => [...tbody.children].filter((tr) => tr._get);
  let sel = null;   // the picked row
  const addBtn = h("button", { type: "button", class: "btn" }, "Add a server");
  const testBtn = h("button", { type: "button", class: "btn" }, "Test");
  const keyBtn = h("button", { type: "button", class: "btn", "aria-expanded": "false" }, "Install key");
  const delBtn = h("button", { type: "button", class: "btn" }, "Remove");
  // Install key: the account's password, used once and kept nowhere
  const pw = h("input", { type: "password", autocomplete: "new-password", "aria-label": "Password of the account on the server" });
  const installBtn = h("button", { type: "button", class: "btn" }, "Install");
  const keyOut = h("span", { class: "small" });
  const keyForm = h("div", { class: "toolbar tight bk-keyform", hidden: true }, pw, installBtn, keyOut);
  const closeKey = () => { keyForm.hidden = true; keyBtn.setAttribute("aria-expanded", "false"); pw.value = ""; keyOut.textContent = ""; };
  const pickRow = (tr) => {
    if (sel !== tr) {
      if (sel) { sel.classList.remove("sel"); sel._statRow.classList.remove("sel"); }
      sel = tr && tr.isConnected ? tr : null;
      if (sel) { sel.classList.add("sel"); sel._statRow.classList.add("sel"); }
      closeKey();
    }
    testBtn.disabled = keyBtn.disabled = delBtn.disabled = !sel;
    addBtn.disabled = rows().length >= 8;
  };
  const addRow = (t) => {
    t = t || {};
    const ins = {};
    const tr = h("tr", {});
    for (const [k, l, ty, ph] of BACKUP_COLS) {
      ins[k] = h("input", { type: ty === "int" ? "number" : "text", min: ty === "int" ? "0" : undefined, max: k === "port" ? "65535" : k === "keep" ? "365" : undefined,
        placeholder: ph, spellcheck: "false", autocomplete: "off", "aria-label": l, class: "bk-" + k });
      ins[k].value = t[k] == null || t[k] === 0 ? "" : t[k];
      tr.append(h("td", {}, ins[k]));
    }
    const stat = h("span", {});
    const msg = h("span", {});
    const statRow = h("tr", { class: "bk-statrow" }, h("td", { colspan: String(BACKUP_COLS.length), class: "small" }, stat, msg));
    tr._statRow = statRow;
    tr._ins = ins;
    tr._index = () => rows().indexOf(tr);
    tr._say = (bad, x) => { msg.textContent = x; msg.className = bad ? "bad-text" : ""; };
    for (const r of [tr, statRow]) {
      r.addEventListener("focusin", () => pickRow(tr));
      r.addEventListener("mousedown", () => pickRow(tr));
    }
    tr._get = () => {
      const o = {};
      for (const [k, , ty] of BACKUP_COLS) {
        const v = ins[k].value.trim();
        if (v === "" || (ty === "int" && Number(v) === 0)) continue;
        o[k] = ty === "int" ? Number(v) : v;
      }
      return o;
    };
    // the status of the saved server at this place in the list (nothing while the row is not saved yet)
    tr._status = (ts) => {
      const t = ts[tr._index()];
      clear(stat);
      if (!t || t.host !== ins.host.value.trim() || t.user !== ins.user.value.trim()) return;
      const s = t.status || {};
      if (s.last_ok) stat.append(h("span", { class: "muted", title: (s.last_file || "") + (s.last_size ? ", " + bytes(s.last_size) : "") }, "Last: " + at(s.last_ok)));
      else stat.append(h("span", { class: "muted" }, "No backup yet"));
      const n = (s.remote || []).length;
      if (n) stat.append(h("span", { class: "muted", title: s.remote.slice().reverse().join("\n") }, " · " + n + " on the server"));
      if (s.last_error && !(msg.className === "bad-text" && msg.textContent)) stat.append(h("span", { class: "bad-text" }, " · Failed: " + s.last_error));
    };
    tbody.append(tr, statRow);
    if (last) tr._status(last.targets || []);
    return tr;
  };
  initial.forEach(addRow);
  if (!initial.length) addRow();
  addBtn.addEventListener("click", () => { if (rows().length < 8) { const tr = addRow(); pickRow(tr); tr._ins.name.focus(); } });
  testBtn.addEventListener("click", async () => {
    const tr = sel; if (!tr) return;
    testBtn.disabled = true; testBtn.textContent = "Testing…"; tr._say(false, "");
    try { await api("POST", "/api/backup/test", { index: tr._index() }); tr._say(false, " · Connected"); show(); }
    catch (e) { tr._say(true, " · Failed: " + e.message); show(); }
    finally { testBtn.textContent = "Test"; testBtn.disabled = !sel; }
  });
  keyBtn.addEventListener("click", () => {
    if (!sel) return;
    if (!keyForm.hidden) { closeKey(); return; }
    keyForm.hidden = false; keyBtn.setAttribute("aria-expanded", "true");
    pw.placeholder = "Password of " + (sel._ins.user.value.trim() || "the user") + "@" + (sel._ins.host.value.trim() || "the server");
    pw.focus();
  });
  installBtn.addEventListener("click", async () => {
    const tr = sel; if (!tr) return;
    installBtn.disabled = true; installBtn.textContent = "Installing…"; keyOut.textContent = ""; keyOut.className = "small";
    try {
      const r = (await api("POST", "/api/backup/install", { index: tr._index(), password: pw.value })).data;
      pw.value = "";
      keyOut.textContent = (r.added ? "Installed for " + r.added + " of " + r.nodes + " node(s)." : "Already installed.") + (r.connected ? "" : " Login still fails: " + r.test_error) + ((r.missing || []).length ? " No key from " + r.missing.join(", ") + "." : "");
      if (!r.connected || (r.missing || []).length) keyOut.className = "small bad-text";
      show();
    } catch (e) { keyOut.textContent = e.message; keyOut.className = "small bad-text"; }
    finally { installBtn.disabled = false; installBtn.textContent = "Install"; }
  });
  pw.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); installBtn.click(); } else if (e.key === "Escape") { closeKey(); keyBtn.focus(); } });
  delBtn.addEventListener("click", () => {
    const tr = sel; if (!tr) return;
    pickRow(null);
    tr._statRow.remove(); tr.remove();
    tbody.dispatchEvent(new Event("change", { bubbles: true }));
    pickRow(null);   // the Add button again
  });
  // Use the cluster nodes: every node makes the account, the directory and the keys itself and becomes a server of the list
  const clusterBtn = h("button", { type: "button", class: "btn", title: "Every node keeps the backups of the others. The account, keys and directory are made on each." }, "Use the cluster nodes");
  const clusterOut = h("span", { class: "small bad-text" });
  clusterBtn.addEventListener("click", async () => {
    clusterBtn.disabled = true; clusterBtn.textContent = "Setting up…"; clusterOut.textContent = "";
    try {
      const r = (await api("POST", "/api/backup/cluster", {})).data;
      // the server saved the new list: show it, and make it what this page holds, without another save
      pickRow(null);
      clear(tbody);
      (r.targets || []).forEach(addRow);
      if (!rows().length) addRow();
      pickRow(null);
      if (state.cfg && state.cfg.settings) state.cfg.settings.backup = { ...(state.cfg.settings.backup || {}), targets: r.targets || [] };
      const bad = (r.nodes || []).filter((n) => n.error).map((n) => n.node + ": " + n.error);
      if (r.full) bad.push(r.full + " node(s) not added: at most 8 servers");
      clusterOut.textContent = bad.join(" · ");
      show();
    } catch (e) { clusterOut.textContent = e.message; }
    finally { clusterBtn.disabled = false; clusterBtn.textContent = "Use the cluster nodes"; }
  });
  pickRow(null);
  const bar = notSetting(h("div", { class: "toolbar tight" }, addBtn, testBtn, keyBtn, delBtn, ...(state.clustered ? [clusterBtn, clusterOut] : [])));
  notSetting(keyForm);
  const table = h("div", { class: "scroll" }, h("table", { class: "tight bk-table" },
    h("thead", {}, h("tr", {}, BACKUP_COLS.map((c) => h("th", {}, c[1])))), tbody));
  const servers = section("Servers", bar, keyForm, table);
  { const tag = sharedTag({ shared: true }); if (tag) servers.querySelector("h2").append(" ", tag); }   // the list is the cluster's

  // ── this node's status, in the two cards above ──
  let timer = null;
  const stop = () => { if (timer) { clearInterval(timer); timer = null; } };
  function start() { if (!timer) timer = setInterval(() => show(true), 3000); }
  async function show(fromTimer) {
    if (fromTimer === true && !schedule.isConnected) { stop(); return; }
    let v;
    try { v = (await api("GET", "/api/backup")).data; } catch (e) { runErr.textContent = e.message; stop(); return; }
    last = v;
    const st = v.status || {};
    runBtn.disabled = !!v.running; runBtn.textContent = v.running ? "Backing up…" : "Back up now";
    lastEl.textContent = at(st.last_ok) + (v.retry ? " · a failed server is tried again " + at(v.retry) : "");
    showWhen();
    rows().forEach((tr) => tr._status(v.targets || []));
    restoreFrom(v);
    if (v.running) start(); else stop();
  }
  // a saved edit can change the servers: read their status again once the save is through
  let again = null;
  const later = () => { clearTimeout(again); again = setTimeout(show, 1500); };

  // ── Restore: pick where the backup is and which one, then Restore (one confirmation, then the node restarts) ──
  const rbody = h("div", {});
  const restore = notSetting(section("Restore", rbody));
  // the configured servers are the first choices and are read from the status, so a server added on this page shows up
  // here at once; picking one lists its backups straight away (only Another server… needs List backups)
  let restoreFrom = () => {};
  function restoreUI() {
    // why the backups could not be listed, or the restore failed: a line of its own under the controls
    const rerr = h("span", {});
    const lerr = h("span", {});
    const errLine = h("div", { class: "bad-text small bk-err" }, lerr, rerr);
    const otherOpt = h("option", { value: "other" }, "Another server");
    const src = h("select", { "aria-label": "Where the backup is" }, otherOpt, h("option", { value: "upload" }, "A file from this computer"));
    let chosen = false;   // the person picked a source: do not move it
    const o = { host: h("input", { type: "text", placeholder: "Server", spellcheck: "false", "aria-label": "Server" }), port: h("input", { type: "number", placeholder: "22", class: "arule-n", "aria-label": "SSH port" }),
      user: h("input", { type: "text", placeholder: "User", spellcheck: "false", "aria-label": "User" }), dir: h("input", { type: "text", placeholder: "Directory", spellcheck: "false", "aria-label": "Directory" }),
      pw: h("input", { type: "password", autocomplete: "new-password", placeholder: "Account password", "aria-label": "Password of the account on that server" }) };
    const otherBox = h("div", { class: "toolbar tight", hidden: true }, o.host, o.port, o.user, o.dir, o.pw);
    const fileIn = h("input", { type: "file", accept: ".netbak", hidden: true, "aria-label": "Backup file" });
    const list = h("select", { "aria-label": "Backup to restore", hidden: true });
    const listBtn = h("button", { type: "button", class: "btn" }, "List backups");
    // the list shows this node's backups; "All nodes" adds the other nodes' (to rebuild a lost node on this one)
    const allIn = h("input", { type: "checkbox" });
    const allBox = h("label", { class: "check", hidden: true }, allIn, " All nodes");
    let files = [], myNode = "";
    const showFiles = () => {
      const mine = files.filter((f) => allIn.checked || f.node === myNode);
      clear(list).append(...mine.map((f) => h("option", { value: f.name }, (allIn.checked ? f.node + " — " : "") + new Date(f.time).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }))));
      list.hidden = !mine.length;
      allBox.hidden = !files.length;   // only once there is a list to widen
      lerr.textContent = mine.length ? "" : files.length ? "No backups of this node there: tick All nodes to see the others." : "No backups there.";
      canGo();
    };
    allIn.addEventListener("change", showFiles);
    const go = h("button", { type: "button", class: "btn danger", disabled: true }, "Restore");
    // Restore is for a picked backup: a listed one, or a chosen file
    const canGo = () => { go.disabled = src.value === "upload" ? !fileIn.files.length : (list.hidden || list.disabled || !list.value); };
    fileIn.addEventListener("change", canGo);
    list.addEventListener("change", canGo);
    let seq = 0;
    async function listFiles() {
      const n = ++seq;
      rerr.textContent = ""; lerr.textContent = "";
      listBtn.disabled = true; listBtn.textContent = "Listing…";
      clear(list).append(h("option", { value: "" }, "Listing…")); list.disabled = true; list.hidden = false; canGo();
      try {
        const r = (await api("POST", "/api/backup/files", serverArg())).data.files || [];
        if (n !== seq) return;
        files = r;
        list.disabled = false;
        showFiles();
      } catch (e) { if (n === seq) { files = []; list.hidden = true; allBox.hidden = true; lerr.textContent = "Cannot list the backups: " + e.message; } }
      finally { if (n === seq) { list.disabled = false; listBtn.disabled = false; listBtn.textContent = "List backups"; canGo(); } }
    }
    listBtn.addEventListener("click", listFiles);
    go.addEventListener("click", async () => {
      go.disabled = true; go.textContent = "Opening…"; rerr.textContent = "";
      let prepared = false;
      try {
        let body;
        if (src.value === "upload") {
          if (!fileIn.files[0]) throw new Error("Choose the backup file first.");
          await apiUpload("/api/backup/upload", fileIn.files[0]);
          body = { source: "upload" };
        } else {
          if (list.hidden || list.disabled || !list.value) throw new Error(src.value === "other" ? "List the backups and pick one." : "Pick a backup.");
          body = { source: "server", file: list.value, ...serverArg() };
        }
        const r = (await api("POST", "/api/backup/restore/prepare", body)).data;
        prepared = true;
        o.pw.value = "";
        // one question; for another node's backup it is the "are you sure" one
        const newer = r.newer ? "\n\nIt was made by a newer version (" + r.version + ") than this node runs." : "";
        const ok = confirm(r.same_node
          ? "Restore the backup of " + r.node + " made " + r.created + "?\n\nThis node's settings and keys are replaced and it restarts. The old ones are kept next to its state directory." + newer
          : "Are you sure? This is a backup of " + r.node + " (made " + r.created + "), not of this node (" + (myNode || "this node") + ").\n\nThis node becomes " + r.node + ": its identity, keys and certificates, and it restarts. Do this only to replace " + r.node + " when it is gone, never while it is still running." + newer);
        if (!ok) throw new Error("");   // declined: drop what was opened
        await api("POST", "/api/backup/restore/apply", {});
        go.textContent = "Restarting…";
        const wait = async () => { try { const r2 = await fetch("/api/session", { credentials: "same-origin" }); if (r2.status < 500) { location.reload(); return; } } catch (_) { /* still down */ } setTimeout(wait, 3000); };
        setTimeout(wait, 6000);
        return;   // the button stays as it is until the page reloads
      } catch (e) {
        rerr.textContent = e.message;
        if (prepared) api("POST", "/api/backup/restore/cancel", {}).catch(() => {});
      }
      go.textContent = "Restore"; canGo();
    });
    function serverArg() {
      if (src.value.startsWith("s")) return { index: Number(src.value.slice(1)) };
      return { host: o.host.value.trim(), port: Number(o.port.value) || 0, user: o.user.value.trim(), dir: o.dir.value.trim(), server_password: o.pw.value };
    }
    const sync = () => {
      const other = src.value === "other";
      seq++;
      otherBox.hidden = !other; fileIn.hidden = src.value !== "upload"; listBtn.hidden = !other; list.hidden = true; list.disabled = false; rerr.textContent = ""; lerr.textContent = "";
      allBox.hidden = true; files = [];
      canGo();
      if (src.value.startsWith("s")) listFiles();
    };
    src.addEventListener("change", () => { chosen = true; sync(); });
    let known = null;
    restoreFrom = (v) => {
      myNode = v.node || "";
      const tl = v.targets || [];
      const sig = JSON.stringify(tl.map((t) => [t.label, t.host, t.user]));
      if (sig === known) return;
      known = sig;
      const was = src.value;
      [...src.options].filter((op) => op.value.startsWith("s")).forEach((op) => op.remove());
      tl.forEach((t, i) => src.insertBefore(h("option", { value: "s" + i }, t.label), otherOpt));
      if (chosen && [...src.options].some((op) => op.value === was)) src.value = was;
      else { chosen = chosen && !was.startsWith("s"); src.value = !chosen && tl.length ? "s0" : (was.startsWith("s") ? "other" : was); }
      sync();
    };
    sync();
    rbody.replaceChildren(h("div", { class: "bk-restore" }, h("div", { class: "toolbar nomargin" }, src, listBtn, list, fileIn, allBox, go), otherBox, errLine));
  }
  restoreUI();
  show();

  const el = h("div", {}, schedule, servers, restore);
  el.addEventListener("change", later);
  return {
    el,
    get() {
      const b = bcfg.password ? { password: bcfg.password } : {};   // the old archive password, kept to open old archives
      const ts = rows().map((tr) => tr._get()).filter((t) => Object.keys(t).length);
      if (ts.length) b.targets = ts;
      return Object.keys(b).length ? b : undefined;
    },
  };
};

const makeConfigView = (only) => {
  let holder, status, collect = null, refreshSNMP = () => {}, refreshSyslog = () => {}, refreshDNSReg = () => {}, refreshLLDP = () => {};
  const tab = only;

  // Action results ("Saved", "Restored" …) are not announced; only errors, warnings and hints are.
  const say = (kind, ...msg) => kind !== "bad" ? clear(status) : clear(status).append(h("div", { class: "notice " + kind, role: kind === "bad" ? "alert" : "status" }, ...msg));

  function renderForm(cfg) {
    const logs = fieldset(LOG_FIELDS, cfg);
    const set = cfg.settings = cfg.settings || {};
    mcpBaseURL = vipBase(cfg);
    const syslog = fieldset(SYSLOG_FIELDS, cfg.syslog || {});
    const dnsreg = fieldset(DNSREG_FIELDS, Object.assign({}, cfg.dns_register || {}, { skip_interfaces: ((cfg.dns_register || {}).skip_interfaces || []).join(", ") }));
    const web = fieldset(WEB_FIELDS, cfg.web);
    const sso = ssoTabs(cfg.web);
    const ldap = ldapTab(cfg.web);
    devChoices = { names: (set.devices || []).map((d) => d.name).filter(Boolean).sort(), tags: [...new Set((set.devices || []).flatMap((d) => d.tags || []))].sort(), gateways: (cfg.groups || []).map((g) => ({ id: g.group_id, name: g.name || "" })) };
    devExtra = Object.fromEntries((set.devices || []).map((d) => { const { options, ca_pem, disabled } = d; return [d.name, { ...(options ? { options } : {}), ...(ca_pem ? { ca_pem } : {}), ...(disabled ? { disabled } : {}) }]; }));
    const devices = fieldset(DEVICE_FIELDS, { devices: set.devices });
    const devcreds = fieldset(DEVCRED_FIELDS, { device_credentials: set.device_credentials });
    // the Login column of the devices table offers the names in the Logins table below it, as they stand now (unsaved rows too)
    const loginList = h("datalist", { id: "device-logins" });
    ROW_TABLES.devices.onList = () => { let names = []; try { names = (devcreds.get().device_credentials || []).map((c) => c.name).filter(Boolean); } catch (_) { /* a row that is not finished */ } loginList.replaceChildren(...[...new Set(names)].sort().map((n) => h("option", { value: n }))); };
    // a login renamed in the Logins table: every device that used it under its old name takes the new one (this runs before the form saves)
    devcreds.el.addEventListener("change", () => {
      const lt = devcreds.table("device_credentials"), dt = devices.table("devices"), ren = lt.renames();
      if (ren.size) dt.retarget(ROW_TABLES.devices.cols.findIndex((c) => c.name === "Login"), ren);
      lt.commit();
    });
    // the tags of the devices table as it stands now (rows not saved yet too): offered while a Tags box is typed in, and listed on the Tags tab
    const tagCol = ROW_TABLES.devices.cols.findIndex((c) => c.name === "Tags");
    ROW_TABLES.devices.tagsNow = () => devices.table("devices").words(tagCol);
    // the Tags tab: a table like the others (filter, pages, right-click), one row to a tag, made from the Tags column of the devices table
    let tabsShow = () => {};
    const tagsTab = tagTable(() => devices.table("devices"), tagCol, () => { tabsShow(0); });
    devices.el.addEventListener("change", tagsTab.refresh);
    const devcheck = fieldset(DEVCHECK_FIELDS, { device_check_s: set.device_check_s, device_facts_min: set.device_facts_min, device_live_check_s: set.device_live_check_s, device_live_facts_min: set.device_live_facts_min });
    const devcheckShared = () => { const c = devcheck.get(), o = {}; for (const k of ["device_live_check_s", "device_live_facts_min", "device_check_s", "device_facts_min"]) if (c[k] > 0) o[k] = c[k]; return o; };
    const cluster = fieldset(CLUSTER_FIELDS, cfg.cluster || {});
    const snmp = fieldset(SNMP_FIELDS, { snmp_communities: set.snmp_communities, snmp_acl: set.snmp_acl, snmp_contact: set.snmp_contact, location: (cfg.snmp || {}).location });
    const prom = fieldset(PROM_FIELDS, { metrics_acl: set.metrics_acl });
    const mcp = fieldset(MCP_FIELDS, { mcp_port: set.mcp_port, mcp_max_result_mb: set.mcp_max_result_mb, mcp_log: !!set.mcp_log, mcp_log_mb: set.mcp_log_mb, mcp_log_entry_kb: set.mcp_log_entry_kb, mcp_acl: set.mcp_acl, mcp_keys: set.mcp_keys });
    const topo = fieldset(TOPO_FIELDS, { topology_squares_above: set.topology_squares_above });
    const topoShared = () => { const n = topo.get().topology_squares_above; return n > 0 && n !== 36 ? { topology_squares_above: n } : {}; };
    const lldp = fieldset(LLDP_FIELDS, { lldp: !!set.lldp });
    const priv = privacyForm(set.privacy);
    const privShared = () => { const p = priv.get(); return p ? { privacy: p } : {}; };
    const lldpShared = () => ({ lldp: lldp.get().lldp });
    // what lldpd is doing on this node, beside the box (refreshed after every save); a few words, never a banner
    const lldpState = h("span", { class: "muted small" });
    const lldpBox = lldp.el.querySelector("input[type=checkbox]");
    refreshLLDP = async () => {
      try {
        const st = (await api("GET", "/api/lldp")).data;
        const words = lldpWords(st);
        clear(lldpState).append(...(st.running ? [pill("ACTIVE", "ok tiny")] : []), words === "Running" ? "" : " " + words);
        lldpBox.disabled = !!st.deferred;   // another program on this host decides
      } catch (_) { clear(lldpState); }
    };
    refreshLLDP();
    // lldpd starts or stops a moment after a save, and can be changed behind the page's back: ask again every few seconds
    // while the card is on screen (the tab shown, the window visible); the timer ends once the page is drawn again or left
    const lldpTimer = setInterval(() => {
      if (!lldpState.isConnected) { clearInterval(lldpTimer); return; }
      if (lldpState.offsetParent !== null && !document.hidden) refreshLLDP();
    }, 3000);
    const alerts = alertsForm(set.alerts);
    const alertsShared = () => { const a = alerts.get(); return a ? { alerts: a } : {}; };
    const backup = backupForm(set.backup, (sch) => { set.schedule = sch; if (state.cfg && state.cfg.settings) state.cfg.settings.schedule = sch; });
    const backupShared = () => { const b = backup.get(); return b ? { backup: b } : {}; };
    // what snmpd is doing, under the form (refreshed after every save)
    const snmpShared = () => { const v = snmp.get(), m = prom.get(); return { snmp_communities: v.snmp_communities, snmp_acl: v.snmp_acl, snmp_contact: v.snmp_contact, metrics_acl: m.metrics_acl, mcp_acl: mcp.get().mcp_acl, mcp_keys: mcp.get().mcp_keys, ...(mcp.get().mcp_port ? { mcp_port: mcp.get().mcp_port } : {}), ...(mcp.get().mcp_max_result_mb > 1 ? { mcp_max_result_mb: mcp.get().mcp_max_result_mb } : {}), ...(mcp.get().mcp_log ? { mcp_log: true } : {}), ...(mcp.get().mcp_log_mb > 0 ? { mcp_log_mb: mcp.get().mcp_log_mb } : {}), ...(mcp.get().mcp_log_entry_kb > 0 ? { mcp_log_entry_kb: mcp.get().mcp_log_entry_kb } : {}) }; };
    const snmpLocal = () => { const v = snmp.get(); return { location: v.location }; };
    const snmpPill = h("span");   // ACTIVE beside the heading while snmpd is running
    refreshSNMP = async () => {
      try {
        const st = (await api("GET", "/api/snmp")).data;
        clear(snmpPill);
        if (st.enabled && st.installed && st.running) snmpPill.append(pill("ACTIVE", "ok tiny"));
      } catch (_) { clear(snmpPill); }  // no tag when the node cannot be asked
    };
    refreshSNMP();
    const groupsEl = h("div", {});
    const groups = []; // {el, get}
    const addGroup = (g) => {
      const fs = fieldset(GROUP_FIELDS, g);
      const entry = { fs, orig: g };
      const title = h("h3", {}, "Group");
      const card = h("div", { class: "card" },
        h("header", {}, title),
        h("div", { class: "body" }, fs.el));
      entry.card = card;
      const gid = fs.el.querySelector("input[type=number]");
      const retitle = () => { title.textContent = "Group " + gid.value; };
      gid.addEventListener("input", retitle); retitle();
      groups.push(entry);
      groupsEl.append(card);
    };
    cfg.groups.forEach(addGroup);
    const section = (title, ...kids) => h("div", { class: "card" }, h("header", {}, h("h2", {}, tc(title))), h("div", { class: "body" }, ...kids));
    // the devices a gateway has (Topology) are not a field of this page: keep them, less any the Devices table no longer lists
    const keptDevices = (orig) => {
      const have = new Set((devices.get().devices || []).map((d) => d.name));
      const l = (orig.devices || []).filter((n) => have.has(n));
      return l.length ? { devices: l } : {};
    };
    collect = () => ({
      ...logs.get(),
      // keep what this form has no fields for (pauses, removed nodes, the order of the nodes, anycast addresses)
      groups: groups.map((g) => ({ ...(g.orig.paused ? { paused: true } : {}), ...(g.orig.paused_all ? { paused_all: true } : {}), ...(g.orig.excluded_nodes ? { excluded_nodes: g.orig.excluded_nodes } : {}), ...(g.orig.node_order ? { node_order: g.orig.node_order } : {}), ...(g.orig.paused_vips ? { paused_vips: g.orig.paused_vips } : {}), ...(g.orig.paused_vips_here ? { paused_vips_here: g.orig.paused_vips_here } : {}), ...(g.orig.extra_vips ? { extra_vips: g.orig.extra_vips } : {}), ...keptDevices(g.orig), ...g.fs.get() })),
      settings: { ...(set.schedule ? { schedule: set.schedule } : {}), ...devices.get(), ...devcreds.get(), ...devcheckShared(), ...snmpShared(), ...lldpShared(), ...topoShared(), ...privShared(), ...alertsShared(), ...backupShared() },
      // the certificate is managed under Web GUI; keep any file paths already in the config
      web: { cert_file: cfg.web.cert_file || "", key_file: cfg.web.key_file || "", ...web.get(), ...sso.get(), ...ldap.get() },
      cluster: cluster.get(),
      snmp: snmpLocal(),
      ...(() => { const v = syslog.get(); return v.enabled || v.server ? { syslog: v } : {}; })(), // empty settings leave no key
      ...(() => {
        const v = dnsreg.get();
        const o = { enabled: v.enabled, key: v.key, domain: v.domain, server: v.server, interval_sec: v.interval_sec === 300 ? 0 : v.interval_sec, ttl: v.ttl === 900 ? 0 : v.ttl,
          skip_interfaces: String(v.skip_interfaces || "").split(",").map((x) => x.trim()).filter(Boolean) };   // the defaults are not written
        return o.enabled || o.key || o.domain || o.server || o.interval_sec || o.ttl || o.skip_interfaces.length ? { dns_register: o } : {};
      })(),
      ...(cfg.bgp ? { bgp: cfg.bgp } : {}), // edited on the Anycast page
      ...(cfg.ospf ? { ospf: cfg.ospf } : {}), // likewise
      ...(cfg.node_paused ? { node_paused: true } : {}), // set on the Node page
    });
    // every committed edit (leaving a field, picking an option, ticking a box) is saved and applied
    // Automatic updates are not part of the config file: switching them is its own call, made at once
    const updatesCard = () => {
      if (state.autoUpdate == null) return null;
      const cb = h("input", { type: "checkbox", checked: state.autoUpdate });
      cb.addEventListener("change", async (ev) => {
        ev.stopPropagation(); // not a config edit
        const on = cb.checked;
        if (on && !confirm("Turn automatic updates on?\n\nEvery node will build and install any newer staged release, one node at a time.")) { cb.checked = false; return; }
        try { await api("POST", "/api/update/auto", { enabled: on }); state.autoUpdate = on; say("ok"); }
        catch (e) { cb.checked = !on; say("bad", "Not changed: " + (e.message || e)); }
      });
      // the repository "Fetch from online" downloads from: shared, saved when the field is left; empty goes back to the default
      const DEFAULT_REPO = "https://github.com/micush/netdir";
      const repoIn = h("input", { type: "text", value: state.updateRepo ? "https://github.com/" + state.updateRepo : DEFAULT_REPO, spellcheck: "false", autocomplete: "off", "aria-label": "Online repository" });
      const repoErr = h("span", { class: "notice bad", role: "alert" });
      repoIn.addEventListener("change", async (ev) => {
        ev.stopPropagation(); // not a config edit
        clear(repoErr);
        try {
          await api("POST", "/api/update/repo", { repo: repoIn.value.trim() });
          state.updateRepo = ((await api("GET", "/api/update")).data.intent.repo) || "";
          repoIn.value = state.updateRepo ? "https://github.com/" + state.updateRepo : DEFAULT_REPO;
        } catch (e) { repoErr.textContent = e.message || String(e); }
      });
      return section("Upgrades", h("label", { class: "f check" }, cb, "Update every node automatically when a newer release is staged (one node at a time)"),
        h("label", { class: "f repo" }, h("span", {}, "Online repository"), repoIn, repoErr),
        h("p", { class: "hint" }, "Upload a release on the Upgrade page; with this on, each node then builds and installs it in turn and rolls back by itself if the new version does not stay up."));
    };
    // the GUI certificate lives under Web GUI; its own controls save through their own calls, never through the settings form
    const certBox = h("div", {});
    certBox.addEventListener("change", (e) => e.stopPropagation());
    VIEWS.certificate.mount(certBox);
    // the Monitoring page is two tabs: SNMP and Metrics (every card stays in the page, so a save reads them all)
    const monitoringTabs = () => {
      const TABS = [
        ["SNMP", (() => { const c = section("SNMP", snmp.el); c.querySelector("h2").append(snmpPill); return c; })()],
        ["Metrics", section("Metrics", prom.el, h("p", { class: "muted small" },
          h("a", { href: "/api/metrics/dashboard.json", download: "netdir-grafana-dashboard.json" }, "Grafana dashboard example"), "\u00a0\u00a0-\u00a0\u00a0",
          h("a", { href: "/api/metrics/alerts.yml", download: "netdir-prometheus-alerts.yml" }, "Prometheus alert rules example")))],
      ];
      const panes = TABS.map(([, el]) => h("div", { role: "tabpanel" }, el));
      const buttons = TABS.map(([name], i) => h("button", { type: "button", role: "tab", class: "dtab", onclick: () => show(i) }, name));
      function show(i, focus) {
        state.monTab = i;
        refreshHelp();
        panes.forEach((p, j) => { p.hidden = j !== i; });
        buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
        if (focus) buttons[i].focus();
      }
      const strip = h("div", { class: "dtabs", role: "tablist", "aria-label": "Monitoring settings" }, buttons);
      strip.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        show((state.monTab + d + TABS.length) % TABS.length, true);
      });
      show(state.monTab >= 0 && state.monTab < TABS.length ? state.monTab : 0);
      return h("div", {}, strip, ...panes);
    };
    // the Devices page is four tabs: Devices, Logins, Checks and Tags (every table stays in the page, so a save reads them all)
    const devicesTabs = () => {
      const TABS = [["Devices", section("Devices", devices.el, loginList)], ["Logins", section("Logins", devcreds.el)], ["Checks", section("Checks", devcheck.el)], ["Tags", section("Tags", tagsTab.el)]];
      const panes = TABS.map(([, el]) => h("div", { role: "tabpanel" }, el));
      const buttons = TABS.map(([name], i) => h("button", { type: "button", role: "tab", class: "dtab", onclick: () => show(i) }, name));
      function show(i, focus) {
        state.devTab = i;
        refreshHelp();
        panes.forEach((p, j) => { p.hidden = j !== i; });
        buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
        if (focus) buttons[i].focus();
      }
      const strip = h("div", { class: "dtabs", role: "tablist", "aria-label": "Device settings" }, buttons);
      strip.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        show((state.devTab + d + TABS.length) % TABS.length, true);
      });
      tabsShow = show;
      show(state.devTab >= 0 && state.devTab < TABS.length ? state.devTab : 0);
      return h("div", {}, strip, ...panes);
    };
    // Syslog: the state of the connection is shown under the settings, with a button that sends a test message
    const syslogState = h("div", { class: "hint" });
    const syslogMsg = h("span", { class: "hint" });
    refreshSyslog = async () => {
      try {
        const st = (await api("GET", "/api/syslog")).data.status;
        clear(syslogState);
        if (!st.enabled) { syslogState.append("Forwarding is off."); return; }
        syslogState.append(pill(st.connected ? "connected" : "not connected", st.connected ? "ok tiny" : "bad tiny"),
          " " + st.protocol + " to " + st.address + " · " + st.sent + " sent, " + st.dropped + " dropped" + (st.last_error ? " · " + st.last_error : ""));
      } catch (_) { clear(syslogState); }
    };
    refreshSyslog();
    const syslogTest = h("button", { class: "btn", type: "button" }, "Send test message");
    syslogTest.addEventListener("click", async (ev) => {
      ev.stopPropagation(); // not a config edit
      clear(syslogMsg); syslogTest.disabled = true;
      try { await api("POST", "/api/syslog/test", {}); syslogMsg.textContent = "Delivered."; }
      catch (e) { if (e.message === "unauthenticated") throw e; syslogMsg.textContent = "Not delivered: " + (e.message || e); }
      syslogTest.disabled = false;
      refreshSyslog();
    });
    // DNS registration: what the last run did is shown under the settings, with buttons that run it now or take the records out
    const dnsState = h("div", { class: "hint" });
    const dnsMsg = h("span", { class: "hint" });
    refreshDNSReg = async () => {
      try {
        const st = (await api("GET", "/api/dnsreg")).data.status;
        clear(dnsState);
        if (!st.last_run) { dnsState.append(st.enabled ? "Registering shortly." : "Registration is off."); return; }
        const when = new Date(st.last_run).toLocaleString();
        dnsState.append(pill(st.failed ? "failed" : "ok", st.failed ? "bad tiny" : "ok tiny"),
          " " + (st.action === "remove" ? "Removal" : "Last check") + " " + when + " · " + st.existing + " right, " + st.updated + " updated" + (st.removed ? ", " + st.removed + " removed" : "") + ", " + st.failed + " failed" + (st.server ? " · server " + st.server : ""));
        const bad = (st.records || []).filter((x) => x.result === "failed").slice(0, 5);
        if (st.last_error && !bad.length) dnsState.append(h("div", {}, st.last_error));   // a run that failed before any record: the one error
        for (const r of bad) dnsState.append(h("div", {}, r.type + " " + r.name + ": " + (r.error || "failed")));
      } catch (_) { clear(dnsState); }
    };
    refreshDNSReg();
    const dnsBtn = (label, path, done) => {
      const b = h("button", { class: "btn", type: "button" }, label);
      b.addEventListener("click", async (ev) => {
        ev.stopPropagation(); // not a config edit
        if (path.endsWith("/remove") && b.dataset.sure !== "1") {   // a second click confirms
          b.dataset.sure = "1"; b.textContent = "Click again to remove";
          setTimeout(() => { b.dataset.sure = ""; b.textContent = label; }, 4000);
          return;
        }
        b.dataset.sure = ""; b.textContent = label;
        clear(dnsMsg); b.disabled = true; dnsMsg.textContent = "Working…";
        try { await api("POST", path, {}); dnsMsg.textContent = done; }
        catch (e) { if (e.message === "unauthenticated") throw e; dnsMsg.textContent = "Not done: " + (e.message || e); }
        b.disabled = false;
        refreshDNSReg();
      });
      return b;
    };
    // the Settings page is tabs (every card stays in the page, so a save reads all of them)
    const settingsTabs = () => {
      const TABS = [
        ["general", "General", h("div", {}, section("Neighbor discovery", lldp.el, h("p", { class: "f" }, lldpState)), section("Topology", topo.el))],
        ["logs", "Logs", h("div", {}, section("Log level", logs.el),
          section("Syslog", syslog.el, h("div", { class: "toolbar" }, syslogTest, syslogMsg, syslogState),
            h("p", { class: "hint" }, "Every line the log shows is also sent to the server, from this node only: the setting is not copied to the other nodes. A server that is down never holds anything up; the newest messages wait in a queue and the oldest are dropped if it fills.")))],
        ["dns", "DNS", h("div", {}, section("DNS registration", dnsreg.el, h("div", { class: "toolbar" }, dnsBtn("Register now", "/api/dnsreg/now", "Checked."), dnsBtn("Remove records", "/api/dnsreg/remove", "Removed."), dnsMsg, dnsState),
          h("p", { class: "hint" }, "This node puts its own addresses into DNS: its first address of each family as its host name, every interface as host-interface, and a PTR record for each address. The names given to the gateways are registered too: a gateway's VIP FQDN holds its shared addresses and its Anycast FQDN its anycast addresses, each address with a PTR record back to its name (set them under Topology ▸ Edit gateway); the shared addresses are never registered under this node's own name. Register now and Remove records use the saved settings. Turning this off leaves the records where they are; Remove records takes them out (turn this off first, or the next check puts them back). The setting is not copied to the other nodes.")))],
        ["upgrades", "Upgrades", updatesCard() || section("Upgrades", h("p", { class: "hint" }, "The upgrade settings cannot be read right now."))],
        ["cluster", "Cluster", section("Cluster", cluster.el)],
      ];
      const panes = TABS.map(([, , el]) => h("div", { role: "tabpanel" }, el));
      const buttons = TABS.map(([, name], i) => h("button", { type: "button", role: "tab", class: "dtab", onclick: () => show(i) }, name));
      function show(i, focus) {
        state.settingsTab = TABS[i][0];
        refreshHelp();
        panes.forEach((p, j) => { p.hidden = j !== i; });
        buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
        if (focus) buttons[i].focus();
      }
      const strip = h("div", { class: "dtabs", role: "tablist", "aria-label": "Settings" }, buttons);
      strip.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        const cur = Math.max(0, TABS.findIndex((t) => t[0] === state.settingsTab));
        show((cur + d + TABS.length) % TABS.length, true);
      });
      show(Math.max(0, TABS.findIndex((t) => t[0] === state.settingsTab)));
      return h("div", {}, strip, ...panes);
    };
    // one card per tab; every tab stays in the page (the hidden ones are just not shown) so a save reads all of them
    const panels = [
      ["general", "Settings", settingsTabs()],
      ["groups", "Gateway groups", h("div", {}, groupsEl)],
      ["devices", "Devices", devicesTabs()],
      ["web", "Web GUI", h("div", {}, section("Web GUI", web.el), certBox)],
      ["sso", "SSO", section("Single sign-on",
        sso.el)],
      ["ldap", "LDAP", section("LDAP sign-in", ldap.el)],
      ["mcp", "MCP", (() => { const c = section("MCP", mcp.el, h("p", { class: "muted small mono" }, mcpURL())); c.classList.add("mcpcard"); return c; })()],
      ["privacy", "Privacy", priv.el],
      ["monitoring", "Monitoring", monitoringTabs()],
      ["alerts", "Alerts", section("Alerts", alerts.el)],
      ["backup", "Backup", backup.el],
    ];
    for (const [pid, , el] of panels) el.hidden = pid !== tab;
    const form = h("div", {}, ...panels.map((p) => p[2]));
    form.addEventListener("change", () => autosave());
    return form;
  }

  function draw() {
    clear(holder).append(renderForm(state.cfg));
  }

  async function load() {
    try {
      const c = await api("GET", "/api/cluster");
      state.clustered = !!(c.data.enabled && c.data.peers.length > 1);
    } catch (e) { if (e.message === "unauthenticated") throw e; }
    try { const u = (await api("GET", "/api/update")).data.intent; state.autoUpdate = !!u.auto_all; state.updateRepo = u.repo || ""; } catch (e) { if (e.message === "unauthenticated") throw e; state.autoUpdate = null; }
    const r = await api("GET", "/api/config");
    state.cfg = r.config;
    state.cfgInfo = r;
    state.cfgBase = r.base;
    clear(status);
    if (!r.exists) say("info", "No config file at " + r.path + " yet — the first change creates it.");
    draw();
  }

  // Saving is automatic: there is no Save or Apply button.  One save runs at a
  // time; an edit made while one is running triggers another straight after.
  let busy = false, again = false;
  async function autosave() {
    if (busy) { again = true; return; }
    busy = true;
    try { do { again = false; await save(); } while (again); } finally { busy = false; }
  }

  async function save() {
    let cfg;
    try { cfg = collect(); } catch (e) { say("bad", e.message); return; }
    const was = state.cfg && state.cfg.web ? state.cfg.web : {};
    if (cfg.web.listen !== was.listen &&
      !confirm("Change the GUI listen address to " + cfg.web.listen + "?\n\nThe GUI restarts and every session ends. If the address is wrong you will lose access to this page.")) {
      draw(); // put the old value back
      return;
    }
    try {
      const r = await api("PUT", "/api/config", { config: cfg, base: state.cfgBase });
      state.cfg = r.config;
      state.cfgBase = r.base;
      clear(status);
      state.cfgInfo.exists = true;
      setTimeout(() => refreshSNMP(), 1500);   // snmpd was (re)started by the save
      setTimeout(() => refreshSyslog(), 800);  // so was the connection to the syslog server
      setTimeout(() => refreshDNSReg(), 6000); // and the DNS registration loop checks a few seconds after it starts
      setTimeout(() => refreshLLDP(), 1500);   // and lldpd started or stopped
    } catch (e) {
      if (e.message === "unauthenticated") return;
      if (e.status === 409) {   // the saved configuration is newer than this page's copy: take it (as the message says), or every later save is refused too
        try { await load(); } catch (_) { /* the message below still tells what happened */ }
      }
      say("bad", "Not saved: " + e.message);
    }
  }

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      holder = h("div", {});
      main.append(status, holder);
      load().catch((e) => { if (e.message !== "unauthenticated") say("bad", e.message); });
    },
  };
};
for (const id of ["general", "groups", "mcp", "privacy", "devices", "web", "sso", "ldap", "monitoring", "alerts", "backup"]) VIEWS["cfg_" + id] = makeConfigView(id);
