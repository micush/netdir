"use strict";
// MCP Network Director web GUI: what every page shares (state, the API, drawing helpers, the shell, sign-in).  No framework, no
// innerHTML: every value from the server goes through textContent, so nothing it returns can inject markup.
//
// The GUI is classic scripts that share one global scope, loaded in order by index.html:
// this file, one file per page (each adds its view to VIEWS), and boot.js last.

const POLL_MS = 2000;
const state = { prefill: {}, topo: { list: [], gid: null, action: null }, session: null, tab: "topology", timer: null, cfg: null, cfgMode: "form", cfgInfo: null, usersTab: 0,
  target: null, nodes: [], clustered: false }; // target: address of the node being driven, null = this one
const root = document.getElementById("app");

// Theme: Auto follows the system (prefers-color-scheme); Light and Dark force one.  The choice is kept in this browser only.
const THEMES = [["auto", "Auto"], ["light", "Light"], ["dark", "Dark"]];
const themeGet = () => { try { const t = localStorage.getItem("theme"); return THEMES.some(([k]) => k === t) ? t : "auto"; } catch (_) { return "auto"; } };
const themeApply = (t) => { if (t === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t; };
themeApply(themeGet());
function themeToggle() {
  const svg = (tag, a) => { const e = document.createElementNS("http://www.w3.org/2000/svg", tag); for (const k in a) e.setAttribute(k, a[k]); return e; };
  const ICON = {
    auto: () => [svg("circle", { cx: 8, cy: 8, r: 6 }), svg("path", { d: "M8 2a6 6 0 0 1 0 12z", fill: "currentColor" })],
    light: () => [svg("circle", { cx: 8, cy: 8, r: 3 }), ...[0, 45, 90, 135, 180, 225, 270, 315].map((a) => svg("path", { d: "M8 1.2v1.6", transform: "rotate(" + a + " 8 8)" }))],
    dark: () => [svg("path", { d: "M13.4 9.6A5.6 5.6 0 0 1 6.4 2.6a5.6 5.6 0 1 0 7 7z" })],
  };
  const btn = h("button", { class: "theme-btn", type: "button" });
  const draw = () => {
    const t = themeGet(), i = THEMES.findIndex(([k]) => k === t), next = THEMES[(i + 1) % THEMES.length];
    const s = svg("svg", { viewBox: "0 0 16 16", width: 16, height: 16, fill: "none", stroke: "currentColor", "stroke-width": 1.5, "stroke-linecap": "round", "aria-hidden": "true" });
    for (const e of ICON[t]()) s.append(e);
    btn.replaceChildren(s);
    btn.title = "Theme: " + THEMES[i][1] + (t === "auto" ? " (follows the system)" : "") + ". Click for " + next[1] + ".";
    btn.setAttribute("aria-label", btn.title);
  };
  btn.addEventListener("click", () => {
    const next = THEMES[(THEMES.findIndex(([k]) => k === themeGet()) + 1) % THEMES.length][0];
    try { if (next === "auto") localStorage.removeItem("theme"); else localStorage.setItem("theme", next); } catch (_) { /* no storage: lasts until reload */ }
    themeApply(next); draw();
  });
  draw();
  return h("div", { class: "nav-theme" }, btn);
}

// A small eye (struck through while the value is shown), drawn with DOM calls: no innerHTML.
function eyeIcon(struck) {
  const NS = "http://www.w3.org/2000/svg";
  const el = (n, a) => { const e = document.createElementNS(NS, n); for (const k in a) e.setAttribute(k, a[k]); return e; };
  const svg = el("svg", { viewBox: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" });
  svg.append(el("path", { d: "M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z" }), el("circle", { cx: "12", cy: "12", r: "3" }));
  if (struck) svg.append(el("path", { d: "M3 3l18 18" }));
  return svg;
}

// Every password box except the sign-in one gets an eye button beside it, so a saved password, token or key can be read.
(function revealPasswords() {
  const decorate = (inp) => {
    if (inp._rv || inp.getAttribute("autocomplete") === "current-password") return;
    inp._rv = true;
    const b = document.createElement("button");
    b.type = "button"; b.className = "reveal"; b.title = "Show";
    b.append(eyeIcon(false));
    b.setAttribute("aria-pressed", "false");
    b.setAttribute("aria-label", "Show " + (inp.getAttribute("aria-label") || "value"));
    b.addEventListener("click", (e) => {
      e.preventDefault(); e.stopPropagation();
      const on = inp.type === "password";
      inp.type = on ? "text" : "password";
      b.title = on ? "Hide" : "Show";
      b.replaceChildren(eyeIcon(on));
      b.setAttribute("aria-pressed", String(on));
    });
    const wrap = document.createElement("span");
    wrap.className = "reveal-wrap";
    inp.replaceWith(wrap);
    wrap.append(inp, b);
  };
  const scan = (n) => {
    if (n.nodeType !== 1) return;
    if (n.matches("input[type=password]")) decorate(n);
    else n.querySelectorAll("input[type=password]").forEach(decorate);
  };
  new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach(scan))).observe(root, { childList: true, subtree: true });
})();

// The daemon puts its version in BUILD when it serves this file. After an upgrade the daemon restarts with a new
// interface; a page left open notices (the session says which version answers) and reloads itself, but not while
// a dialog is open, a field is being typed in, or a Configure page is open (it may hold changes not yet saved).
const BUILD = "@@BUILD@@";
let reloading = false;
function checkBuild(v) {
  if (reloading || BUILD.charAt(0) === "@" || !v || String(v) === BUILD) return;
  reloading = true;
  const go = () => {
    const a = document.activeElement, typing = a && (a.tagName === "TEXTAREA" || a.tagName === "SELECT" || (a.tagName === "INPUT" && a.type !== "checkbox" && a.type !== "radio" && a.type !== "button"));
    if (document.querySelector("dialog[open]") || typing || String(state.tab).startsWith("cfg")) { setTimeout(go, 3000); return; }
    location.reload();
  };
  go();
}
setInterval(() => {
  if (!state.session || document.hidden || reloading) return;
  api("GET", "/api/session", undefined, true).then((s) => checkBuild(s && s.version)).catch(() => { /* the daemon is restarting: look again next time */ });
}, 15000);

// ── DOM helper ────────────────────────────────────────────────────────────
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) { el.addEventListener(k.slice(2), v); (el.__on = el.__on || {})[k.slice(2)] = v; }
    else if (k === "value") el.value = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
// A box of tags (words separated by spaces or commas) that offers the tags already in use while the last word is typed: a list under the box,
// chosen with the mouse, or with Down/Up and Enter or Tab.  Enter with nothing chosen is left alone (it still submits the form).
// `tagsNow()` gives every tag in use at that moment (a table may hold rows that are not saved yet).
// A filter box: words must all match (AND, also written out); OR makes alternatives; a ! before a word (!dns), or NOT, means "does not match".
// "phx AND !dns" and "phx !dns" both find what has phx and not dns; "phx OR sea" finds either.  `match(test)` asks test(word) for each word.
function parseFilter(text) {
  const groups = [[]];
  let pend = false;   // a "not" waits for the word it applies to
  for (const raw of String(text || "").toLowerCase().split(/\s+/).filter(Boolean)) {
    if (raw === "and") { pend = false; continue; }
    if (raw === "or") { pend = false; if (groups[groups.length - 1].length) groups.push([]); continue; }
    if (raw === "not") { pend = !pend; continue; }
    const w = raw.replace(/^!+/, ""), neg = ((raw.length - w.length) % 2 === 1) !== pend;
    pend = false;
    if (w) groups[groups.length - 1].push({ w, neg });
  }
  const gs = groups.filter((g) => g.length);
  return { empty: !gs.length, match: (test) => !gs.length || gs.some((g) => g.every((t) => !!test(t.w) !== t.neg)) };
}
function tagSuggest(input, tagsNow) {
  let pop = null, items = [], at = -1;
  const word = () => { const m = /[^\s,]*$/.exec(input.value); return m ? m[0] : ""; };
  const close = () => { if (pop) { pop.remove(); pop = null; } items = []; at = -1; };
  const pick = (t) => {
    input.value = input.value.slice(0, input.value.length - word().length) + t + " ";
    close();
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
  };
  const paint = () => { if (pop) [...pop.children].forEach((b, i) => b.classList.toggle("on", i === at)); };
  const open = (all) => {
    const w = word().toLowerCase(), have = new Set(input.value.split(/[\s,]+/).filter(Boolean).slice(0, -1).map((x) => x.toLowerCase()));
    if (!w && !all) return close();
    let tags = []; try { tags = tagsNow() || []; } catch (_) { /* a row that is not finished */ }
    items = [...new Set(tags)].filter((t) => !have.has(t.toLowerCase()) && t.toLowerCase() !== w && t.toLowerCase().includes(w)).sort((a, b) => (b.toLowerCase().startsWith(w) ? 1 : 0) - (a.toLowerCase().startsWith(w) ? 1 : 0) || a.localeCompare(b)).slice(0, 8);
    if (!items.length) return close();
    if (!pop) pop = h("div", { class: "tagpop", role: "listbox", "aria-label": "Tags in use" });
    clear(pop).append(...items.map((t) => h("button", { type: "button", role: "option", tabindex: "-1", onmousedown: (e) => { e.preventDefault(); pick(t); } }, t)));
    const r = input.getBoundingClientRect();
    pop.style.left = r.left + "px"; pop.style.top = r.bottom + 2 + "px"; pop.style.minWidth = r.width + "px";
    (input.closest("dialog") || document.body).append(pop);
    at = -1;
  };
  input.setAttribute("autocomplete", "off");
  input.addEventListener("input", () => open(false));
  input.addEventListener("blur", close);
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" && !pop) { open(true); if (pop) { at = 0; paint(); e.preventDefault(); } return; }
    if (!pop) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); at = (at + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length; paint(); }
    else if ((e.key === "Enter" || e.key === "Tab") && at >= 0) { e.preventDefault(); pick(items[at]); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); }
  });
}

// morph makes the children of dst the same as the children of src, reusing the elements that are already there (only
// their text and attributes are patched).  A page that is redrawn on a timer uses it so that what the browser keeps
// about an element survives the redraw: the position of a horizontal scroll bar, a text selection.  Emptying a
// container and building it again, which these pages did, destroys every scroll box in it, so a scroll bar that had been
// moved sprang back and the bars flashed on every redraw.  Only for markup without event handlers: the handlers are
// not copied.  An inline style is skipped too (the page's policy allows it only through the CSSOM, so the caller sets it).
function morph(dst, src) {
  const from = Array.from(src.childNodes);
  from.forEach((s, i) => {
    const d = dst.childNodes[i];
    if (!d) { dst.appendChild(s); return; }
    if (d.nodeType !== s.nodeType || d.nodeName !== s.nodeName) { dst.replaceChild(s, d); return; }
    if (s.nodeType !== 1) { if (d.nodeValue !== s.nodeValue) d.nodeValue = s.nodeValue; return; }
    for (const at of Array.from(d.attributes)) if (at.name !== "style" && !s.hasAttribute(at.name)) d.removeAttribute(at.name);
    for (const at of Array.from(s.attributes)) if (at.name !== "style" && d.getAttribute(at.name) !== at.value) d.setAttribute(at.name, at.value);
    // handlers: the new element's replace the old ones (they close over the new data)
    const dOn = d.__on || {}, sOn = s.__on || {};
    for (const ev of Object.keys(dOn)) if (dOn[ev] !== sOn[ev]) d.removeEventListener(ev, dOn[ev]);
    for (const ev of Object.keys(sOn)) if (dOn[ev] !== sOn[ev]) d.addEventListener(ev, sOn[ev]);
    d.__on = sOn;
    // form state is a property, not an attribute; what the person is typing into is left alone
    if (d.nodeName === "INPUT" && d !== document.activeElement) { if (d.type === "checkbox" || d.type === "radio") d.checked = s.checked; else if (d.value !== s.value) d.value = s.value; }
    if (d.nodeName === "INPUT" || d.nodeName === "BUTTON") d.disabled = s.disabled;
    morph(d, s);
  });
  while (dst.childNodes.length > from.length) dst.removeChild(dst.lastChild);
}
// fill(el, ...kids): what `clear(el).append(...kids)` does, but el keeps the elements it already has (see morph), so the
// scroll boxes inside it are not destroyed and re-created by every poll.
const fill = (el, ...kids) => { morph(el, h("div", {}, ...kids)); return el; };
// tc(text): a card heading in title case ("Upload a release" -> "Upload a Release").  Short joining words stay small (but not
// first); a word that already has a capital after its first letter (BGP, NTS, GUI) is left as it is, and so is what follows a
// hyphen ("Kiss-o'-death", "Policy-Based").
const SMALL_WORDS = new Set(["a", "an", "and", "as", "at", "but", "by", "for", "in", "nor", "of", "on", "or", "per", "the", "to", "via", "vs"]);
const tc = (t) => (typeof t !== "string" ? t : t.replace(/(?<![\w'’-])[A-Za-z][A-Za-z'’]*/g, (w, i) => ((i > 0 && SMALL_WORDS.has(w)) || /[A-Z]/.test(w.slice(1)) ? w : w[0].toUpperCase() + w.slice(1))));
const pill = (text, kind) => h("span", { class: "pill " + (kind || "") }, text);
// what lldpd is doing on a node (GET /api/lldp), in a few words; the same as `netdir --lldp`
const lldpWords = (st) => !st.installed ? "lldpd is not installed on this node"
  : st.deferred ? (st.running ? "Running, managed in AnyName on this host" : "Stopped: AnyName is on this host and decides")
  : st.running ? "Running" : st.enabled ? "Stopped: see the log" : "Stopped";

// ── API ───────────────────────────────────────────────────────────────────
// Everything follows the node picked in the top bar (relayed through the node
// you are logged in to) except the login itself.  The picker's own list of
// nodes is asked of the login node explicitly (api(..., true)).
const LOCAL_API = /^\/api\/(login|logout|session|proxy|tshoot\/download)(\/|\?|$)/;
// The Node menu's "Cluster" entry: Monitor ▸ Node shows every node's numbers added together (the node you are logged in to
// asks the others), and Monitor ▸ Capture captures on every node.  Only those pages offer it, and only their requests change;
// anything else a page asks goes to this node as before.
const CLUSTER = "*cluster";
// Node and Capture also offer each gateway: the nodes that serve it, together like Cluster.
const GW = "*gw:";
const GW_TABS = ["host", "capture"];   // the pages that offer the gateways
const isGw = () => typeof state.target === "string" && state.target.startsWith(GW);
const gwTitle = (g) => g.name || String(g.vip4 || g.vip6 || "").split("/")[0] || "gateway " + g.group_id;
const gwItems = () => (state.gws || []).map((g) => {
  const n = state.nodes.filter((p) => !(g.excluded_nodes || []).includes(p.node_id)).length;
  return n ? [GW + g.group_id, "Gateway " + gwTitle(g) + " (" + n + ")", false] : null;
}).filter(Boolean);
const CLUSTER_TABS = ["host", "capture"];
const CLUSTER_API = [[/^\/api\/host(\?|$)/, "/api/clusterhost"]];
function route(path) {
  if (isGw()) { const to = /^\/api\/host(\?|$)/.test(path) ? "/api/clusterhost" : ""; return to ? path.replace(/^\/api\/[a-z]+/, to) + (path.includes("?") ? "&" : "?") + "gw=" + encodeURIComponent(state.target.slice(GW.length)) : path; }
  if (state.target === CLUSTER) {
    for (const [re, to] of CLUSTER_API) if (re.test(path)) return path.replace(/^\/api\/[a-z]+/, to);
    return path;
  }
  if (!state.target || LOCAL_API.test(path)) return path;
  return "/api/proxy?node=" + encodeURIComponent(state.target) + "&path=" + encodeURIComponent(path);
}
async function api(method, path, body, local) {
  const orig = path;
  if (!local) path = route(path);
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (state.session && method !== "GET") headers["X-CSRF-Token"] = state.session.csrf;
  const res = await fetch(path, {
    method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON error */ }
  if (res.status === 401 && orig !== "/api/login") {
    stopAllTimers();
    state.session = null;
    showLogin();
    throw new Error("unauthenticated");
  }
  if (!res.ok) {
    const err = new Error((data && data.error) || res.statusText || "request failed");
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// Upload raw bytes (release archive); the CSRF token still applies.
async function apiUpload(path, file) {
  const res = await fetch(route(path), {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/octet-stream", "X-CSRF-Token": state.session.csrf },
    body: file,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON error */ }
  if (res.status === 401) { stopAllTimers(); state.session = null; showLogin(); throw new Error("unauthenticated"); }
  if (!res.ok) throw new Error((data && data.error) || res.statusText || "upload failed");
  return data;
}

// Download a file the daemon builds (a capture): fetched with the session, named by the server's Content-Disposition.
async function apiDownload(path, fallback) {
  const res = await fetch(route(path), { credentials: "same-origin" });
  if (res.status === 401) { stopAllTimers(); state.session = null; showLogin(); throw new Error("unauthenticated"); }
  if (!res.ok) {
    let data = null;
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    throw new Error((data && data.error) || res.statusText || "download failed");
  }
  const m = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") || "");
  const a = h("a", { href: URL.createObjectURL(await res.blob()), download: m ? m[1] : fallback });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

// ── login ─────────────────────────────────────────────────────────────────
function showLogin(message) {
  stopAllTimers();
  // Already showing the form (a late 401 from a request still in flight): leave
  // it alone, so nothing being typed is wiped.
  if (!message && root.querySelector("form input[name=username]")) return;
  clear(root);
  const err = h("div", { class: "notice bad hidden", role: "alert" });
  if (message) { err.textContent = message; err.classList.remove("hidden"); }
  const user = h("input", { type: "text", name: "username", autocomplete: "username", required: true, autofocus: true, autocapitalize: "none", spellcheck: "false" });
  const pass = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Log in");
  let lockTimer = null;
  const setLocked = (on) => { user.disabled = pass.disabled = btn.disabled = on; };
  // Locked out: disable the form and count down to the end of the lockout.
  function lockFor(secs) {
    const end = Date.now() + secs * 1000;
    setLocked(true);
    clearInterval(lockTimer);
    const tick = () => {
      const left = Math.ceil((end - Date.now()) / 1000);
      if (!form.isConnected) { clearInterval(lockTimer); return; }
      if (left <= 0) {
        clearInterval(lockTimer);
        setLocked(false);
        err.classList.add("hidden");
        user.focus();
        return;
      }
      err.textContent = "Too many failed attempts.";
      err.classList.remove("hidden");
    };
    tick();
    lockTimer = setInterval(tick, 1000);
  }
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      err.classList.add("hidden");
      try {
        state.session = await api("POST", "/api/login", { username: user.value, password: pass.value });
        checkBuild(state.session.version);
        pass.value = "";
        showShell();
      } catch (ex) {
        pass.value = "";
        const d = ex.data || {};
        if (ex.status === 429 && d.retry_after) { lockFor(d.retry_after); return; }
        err.textContent = ex.message;
        err.classList.remove("hidden");
        pass.focus();
        btn.disabled = false;
      }
    },
  },
    h("label", { class: "f" }, "Username", user),
    h("label", { class: "f" }, "Password", pass),
    btn);
  const ssoBox = h("div", { class: "sso-buttons hidden" });
  root.append(h("div", { class: "login-wrap" }, h("div", { class: "login" },
    h("div", { class: "card" }, h("div", { class: "body" },
      h("h1", {}, "MCP Network Director"),
      h("p", { class: "sub" }, "Sign in with your system account"),
      err, form, ssoBox)))));
  user.focus();
  // back from a failed single sign-on: say why
  try {
    const sp = new URLSearchParams(location.search);
    if (sp.get("sso_error")) { err.textContent = sp.get("sso_error"); err.classList.remove("hidden"); history.replaceState(null, "", location.pathname); }
  } catch (_) { /* no message */ }
  // already locked out (page reloaded)? show it before anything is typed
  fetch("/api/login/state", { credentials: "same-origin" }).then((r) => r.json()).then((d) => {
    if (d.locked && d.retry_after) lockFor(d.retry_after);
    // the providers that are set up: a full-page trip to the provider and back (no script on the way)
    for (const p of d.sso || []) ssoBox.append(h("a", { class: "btn sso", href: "/api/sso/start?p=" + encodeURIComponent(p.id) }, "Sign in with " + p.title));
    if ((d.sso || []).length) ssoBox.classList.remove("hidden");
  }).catch(() => { /* the form still works */ });
}

// ── shell / navigation ────────────────────────────────────────────────────
// Sidebar groups: one open at a time; the group holding the current page is open.
// Topology comes first; its items are the gateways themselves (filled in from the daemon).
const TOPO = "Topology";
const NAV_GROUPS = [
  ["Configure", [["cfg_general", "Settings"], ["cfg_groups", "Gateways"], ["cfg_mcp", "MCP"], ["cfg_privacy", "Privacy"], ["cfg_devices", "Devices"], ["cfg_web", "Web GUI"], ["cfg_monitoring", "Monitoring"], ["cfg_alerts", "Alerts"], ["cfg_backup", "Backup"], ["anycast", "Anycast"], ["users", "Users"]]],
  ["Operate", [["node", "Node"], ["cluster", "Cluster"], ["anycastop", "Anycast"], ["scheduler", "Scheduler"], ["history", "History"], ["updates", "Upgrade"]]],
  ["Monitor", [["mcpusage", "MCP"], ["host", "Node"], ["devices", "Devices"], ["gateways", "Gateways"], ["nodes", "Cluster"], ["anycaststatus", "Anycast"], ["alerts", "Alerts"], ["capture", "Capture"], ["log", "Log"]]],
];
const TABS = [["topology", TOPO]].concat(NAV_GROUPS.flatMap(([, items]) => items));
const groupOf = (id) => (id === "topology" ? TOPO : (NAV_GROUPS.find(([, items]) => items.some(([i]) => i === id)) || [null])[0]);
const bareIP = (a) => (a || "").split("/")[0];

// The gateways listed under Topology: bare address, a status dot, nothing else.
async function refreshTopoNav() {
  try {
    // always the node you signed in to, and the gateway's state for the cluster as a whole (from its nodes), so the dot does not change with the Node menu
    const r = await api("GET", "/api/canvas?own=1", undefined, true);
    state.topo.list = (r.data || []).map((g) => ({ id: g.group_id, label: g.name || bareIP(g.vip4) || bareIP(g.vip6) || "gateway " + g.group_id,
      status: g.cluster_status || g.status, title: "Group " + g.group_id + (g.name ? " · " + (bareIP(g.vip4) || bareIP(g.vip6)) : "") + " — " + (g.cluster_status ? g.cluster_detail : g.detail) }));
  } catch (_) { return; }
  state.topo.list.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: "base" }) || a.id - b.id);   // alphabetical (10.0.0.2 before 10.0.0.10)
  if (!state.topo.list.some((g) => g.id === state.topo.gid)) state.topo.gid = state.topo.list.length ? state.topo.list[0].id : null;
  renderTopoNav();
}
// A red warning triangle on Monitor ▸ Alerts (and on the Monitor heading, which may be folded) while the node picked in the top bar has an alert
// that is open, not acknowledged and not silenced.
const alertMark = () => {
  const m = h("span", { class: "alert-mark", role: "img", title: "There is an alert that needs attention", "aria-label": "alert" });
  m.innerHTML = '<svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true"><path d="M8 1.4 15 14H1z" fill="#fff" stroke="#d32f2f" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 5.9v3.9M8 11.3v1" stroke="#d32f2f" stroke-width="1.7" stroke-linecap="round"/></svg>';
  return m;
};
async function refreshAlertMark() {
  let on = false;
  try {
    const v = (await api("GET", "/api/alerts")).data;
    on = (v.alerts || []).some((a) => !a.closed && !a.acked && !a.silenced_until);
  } catch (_) { return; }
  const marks = [root.querySelector('.nav-item[data-tab="alerts"]'), root.querySelector('.nav-group[data-group="Monitor"] .nav-group-label')];
  for (const el of marks) {
    if (!el) continue;
    const old = el.querySelector(".alert-mark");
    if (on && !old) el.append(alertMark());
    else if (!on && old) old.remove();
  }
}
function renderTopoNav() {
  const box = root.querySelector('.nav-group[data-group="' + TOPO + '"] .nav-items');
  if (!box) return;
  const here = state.tab === "topology";
  clear(box).append(...state.topo.list.map((g) => h("button", { type: "button", class: "nav-item", title: g.title, "data-gw": g.id,
      "aria-current": here && g.id === state.topo.gid ? "page" : null,
      onclick: () => { state.topo.gid = g.id; selectTab("topology"); },
      oncontextmenu: rowMenu([["Rename", () => { state.topo.gid = g.id; state.topo.action = "rename"; selectTab("topology"); }],
        ["MCP", () => selectTab("cfg_mcp")],
        ["Delete", () => { state.topo.gid = g.id; state.topo.action = "delete"; selectTab("topology"); }, "danger"]]) },
    h("span", { class: "dot st-" + g.status }), g.label)),
    h("button", { type: "button", class: "nav-item add", onclick: () => { state.topo.action = "new"; selectTab("topology"); } }, "＋ New gateway"));
}

function openNavGroup(name) {
  for (const g of root.querySelectorAll(".nav-group")) {
    const open = g.dataset.group === name;
    g.querySelector(".nav-group-label").classList.toggle("open", open);
    g.querySelector(".nav-group-label").setAttribute("aria-expanded", String(open));
    g.querySelector(".nav-items").classList.toggle("hidden", !open);
  }
}

function showShell() {
  stopAllTimers();
  clear(root);
  const s = state.session;
  const groups = [[TOPO, []]].concat(NAV_GROUPS).map(([name, items]) => h("div", { class: "nav-group", "data-group": name },
    h("button", { type: "button", class: "nav-group-label", "aria-expanded": "false",
      onclick: () => { if (name === TOPO) selectTab("topology"); else openNavGroup(name); } },
      h("span", { class: "nav-chevron" }), name),
    h("div", { class: "nav-items hidden" },
      items.map(([id, label]) => h("button", { type: "button", class: "nav-item", "data-tab": id, onclick: () => selectTab(id) }, label)))));
  const nav = h("nav", { class: "side", "aria-label": "Sections" },
    h("div", { class: "mark" }, h("div", { class: "brand" }, "MCP Network Director"),
      h("div", { class: "muted small" }, "v" + s.version + (s.hostname && s.hostname.toLowerCase() !== "netdir" ? " · " + s.hostname : ""))),
    h("div", { class: "nav-section" }, groups),
    themeToggle(),
    h("div", { class: "nav-footer" },
      h("div", { class: "who" }, "Signed in as ", h("strong", {}, s.user)),
      h("button", { class: "nav-signout", type: "button", onclick: logout }, "Sign out")));
  root.append(helpControls());
  root.append(h("div", { class: "shell" }, nav,
    h("div", { class: "content" },
      h("div", { id: "topbar", class: "topbar hidden" }),
      h("div", { id: "banner", class: "banner" }),
      h("main", { id: "main" }))));
  state.target = null;
  state.nodes = [];
  state.clustered = false;
  document.body.classList.remove("remote");
  certBanner();
  refreshTopoNav();
  refreshNodes();
  state.topoTimer = setInterval(() => { if (!document.hidden) refreshTopoNav(); }, 4000);
  state.nodesTimer = setInterval(() => { if (!document.hidden) refreshNodes(); }, 6000);
  refreshAlertMark();
  state.alertTimer = setInterval(() => { if (!document.hidden) refreshAlertMark(); }, 5000);
  let wanted = location.hash.slice(1);
  if (wanted === "canvas") wanted = "topology"; // the page's old name: keep old bookmarks working
  if (wanted === "neighbors") wanted = "nodes"; // likewise
  if (wanted === "power" || wanted === "gateway") wanted = "node"; // Power and the short-lived Gateway page became Operate ▸ Node
  if (wanted === "bgpstatus") wanted = "anycaststatus"; // Monitor ▸ BGP became Monitor ▸ Anycast
  if (wanted === "bgp") wanted = "anycast"; // likewise Configure ▸ BGP
  if (wanted === "certificate") wanted = "cfg_web"; // moved under Configure ▸ Web GUI
  if (wanted === "config") wanted = "cfg_general"; // Configure ▸ Settings was split into one page per tab
  if (wanted === "cfg_cluster") { wanted = "cfg_general"; state.settingsTab = "cluster"; } // moved under Configure ▸ Settings
  selectTab(TABS.some(([id]) => id === wanted) ? wanted : "topology");
}

async function logout() {
  try { await api("POST", "/api/logout", {}); } catch (_) { /* already gone */ }
  stopAllTimers();
  state.target = null;
  document.body.classList.remove("remote");
  state.session = null;
  showLogin();
}

function selectTab(id) {
  state.tab = id;
  if (state.target === CLUSTER && !CLUSTER_TABS.includes(id)) state.target = null;   // the other pages are about one node: back to this one
  if (isGw() && !GW_TABS.includes(id)) state.target = null;
  renderTopbar();   // the Cluster entry is on the menu for Statistics and Monitor ▸ Node only
  history.replaceState(null, "", "#" + id);
  for (const b of root.querySelectorAll("nav.side .nav-item[data-tab]")) {
    if (b.dataset.tab === id) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  const grp = groupOf(id);
  if (grp) openNavGroup(grp);
  renderTopoNav();
  stopPolling();
  const main = clear(document.getElementById("main"));
  const view = VIEWS[id];
  view.mount(main);
  if (document.getElementById("help-panel") && document.getElementById("help-panel").classList.contains("open")) fillHelp();
  if (view.poll) {
    startPolling(view.poll);
  }
}

// ── help: the "?" in the top right, a slide-out panel for the current page ──
// Content is data in help.js (NETDIR_HELP); this builds it with DOM calls only.
function richText(str) {
  const out = [];
  for (const part of String(str).split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/)) {
    if (!part) continue;
    if (part.startsWith("**")) out.push(h("strong", {}, part.slice(2, -2)));
    else if (part.startsWith("`")) out.push(h("code", {}, part.slice(1, -1)));
    else if (part.startsWith("*") && part.length > 2) out.push(h("em", {}, part.slice(1, -1)));
    else out.push(part);
  }
  return out;
}
function helpBody(topic) {
  const t = NETDIR_HELP[topic] || NETDIR_HELP._default;
  const kids = t.body.map((blk) => {
    if (typeof blk === "string") return h("p", {}, richText(blk));
    if (blk[0] === "h") return h("h3", {}, blk[1]);
    if (blk[0] === "ul") return h("ul", {}, blk[1].map((li) => h("li", {}, richText(li))));
    if (blk[0] === "ol") return h("ol", {}, blk[1].map((li) => h("li", {}, richText(li))));
    if (blk[0] === "note") return h("p", { class: "help-note" }, richText(blk[1]));
    if (blk[0] === "fields") return h("dl", { class: "help-fields" }, blk[1].flatMap(([name, text]) => [h("dt", {}, name), h("dd", {}, richText(text))]));
    if (blk[0] === "cli") return h("div", {}, h("h3", {}, "Command line"), h("pre", { class: "help-cli" }, blk[1]));
    return null;
  });
  return [t.title, kids];
}
function helpControls() {
  const overlay = h("div", { class: "help-overlay hidden", id: "help-overlay" });
  const title = h("h2", { id: "help-title" });
  const body = h("div", { class: "help-panel-body", id: "help-body" });
  // Find: every match in the page's help is marked; Enter goes to the next one, Shift+Enter to the one before, Esc empties the box
  const find = h("input", { type: "text", class: "help-find", id: "help-find", placeholder: "Find", "aria-label": "Find in help", autocomplete: "off", spellcheck: "false",
    oninput: () => markHelp(true),
    onkeydown: (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); stepHelp(ev.shiftKey ? -1 : 1); }
      else if (ev.key === "Escape" && find.value) { ev.stopPropagation(); find.value = ""; markHelp(true); }
    } });
  const panel = h("aside", { class: "help-panel", id: "help-panel", "aria-hidden": "true", "aria-label": "Help" },
    h("div", { class: "help-panel-header" }, title),
    h("div", { class: "help-find-row" }, find, h("span", { class: "help-find-count muted small", id: "help-find-count" })), body);
  const btn = h("button", { class: "help-btn", id: "help-btn", type: "button", title: "Help for this page", "aria-label": "Help",
    onclick: () => setHelp(!panel.classList.contains("open")) }, "?");
  overlay.addEventListener("click", () => setHelp(false));
  return h("div", {}, btn, overlay, panel);
}
// Opening (and every page change while open) fills the panel for the current page.
function setHelp(open) {
  const panel = document.getElementById("help-panel"), overlay = document.getElementById("help-overlay");
  if (!panel) return;
  if (open) fillHelp();
  panel.classList.toggle("open", !!open);
  overlay.classList.toggle("hidden", !open);
  panel.setAttribute("aria-hidden", open ? "false" : "true");
  const b = document.getElementById("help-btn");
  b.setAttribute("aria-label", open ? "Close help" : "Help");
  b.title = open ? "Close help (Esc)" : "Help for this page";
}
let helpHits = [], helpAt = 0;
function markHelp(jump) {
  const body = document.getElementById("help-body"), box = document.getElementById("help-find"), count = document.getElementById("help-find-count");
  if (!body || !box) return;
  for (const m of body.querySelectorAll("mark.help-hit")) m.replaceWith(document.createTextNode(m.textContent));   // take the old marks out
  body.normalize();
  helpHits = []; helpAt = 0;
  const q = box.value.toLowerCase();
  if (q) {
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
    const texts = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) texts.push(n);
    for (const node of texts) {
      let cur = node;
      for (let i = cur.data.toLowerCase().indexOf(q); i >= 0; i = cur.data.toLowerCase().indexOf(q)) {
        const hit = cur.splitText(i), rest = hit.splitText(q.length);
        const m = h("mark", { class: "help-hit" }, hit.data);
        hit.replaceWith(m);
        helpHits.push(m);
        cur = rest;
      }
    }
  }
  count.textContent = q ? (helpHits.length ? "1 / " + helpHits.length : "0") : "";
  if (helpHits.length) stepHelp(0, jump);
}
// the current match gets its own colour and is scrolled into view
function stepHelp(d, jump = true) {
  if (!helpHits.length) return;
  helpHits[helpAt].classList.remove("cur");
  helpAt = (helpAt + d + helpHits.length) % helpHits.length;
  const m = helpHits[helpAt];
  m.classList.add("cur");
  document.getElementById("help-find-count").textContent = (helpAt + 1) + " / " + helpHits.length;
  if (jump) m.scrollIntoView({ block: "center" });
}
// Which panel the help shows: one for every page, and for every tab and sub-tab of a page that has them.
function helpTopicKey() {
  const k = (() => {
    switch (state.tab) {
    case "cfg_general": return state.settingsTab === "cluster" ? "config_cluster" : state.settingsTab === "upgrades" ? "config_upgrades" : state.settingsTab === "dns" ? "config_dns" : state.settingsTab === "general" ? "config_general" : "config_logs";
    case "cfg_groups": return "config_groups";
    case "cfg_devices": return state.devTab === 3 ? "config_tags" : state.devTab === 2 ? "config_checks" : state.devTab === 1 ? "config_logins" : "config_devices";
    case "cfg_web": return "config_web";
    case "anycast": return "anycast_" + (state.anycastTab === 1 ? "ospf" : "bgp");
    case "anycaststatus": return "anycaststatus_" + (state.anycastMonTab === 1 ? "ospf" : "bgp");
    case "anycastop": return "anycastop_" + (state.anycastOpTab === 1 ? "ospf" : "bgp");
    case "cfg_alerts": return "config_alerts";
    case "cfg_backup": return "config_backup";
    case "cfg_mcp": return "config_mcp";
    case "cfg_privacy": return "config_privacy";
    case "cfg_monitoring": return state.monTab === 1 ? "config_metrics" : "config_snmp";
    case "users": return state.usersTab === 1 ? "users_ldap" : state.usersTab === 2 ? "users_sso" + (state.ssoTab >= 0 ? state.ssoTab : 0) : "users_local";
    default: return state.tab;
    }
  })();
  return NETDIR_HELP[k] ? k : state.tab;
}
// a tab inside a page was changed: if the help is open, show the panel of that tab
function refreshHelp() {
  const pn = document.getElementById("help-panel");
  if (pn && pn.classList.contains("open")) fillHelp();
}
function fillHelp() {
  const topic = helpTopicKey();
  const [t, kids] = helpBody(topic);
  document.getElementById("help-title").textContent = t;
  const body = clear(document.getElementById("help-body"));
  body.append(...kids);
  body.scrollTop = 0;
  markHelp(false);   // a word typed in Find stays marked on the next page's help
}
document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") setHelp(false); });

// ── node picker (top right) ────────────────────────────────────────────────
const selfNode = () => state.nodes.find((n) => n.self) || null;
const currentNode = () => state.nodes.find((n) => n.addr === state.target) || null;
// the host name, or the address too when two nodes share a name
const nodeLabel = (n) => {
  if (!n) return "this node";
  if (!n.hostname) return n.addr;
  return state.nodes.filter((x) => x.hostname === n.hostname).length > 1 ? n.hostname + " (" + n.addr + ")" : n.hostname;
};

async function refreshNodes() {
  let v;
  try { v = (await api("GET", "/api/cluster", undefined, true)).data; } catch (_) { return; }
  state.clustered = !!(v && v.enabled && (v.peers || []).length > 1);
  state.nodes = state.clustered ? v.peers : [];
  if (GW_TABS.includes(state.tab) && state.nodes.length >= 2 && Date.now() - (state.gwsAt || 0) > 20000) {   // the gateways for the Node menu
    state.gwsAt = Date.now();
    try { state.gws = ((await api("GET", "/api/config", undefined, true)).config || {}).groups || []; } catch (_) { /* the last list stays */ }
  }
  if (state.target === CLUSTER || isGw() ? state.nodes.length < 2 : state.target && !state.nodes.some((n) => n.addr === state.target && !n.self)) setTarget(null);
  renderTopbar();
}

// The filter box takes the focus when a gateway's drawing is opened, and again for each gateway picked in the sidebar, but not from another
// box being typed in or an open dialog, and never again for the same gateway (the drawing and the bar are redrawn all the time).
function focusTopoFilter(gid) {
  if (state.topoFocusGid === gid) return;
  const f = document.querySelector("input.cv-filter");
  if (!f) return;
  state.topoFocusGid = gid;
  const ae = document.activeElement;
  if (document.querySelector("dialog[open]") || (ae && ae !== f && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName))) return;
  f.focus();
}
function renderTopbar() {
  const bar = document.getElementById("topbar");
  if (!bar) return;
  // The nodes are asked for every few seconds; the bar is only redrawn when what it shows changed, and not at all while one of its
  // pickers has the focus (redrawing it shut an open list).
  const view = [state.tab, state.target];
  const sig = JSON.stringify([view, GW_TABS.includes(state.tab) ? gwItems() : null, state.nodes.map((n) => [n.addr, nodeLabel(n), n.is_primary, n.reachable, !!n.self])]);
  if (bar.dataset.sig === sig) return;
  if (bar.contains(document.activeElement) && bar.dataset.view === JSON.stringify(view)) return;
  bar.dataset.sig = sig;
  bar.dataset.view = JSON.stringify(view);
  clear(bar);
  const rows = [];
  if (state.tab === "topology") {   // the filter of the Topology map sits at the left of the bar, level with the node picker
    const fin = h("input", { type: "text", class: "cv-filter", value: state.topoFilter || "", placeholder: "Filter devices", autocomplete: "off", spellcheck: "false", "aria-label": "Filter devices",
      oninput: () => { state.topoFilter = fin.value; if (state.onTopoFilter) state.onTopoFilter(); } });
    rows.push(h("div", { class: "tbrow tbfilter" }, fin));
    // the box has the focus when a gateway's drawing is opened (once for each: later redraws of the bar never take the focus from what is being typed)
    setTimeout(() => focusTopoFilter(state.topo.gid), 0);
  } else state.topoFocusGid = null;
  if (state.nodes.length >= 2) {
    const sel = h("select", { id: "node-pick", "aria-label": "Node to configure and monitor", onchange: (e) => setTarget(e.target.value || null) });
    const self = selfNode();
    sel.append(h("option", { value: "" }, nodeLabel(self) + " (this node)"));
    for (const n of state.nodes.filter((x) => !x.self)) {
      const o = h("option", { value: n.addr }, nodeLabel(n) + (n.is_primary ? " · primary" : "") + (n.reachable ? "" : " · unreachable"));
      if (!n.reachable && n.addr !== state.target) o.disabled = true;
      sel.append(o);
    }
    if (GW_TABS.includes(state.tab)) for (const [value, text] of gwItems()) sel.append(h("option", { value }, text));   // nodes, then gateways, then the whole cluster
    if (CLUSTER_TABS.includes(state.tab)) sel.append(h("option", { value: CLUSTER }, "Cluster (" + state.nodes.length + ")"));
    sel.value = state.target || "";
    rows.push(h("div", { class: "tbrow tbnode" }, h("label", { for: "node-pick", class: "muted small" }, "Node"), sel));
  }
  bar.classList.toggle("hidden", rows.length === 0);
  bar.append(...rows);
}

function setTarget(addr) {
  if ((addr || null) === state.target) return;
  state.target = addr || null;
  document.body.classList.toggle("remote", !!state.target && state.target !== CLUSTER && !isGw());   // another node's page is marked; the cluster's is no node
  renderTopbar();
  state.topo.action = null;   // the gateway picked stays picked: the sidebar list is the signed-in node's, whichever node is driven
  refreshTopoNav();
  certBanner();
  if (document.getElementById("main")) selectTab(state.tab);
}

function startPolling(fn) {
  const tick = async () => { if (!document.hidden) { try { await fn(); } catch (_) { /* shown by view */ } } };
  tick();
  state.timer = setInterval(tick, POLL_MS);
}
function stopPolling() { if (state.timer) clearInterval(state.timer); state.timer = null; }
// Every timer the signed-in shell owns.  A session that ends by itself (an
// update restarts the daemon, an idle timeout) must stop the sidebar and node
// pollers too: they kept getting 401 and redrew the login form every few
// seconds, wiping what was being typed (it looked like the form blinking).
function stopAllTimers() {
  stopPolling();
  if (state.topoTimer) clearInterval(state.topoTimer);
  if (state.nodesTimer) clearInterval(state.nodesTimer);
  if (state.alertTimer) clearInterval(state.alertTimer);
  state.topoTimer = state.nodesTimer = state.alertTimer = null;
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.timer && VIEWS[state.tab].poll) VIEWS[state.tab].poll().catch(() => {});
});

// partialLast: the range ends inside the last bucket (more than one bucket, so there is something left to draw)
const partialLast = (d, len) => len > 2 && d.to < d.start + len * d.step;
// the canary soak: a node that took a new update first shows an hourglass until the others are let go (sec = seconds left)
const soakTip = (sec) => "soaking: " + sec + "s remaining";
const soakMark = (sec) => (sec > 0 ? [" ", h("span", { class: "soak", title: soakTip(sec), "aria-label": soakTip(sec) }, "⏳")] : null);
// right-click menu items are written plain: no … after a label that opens a dialog
function plain(l) { return typeof l === "string" ? l.replace(/…(?=$| \()/, "") : l; }
function errorBox(el, msg) {
  clear(el).append(h("div", { class: "notice bad", role: "alert" }, msg));
}

// ── views ─────────────────────────────────────────────────────────────────
const VIEWS = {};

// ── network tools of an address, run on the picked node (CLI: --ping, --traceroute, --scan, --host-lookup, --whois) ──
const whoisText = (w) => {
  if (w.kind === "ip") {
    if (!w.found) return w.domain + " — " + w.note;
    return [w.domain, w.network && "Network: " + w.network, w.netname && "Name: " + w.netname, w.org && "Organization: " + w.org, w.country && "Country: " + w.country,
      w.origin && "Origin AS: " + w.origin, "From: " + w.server].filter(Boolean).join("\n");
  }
  const addrs = w.name ? [w.name, w.ipv4 && "IPv4: " + w.ipv4, w.ipv6 && "IPv6: " + w.ipv6, !w.ipv4 && !w.ipv6 && "No address found", ""].filter((x) => x !== false && x !== undefined && x !== null && x !== 0).join("\n") + "\n" : "";
  if (!w.found) return addrs + w.domain + " — " + w.note;
  return addrs + [w.domain, w.registrar && "Registrar: " + w.registrar, w.registrant && "Registrant: " + w.registrant, w.registered && "Registered: " + w.registered,
    w.updated && "Updated: " + w.updated, w.expires && "Expires: " + w.expires, (w.name_servers || []).length && "Name servers: " + w.name_servers.join(", "), "From: " + w.server].filter(Boolean).join("\n");
};
// Scan: an nmap of an address, run on the picked node; a popup with the report when it is done
function scanPopup(addr) {
  textPopup("Scan " + addr, async (put, live) => {
    let j = (await api("POST", "/api/scan", { client: addr })).data;
    while (j.state === "running") {
      await new Promise((r) => setTimeout(r, 3000));
      if (!live()) return;
      j = (await api("GET", "/api/scan?client=" + encodeURIComponent(addr))).data;
    }
    put(j.text || "nmap printed nothing");
  });
}

// Virtual MACs: what the test found, in words (Monitor ▸ Gateways ▸ [Test]).
const vmacWords = { delivered: "delivered", "not-delivered": "NOT delivered", inconclusive: "inconclusive" };
const vmacLine = (r) => "Virtual MACs: " + (vmacWords[r.verdict] || r.verdict) + " — " + r.detail;

// A popup with text in it that a function fills in: Whois, Ping, Traceroute.
// run(put, live) calls put(text) as often as it likes and returns when done; live() says whether the popup still wants it.
function textPopup(title, run, extra) {
  const out = h("pre", { class: "nt-out", tabindex: "0", "aria-live": "off" }, "…");
  const d = h("dialog", { class: "cv-dialog nt-dialog", "aria-label": title });
  let alive = true, round = 0;
  const close = () => { alive = false; try { d.close(); } catch (_) { /* closed */ } d.remove(); };
  d.addEventListener("close", () => { alive = false; d.remove(); });
  d.append(h("h2", {}, title), out,
    h("div", { class: "toolbar nt-bar" }, extra || null, h("button", { class: "btn", type: "button", onclick: close }, "Close")));
  root.append(d);
  d.showModal();
  const go = async () => {
    const me = ++round;
    const live = () => alive && me === round;
    out.textContent = "…";
    const put = (text) => { if (!live()) return; const end = out.scrollTop + out.clientHeight >= out.scrollHeight - 4; out.textContent = text; if (end) out.scrollTop = out.scrollHeight; };
    try { await run(put, live); } catch (e) { if (live() && e.message !== "unauthenticated") out.textContent = e.message; }
  };
  go();
}
// Ping / Traceroute of an address: ping or mtr run on the picked node, shown as it comes in
// a traceroute as a table, with the host names or the addresses (the daemon looks the names up as the hops appear, so the box can be ticked at any time)
let traceNames = false;
try { traceNames = localStorage.getItem("nt_trace_names") === "1"; } catch (_) { /* no storage */ }
const traceText = (j, names) => {
  if (!j.hops || !j.hops.length) return j.text || "";
  const who = (x) => (names && x.name ? x.name : x.addr) || "???";
  const w = Math.max(7, ...j.hops.map((x) => who(x).length));
  const f = (v) => v.toFixed(1).padStart(7);
  return (j.text || "").split("\n")[0] + "\n" + "".padEnd(w + 4) + "  " + "Loss%".padStart(6) + " " + "Snt".padStart(4) + " " + ["Last", "Avg", "Best", "Wrst"].map((x) => x.padStart(7)).join(" ") + "\n" +
    j.hops.map((x, i) => String(i + 1).padStart(2) + ". " + who(x).padEnd(w) + "  " + (x.loss.toFixed(1) + "%").padStart(6) + " " + String(x.sent).padStart(4) + " " + [x.last, x.avg, x.best, x.worst].map(f).join(" ")).join("\n") + "\n";
};
function netTool(kind, name) {
  let putFn = null, last = null;
  const box = h("input", { type: "checkbox", checked: traceNames });
  const show = () => { if (putFn && last) putFn(kind === "trace" ? traceText(last, box.checked) : last.text); };
  box.addEventListener("change", () => { traceNames = box.checked; try { localStorage.setItem("nt_trace_names", traceNames ? "1" : "0"); } catch (_) { /* no storage */ } show(); });
  const extra = kind === "trace" ? h("label", { class: "nt-opt", title: "Show the host name of each hop where it has one; untick for the addresses" }, box, " Resolve names") : null;
  textPopup((kind === "ping" ? "Ping " : "Traceroute ") + name, async (put, live) => {
    putFn = put;
    let j = (await api("POST", "/api/nettool", { kind, client: name })).data;
    for (;;) {
      last = j;
      if (j.text) show();
      if (j.state !== "running") return;
      await new Promise((r) => setTimeout(r, 1000));
      if (!live()) return;
      j = (await api("GET", "/api/nettool?kind=" + kind + "&client=" + encodeURIComponent(name))).data;
    }
  }, extra);
}
// Lookup: what this node's resolver says about an address (its reverse names) or a name (addresses, CNAME, MX, NS, TXT)
function lookupPopup(name) {
  textPopup("Lookup " + name, async (put) => put((await api("GET", "/api/dnslookup/full?lookup=" + encodeURIComponent(name))).data.text));
}
// Recheck: the device is asked again now, whatever its state (a login or a firewall rule was corrected)
function recheckPopup(name) {
  const WORDS = { ok: "answering", warn: "refusing", bad: "unreachable", paused: "disabled" };
  textPopup("Recheck " + name, async (put) => {
    const hl = (await api("POST", "/api/devices/recheck", { name })).data.health;
    const word = WORDS[hl.status] || hl.status;
    put(name + ": " + word + (hl.detail && hl.detail !== word ? "\n" + hl.detail : ""));   // "answering" needs no second line
    if (state.tab === "devices") VIEWS.devices.refresh().catch(() => {});   // the Monitor page shows it at once
  });
}
function whoisPopup(name) {
  textPopup("Whois " + name, async (put) => put(whoisText((await api("GET", "/api/whois?lookup=" + encodeURIComponent(name))).data)));
}

const toolItems = (addr, device) => [["Ping", () => netTool("ping", addr)], ["Traceroute", () => netTool("trace", addr)], ["Scan", () => scanPopup(addr)], "-", ["Lookup", () => lookupPopup(addr)], ["Whois", () => whoisPopup(addr)],
  ...(device ? ["-", ["Recheck", () => recheckPopup(device)]] : [])];   // device: the inventory name of a device of this gateway (not one below another Network Director)

// ── configuration  (CLI: --show-config, --configure) ──  // ── configuration  (CLI: --show-config, --configure) ──────────────────────
const PORT_DEF = { ad: "636", ios: "161", proxmox: "8006", pbs: "8007", pdm: "8443", junos: "3443", linux: "22", windows: "22", technitium: "53443", dnsdir: "53853", ntpdir: "12380", netdir: "22161", mediaencoder: "8765", sonarr: "8989", radarr: "7878", lidarr: "8686", prowlarr: "9696", bazarr: "6767", qbittorrent: "8080", tautulli: "8181", seerr: "5055", plex: "32400", jellyfin: "8096" };   // the API port of a platform that is not 443
const portDef = (platform) => PORT_DEF[platform] || "443";

// Shown only when this node is part of a multi-node cluster.
const sharedTag = (f) => (f.shared && state.clustered
  ? h("span", { class: "pill info tiny", title: "Replicated from the cluster's primary. Changes made here are accepted by the primary first." }, "shared") : null);

// A small table for a list of lines made of a few columns (servers, clients, keys): rows to edit in place, drag to
// reorder, a filter box, paging, a and a right-click menu (Edit, Copy, Paste, Add row, Move, Delete).
// spec: {cols: [{name, ph, opts?}], parse(line) -> [cell, ...], format(cells) -> [line, ...], mark(cells) -> true when the row is
// not complete (outlined and not saved), empty: text for no rows}.
const rowClips = {};
// A row copied here is pasted from the page's own clipboard: reading the system clipboard makes the browser show its own "Paste" button, which had to be pressed a second time.
// After the person has been in another window the system clipboard may hold something else, so the next Paste reads it.
window.addEventListener("blur", () => { for (const k of Object.keys(rowClips)) delete rowClips[k]; });

// A box of tags as pills: type a tag, then a space, a comma or Enter to make it a pill; the x on a pill removes it; Backspace in the empty box takes the last one back.
// The tags already in use are offered while typing (tagsNow()).  `.value` is the tags separated by spaces (what the daemon's lists are saved from).
function tagPicker(list, onChange, tagsNow, label) {
  let items = [...new Set((list || []).filter(Boolean))];
  const el = h("div", { class: "devpick tagpick", role: "group", "aria-label": label || "Tags" });
  const input = h("input", { type: "text", autocomplete: "off", spellcheck: "false", "aria-label": "Add a tag", title: "Type a tag such as site=dc1, then a space or Enter. Tags in use are offered." });
  tagSuggest(input, () => (tagsNow ? tagsNow() : []).filter((t) => !items.includes(t)));
  function draw() {
    clear(el).append(...items.map((x) => h("span", { class: "pill info" }, x, h("button", { type: "button", "aria-label": "Remove " + x, title: "Remove " + x, onclick: () => set(items.filter((y) => y !== x), true) }, "\u00d7"))), input);
    input.placeholder = items.length ? "" : "add tag";
  }
  function set(next, focus) {
    items = next;
    draw();
    onChange(items);
    el.dispatchEvent(new Event("change", { bubbles: true }));
    if (focus) input.focus();
  }
  function add(focus) {
    const w = input.value.split(/[\s,]+/).filter(Boolean);
    input.value = "";
    if (!w.length) return false;
    const next = [...items];
    for (const x of w) if (!next.includes(x)) next.push(x);
    set(next, focus);
    return true;
  }
  input.addEventListener("input", () => { if (/[\s,]/.test(input.value)) add(true); });   // a space or a comma, a paste, or a choice from the list
  input.addEventListener("keydown", (e) => {
    if (e.defaultPrevented) return;
    if (e.key === "Enter" && input.value.trim()) { e.preventDefault(); e.stopPropagation(); add(true); }
    else if (e.key === "Backspace" && !input.value && items.length) set(items.slice(0, -1), true);
  });
  input.addEventListener("change", (e) => { e.stopPropagation(); add(false); });
  Object.defineProperty(el, "value", { get: () => items.concat(input.value.split(/[\s,]+/).filter(Boolean)).join(" "), configurable: true });
  draw();
  return el;
}
// the lists that are tables
// the drivers in device/, alphabetical: a new device starts with the first; the daemon checks the name when the page saves
// the API address of the platforms that are a cloud service
const SERVICE_ADDR = { meraki: "api.meraki.com", entra: "graph.microsoft.com", nsone: "api.nsone.net", rcode0: "my.rcodezero.at" };
// what the list and the tiles say for a platform whose stored name is not what people call it; the stored name stays
const PLATFORM_LABEL = {
  aci: "Cisco ACI", afc: "Aruba Fabric Controller", aoscx: "ArubaOS-CX", aviatrix: "Aviatrix Controller", aviatrixcopilot: "Aviatrix CoPilot", bigip: "F5 BigIP", centreon: "Centreon", dnsdir: "AnyName DNS Director",
  ntpdir: "AnyTime NTP Director", entra: "Microsoft Entra ID", eos: "Arista EOS", fortios: "Fortinet FortiOS", ios: "Cisco IOS", iosxe: "Cisco IOS-XE", nsxt: "VMware NSX-T", unimus: "Unimus", device42: "Device42", smax: "Micro Focus SMAX", confluence: "Atlassian Confluence", ad: "Active Directory", tools: "Network tools", sdwan: "Cisco Catalyst SD-WAN",
  proxmox: "Proxmox VE", pbs: "Proxmox Backup Server", pdm: "Proxmox Datacenter Manager", ipfabric: "IP Fabric", junos: "Juniper Junos", linux: "Linux (SSH)", windows: "Windows (SSH)",
  meraki: "Cisco Meraki", nios: "Infoblox NIOS", nsone: "NSOne", nxos: "Cisco NX-OS", observium: "Observium", panorama: "Palo Alto Panorama",
  netdir: "MCP Network Director", logdir: "LogDirector", filedir: "FileDirector", flowdir: "FlowDirector", mediaencoder: "multi-media[encoder]", panos: "Palo Alto PanOS", rcode0: "RcodeZero", technitium: "Technitium DNS Server", vcenter: "VMware vCenter Server",
  sonarr: "Sonarr", radarr: "Radarr", lidarr: "Lidarr", prowlarr: "Prowlarr", bazarr: "Bazarr", qbittorrent: "qBittorrent", tautulli: "Tautulli", seerr: "Seerr (Overseerr, Jellyseerr)", plex: "Plex Media Server", jellyfin: "Jellyfin",
};
const platformName = (p) => PLATFORM_LABEL[p] || p;
const PLATFORMS = Object.keys(PLATFORM_LABEL).sort((a, b) => PLATFORM_LABEL[a].localeCompare(PLATFORM_LABEL[b]));   // as the person reads them

// The address an MCP client connects to: the first gateway's shared (VIP) address on the MCP port (443 unless set), not the
// address of the node the page was opened on.  Set when a page that knows the configuration is drawn.
let mcpBaseURL = "";
function vipBase(cfg) {
  const gs = ((cfg && cfg.groups) || []).slice().sort((a, b) => a.group_id - b.group_id);
  const g = gs.find((x) => x.vip4) || gs.find((x) => x.vip6);
  if (!g) return "";
  const ip = (g.vip4 || g.vip6).split("/")[0];
  const port = (cfg.settings && cfg.settings.mcp_port) || 443;   // the MCP listener on the gateway address, not the GUI's port
  return "https://" + (ip.includes(":") ? "[" + ip + "]" : ip) + (port === 443 ? "" : ":" + port);
}
function randomKey() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return "netdir_" + btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// A right-click menu for a table row: items are [label, handler, "danger"?]. Reuses the Topology menu's look.
let rowMenuEl = null, rowSubEl = null;
const closeRowSub = () => { if (rowSubEl) { rowSubEl.remove(); rowSubEl = null; } if (rowMenuEl) rowMenuEl.querySelectorAll(".has-sub.open").forEach((b) => b.classList.remove("open")); };
// an item whose handler is an array is a sub-menu: [label, [[label, handler], ...]]; it opens beside the item
const openRowSub = (btn, subItems) => {
  closeRowSub();
  btn.classList.add("open");
  rowSubEl = h("div", { class: "cv-menu", role: "menu" }, subItems.map((it) => h("button", { type: "button", role: "menuitem", onclick: () => { closeRowMenu(); it[1](); } }, plain(it[0]))));
  document.body.append(rowSubEl);
  const br = btn.getBoundingClientRect(), r = rowSubEl.getBoundingClientRect();
  const left = br.right + r.width + 4 <= window.innerWidth ? br.right - 2 : Math.max(4, br.left - r.width + 2);
  rowSubEl.style.left = left + "px";
  rowSubEl.style.top = Math.max(4, Math.min(br.top - 4, window.innerHeight - r.height - 4)) + "px";
};
const rowMenuClick = (e) => {
  const b = e.target.closest ? e.target.closest("button.has-sub") : null;
  if (b && rowMenuEl && rowMenuEl.contains(b)) { e.stopPropagation(); e.preventDefault(); b.dispatchEvent(new Event("opensub")); return; }
  closeRowMenu();
};
const closeRowMenu = () => {
  if (!rowMenuEl) return;
  closeRowSub();
  rowMenuEl.remove(); rowMenuEl = null;
  document.removeEventListener("click", rowMenuClick, true);
  document.removeEventListener("keydown", rowMenuKey, true);
  window.removeEventListener("blur", closeRowMenu);
  window.removeEventListener("resize", closeRowMenu);
};
const rowMenuKey = (e) => {
  if (e.key === "Escape") { e.preventDefault(); closeRowMenu(); return; }
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const items = [...rowMenuEl.querySelectorAll("button")], i = items.indexOf(document.activeElement);
  if (e.key === "ArrowRight" && document.activeElement.classList.contains("has-sub")) { document.activeElement.dispatchEvent(new Event("opensub")); if (rowSubEl) rowSubEl.querySelector("button").focus(); return; }
  items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus();
};
const rowMenu = (items) => (e) => {
  e.preventDefault(); e.stopPropagation();
  closeRowMenu();
  // "-" between items draws a line between groups
  rowMenuEl = h("div", { class: "cv-menu", role: "menu" }, items.map((it) => {
    if (it === "-") return h("div", { class: "sep", role: "separator" });
    if (Array.isArray(it[1])) {
      const b = h("button", { type: "button", role: "menuitem", class: "has-sub", "aria-haspopup": "true" }, plain(it[0]), h("span", {}, "▸"));
      b.addEventListener("opensub", () => openRowSub(b, it[1]));
      b.addEventListener("mouseenter", () => openRowSub(b, it[1]));
      return b;
    }
    const b = h("button", { type: "button", role: "menuitem", class: it[2] || "", onclick: () => { closeRowMenu(); it[1](); } }, plain(it[0]));
    b.addEventListener("mouseenter", closeRowSub);
    return b;
  }));
  document.body.append(rowMenuEl);
  const r = rowMenuEl.getBoundingClientRect(), b = e.target.getBoundingClientRect ? e.target.getBoundingClientRect() : { left: 0, bottom: 0 };
  const x = e.clientX || b.left, y = e.clientY || b.bottom;
  rowMenuEl.style.left = Math.max(4, Math.min(x, window.innerWidth - r.width - 4)) + "px";
  rowMenuEl.style.top = Math.max(4, Math.min(y, window.innerHeight - r.height - 4)) + "px";
  rowMenuEl.querySelector("button").focus();
  document.addEventListener("click", rowMenuClick, true);
  document.addEventListener("keydown", rowMenuKey, true);
  window.addEventListener("blur", closeRowMenu);
  window.addEventListener("resize", closeRowMenu);
};
const when = (t) => (t && !String(t).startsWith("0001") ? new Date(t).toLocaleString() : "–");
// The cluster's member table: the Cluster page passes a remove handler (right-click a node ▸ Remove), the Monitor page none.
// The Monitor page (named) has the node's name and its addresses in two columns; the cluster address is the name's tooltip.
const membersTable = (v, onRemove, named) => {
  const roleOf = (p) => (p.is_primary ? "primary" : (p.role || "replica"));
  const rows = v.peers.map((p) => h("tr", Object.assign({ class: p.self ? "local" : "" }, onRemove && !p.self ? { tabindex: "0", oncontextmenu: rowMenu([["Delete", () => onRemove(p), "danger"]]) } : {}),
    named ? h("td", { class: "nname", title: p.addr }, p.hostname || p.addr, p.self ? " ★" : "", soakMark(p.soak_sec)) : h("td", { class: "mono" }, p.addr, p.self ? " ★" : "", soakMark(p.soak_sec)),
    named ? h("td", { class: "mono" }, (p.ips && p.ips.length) ? p.ips.map((ip) => h("div", {}, ip)) : "–") : null,
    h("td", {}, pill(roleOf(p), p.is_primary ? "ok" : "info")),
    h("td", {}, p.reachable ? pill("yes", "ok") : p.restarting ? pill("restarting", "info") : pill("NO", "bad"), p.updating || p.restarting ? [" ", pill("updating", "warn")] : null),
    h("td", { class: "num" }, p.reachable ? p.epoch : "–"),
    h("td", { class: "num" }, p.version || "–"), h("td", { class: "num" }, p.source_version || "–"),
    h("td", {}, p.self ? "now" : when(p.last_seen)),
    h("td", { class: "wrap muted" }, p.error || "")));
  return h("div", { class: "scroll" }, h("table", { class: named ? "tight" : null },
    h("thead", {}, h("tr", {}, (named ? ["Node name", "Node IP"] : ["Node"]).concat(["Role", "Reachable", "Epoch", "Running", "Source", "Last seen", ""]).map((t, i) => h("th", { class: i >= (named ? 4 : 3) && i <= (named ? 6 : 5) ? "num" : "" }, t)))),
    h("tbody", {}, rows)));
};
const say = (el, kind, ...msg) => kind !== "bad" ? clear(el) : clear(el).append(h("div", { class: "notice " + kind, role: kind === "bad" ? "alert" : "status" }, ...msg));
const fail = (el) => (e) => { if (e.message !== "unauthenticated") say(el, "bad", e.message); };
const kv = (rows) => h("dl", { class: "kv" }, rows.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
const section = (title, ...kids) => h("div", { class: "card" }, h("header", {}, h("h2", {}, tc(title))), h("div", { class: "body" }, ...kids));
const copyBtn = (getText) => h("button", { class: "btn small", type: "button", onclick: async (ev) => {
  try { await navigator.clipboard.writeText(getText()); ev.target.textContent = "Copied"; setTimeout(() => { ev.target.textContent = "Copy"; }, 1500); }
  catch (_) { ev.target.textContent = "Select and copy manually"; }
} }, "Copy");
// The small download icon on the cards of Monitor ▸ MCP and Monitor ▸ Node: the card's numbers as a CSV file, built in the
// browser from what the page already holds.  rows() runs at the click (the first row is the header).  A text cell that starts with
// = + - or @ is written with a leading apostrophe, so a spreadsheet cannot read a name that came from the network as a formula.
const csvCell = (v) => {
  if (v == null) return "";
  let s = String(v);
  if (typeof v !== "number" && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const csvIso = (sec) => new Date(sec * 1000).toISOString();
function saveCsv(name, rows) {
  const url = URL.createObjectURL(new Blob([rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" }));
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
function csvButton(title, rows) {
  const ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg"), p = document.createElementNS(ns, "path");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", "aria-hidden": "true", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" })) svg.setAttribute(k, v);
  p.setAttribute("d", "M12 3v12m0 0l-4.5-4.5M12 15l4.5-4.5M4 20h16");
  svg.append(p);
  const file = "netdir-" + title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + ".csv";
  return h("button", { type: "button", class: "btn small csv", title: "Download as CSV", "aria-label": "Download " + title + " as CSV", onclick: () => saveCsv(file, rows()) }, svg);
}
// Expiry warning under the tabs (certificate state is cheap to check once per login).
async function certBanner() {
  const slot = document.getElementById("banner");
  if (!slot) return;
  try {
    const c = (await api("GET", "/api/tls")).data;
    clear(slot);
    if (c.expired) slot.append(h("div", { class: "notice bad", role: "alert" }, "The GUI certificate has expired. Install a new one under Configure ▸ Web GUI."));
  } catch (_) { /* not critical */ }
}

// ── Anycast, tab strip shared by Monitor and Operate: BGP | OSPF (Configure builds its own) ──
function anycastTabs(key, label, panes) {
  const NAMES = ["BGP", "OSPF"];
  const buttons = NAMES.map((name, i) => h("button", { type: "button", role: "tab", class: "dtab", onclick: () => show(i) }, name));
  function show(i, focus) {
    state[key] = i;
    refreshHelp();
    panes.forEach((p, j) => { p.hidden = j !== i; });
    buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
    if (focus) buttons[i].focus();
  }
  const strip = h("div", { class: "dtabs", role: "tablist", "aria-label": label }, buttons);
  strip.addEventListener("keydown", (e) => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    show((state[key] + d + NAMES.length) % NAMES.length, true);
  });
  show(state[key] >= 0 && state[key] < NAMES.length ? state[key] : 0);
  return strip;
}
const BOTH_BLOCKED = "BGP and OSPF are unavailable: AnyName is installed on this host.";
