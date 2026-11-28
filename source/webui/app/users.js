"use strict";
// MCP Network Director web GUI: the users page.

// ── Users  (CLI: --users, --user-add, --user-passwd, --user-expiry, --user-del) ──
VIEWS.usersLocal = (() => {
  // Layout: the accounts in a list on the left, the chosen one (or the "new user" / "existing account" form) on the right.
  let status, listBox, detail, filterIn, users = [], others = [], group = "", readGroup = "", sel = null, mode = "user", otherList = null;
  const dateText = (u) => (u.expires ? new Date(u.expires * 1000).toISOString().slice(0, 10) : "never");
  const toUnix = (d) => (/^\d{4}-\d{2}-\d{2}$/.test(d) ? Math.floor(Date.UTC(+d.slice(0, 4), +d.slice(5, 7) - 1, +d.slice(8, 10), 12) / 1000) : 0);
  const me = () => (state.session && state.session.user) || "";
  const current = () => users.find((u) => u.name === sel) || null;
  // Access: full (may change things) or read-only; offered only while a read-only group is set
  const accessSel = (ro) => h("select", { "aria-label": "Access" }, h("option", { value: "full" }, "Full access"), h("option", { value: "ro", selected: ro ? "" : null }, "Read-only"));

  async function call(path, body, done) {
    try {
      const r = (await api("POST", "/api/users/" + path, body)).data;
      if (r.partial) say(status, "bad", r.message); else clear(status); // success shows in the list; only a node that missed it is worth saying
      if (done) done();
      await VIEWS.usersLocal.poll();
    } catch (e) { fail(status)(e); }
  }

  function drawList() {
    const real = listBox; listBox = h("div", { class: "ulist" });
    try {
      const flt = parseFilter(filterIn ? filterIn.value : "");
      const shown = users.filter((u) => flt.match((w) => u.name.toLowerCase().includes(w)));
      if (!users.length) listBox.append(h("div", { class: "empty" }, "Nobody is in the " + group + " group, so nobody can sign in."));
      else if (!shown.length) listBox.append(h("div", { class: "empty" }, "No user matches."));
      shown.forEach((u) => {
        const on = mode === "user" && u.name === sel;
        listBox.append(h("button", { type: "button", class: "uitem" + (on ? " on" : ""), "data-user": u.name,
          onclick: () => { sel = u.name; mode = "user"; drawList(); drawDetail(); } },
          h("span", { class: "uname" }, u.name, u.name === me() ? h("span", { class: "pill info tiny" }, "you") : null, u.read_only ? h("span", { class: "pill tiny" }, "read-only") : null),
          u.expired ? h("span", { class: "usub bad" }, "expired " + dateText(u)) : h("span", { class: "usub" }, u.expires ? "expires " + dateText(u) : "never expires")));
      });
    } finally { morph(real, listBox); listBox = real; }
  }

  let shown = "";   // what the detail panel is showing: the mode and the account
  function drawDetail() {
    shown = mode + "/" + (mode === "user" ? sel : "");
    clear(detail);
    if (mode === "new") {
      const name = h("input", { type: "text", autocomplete: "off", spellcheck: "false", autocapitalize: "none", maxlength: "32" });
      const pw = h("input", { type: "password", autocomplete: "new-password" });
      const exp = h("input", { type: "date" });
      const acc = readGroup ? accessSel(false) : null;
      const add = () => call("add", { username: name.value.trim(), password: pw.value, expires: toUnix(exp.value), read_only: !!acc && acc.value === "ro" }, () => { sel = name.value.trim(); mode = "user"; });
      pw.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
      detail.append(h("header", {}, h("h2", {}, tc("New user"))), h("div", { class: "body" },
        h("div", { class: "grid c3" }, h("label", { class: "f" }, "Name", name), h("label", { class: "f" }, "Password", pw), h("label", { class: "f" }, "Expires (blank = never)", exp), acc ? h("label", { class: "f" }, "Access", acc) : null),
        h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "button", onclick: add }, "Add user"))));
      name.focus();
      return;
    }
    if (mode === "existing") {
      const who = h("input", { type: "text", list: "users-others", autocomplete: "off", spellcheck: "false", autocapitalize: "none", maxlength: "64" });
      const acc = readGroup ? accessSel(false) : null;
      const grant = () => call("grant", { username: who.value.trim(), read_only: !!acc && acc.value === "ro" }, () => { sel = who.value.trim(); mode = "user"; });
      who.addEventListener("keydown", (e) => { if (e.key === "Enter") grant(); });
      detail.append(h("header", {}, h("h2", {}, tc("Add an existing account"))), h("div", { class: "body" },
        h("p", { class: "muted small" }, "An account that already exists on this host, including one from a directory (Active Directory, LDAP through sssd), can be allowed to sign in here by adding it to the " + group + " group. A directory account keeps its password in the directory."),
        h("div", { class: "grid c3" }, h("label", { class: "f" }, "Name", who, otherList), acc ? h("label", { class: "f" }, "Access", acc) : null),
        h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "button", onclick: grant }, "Add to group"))));
      who.focus();
      return;
    }
    const u = current();
    if (!u) { detail.append(h("div", { class: "empty" }, users.length ? "Choose a user on the left." : "Add a user to get started.")); return; }
    const self = u.name === me();
    const pw = h("input", { type: "password", autocomplete: "new-password", "aria-label": "New password for " + u.name });
    const d = h("input", { type: "date", value: u.expires ? dateText(u) : "", "aria-label": "Expiry date for " + u.name });
    const acc = readGroup && !self ? accessSel(!!u.read_only) : null;
    const note = h("span", { class: "usaved", "aria-live": "polite" });
    // Save sends what changed: a new password if one was typed, the date if it differs (blank = never expires)
    const save = async () => {
      const was = u.expires ? dateText(u) : "";
      const accChanged = !!acc && (acc.value === "ro") !== !!u.read_only;
      if (!pw.value && d.value === was && !accChanged) { note.textContent = "Nothing to save"; return; }
      note.textContent = "";
      if (pw.value) {
        let ok = true;
        await call("password", { username: u.name, password: pw.value }, () => { pw.value = ""; });
        if (pw.value) ok = false;   // still there: the call failed and the message is shown above
        if (!ok) return;
      }
      if (d.value !== was) await call("expiry", { username: u.name, expires: d.value ? toUnix(d.value) : 0 });
      if (accChanged) await call("access", { username: u.name, read_only: acc.value === "ro" });
      drawDetail();
      const n = detail.querySelector(".usaved"); if (n) n.textContent = "Saved";
    };
    pw.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); });
    const body = h("div", { class: "body ubody" },
      h("div", { class: "urow" }, h("label", { class: "f grow" }, "New password", pw)),
      h("div", { class: "urow" }, h("label", { class: "f grow" }, "Expires (blank = never)", d)),
      acc ? h("div", { class: "urow" }, h("label", { class: "f grow" }, "Access", acc)) : null);
    const left = [];
    if (!self) {
      left.push(h("button", { class: "btn", type: "button", onclick: () => {
        if (confirm("Disable " + u.name + "?\n\nThe account is kept; it just cannot sign in here any more.")) call("revoke", { username: u.name });
      } }, "Disable"),
      h("button", { class: "btn danger", type: "button", onclick: () => {
        if (confirm("Delete the account " + u.name + "?")) call("delete", { username: u.name });
      } }, "Delete"));
    }
    body.append(h("div", { class: "urow actions" }, ...left, h("span", { class: "grow" }), note, h("button", { class: "btn primary", type: "button", onclick: save }, "Save")));
    detail.append(h("header", {}, h("h2", {}, u.name)), body);
  }

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      listBox = h("div", { class: "ulist" });
      detail = h("div", { class: "card udetail" });
      otherList = h("datalist", { id: "users-others" });
      filterIn = h("input", { type: "text", class: "ufilter", placeholder: "Filter", "aria-label": "Filter users", autocomplete: "off", spellcheck: "false", oninput: drawList });
      sel = null; mode = "user";
      const left = h("div", { class: "card ulistcard" },
        h("header", { class: "bar" }, h("h2", {}, tc("Users")), h("span", { class: "grow" }),
          h("button", { class: "btn primary small", type: "button", onclick: () => { mode = "new"; drawList(); drawDetail(); } }, "+ New")),
        h("div", { class: "ufilterbar" }, filterIn),
        listBox,
        h("div", { class: "ufoot" }, h("button", { class: "btn", type: "button", onclick: () => { mode = "existing"; drawList(); drawDetail(); } }, "Add an existing account")));
      main.append(status, h("div", { class: "usersplit" }, left, detail));
    },
    async poll() {
      const r = (await api("GET", "/api/users")).data;
      users = r.users || [];
      others = r.others || [];
      group = r.group;
      readGroup = r.read_group || "";
      if (otherList) clear(otherList).append(...others.map((n) => h("option", { value: n })));
      if (mode === "user" && !current()) sel = users.length ? users[0].name : null;
      drawList();
      // the panel is left alone on a poll so what is being typed survives, and redrawn when what it should show has changed
      if (!detail.firstChild || shown !== mode + "/" + (mode === "user" ? sel : "")) drawDetail();
    },
  };
})();

// Configure ▸ Users: two tabs, Local (the accounts of this host) and SSO (Google / Microsoft sign-in and who may use it)
VIEWS.users = (() => {
  return {
    mount(main) {
      const TABS = [["Local", VIEWS.usersLocal], ["LDAP", VIEWS.cfg_ldap], ["SSO", VIEWS.cfg_sso]];
      const panes = TABS.map(([, v]) => { const p = h("div", { role: "tabpanel" }); v.mount(p); return p; });
      const buttons = TABS.map(([name], i) => h("button", { type: "button", role: "tab", class: "dtab", onclick: () => show(i) }, name));
      function show(i, focus) {
        state.usersTab = i;
        if (document.getElementById("help-panel") && document.getElementById("help-panel").classList.contains("open") && state.tab === "users") queueMicrotask(fillHelp);
        panes.forEach((p, j) => { p.hidden = j !== i; });
        buttons.forEach((b, j) => { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; b.classList.toggle("on", j === i); });
        if (focus) buttons[i].focus();
      }
      const strip = h("div", { class: "dtabs", role: "tablist", "aria-label": "Users" }, buttons);
      strip.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        show((state.usersTab + d + TABS.length) % TABS.length, true);
      });
      main.append(strip, ...panes);
      show(state.usersTab >= 0 && state.usersTab < TABS.length ? state.usersTab : 0);
    },
    poll: () => VIEWS.usersLocal.poll(),
    poll_ms: 5000,
  };
})();
