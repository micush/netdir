"use strict";
// MCP Network Director web GUI: the history page.

// ── History  (CLI: --versions, --version-show/-diff/-snapshot/-restore/-export, --config-import) ──
VIEWS.history = (() => {
  let tbody, panel, status, picked = [], list = [], sel = null, actBtns = [];
  const actor = (v) => v.actor + (v.manual ? " · manual" : "");

  // The actions work on the highlighted row, so the table has no buttons of its own.
  function select(id) {
    sel = id;
    for (const tr of tbody.querySelectorAll("tr[data-id]")) tr.classList.toggle("sel", tr.dataset.id === id);
    for (const b of actBtns) b.disabled = !b.dataset.always && (id === null || (b.dataset.needs === "previous" && !previous()));
  }
  const current = () => list.find((v) => v.id === sel) || null;
  const previous = () => { const i = list.findIndex((v) => v.id === sel); return i >= 0 && i + 1 < list.length ? list[i + 1] : null; };
  function download(id) {
    const a = h("a", { href: route("/api/versions/download?id=" + encodeURIComponent(id)), download: "" });
    document.body.append(a); a.click(); a.remove();
  }

  function drawDiff(d) {
    const rows = (d.lines || []).map((l) => h("tr", { class: "dl " + ({ "+": "add", "-": "del", "@": "skip" }[l.op] || "ctx") },
      h("td", { class: "op" }, l.op === "@" ? "" : l.op), h("td", { class: "mono ln" }, l.op === "@" ? "… " + l.text : l.text)));
    clear(panel).append(h("div", { class: "card" },
      h("header", {}, h("h2", {}, tc("Changes")), h("span", { class: "mono muted" }, d.a.id + " → " + d.b.id),
        h("span", { class: "spacer" }), h("button", { class: "btn small", type: "button", onclick: () => clear(panel) }, "Close")),
      h("div", { class: "body" },
        d.same ? h("div", { class: "empty" }, "The two versions are identical.") : [
          h("ul", { class: "changes" }, (d.sections || []).map((s) => h("li", {}, h("strong", {}, s.label + ": "), s.detail))),
          h("div", { class: "scroll" }, h("table", { class: "diff" }, h("tbody", {}, rows)))])));
    panel.scrollIntoView({ block: "nearest" });
  }
  async function diff(a, b) {
    try { drawDiff((await api("GET", "/api/versions/diff?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b))).data); }
    catch (e) { fail(status)(e); }
  }
  async function view(id) {
    try {
      const r = (await api("GET", "/api/versions/get?id=" + encodeURIComponent(id))).data;
      clear(panel).append(h("div", { class: "card" },
        h("header", {}, h("h2", {}, "Version " + id), h("span", { class: "muted" }, when(r.meta.at) + " · " + r.meta.actor),
          h("span", { class: "spacer" }), h("button", { class: "btn small", type: "button", onclick: () => clear(panel) }, "Close")),
        h("div", { class: "body" }, h("pre", { class: "help" }, JSON.stringify(r.config, null, 2)))));
    } catch (e) { fail(status)(e); }
  }
  async function restore(v) {
    if (!confirm("Restore version " + v.id + " (" + when(v.at) + ") and apply it now?\n\nThe current configuration is saved as a new version first, so you can come back.")) return;
    try { await api("POST", "/api/versions/restore", { id: v.id }); say(status, "ok", "Version " + v.id + " restored and applied."); await load(); }
    catch (e) { fail(status)(e); }
  }
  async function load() {
    list = (await api("GET", "/api/versions")).data;
    picked = picked.filter((id) => list.some((v) => v.id === id));
    if (sel !== null && !list.some((v) => v.id === sel)) sel = null;
    clear(tbody);
    if (!list.length) { tbody.append(h("tr", {}, h("td", { colspan: 4, class: "empty" }, "Nothing recorded yet. A version is saved every time the configuration changes."))); select(null); return; }
    list.forEach((v, i) => {
      const cb = h("input", { type: "checkbox", "aria-label": "Compare version " + v.id, checked: picked.includes(v.id), onchange: () => {
        picked = cb.checked ? [...picked, v.id].slice(-2) : picked.filter((x) => x !== v.id);
        for (const o of tbody.querySelectorAll("input[type=checkbox]")) o.checked = picked.includes(o.dataset.id);
      } });
      cb.dataset.id = v.id;
      const tr = h("tr", { "data-id": v.id, tabindex: "0", "aria-label": "Version " + v.id },
        h("td", {}, cb),
        h("td", { class: "nowrap" }, when(v.at), i === 0 ? [" ", pill("latest", "info")] : null),
        h("td", {}, actor(v)),
        h("td", { class: "wrap" }, v.summary, v.note ? h("div", { class: "muted" }, "“" + v.note + "”") : null));
      tr.addEventListener("click", () => select(v.id));
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { if (e.target === tr) { e.preventDefault(); select(v.id); } } });
      tbody.append(tr);
    });
    select(sel);
  }
  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      panel = h("div", {});
      tbody = h("tbody", {});
      const file = h("input", { type: "file", accept: ".json,application/json", class: "hidden", "aria-label": "Configuration file" });
      file.addEventListener("change", async () => {
        const f = file.files[0]; file.value = "";
        if (!f) return;
        let cfg;
        try { cfg = JSON.parse(await f.text()); } catch (e) { say(status, "bad", "Not valid JSON: " + e.message); return; }
        if (!confirm("Replace the whole configuration with " + f.name + " and apply it now?")) return;
        try { await api("POST", "/api/versions/upload", { config: cfg, note: "uploaded " + f.name }); say(status, "ok", "Configuration from " + f.name + " applied."); await load(); }
        catch (e) { fail(status)(e); }
      });
      const act = (label, needs, fn) => { const b = h("button", { class: "btn small", type: "button", disabled: true, onclick: fn }, label); if (needs) b.dataset.needs = needs; return b; };
      actBtns = [
        h("button", { class: "btn small", type: "button", "data-always": "1", title: "Record the current configuration as a version now", onclick: async () => {
          try { await api("POST", "/api/versions/snapshot", {}); say(status, "ok", "Snapshot saved."); await load(); } catch (e) { fail(status)(e); }
        } }, "Snapshot now"),
        act("View", null, () => { if (sel) view(sel); }),
        act("Diff vs live", null, () => { if (sel) diff(sel, "current"); }),
        act("Diff vs previous", "previous", () => { const p = previous(); if (p) diff(p.id, sel); }),
        h("button", { class: "btn small", type: "button", "data-always": "1", title: "Tick two versions to compare them", onclick: () => { if (picked.length === 2) diff(picked[1], picked[0]); else say(status, "info", "Tick two versions to compare them."); } }, "Compare ticked"),
        act("Restore", null, () => { const v = current(); if (v) restore(v); }),
        act("Download", null, () => { if (sel) download(sel); }),
        h("button", { class: "btn small", type: "button", "data-always": "1", onclick: () => file.click() }, "Upload"),
      ];
      sel = null;
      main.append(
        file,
        status,
        // the buttons belong to the list: they act on the highlighted version
        h("div", { class: "card" },
          h("header", { class: "bar", role: "group", "aria-label": "Versions" }, ...actBtns),
          h("div", { class: "scroll" }, h("table", {},
            h("thead", {}, h("tr", {}, ["", "When", "Who", "What changed"].map((t) => h("th", {}, t)))), tbody))),
        panel);
      load().catch(fail(status));
    },
  };
})();
