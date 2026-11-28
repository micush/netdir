"use strict";
// MCP Network Director web GUI: the updates page.

// ── Upgrade  (CLI: --update-status/-upload/-apply/-push/-cancel/-auto/-history) ──
VIEWS.updates = (() => {
  let dyn, status, stats, selected = new Set(), histPage = 0;
  const HIST_PAGE = 25;
  const stat = (k, val, small) => h("div", { class: "stat" }, h("div", { class: "k" }, k), h("div", { class: "v" + (small ? " small" : "") }, val));

  async function act(path, body, confirmText, okText) {
    if (confirmText && !confirm(confirmText)) return;
    try { await api("POST", path, body || {}); say(status, "ok", okText); await VIEWS.updates.poll(); } catch (e) {
      // updating this node now would leave a gateway unserved: say so and let the admin decide
      if (path === "/api/update/apply" && /^not safe to update/.test(e.message || "") && confirm(e.message.replace(/ \(to update anyway.*$/, "") + "\n\nUpdate anyway? Clients of that gateway will be interrupted.")) {
        try { await api("POST", path, { force: true }); say(status, "ok", okText); await VIEWS.updates.poll(); } catch (e2) { fail(status)(e2); }
        return;
      }
      fail(status)(e);
    }
  }

  function draw(v) { const real = dyn; dyn = h("div", {}); try { build(v); } finally { morph(real, dyn); dyn = real; } }
  // built into a detached copy and morphed in: the page keeps its elements (and so its scroll boxes) from one poll to the next
  function build(v) {
    if (!v.toolchain) dyn.append(h("div", { class: "notice bad", role: "alert" }, "No Go toolchain (≥ 1.24) was found on this node, so it cannot build updates itself. Re-run install.sh, which keeps one under /usr/local/share/netdir/go."));
    const newer = v.source_version && Number(v.source_version) > Number(v.running);
    fill(stats, 
      stat("Running", "v" + v.running), stat("Staged source", v.source_version ? "v" + v.source_version : "none"),
      stat("Auto-update", v.intent.auto_all ? "ON" : "off"),
      stat("This node", v.busy ? (v.phase || "working…") : newer ? "update available" : "up to date", true));
    const addrs = new Set(v.nodes.map((n) => n.addr));
    for (const a of [...selected]) if (!addrs.has(a)) selected.delete(a);
    const picked = v.clustered ? [...selected] : [];
    const go = h("button", { class: "btn primary hdr", type: "button", disabled: v.intent.auto_all || !newer || v.busy || !v.toolchain, title: v.intent.auto_all ? "Automatic updates are on: every node updates itself. Turn them off in Configure ▸ General ▸ Updates to update by hand." : null, onclick: () => picked.length
      ? act("/api/update/push", { nodes: picked }, "Update " + picked.length + " selected node" + (picked.length === 1 ? "" : "s") + " to v" + v.source_version + "?\n\nThey build and restart one at a time.", "Queued " + picked.length + " node(s).")
      : act("/api/update/apply", {}, "Build v" + v.source_version + " on this node and restart into it?\n\nThe node is briefly unavailable. If the new version fails to stay up it is rolled back automatically.", "Building v" + v.source_version + " — this node restarts when it is done.") },
      picked.length ? "Update " + picked.length + " selected" : "Update this node now");
    const rows = v.nodes.map((n) => {
      const state = n.updating || n.restarting ? pill("updating", "warn") : n.failed ? pill("failed v" + n.failed, "bad") : n.behind ? pill("behind", "warn") : pill("ok", "ok");
      const cb = h("td", {}, h("input", { type: "checkbox", checked: selected.has(n.addr), disabled: v.intent.auto_all, "aria-label": "Select " + n.addr, onchange: (ev) => { if (ev.target.checked) selected.add(n.addr); else selected.delete(n.addr); VIEWS.updates.poll(); } }));
      return h("tr", { class: n.self ? "local" : "" }, v.clustered ? cb : null,
        h("td", { class: "mono" }, n.addr, n.self ? " ★" : "", soakMark(n.soak_sec)),
        h("td", {}, n.running || "–"), h("td", {}, n.source || "–"),
        h("td", {}, n.reachable ? pill("yes", "ok") : n.restarting ? pill("restarting", "info") : pill("NO", "bad")),
        h("td", {}, n.queued ? pill(v.intent.auto_all ? "auto" : "queued", "info") : ""), h("td", {}, state));
    });
    const heads = (v.clustered ? [""] : []).concat(["Node", "Running", "Source", "Reachable", "Queued", "State"]);
    const off = v.clustered ? 1 : 0;
    dyn.append(h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc("Nodes")), h("span", { class: "grow" }), go),
      h("div", { class: "scroll" }, h("table", { class: "evencols" }, h("thead", {}, h("tr", {}, heads.map((t, i) => h("th", { class: t === "Node" ? "w-node" : t === "Running" || t === "Source" ? "w-ver" : t === "" ? "w-cb" : "w-pill" }, t)))), h("tbody", {}, rows)))));
    const row = (e) => h("tr", {}, h("td", {}, when(e.at)), h("td", { class: "mono" }, e.node), h("td", {}, pill(e.kind, e.kind === "failed" || e.kind === "rolled-back" ? "bad" : e.kind === "applied" ? "ok" : "info")),
      h("td", { class: "num" }, (e.from ? e.from + " → " : "") + (e.to || "")), h("td", { class: "wrap" }, [e.detail, e.by ? " (by " + e.by + ")" : ""].join("")));
    const pages = Math.max(1, Math.ceil(v.history.length / HIST_PAGE));
    histPage = Math.min(Math.max(histPage, 0), pages - 1);   // newest first; page 0 is the newest
    const shown = v.history.slice(histPage * HIST_PAGE, (histPage + 1) * HIST_PAGE);
    const go2 = (d) => () => { histPage += d; VIEWS.updates.poll(); };
    const pager = pages > 1 ? h("span", { class: "pager" },
      h("span", { class: "muted small" }, "Events " + (histPage * HIST_PAGE + 1) + "–" + (histPage * HIST_PAGE + shown.length) + " of " + v.history.length),
      h("button", { class: "btn small", type: "button", disabled: histPage === 0, onclick: go2(-1) }, "‹ Newer"),
      h("span", { class: "muted small" }, "Page " + (histPage + 1) + " of " + pages),
      h("button", { class: "btn small", type: "button", disabled: histPage >= pages - 1, onclick: go2(1) }, "Older ›")) : null;
    dyn.append(h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc("History")), h("span", { class: "grow" }), pager),
      shown.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["When", "Node", "Event", "Version", "Detail"].map((t) => h("th", {}, t)))), h("tbody", {}, shown.map(row))))
        : h("div", { class: "empty" }, "No update activity yet.")));
  }

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      dyn = h("div", {});
      stats = h("div", { class: "stats" });
      const file = h("input", { type: "file", accept: ".tgz,.tar.gz,.zip,application/gzip,application/zip", "aria-label": "Release archive", disabled: true });
      const note = h("span", { class: "muted small", role: "status", "aria-live": "polite" });
      const online = h("input", { type: "checkbox", checked: true, "aria-label": "Fetch from online", title: "Download the newest release from GitHub instead of using a file", onchange: () => { file.disabled = online.checked; note.textContent = ""; } });
      const up = h("button", { class: "btn primary hdr", type: "button", onclick: async (ev) => {
        const f = file.files[0];
        if (!online.checked && !f) { note.textContent = "Choose a release archive first, or tick Fetch from online."; return; }
        note.textContent = ""; note.classList.remove("bad-text"); clear(status);
        ev.target.disabled = true;
        try {
          if (online.checked) {
            note.textContent = "Downloading…";
            const r = await api("POST", "/api/update/fetch");
            note.textContent = "Staged v" + r.data.version + ".";
          } else {
            const r = await apiUpload("/api/update/upload", f); file.value = ""; note.textContent = "Staged v" + r.data.version + ".";
          }
          await VIEWS.updates.poll();
        } catch (e) { if (e.message !== "unauthenticated") { note.textContent = e.message; note.classList.add("bad-text"); } } finally { ev.target.disabled = false; }
      } }, "Upload");
      main.append(stats, status,
        h("div", { class: "card" }, h("header", { class: "bar" }, h("h2", {}, tc("Upload a release")), h("span", { class: "grow" }), up),
          h("div", { class: "body" },
            h("p", { class: "hint" }, "Select a release archive. It is checked and staged on this node; other cluster members pull it from here."),
            h("div", { class: "toolbar tight" }, file, h("label", { class: "check" }, online, " Fetch from online"), note))),
        dyn);
    },
    async poll() { draw((await api("GET", "/api/update")).data); },
    poll_ms: 2000,
  };
})();
