"use strict";
// MCP Network Director web GUI: the cluster page.

// ── Cluster  (CLI: --cluster-status/-token/-join/-promote/-remove/-unremove/-leave/-sync) ──
VIEWS.cluster = (() => {
  let dyn, status, tokenBox, joinBox, clearBtn;

  async function act(path, body, confirmText, okText) {
    if (confirmText && !confirm(confirmText)) return;
    try { await api("POST", path, body || {}); say(status, "ok", okText); await VIEWS.cluster.poll(); } catch (e) { fail(status)(e); }
  }

  function draw(v) { const real = dyn; dyn = h("div", {}); try { build(v); } finally { morph(real, dyn); dyn = real; } }
  // built into a detached copy and morphed in: the page keeps its elements (and so its scroll boxes) from one poll to the next
  function build(v) {
    if (v.conflict) dyn.append(h("div", { class: "notice bad", role: "alert" }, "Conflict: " + v.conflict));
    for (const w of v.warnings) dyn.append(h("div", { class: "notice bad", role: "alert" }, w));
    if (v.last_sync_error) dyn.append(h("div", { class: "notice bad", role: "alert" }, "Last sync failed: " + v.last_sync_error));
    const stat = (k, val, small) => h("div", { class: "stat" }, h("div", { class: "k" }, k), h("div", { class: "v" + (small ? " small" : "") }, val));
    dyn.append(h("div", { class: "stats" },
      stat("This node", v.self, true), stat("Role", v.role.toUpperCase()), stat("Epoch", v.epoch),
      stat("Primary", v.primary_addr, true), stat("Shared settings rev.", v.shared_rev)));
    dyn.append(h("div", { class: "card" },
      h("header", {}, h("h2", {}, tc("Members"))),
      membersTable(v, (p) => act("/api/cluster/peers/delete", { addr: p.addr }, "Delete " + p.addr + " from the cluster? Nothing is kept about it. A copy that is still running resets itself to a single-node cluster.", p.addr + " deleted."))));
    if (v.removed.length) dyn.append(h("div", { class: "card" }, h("header", {}, h("h2", {}, tc("Removed nodes"))), h("div", { class: "body" },
      h("p", { class: "hint" }, "Nodes removed from the cluster before (on the command line, with --cluster-remove). They cannot be re-added by gossip. Delete one to forget it entirely."),
      v.removed.map((a) => h("div", { class: "toolbar" }, h("span", { class: "mono" }, a),
        h("button", { class: "btn small", type: "button", onclick: () => act("/api/cluster/peers/delete", { addr: a }, null, a + " deleted.") }, "Delete"))))));
    // join form only makes sense for an untouched node
    joinBox.classList.toggle("hidden", !v.joinable);
    leaveBtn.classList.toggle("hidden", v.joinable);
    promoteBtn.classList.toggle("hidden", v.role === "primary");
    clearBtn.disabled = !v.join_codes;
    clearBtn.title = v.join_codes ? v.join_codes + " unused" : "No unused join codes";
    lastView = v;
  }
  let leaveBtn, promoteBtn, lastView = null;

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      dyn = h("div", {});
      tokenBox = h("div", {});
      const code = h("textarea", { rows: 3, spellcheck: "false", class: "pem", placeholder: "netdir-join-v1:…", "aria-label": "Join code" });
      joinBox = section("Join an existing cluster",
        h("p", { class: "hint" }, "Paste a join code created on a member (“Create join code” there). This node's shared settings — the settings block, VIPs, keys and timers — are replaced by the cluster's; its interface, priority, weight, preemption and neighbours stay its own. A snapshot of the current configuration is saved first."),
        code, h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "button", onclick: async (ev) => {
          if (!confirm("Join this node to the cluster? Its shared settings will be replaced by the cluster's.")) return;
          ev.target.disabled = true;
          try { await api("POST", "/api/cluster/join", { code: code.value.trim() }); code.value = ""; say(status, "ok", "Joined the cluster."); await VIEWS.cluster.poll(); }
          catch (e) { fail(status)(e); } finally { ev.target.disabled = false; }
        } }, "Join cluster")));
      leaveBtn = h("button", { class: "btn danger", type: "button", onclick: () => act("/api/cluster/leave", {}, "Leave the cluster? This node keeps its settings and becomes its own single-node cluster.", "Left the cluster.") }, "Leave cluster");
      // withdraws the join codes this node handed out that nobody used (there can be 20 at most); the code shown above goes with them
      clearBtn = h("button", { class: "btn", type: "button", disabled: true, onclick: async () => {
        if (!confirm("Clear this node's unused join codes?\n\nA code created before no longer works.")) return;
        try { await api("POST", "/api/cluster/token/clear", {}); clear(tokenBox); clear(status); await VIEWS.cluster.poll(); } catch (e) { fail(status)(e); }
      } }, "Clear join codes");
      promoteBtn = h("button", { class: "btn warn", type: "button", onclick: () => act("/api/cluster/promote", {}, "Promote THIS node to primary?\n\nDo this only if the current primary is gone for good (or you are moving the role on purpose). Every other member follows the new primary.", "This node is now the primary.") }, "Promote this node");
      main.append(status,
        h("div", { class: "toolbar" },
          h("button", { class: "btn", type: "button", onclick: async () => {
            try {
              const r = (await api("POST", "/api/cluster/token", {})).data;
              const ta = h("textarea", { rows: 4, readonly: true, class: "pem", "aria-label": "Join code" }); ta.value = r.code;
              clear(tokenBox).append(h("div", { class: "card" }, h("header", {}, h("h2", {}, tc("Join code")), h("span", { class: "muted" }, "single use, valid until " + when(r.expires))),
                h("div", { class: "body" }, ta, h("div", { class: "toolbar" }, copyBtn(() => ta.value),
                  h("span", { class: "hint" }, "Paste it on the new node (Cluster → Join) or run: netdir --cluster-join '<code>'")))));
              VIEWS.cluster.poll().catch(() => {});   // Clear join codes counts the new one at once
            } catch (e) { fail(status)(e); }
          } }, "Create join code"),
          clearBtn,
          h("button", { class: "btn", type: "button", onclick: () => act("/api/cluster/sync", {}, null, "Synced.") }, "Sync now"),
          h("span", { class: "spacer" }), promoteBtn, leaveBtn),
        tokenBox, dyn, h("p", { class: "hint" }, "★ marks this node"), joinBox);
      joinBox.classList.add("hidden"); leaveBtn.classList.add("hidden"); promoteBtn.classList.add("hidden");
    },
    async poll() { draw((await api("GET", "/api/cluster")).data); },
  };
})();
