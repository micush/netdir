"use strict";
// MCP Network Director web GUI: the nodes page.

// Nodes  (CLI: --cluster-status): the cluster's members (the gateway protocol's neighbours are on Gateways)
VIEWS.nodes = (() => {
  let body;
  return {
    mount(main) { body = h("div", {}); main.append(body, h("p", { class: "hint" }, "★ marks this node")); },
    async poll() {
      const c = await api("GET", "/api/cluster").catch(() => null);
      const out = h("div", {});
      if (c && c.data) {
        const v = c.data;
        out.append(h("div", { class: "card" },
          h("header", {}, h("h2", {}, tc("Cluster members")),
            v.conflict ? pill("conflict", "bad") : null),
          membersTable(v, null, true)));
      }
      morph(body, out);
    },
  };
})();
