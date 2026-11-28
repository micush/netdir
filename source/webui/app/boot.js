"use strict";
// MCP Network Director web GUI: starts the page once every script is loaded.

// ── boot ──────────────────────────────────────────────────────────────────
(async () => {
  try {
    state.session = await api("GET", "/api/session");
    checkBuild(state.session.version);
    showShell();
  } catch (e) {
    if (e.message !== "unauthenticated") showLogin();
  }
})();
