package main

import (
	"strings"
	"testing"
)

func TestHelpScriptServedAndOldEndpointGone(t *testing.T) {
	e := newWebEnv(t)
	if r := e.do("GET", "/help.js", nil); r.code != 200 || !strings.Contains(string(r.raw), "NETDIR_HELP") {
		t.Fatalf("help.js: %d", r.code)
	}
	e.login("alice", "pw")
	if r := e.do("GET", "/api/help", nil, withAuth(e, false)); r.code != 404 {
		t.Fatalf("the old /api/help should be gone, got %d", r.code)
	}
}
