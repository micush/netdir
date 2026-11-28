package main

import (
	"context"
	"encoding/json"
	"testing"

	"netdir/internal/core"
	"netdir/internal/mcp"
	"netdir/internal/web"
)

// ── through two real cluster nodes ───────────────────────────────────────────

func withWeb(t *testing.T, n *tnode) {
	t.Helper()
	sup := core.NewSupervisor(context.Background(), core.NewDaemonConfig())
	st := NewStatusServer("", sup)
	st.mg = n.mg
	ws := web.NewWebServer(n.mg, st, &fakeAuth{})
	mcp.NewMCPListeners(ws)
	n.mg.webH = ws.Handler()
}

// Two nodes with one host name are told apart by address, as in the Node menu.
func TestClusterNodesWithOneHostNameAreNamedByAddress(t *testing.T) {
	a, b := twoNodeCluster(t)
	withWeb(t, a)
	withWeb(t, b)
	// both nodes of this test run in one process, so they have one host name
	args, _ := json.Marshal(map[string]string{"from": "1h"})
	got, err := a.mg.Op("host.cluster", args, "tester")
	if err != nil {
		t.Fatal(err)
	}
	nodes := got.(*core.HostResult).Cluster.Nodes
	if len(nodes) != 2 || nodes[0].Name == nodes[1].Name {
		t.Fatalf("nodes %+v", nodes)
	}
}
