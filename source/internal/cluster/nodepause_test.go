package cluster

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestNodePauseHistoryReadsInWords(t *testing.T) {
	a, b := core.NewDaemonConfig(), core.NewDaemonConfig()
	b.NodePaused = true
	var found bool
	for _, s := range configSections(a, b) {
		if s.Label == "Node" && strings.Contains(s.Detail, "paused") {
			found = true
		}
	}
	if !found {
		t.Fatalf("history diff: %+v", configSections(a, b))
	}
}

// Pausing the primary moves the primary role to a node that is running, never to a paused one.
func TestPickSuccessorSkipsPausedNodes(t *testing.T) {
	peers := []core.PeerView{
		{Addr: "10.0.0.1:22162", Self: true, IsPrimary: true, Reachable: true},
		{Addr: "10.0.0.2:22162", Reachable: true, NodePaused: true, SharedRev: 9},
		{Addr: "10.0.0.3:22162", Reachable: true, SharedRev: 5},
	}
	if got := pickSuccessor(peers, "1"); got != "10.0.0.3:22162" {
		t.Fatalf("successor %q, want the running node", got)
	}
	peers[2].NodePaused = true
	if got := pickSuccessor(peers, "1"); got != "" {
		t.Fatalf("every other node is paused: successor %q", got)
	}
}
