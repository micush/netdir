package mcp

import (
	"testing"

	"netdir/internal/core"
)

// Where a gateway's tools run: here when this node serves it, otherwise on a reachable node that does (the one the Topology page asks).
func TestToolsNodeFor(t *testing.T) {
	n := func(addr, gw string, self bool) core.CanvasNode {
		return core.CanvasNode{Addr: addr, Gw: gw, Self: self, Reachable: true}
	}
	g := func(nodes ...core.CanvasNode) core.CanvasGateway {
		return core.CanvasGateway{GroupID: 162, Name: "phx", Nodes: nodes}
	}
	for _, c := range []struct {
		name, want string
		gw         core.CanvasGateway
		fail       bool
	}{
		{"served here", "", g(n("a", "ok", true), n("b", "ok", false)), false},
		{"degraded here", "", g(n("a", "degraded", true), n("b", "ok", false)), false},
		{"served by a peer", "b", g(n("a", "notserving", true), n("c", "degraded", false), n("b", "ok", false)), false},
		{"paused here", "b", g(n("a", "paused", true), n("b", "ok", false)), false},
		{"nobody", "", g(n("a", "notserving", true), n("b", "notserving", false), n("c", "down", false)), true},
		{"a single node", "", g(), false},
	} {
		got, err := toolsNodeFor(c.gw)
		if (err != nil) != c.fail || got != c.want {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
}
