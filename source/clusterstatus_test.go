package main

import (
	"testing"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// On two real nodes, one serving and one not (another subnet), the cluster reads served whichever node is asked, though
// the gateway's own colour differs between them.
func TestClusterGatewayIsTheSameFromEveryNode(t *testing.T) {
	old := core.HostLoadFn
	t.Cleanup(func() { core.HostLoadFn = old })
	core.HostLoadFn = func() (core.HostLoad, bool) { return core.HostLoad{CPU: 1, Mem: 1, Disk: 1}, true }
	a, b := twoNodeCluster(t)
	a.mg.gwFn = func() []core.GwState { return []core.GwState{{GroupID: 1, Serving: true, Health: "ok"}} }
	b.mg.gwFn = func() []core.GwState {
		return []core.GwState{{GroupID: 1, Serving: false, Health: "idle", HealthWhy: "not running here — this node has no address in the gateway's subnet"}}
	}
	a.sync()
	b.sync()
	fromA := a.mg.cl.CanvasNodes(1, "ok", "running and answering", false)
	fromB := b.mg.cl.CanvasNodes(1, "idle", "not running here", false)
	for name, ns := range map[string][]core.CanvasNode{"A": fromA, "B": fromB} {
		if len(ns) != 2 {
			t.Fatalf("from %s: %d nodes", name, len(ns))
		}
		st, why := cluster.ClusterGateway(ns)
		if st != "ok" || why != "Served by 1 of 2 nodes" {
			t.Errorf("asked %s: %q %q, want ok, served by 1 of 2 nodes", name, st, why)
		}
	}
	if fromA[0].Gw != "ok" || fromA[1].Gw != "notserving" || fromB[0].Gw != "notserving" || fromB[1].Gw != "ok" {
		t.Errorf("states from A %q %q, from B %q %q", fromA[0].Gw, fromA[1].Gw, fromB[0].Gw, fromB[1].Gw)
	}
}
