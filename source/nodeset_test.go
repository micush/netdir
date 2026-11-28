package main

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

// withLocalNode pretends to be the node with this ID for one test.
func withLocalNode(t *testing.T, id string) {
	t.Helper()
	old := core.LocalNodeID()
	core.SetLocalNodeID(id)
	t.Cleanup(func() { core.SetLocalNodeID(old) })
}

func nodeEdit(dc *core.DaemonConfig, action, id string, members ...string) (string, error) {
	return applyCanvasEdit(dc, canvasEdit{Action: action, Kind: "node", Group: 1, Node: id, nodeID: id, members: strings.Join(members, ",")})
}

// Whichever node you ask, a removed node reads "removed", and the others do not.
func TestRemovedNodeIsShownOnEveryNode(t *testing.T) {
	old := core.HostLoadFn // a full disk on the machine running the test turns a shape yellow whatever it is doing
	t.Cleanup(func() { core.HostLoadFn = old })
	core.HostLoadFn = func() (core.HostLoad, bool) { return core.HostLoad{CPU: 1, Mem: 1, Disk: 1}, true }
	a, b := twoNodeCluster(t)
	bid := b.mg.cl.Node.Self().NodeID
	for _, from := range []*tnode{a, b} {
		ns := from.mg.cl.CanvasNodesEx(1, "ok", "IPv4: running", false, []string{bid})
		if len(ns) != 2 {
			t.Fatalf("%d nodes", len(ns))
		}
		for _, n := range ns {
			removed := n.NodeID == bid
			if n.NodeID == "" || n.Excluded != removed {
				t.Errorf("from %s: %s (%q) excluded=%v", from.name, n.Name, n.NodeID, n.Excluded)
			}
			if removed && (n.Label != "removed" || n.Status != "paused") {
				t.Errorf("from %s: %s reads %q %q", from.name, n.Name, n.Label, n.Status)
			}
			if !removed && n.Label == "removed" {
				t.Errorf("from %s: %s reads removed", from.name, n.Name)
			}
		}
	}
}

// The whole path on two real nodes: removed from A by name, B's file has it, B stops serving that gateway and A does not.
func TestRemoveNodeThroughTheClusterReachesTheNode(t *testing.T) {
	a, b := twoNodeCluster(t)
	if _, err := a.mg.CanvasEdit(canvasEdit{Action: "del", Kind: "node", Group: 1, Node: b.addr}, "test"); err != nil {
		t.Fatal(err)
	}
	b.sync()
	bid := b.mg.cl.Node.Self().NodeID
	if got := b.cfg().Groups[0].ExcludedNodes; len(got) != 1 || got[0] != bid {
		t.Fatalf("B's file lists %v, want [%s]", got, bid)
	}
	withLocalNode(t, bid)
	if e := b.cfg().Effective(); !e.Groups[0].Paused || !e.Groups[0].ExcludedHere {
		t.Fatal("B still serves the gateway")
	}
	withLocalNode(t, a.mg.cl.Node.Self().NodeID)
	if e := a.cfg().Effective(); e.Groups[0].Paused {
		t.Fatal("A stopped serving too")
	}
	// the last node cannot be removed, and a node can be added back from the other side
	if _, err := b.mg.CanvasEdit(canvasEdit{Action: "del", Kind: "node", Group: 1, Node: a.addr}, "test"); err == nil {
		t.Fatal("removed the last serving node")
	}
	if _, err := b.mg.CanvasEdit(canvasEdit{Action: "add", Kind: "node", Group: 1, Node: b.addr}, "test"); err != nil {
		t.Fatal(err)
	}
	a.sync()
	if got := a.cfg().Groups[0].ExcludedNodes; len(got) != 0 {
		t.Fatalf("A still lists %v", got)
	}
}

func TestCanvasEditAddsAndRemovesNodes(t *testing.T) {
	dc := pauseTestConfig()
	if _, err := nodeEdit(dc, "del", "aa", "aa", "bb"); err != nil || len(dc.Groups[0].ExcludedNodes) != 1 {
		t.Fatalf("remove: %v %v", err, dc.Groups[0].ExcludedNodes)
	}
	if msg, _ := nodeEdit(dc, "del", "aa", "aa", "bb"); !strings.Contains(msg, "already removed") || len(dc.Groups[0].ExcludedNodes) != 1 {
		t.Fatalf("removing twice: %q", msg)
	}
	if _, err := nodeEdit(dc, "del", "bb", "aa", "bb"); err == nil || !strings.Contains(err.Error(), "no node serving") {
		t.Fatalf("the last serving node was removed: %v", err)
	}
	if _, err := nodeEdit(dc, "add", "aa", "aa", "bb"); err != nil || len(dc.Groups[0].ExcludedNodes) != 0 {
		t.Fatalf("add back: %v %v", err, dc.Groups[0].ExcludedNodes)
	}
	if msg, _ := nodeEdit(dc, "add", "aa", "aa", "bb"); !strings.Contains(msg, "already serving") {
		t.Fatalf("adding twice: %q", msg)
	}
	// a node that already left the cluster does not count as one that could serve
	dc.Groups[0].ExcludedNodes = []string{"dead"}
	if _, err := nodeEdit(dc, "del", "aa", "aa", "dead"); err == nil {
		t.Fatal("removed the only node left in the cluster")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "del", Kind: "node", Group: 9, nodeID: "aa"}); err == nil {
		t.Fatal("a gateway that does not exist")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "del", Kind: "node", Group: 1}); err == nil {
		t.Fatal("no node named")
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The gateway's own circle on the removed node says it was removed, not paused.
func TestCanvasSaysThisNodeWasRemoved(t *testing.T) {
	dc := pauseTestConfig()
	dc.Groups[0].ExcludedNodes = []string{"aaaa1111"}
	withLocalNode(t, "aaaa1111")
	cv := buildCanvas(dc.Effective(), nil)
	if len(cv) != 1 || !cv[0].Excluded || cv[0].Status != "paused" || !strings.Contains(cv[0].Detail, "removed from the gateway") || cv[0].PausedScope != "" {
		t.Fatalf("%+v", cv[0])
	}
	if len(cv[0].ExcludedNodes) != 1 {
		t.Fatalf("the list is not in the view: %v", cv[0].ExcludedNodes)
	}
}
