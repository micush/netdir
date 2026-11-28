package core

import (
	"testing"
)

func viaNodes(self string, others ...CanvasNode) []CanvasNode {
	return append([]CanvasNode{{Name: "me", Addr: "10.0.0.1:1", Self: true, Gw: self, Reachable: true}}, others...)
}

func peer(name, gw string) CanvasNode {
	return CanvasNode{Name: name, Addr: "10.0.0." + name + ":1", Gw: gw, Reachable: true}
}

// Only a node that does not serve the gateway takes the picture of one that does, best serving node first.
func TestServingPeersAreAskedOnlyWhenThisNodeDoesNotServe(t *testing.T) {
	others := []CanvasNode{peer("5", "degraded"), peer("4", "ok"), peer("3", "notserving"), peer("2", "ok")}
	for _, self := range []string{"ok", "degraded", "bad", "starting", ""} {
		if l := ServingPeers(CanvasGateway{Nodes: viaNodes(self, others...)}); len(l) != 0 {
			t.Errorf("this node is %q: %d nodes asked", self, len(l))
		}
	}
	for _, self := range []string{"notserving", "paused", "removed"} {
		l := ServingPeers(CanvasGateway{Nodes: viaNodes(self, others...)})
		if len(l) != 3 || l[0].Name != "2" || l[1].Name != "4" || l[2].Name != "5" {
			t.Errorf("this node is %q: %+v", self, l)
		}
	}
	gone := peer("6", "ok")
	gone.Reachable = false
	removed := peer("7", "ok")
	removed.Excluded = true
	if l := ServingPeers(CanvasGateway{Nodes: viaNodes("notserving", gone, removed, peer("8", "paused"), peer("9", "down"))}); len(l) != 0 {
		t.Errorf("nodes that cannot say were asked: %+v", l)
	}
}

// The serving node's own member is "local" to it; borrowed by a paused node it must not read as this node,
// or the controller mark lands on the node the page is open on.
func TestTakeFromClearsLocalOnMembers(t *testing.T) {
	mine := CanvasGateway{GroupID: 1, Nodes: viaNodes("paused")}
	theirs := CanvasGateway{GroupID: 1, Members: []CanvasMember{{IP: "10.0.0.3", Local: true, AGC: true}, {IP: "10.0.0.4"}}}
	mine.TakeFrom(theirs, peer("3", "ok"))
	for _, m := range mine.Members {
		if m.Local {
			t.Errorf("%s still local", m.IP)
		}
	}
	if !mine.Members[0].AGC || !theirs.Members[0].Local || !mine.Members[0].ViaLocal || mine.Members[1].ViaLocal {
		t.Errorf("the controller flag must stay, and the serving node's own copy must not change: %+v %+v", mine.Members, theirs.Members)
	}
}

func TestTakeFromKeepsThisNodesOwnEntry(t *testing.T) {
	mine := CanvasGateway{GroupID: 1, Name: "x", Status: "idle", Detail: "not running here", Nodes: viaNodes("notserving"), Paused: true, NodePaused: true}
	theirs := CanvasGateway{GroupID: 1, Status: "ok", Detail: "running and answering", Anycast: []AnycastState{{Addr: "192.0.2.1", Up: true}}, Families: []CanvasFamily{{AF: "v4", Status: "ok"}}}
	mine.TakeFrom(theirs, peer("2", "ok"))
	if mine.Status != "ok" || mine.Detail != "running and answering" || len(mine.Anycast) != 1 || len(mine.Families) != 1 {
		t.Fatalf("not taken: %+v", mine)
	}
	if mine.Via != "2" || mine.ViaAddr != "10.0.0.2:1" || len(mine.Nodes) != 1 || mine.Name != "x" || !mine.Paused {
		t.Fatalf("this node's own part changed: %+v", mine)
	}
}
