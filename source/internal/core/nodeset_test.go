package core

import (
	"encoding/json"
	"strings"
	"testing"
)

// withLocalNode pretends to be the node with this ID for one test.
func withLocalNode(t *testing.T, id string) {
	t.Helper()
	old := LocalNodeID()
	SetLocalNodeID(id)
	t.Cleanup(func() { SetLocalNodeID(old) })
}

// A node removed from a gateway serves nothing of it, the others and the gateway's other nodes carry on.
func TestExcludedNodeDoesNotServeTheGateway(t *testing.T) {
	dc := NewDaemonConfig()
	dc.Groups[0].GroupID = 1
	g2 := DefaultGroup()
	g2.GroupID, g2.VIP4 = 2, "10.0.1.1/24"
	dc.Groups = append(dc.Groups, g2)
	dc.Groups[0].ExcludedNodes = []string{"aaaa1111"}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	withLocalNode(t, "aaaa1111")
	e := dc.Effective()
	if !e.Groups[0].Paused || !e.Groups[0].ExcludedHere {
		t.Fatalf("the removed node still serves gateway 1: %+v", e.Groups[0])
	}
	if e.Groups[1].Paused || e.Groups[1].ExcludedHere {
		t.Fatal("removing it from gateway 1 stopped gateway 2 too")
	}
	if dc.Groups[0].Paused || dc.Groups[0].ExcludedHere {
		t.Fatal("effective() changed the saved configuration")
	}
	withLocalNode(t, "bbbb2222")
	if e := dc.Effective(); e.Groups[0].Paused || e.Groups[0].ExcludedHere {
		t.Fatal("a node that was not removed stopped serving")
	}
	// the node that joins later serves it (nothing lists it)
	withLocalNode(t, "cccc3333")
	if e := dc.Effective(); e.Groups[0].Paused {
		t.Fatal("a new node does not serve the gateway")
	}
	// never written to the file: ExcludedHere has no key
	e = dc.Effective()
	withLocalNode(t, "aaaa1111")
	e = dc.Effective()
	b, _ := json.Marshal(e.Groups[0])
	if strings.Contains(string(b), "ExcludedHere") || strings.Contains(string(b), "excluded_here") {
		t.Fatalf("the runtime flag is written: %s", b)
	}
}

func TestPickNodeByAddressHostOrID(t *testing.T) {
	peers := []PeerView{
		{Addr: "10.0.0.1:22162", NodeID: "aa", Hostname: "lsitedns01.example.net"},
		{Addr: "10.0.0.2:22162", NodeID: "bb", Hostname: "lsitedns02"},
		{Addr: "10.0.1.2:22162", NodeID: "cc", Hostname: "lsitedns02.other.net"},
		{Addr: "10.0.2.1:22162", NodeID: ""},
	}
	for name, want := range map[string]string{"10.0.0.1:22162": "aa", "10.0.0.1": "aa", "lsitedns01": "aa", "LSITEDNS01.example.net": "aa", "bb": "bb", "10.0.1.2": "cc"} {
		if id, err := PickNode(peers, nil, name); err != nil || id != want {
			t.Errorf("%q: %q %v, want %q", name, id, err, want)
		}
	}
	if _, err := PickNode(peers, nil, "lsitedns02"); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("an ambiguous host name: %v", err)
	}
	if _, err := PickNode(peers, nil, "nobody"); err == nil {
		t.Error("an unknown node")
	}
	if _, err := PickNode(peers, nil, "10.0.2.1"); err == nil || !strings.Contains(err.Error(), "node ID") {
		t.Errorf("a node with no ID yet: %v", err)
	}
	if id, err := PickNode(peers, []string{"stale99"}, "stale99"); err != nil || id != "stale99" {
		t.Errorf("an entry of a node that left cannot be cleared: %q %v", id, err)
	}
	if _, err := PickNode(peers, nil, " "); err == nil {
		t.Error("an empty name")
	}
}
