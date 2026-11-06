package main

import "testing"

func TestLearnPeerAddrs(t *testing.T) {
	p := ClusterPeer{Addr: "ns2:22162", Fp: "f", NodeID: "n", Alts: []string{"10.0.0.9:22162", "ns2.lan:22162"}}
	np, ok := learnPeerAddrs(p, []string{"192.168.5.55", "fdf5:168:5::55"})
	if !ok {
		t.Fatal("new addresses must be learned")
	}
	want := []string{"192.168.5.55:22162", "[fdf5:168:5::55]:22162", "ns2.lan:22162"}
	if len(np.Alts) != len(want) {
		t.Fatalf("got %v", np.Alts)
	}
	for i := range want {
		if np.Alts[i] != want[i] {
			t.Fatalf("got %v, want %v", np.Alts, want)
		}
	}
	if _, ok := learnPeerAddrs(np, []string{"192.168.5.55", "fdf5:168:5::55"}); ok {
		t.Fatal("nothing changed, nothing to save")
	}
	if _, ok := learnPeerAddrs(np, nil); ok {
		t.Fatal("no report, no change")
	}
}
