package main

import "testing"

// Peer addresses are tried before peer names, so cluster traffic does not depend on DNS.
func TestAddrsForTriesIPsBeforeNames(t *testing.T) {
	c := &Cluster{goodAddr: map[string]string{}}
	p := ClusterPeer{Addr: "ns2:22162", Alts: []string{"ns2.example:22162", "192.168.5.55:22162", "[fdf5:168:5::55]:22162"}}
	want := []string{"192.168.5.55:22162", "[fdf5:168:5::55]:22162", "ns2:22162", "ns2.example:22162"}
	got := c.addrsFor(p)
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	c.noteGoodAddr(p, "[fdf5:168:5::55]:22162")
	if got = c.addrsFor(p); got[0] != "[fdf5:168:5::55]:22162" || got[2] != "ns2:22162" {
		t.Fatalf("the last good address should lead its group: %v", got)
	}
	c.noteGoodAddr(p, "ns2:22162")
	if got = c.addrsFor(p); got[0] != "192.168.5.55:22162" || got[2] != "ns2:22162" {
		t.Fatalf("a good name must not jump ahead of addresses: %v", got)
	}
}
