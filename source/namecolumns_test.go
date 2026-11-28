package main

import (
	"reflect"
	"testing"

	"netdir/internal/core"
)

// The two nodes of a cluster tell each other their addresses, so each can name the other's gateway address.
func TestPeersReportTheirAddresses(t *testing.T) {
	a, b := twoNodeCluster(t)
	a.mg.gwIPsFn = func() []string { return []string{"10.1.1.1", "fe80::1"} }
	b.mg.gwIPsFn = func() []string { return []string{"10.1.1.2", "fe80::2"} }
	a.sync()
	b.sync()
	v := a.mg.cl.View()
	if len(v.Peers) != 2 {
		t.Fatalf("peers %+v", v.Peers)
	}
	self, other := v.Peers[0], v.Peers[1]
	if !self.Self || !reflect.DeepEqual(self.GwIPs, []string{"10.1.1.1", "fe80::1"}) {
		t.Fatalf("self: %+v", self)
	}
	if !reflect.DeepEqual(other.GwIPs, []string{"10.1.1.2", "fe80::2"}) {
		t.Fatalf("the other node's gateway addresses: %+v", other)
	}
	if len(self.IPs) == 0 || !reflect.DeepEqual(self.IPs, other.IPs) { // both nodes of the test are on this one machine
		t.Fatalf("addresses: self %v other %v", self.IPs, other.IPs)
	}
	names := core.NodeNamesByIP(v.Peers)
	if names["10.1.1.2"] == "" || names["10.1.1.2"] != names["fe80::2"] || names["10.1.1.1"] == names["10.1.1.2"] {
		t.Fatalf("names %v", names)
	}
}
