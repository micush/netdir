package core

import (
	"reflect"
	"testing"
)

func TestNodeOrder(t *testing.T) {
	g := DefaultGroup()
	g.VIP4 = "10.0.0.1/24"
	g.NodeOrder = []string{"bb01", "aa02", "bb01", "cc03"}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"bb01", "aa02", "cc03"}; !reflect.DeepEqual(g.NodeOrder, want) { // the order is kept (not sorted), repeats dropped
		t.Fatalf("node_order = %v, want %v", g.NodeOrder, want)
	}
	bad := DefaultGroup()
	bad.VIP4 = "10.0.0.1/24"
	bad.NodeOrder = []string{"nothex"}
	if bad.Validate() == nil {
		t.Fatal("a node ID that is not hexadecimal was accepted")
	}
	// shared: every node gets the order, and a gateway without one carries none
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{g}
	sh := SharedOf(dc)
	var other GroupConfig
	ApplySharedGroup(&other, sh.Groups[0])
	if !reflect.DeepEqual(other.NodeOrder, g.NodeOrder) {
		t.Fatalf("shared node_order = %v", other.NodeOrder)
	}
	g.NodeOrder = nil
	dc.Groups = []GroupConfig{g}
	if sh := SharedOf(dc); sh.Groups[0].NodeOrder != nil {
		t.Fatalf("an unset order must stay out of the shared settings: %v", sh.Groups[0].NodeOrder)
	}
	// a change of order never restarts a gateway
	a, b := g, g
	b.NodeOrder = []string{"aa02", "bb01"}
	if restartDiffers(&a, &b) {
		t.Fatal("reordering the nodes restarted the gateway")
	}
}
