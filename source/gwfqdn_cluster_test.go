package main

import "testing"

// The names set on either node of a real two-node cluster are on both after the nodes have synced, and stay there.
func TestGatewayNamesSurviveClusterSync(t *testing.T) {
	a, b := twoNodeCluster(t) // a is the primary, b the replica
	set := func(n *tnode, fq, any string) {
		t.Helper()
		dc := n.cfg()
		if len(dc.Groups) == 0 {
			dc.Groups = []GroupConfig{defaultGroup()}
		}
		dc.Groups[0].FQDN, dc.Groups[0].AnycastFQDN = fq, any
		if err := n.mg.PutConfigBase(dc, "test", "names", ""); err != nil {
			t.Fatalf("save on %s: %v", n.name, err)
		}
	}
	check := func(when string) {
		t.Helper()
		for _, n := range []*tnode{a, b} {
			g := n.cfg().Groups
			if len(g) == 0 || g[0].FQDN != "files.example.test" || g[0].AnycastFQDN != "any.example.test" {
				t.Fatalf("%s: node %s lost the names: %+v", when, n.name, g)
			}
		}
	}
	set(a, "files.example.test", "any.example.test")
	b.sync()
	a.sync()
	check("set on the primary")
	set(b, "files.example.test", "any.example.test")
	a.sync()
	b.sync()
	a.sync()
	check("saved again on the replica")
}
