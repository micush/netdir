package cluster

import (
	"testing"

	"netdir/internal/core"
)

func TestNeighborsAreShared(t *testing.T) {
	plain := core.NewDaemonConfig()
	h0 := core.SharedOf(plain).Hash()
	dc := core.NewDaemonConfig()
	dc.Groups[0].Neighbors = []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}
	if core.SharedOf(dc).Hash() == h0 {
		t.Fatal("neighbors are not part of the shared document")
	}
	rep := core.NewDaemonConfig()
	if changed, err := MergeShared(rep, core.SharedOf(dc), nil); err != nil || !changed {
		t.Fatalf("merge: %v %v", changed, err)
	}
	if got := rep.Groups[0].Neighbors; len(got) != 3 || got[2] != "10.0.0.13" {
		t.Fatalf("replica neighbors: %v", got)
	}
	e := &core.Engine{MyIP: "10.0.0.12"}
	if !e.IsSelf("10.0.0.12") || e.IsSelf("10.0.0.11") || e.IsSelf("junk") {
		t.Fatal("isSelf wrong")
	}
}
