package cluster

import (
	"testing"

	"netdir/internal/core"
)

func TestAnycastSharedAcrossCluster(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{core.DefaultGroup()}
	plain := core.SharedOf(dc).Hash()
	dc.Groups[0].ExtraVIPs = []string{}
	if core.SharedOf(dc).Hash() != plain {
		t.Fatal("an empty list changes the cluster hash (rolling updates would disagree)")
	}
	dc.Groups[0].ExtraVIPs = []string{"203.0.113.53"}
	sh := core.SharedOf(dc)
	if sh.Hash() == plain {
		t.Fatal("anycast addresses are not part of the shared config")
	}
	rep := core.NewDaemonConfig()
	rep.Groups = []core.GroupConfig{core.DefaultGroup()}
	changed, err := MergeShared(rep, sh, nil)
	if err != nil || !changed || len(rep.Groups[0].ExtraVIPs) != 1 || rep.Groups[0].ExtraVIPs[0] != "203.0.113.53" {
		t.Fatalf("replica did not receive it: %v %v %v", changed, err, rep.Groups[0].ExtraVIPs)
	}
}
