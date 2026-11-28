package cluster

import (
	"testing"

	"netdir/internal/core"
)

func TestGatewayNodesSkipsTheRemovedOnes(t *testing.T) {
	g := &core.GroupConfig{ExcludedNodes: []string{"n2"}}
	keep := GatewayNodes(g)
	for id, want := range map[string]bool{"n1": true, "n2": false, "n3": true, "": true} {
		if got := keep(core.PeerView{NodeID: id}); got != want {
			t.Errorf("node %q: %v, want %v", id, got, want)
		}
	}
}
