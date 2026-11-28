package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNodePauseIsEffectiveButKeepsEachGatewaysOwnFlag(t *testing.T) {
	dc := NewDaemonConfig()
	g1, g2 := DefaultGroup(), DefaultGroup()
	g2.GroupID, g2.Paused = 2, true
	dc.Groups = []GroupConfig{g1, g2}

	if e := dc.Effective(); e.Groups[0].Paused || !e.Groups[1].Paused {
		t.Fatal("a running node must use each gateway's own flag as it is")
	}
	dc.NodePaused = true
	eff := dc.Effective()
	if eff == dc || !eff.Groups[0].Paused || !eff.Groups[1].Paused {
		t.Fatalf("every gateway must be paused while the node is: %+v", eff.Groups)
	}
	if dc.Groups[0].Paused {
		t.Fatal("the file's own gateway flag must not be changed by the node pause")
	}
	dc.NodePaused = false
	if dc.Effective().Groups[0].Paused || !dc.Effective().Groups[1].Paused {
		t.Fatal("after resuming, each gateway is back to its own flag")
	}
}

func TestNodePauseFlagIsLocalAndOptional(t *testing.T) {
	dc := NewDaemonConfig()
	if b, _ := json.Marshal(dc); strings.Contains(string(b), "node_paused") {
		t.Fatalf("a config that never paused the node must have no node_paused key (older versions reject unknown keys): %s", b)
	}
	dc.NodePaused = true
	b, _ := json.Marshal(dc)
	var back DaemonConfig
	if err := json.Unmarshal(b, &back); err != nil || !back.NodePaused {
		t.Fatalf("round trip: %v %+v", err, back.NodePaused)
	}
	if sb, _ := json.Marshal(SharedOf(dc)); strings.Contains(string(sb), "paused") {
		t.Fatalf("the node pause is per node and must not be replicated: %s", sb)
	}
}

func TestLastServing(t *testing.T) {
	mine := []GwState{{GroupID: 1, Serving: true}, {GroupID: 2, Serving: true}}
	peer := func(down bool, serving ...int) PeerGateways {
		p := PeerGateways{Addr: "10.0.0.2", Down: down, Known: true, Serving: map[int]bool{}}
		for _, g := range serving {
			p.Serving[g] = true
		}
		return p
	}
	if why := LastServing(mine, []PeerGateways{peer(false, 1, 2)}); why != "" {
		t.Fatalf("both covered: %q", why)
	}
	// another member exists but serves only gateway 1: this node is the last for gateway 2
	if why := LastServing(mine, []PeerGateways{peer(false, 1)}); !strings.Contains(why, "gateway 2") {
		t.Fatalf("last for gateway 2: %q", why)
	}
	// an unreachable member is no cover
	if why := LastServing(mine, []PeerGateways{peer(true)}); why == "" {
		t.Fatal("a down member covered a gateway")
	}
	// a gateway this node is not serving is nothing to lose
	if why := LastServing([]GwState{{GroupID: 3}}, []PeerGateways{peer(false)}); why != "" {
		t.Fatalf("not serving: %q", why)
	}
}
