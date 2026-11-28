package cluster

import (
	"fmt"
	"testing"
	"time"

	"netdir/internal/core"
)

// Every node serves its own gateway and is excluded from the others' (as in a cluster of single-node gateways in four
// subnets).  The update order must still apply: no member may look "held back by the safety rule" just because the others
// do not report its gateway.  Before v341 every member did, so all of them updated at once and the canary never held.
func TestOrderAppliesWhenEveryNodeServesItsOwnGateway(t *testing.T) {
	names := []string{"A", "B", "C", "D"}
	var members []core.PeerGateways
	var groups []core.GroupConfig
	for i, n := range names {
		gid := i + 1
		pg := selfGateways(n, true, []core.GwState{{GroupID: gid, Serving: true}})
		pg.NodeID = "id" + n
		members = append(members, pg)
		var ex []string
		for _, o := range names {
			if o != n {
				ex = append(ex, "id"+o)
			}
		}
		groups = append(groups, core.GroupConfig{GroupID: gid, ExcludedNodes: ex})
	}
	if !heldBySafety("A", gwList(members[0]), members) {
		t.Fatal("test set-up: without the exclusions A must look held (that is the bug)")
	}
	MarkGatewayExcluded(members, groups)
	for _, m := range members {
		if heldBySafety(m.Addr, gwList(m), members) {
			t.Fatalf("%s must not look held back once the exclusions are known", m.Addr)
		}
	}
}

// gwList turns the map form back into the list heldBySafety takes.
func gwList(p core.PeerGateways) []core.GwState {
	var out []core.GwState
	for id, s := range p.Serving {
		out = append(out, core.GwState{GroupID: id, Serving: s})
	}
	return out
}

// A member that stops answering while it installs an update is "updating", not down: the Topology and Upgrade pages
// show it so, and the gateway it serves reads "updating" (grey) instead of "no node is serving" (red).
func TestRestartingMemberIsNotDown(t *testing.T) {
	next := fmt.Sprintf("%d", mustInt(core.Version())+1)
	recent := time.Now().Add(-20 * time.Second)
	cases := []struct {
		name string
		pi   *peerInfo
		want bool
	}{
		{"installing", &peerInfo{Msg: PeerStatusMsg{Updating: true}, LastSeen: recent}, true},
		{"newer source staged", &peerInfo{Msg: PeerStatusMsg{Version: core.Version(), SourceVersion: next}, LastSeen: recent}, true},
		{"answering", &peerInfo{Reachable: true, Msg: PeerStatusMsg{Updating: true}, LastSeen: recent}, false},
		{"down, nothing pending", &peerInfo{Msg: PeerStatusMsg{Version: core.Version(), SourceVersion: core.Version()}, LastSeen: recent}, false},
		{"gone for an hour", &peerInfo{Msg: PeerStatusMsg{Updating: true}, LastSeen: time.Now().Add(-time.Hour)}, false},
		{"never seen", &peerInfo{Msg: PeerStatusMsg{Updating: true}}, false},
	}
	for _, c := range cases {
		if got := restartingInfo(c.pi); got != c.want {
			t.Errorf("%s: restarting = %v, want %v", c.name, got, c.want)
		}
	}
	st, _ := ClusterGateway([]core.CanvasNode{{Gw: "updating"}})
	if st != "idle" {
		t.Errorf("a gateway whose only node is updating is %q, want idle", st)
	}
	if st, _ := ClusterGateway([]core.CanvasNode{{Gw: "updating"}, {Gw: "down"}}); st != "bad" {
		t.Errorf("an updating node must not hide a node that is really down: %q", st)
	}
	if st, _ := ClusterGateway([]core.CanvasNode{{Gw: "updating"}, {Gw: "ok"}}); st != "ok" {
		t.Errorf("a gateway still served by another node stays ok: %q", st)
	}
}

// The gateway's uptime is the cluster's: the longest unbroken time any node serving it now has served it.
func TestClusterUpSec(t *testing.T) {
	nodes := []core.CanvasNode{
		{Gw: "ok", ServingSec: 90},
		{Gw: "degraded", ServingSec: 4000},
		{Gw: "down", ServingSec: 99999}, // not serving now: does not count
		{Gw: "ok", ServingSec: 5000, Excluded: true},
	}
	if got := ClusterUpSec(nodes); got != 4000 {
		t.Errorf("clusterUpSec = %d, want 4000", got)
	}
	if got := ClusterUpSec(nil); got != 0 {
		t.Errorf("no nodes: %d", got)
	}
}
