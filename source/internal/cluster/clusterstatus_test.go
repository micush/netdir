package cluster

import (
	"testing"

	"netdir/internal/core"
)

func gws(states ...string) []core.CanvasNode {
	var out []core.CanvasNode
	for _, s := range states {
		out = append(out, core.CanvasNode{Gw: s, Excluded: s == "removed"})
	}
	return out
}

// The sidebar's dot is the gateway for the cluster as a whole, whichever node is asked.
func TestClusterGatewayStatus(t *testing.T) {
	for _, c := range []struct {
		name   string
		nodes  []core.CanvasNode
		status string
	}{
		{"two serve, two are on another subnet", gws("ok", "ok", "notserving", "notserving"), "ok"},
		{"one serves of three, the rest down", gws("ok", "down", "paused"), "warn"},
		{"one serves of two, the other is on another subnet", gws("ok", "notserving"), "ok"},
		{"one serves of two, the other is down", gws("ok", "down"), "warn"},
		{"one serves of two, the other is paused", gws("ok", "paused"), "warn"},
		{"two serve of four", gws("ok", "ok", "paused", "paused"), "ok"},
		{"served only degraded", gws("degraded", "notserving"), "warn"},
		{"a degraded one does not hide a good one", gws("degraded", "ok"), "ok"},
		{"nothing serves", gws("notserving", "notserving"), "bad"},
		{"serving but broken is not serving", gws("bad", "notserving"), "bad"},
		{"every node has it paused", gws("paused", "paused"), "paused"},
		{"paused and not serving", gws("paused", "notserving"), "bad"},
		{"all starting", gws("starting", "starting"), "idle"},
		{"one starting, one broken", gws("starting", "bad"), "bad"},
		{"removed nodes do not count", gws("ok", "removed", "removed"), "ok"},
		{"removed nodes do not count towards several", gws("ok", "notserving", "removed", "removed"), "ok"},
		{"only the removed", gws("removed"), "idle"},
		{"an old node that reports nothing counts as serving", gws(""), "ok"},
	} {
		if got, why := ClusterGateway(c.nodes); got != c.status || why == "" {
			t.Errorf("%s: %q (%q), want %q", c.name, got, why, c.status)
		}
	}
	if _, d := ClusterGateway(gws("ok", "ok", "notserving")); d != "Served by 2 of 3 nodes" {
		t.Errorf("detail %q", d)
	}
}

// What a node reports decides its state for the gateway.
func TestGwStateOf(t *testing.T) {
	for _, c := range []struct {
		gs     *core.GwState
		paused bool
		want   string
	}{
		{&core.GwState{Serving: true}, false, "ok"},
		{&core.GwState{Serving: true, Health: "warn"}, false, "degraded"},
		{&core.GwState{Serving: true, Health: "bad"}, false, "bad"},
		{&core.GwState{Serving: false, Health: "idle"}, false, "notserving"},
		{&core.GwState{Serving: false, HealthWhy: "starting — waiting for the DNS servers"}, false, "starting"},
		{nil, false, "paused"},
		{&core.GwState{Serving: true}, true, "paused"},
	} {
		if got := gwStateOf(c.gs, c.paused); got != c.want {
			t.Errorf("%+v paused=%v: %q, want %q", c.gs, c.paused, got, c.want)
		}
	}
}
