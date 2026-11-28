package cluster

import (
	"testing"

	"netdir/internal/core"
)

func TestFailoverEnabled(t *testing.T) {
	for members, want := range map[int]bool{1: false, 2: false, 3: true, 5: true} {
		if got := failoverEnabled(members); got != want {
			t.Errorf("%d members: %v, want %v", members, got, want)
		}
	}
}

func TestPickFailover(t *testing.T) {
	pv := func(addr string, rev uint64, ver string, mods ...func(*core.PeerView)) core.PeerView {
		p := core.PeerView{Addr: addr, Reachable: true, SharedRev: rev, Version: ver}
		for _, m := range mods {
			m(&p)
		}
		return p
	}
	prim := pv("10.0.0.1", 9, "5", func(p *core.PeerView) { p.IsPrimary = true; p.Reachable = false })
	if got := pickFailover([]core.PeerView{prim, pv("10.0.0.3", 8, "5"), pv("10.0.0.2", 9, "5")}, "10.0.0.1"); got != "10.0.0.2" {
		t.Fatalf("newest settings: %q", got)
	}
	if got := pickFailover([]core.PeerView{prim, pv("10.0.0.2", 9, "4"), pv("10.0.0.3", 9, "5")}, "10.0.0.1"); got != "10.0.0.3" {
		t.Fatalf("newest version on a tie: %q", got)
	}
	if got := pickFailover([]core.PeerView{prim, pv("10.0.0.3", 9, "5"), pv("10.0.0.2", 9, "5")}, "10.0.0.1"); got != "10.0.0.2" {
		t.Fatalf("lowest address on a tie: %q", got)
	}
	if got := pickFailover([]core.PeerView{prim, pv("10.0.0.2", 9, "5", func(p *core.PeerView) { p.NodePaused = true }), pv("10.0.0.3", 3, "5")}, "10.0.0.1"); got != "10.0.0.3" {
		t.Fatalf("a paused member was picked: %q", got)
	}
	if got := pickFailover([]core.PeerView{prim, pv("10.0.0.2", 9, "5", func(p *core.PeerView) { p.Updating = true })}, "10.0.0.1"); got != "" {
		t.Fatalf("an updating member was picked: %q", got)
	}
}
