package cluster

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestSafeToTakeDown(t *testing.T) {
	serving := func(ids ...int) map[int]bool {
		m := map[int]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	mine := []core.GwState{{GroupID: 1, Serving: true}, {GroupID: 2, Serving: true}}
	cases := []struct {
		name  string
		mine  []core.GwState
		peers []core.PeerGateways
		ok    bool
	}{
		{"another member serves everything", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(1, 2)}}, true},
		{"split between two members", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(1)}, {Addr: "c", Known: true, Serving: serving(2)}}, true},
		{"the only other member is still recovering", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving()}}, false},
		{"one gateway would be left unserved", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(1)}}, false},
		{"no other member is reachable", mine, nil, false},
		{"an older node cannot say: assumed fine", mine, []core.PeerGateways{{Addr: "b", Known: false}}, true},
		{"this node serves nothing: nothing to lose", []core.GwState{{GroupID: 1, Serving: false}}, nil, true},
		{"no gateways at all", nil, nil, true},
		{"the only other member is on another subnet and can never cover it", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(), Offnet: serving(1, 2)}}, true},
		{"one member is on another subnet, another is just recovering", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(), Offnet: serving(1, 2)}, {Addr: "c", Known: true, Serving: serving()}}, false},
		{"another subnet, but one gateway could be covered", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(), Offnet: serving(1)}}, false},
		{"the other member is unreachable and may come back", mine, []core.PeerGateways{{Addr: "b", Down: true}}, false},
		{"the other member only just came back", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(1, 2), Fresh: serving(1, 2)}}, false},
		{"one settled member is enough", mine, []core.PeerGateways{{Addr: "b", Known: true, Serving: serving(1, 2), Fresh: serving(1, 2)}, {Addr: "c", Known: true, Serving: serving(1, 2)}}, true},
	}
	for _, c := range cases {
		if ok, why := SafeToTakeDown(c.mine, c.peers); ok != c.ok || (!ok && why == "") {
			t.Errorf("%s: got %v %q, want %v", c.name, ok, why, c.ok)
		}
	}
}

// Two of three nodes paused: the one serving node cannot go (nothing covers it),
// so a paused node must not wait for it even though it sorts earlier.
func TestHeldMemberDoesNotBlockPausedOnes(t *testing.T) {
	srv := func(ids ...int) map[int]bool {
		m := map[int]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	active := []core.GwState{{GroupID: 1, Serving: true}}
	members := []core.PeerGateways{
		{Addr: "a", Known: true, Serving: srv(1)}, // the only one serving
		{Addr: "b", Known: true, Serving: srv()},  // paused
		{Addr: "c", Known: true, Serving: srv()},  // paused
	}
	if !heldBySafety("a", active, members) {
		t.Fatal("the only serving member must count as held back")
	}
	if heldBySafety("b", nil, members) {
		t.Fatal("a paused member serves nothing; it is never held back")
	}
	// once a paused member is back and settled, the serving one is no longer held
	members[1].Serving = srv(1)
	if heldBySafety("a", active, members) {
		t.Fatal("with a settled second server the first is free to go")
	}
	// an older node cannot report gateways: never treated as held
	if heldBySafety("a", nil, members) {
		t.Fatal("no gateway report means not held")
	}
}

func TestGatewayStates(t *testing.T) {
	g1, g2, g3 := core.DefaultGroup(), core.DefaultGroup(), core.DefaultGroup()
	g2.GroupID, g2.VIP4, g2.VIP6 = 2, "10.2.0.1/24", "2001:db8::1/64"
	g3.GroupID, g3.VIP4, g3.Paused = 3, "10.3.0.1/24", true
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{g1, g2, g3}
	rows := []core.SnapshotRow{
		{GroupID: 1, AF: "v4", Local: true, State: "forward", ServiceUp: true},
		{GroupID: 2, AF: "v4", Local: true, State: "active"},
		{GroupID: 2, AF: "v6", Local: true, State: "speak"}, // v6 not yet elected
		{GroupID: 1, AF: "v4", Local: false, State: "active"},
	}
	got := GatewayStates(dc, rows)
	if len(got) != 2 || got[0].GroupID != 1 || !got[0].Serving || got[1].GroupID != 2 || got[1].Serving {
		t.Fatalf("gateway states (paused left out, dual-stack needs both, NTP must be up): %+v", got)
	}
	rows[0].ServiceUp = false
	if GatewayStates(dc, rows)[0].Serving {
		t.Fatal("a gateway whose DNS listener is down is not serving")
	}
}

// A gateway paused on every node reads "paused" on every node that answers, not "not serving".
func TestLabelPausedAll(t *testing.T) {
	nodes := []core.CanvasNode{
		{Self: true, Reachable: true, Status: "paused", Label: "paused", Gw: "paused"},
		{Reachable: true, Status: "paused", Label: "not serving", Gw: "paused", Detail: "This gateway is paused or not set up on that node"},
		{Reachable: true, Status: "warn", Label: "not serving", Gw: "notserving", Detail: "That node is up but is not serving this gateway (yet)"},
		{Reachable: false, Status: "bad", Label: "not answering", Gw: "down"},
		{Reachable: true, Excluded: true, Status: "paused", Label: "removed", Gw: "removed"},
		{Reachable: true, Status: "paused", Label: "paused", Gw: "paused", Paused: true, Detail: "This node is paused"},
		{Reachable: true, Status: "warn", Label: "disk 91%", Gw: "paused", Detail: "Over 85%: disk 91%. This gateway is paused or not set up on that node"},
	}
	LabelPausedAll(nodes)
	if nodes[1].Label != "paused" || nodes[1].Status != "paused" || !strings.Contains(nodes[1].Detail, "all nodes") {
		t.Fatalf("a node that answers: %+v", nodes[1])
	}
	if nodes[0].Label != "paused" || nodes[2].Label != "not serving" || nodes[3].Label != "not answering" || nodes[4].Label != "removed" || nodes[5].Detail != "This node is paused" {
		t.Fatalf("the others must keep their words: %+v", nodes)
	}
	if nodes[6].Label != "disk 91%" || !strings.Contains(nodes[6].Detail, "Over 85%") || !strings.Contains(nodes[6].Detail, "all nodes") {
		t.Fatalf("a node that is also over the load limit keeps its warning: %+v", nodes[6])
	}
}

func TestPickSuccessor(t *testing.T) {
	pv := func(addr string, rev uint64, ver string, mods ...func(*core.PeerView)) core.PeerView {
		p := core.PeerView{Addr: addr, Reachable: true, SharedRev: rev, Version: ver}
		for _, m := range mods {
			m(&p)
		}
		return p
	}
	self := pv("10.0.0.1", 9, "5", func(p *core.PeerView) { p.Self = true; p.IsPrimary = true })
	if got := pickSuccessor([]core.PeerView{self}, "5"); got != "" {
		t.Fatalf("alone: %q", got)
	}
	// the newest settings win
	if got := pickSuccessor([]core.PeerView{self, pv("10.0.0.2", 7, "5"), pv("10.0.0.3", 9, "5")}, "5"); got != "10.0.0.3" {
		t.Fatalf("newest revision: %q", got)
	}
	// down, updating or failed members are skipped
	got := pickSuccessor([]core.PeerView{self,
		pv("10.0.0.2", 9, "5", func(p *core.PeerView) { p.Reachable = false }),
		pv("10.0.0.3", 9, "5", func(p *core.PeerView) { p.Updating = true }),
		pv("10.0.0.4", 9, "5", func(p *core.PeerView) { p.UpdateFailed = "x" }),
		pv("10.0.0.5", 3, "5")}, "5")
	if got != "10.0.0.5" {
		t.Fatalf("skipping unavailable members: %q", got)
	}
	// a tie goes to the same version, then the lowest address
	if got := pickSuccessor([]core.PeerView{self, pv("10.0.0.2", 9, "4"), pv("10.0.0.3", 9, "5"), pv("10.0.0.4", 9, "5")}, "5"); got != "10.0.0.3" {
		t.Fatalf("tie: %q", got)
	}
}

func TestPrimaryReturnTarget(t *testing.T) {
	pv := func(addr string, mods ...func(*core.PeerView)) core.PeerView {
		p := core.PeerView{Addr: addr, Reachable: true, Version: "2"}
		for _, m := range mods {
			m(&p)
		}
		return p
	}
	self := pv("10.0.0.2", func(p *core.PeerView) { p.Self = true; p.IsPrimary = true })
	for _, tc := range []struct {
		name        string
		peers       []core.PeerView
		intent      core.UpdateIntent
		busy        bool
		ready, drop bool
	}{
		{"all done", []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3")}, core.UpdateIntent{}, false, true, false},
		{"home gone", []core.PeerView{self, pv("10.0.0.3")}, core.UpdateIntent{}, false, false, true},
		{"home failed", []core.PeerView{self, pv("10.0.0.1", func(p *core.PeerView) { p.UpdateFailed = "x" })}, core.UpdateIntent{}, false, false, true},
		{"home down", []core.PeerView{self, pv("10.0.0.1", func(p *core.PeerView) { p.Reachable = false })}, core.UpdateIntent{}, false, false, false},
		{"queued", []core.PeerView{self, pv("10.0.0.1")}, core.UpdateIntent{Pending: []string{"10.0.0.3"}}, false, false, false},
		{"another node updating", []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3", func(p *core.PeerView) { p.Updating = true })}, core.UpdateIntent{}, false, false, false},
		{"another node restarting", []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3", func(p *core.PeerView) { p.Restarting = true; p.Reachable = false })}, core.UpdateIntent{}, false, false, false},
		{"this node busy", []core.PeerView{self, pv("10.0.0.1")}, core.UpdateIntent{}, true, false, false},
		{"auto, one on the old version", []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3", func(p *core.PeerView) { p.Version = "1" })}, core.UpdateIntent{AutoAll: true}, false, false, false},
		{"auto, the old version failed", []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3", func(p *core.PeerView) { p.Version = "1"; p.UpdateFailed = "x" })}, core.UpdateIntent{AutoAll: true}, false, true, false},
		{"not queued, on another version", []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3", func(p *core.PeerView) { p.Version = "1" })}, core.UpdateIntent{}, false, true, false},
	} {
		ready, drop, why := PrimaryReturnTarget(tc.peers, "10.0.0.1", tc.intent, tc.busy)
		if ready != tc.ready || drop != tc.drop {
			t.Errorf("%s: ready=%v drop=%v (%s), want %v %v", tc.name, ready, drop, why, tc.ready, tc.drop)
		}
	}
	// the home is preferred when it can take the role
	peers := []core.PeerView{self, pv("10.0.0.1"), pv("10.0.0.3", func(p *core.PeerView) { p.SharedRev = 9 })}
	if got := pickSuccessorPrefer(peers, "2", "10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("home not preferred: %q", got)
	}
	if got := pickSuccessorPrefer(peers, "2", "10.0.0.9"); got != "10.0.0.3" {
		t.Errorf("an unknown home changed the pick: %q", got)
	}
}
