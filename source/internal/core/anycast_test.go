package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNormalizeAnycast(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.53": "203.0.113.53", "203.0.113.53/32": "203.0.113.53", " 2001:DB8::53 ": "2001:db8::53",
		"2001:db8::53/128": "2001:db8::53", "::ffff:203.0.113.53": "203.0.113.53",
	} {
		got, err := NormalizeAnycast(in)
		if err != nil || got != want {
			t.Errorf("%q → %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "x", "203.0.113.0/24", "2001:db8::/64", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "fe80::1", "ff02::1", "1.2.3"} {
		if got, err := NormalizeAnycast(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestAnycastConfigRules(t *testing.T) {
	g := DefaultGroup()
	g.ExtraVIPs = []string{"203.0.113.53/32", "2001:db8:53::1"}
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{g}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := dc.Groups[0].ExtraVIPs; got[0] != "203.0.113.53" || got[1] != "2001:db8:53::1" {
		t.Fatalf("not normalised: %v", got)
	}
	// the same anycast address on two gateways is how an anycast service is run; equal to a shared address, or listed twice, is refused
	g2 := DefaultGroup()
	g2.GroupID, g2.VIP4, g2.ExtraVIPs = 2, "10.9.0.1/24", []string{"203.0.113.53"}
	dc.Groups = append(dc.Groups, g2)
	if err := dc.Validate(); err != nil {
		t.Fatalf("the same anycast address on two gateways must be allowed: %v", err)
	}
	g2.ExtraVIPs = []string{"10.0.0.1"} // = group 1's vip4
	dc.Groups[1] = g2
	if err := dc.Validate(); err == nil {
		t.Fatal("anycast address equal to a shared address accepted")
	}
	// the list is applied in place: it never restarts the gateway (election)
	a, b := DefaultGroup(), DefaultGroup()
	b.ExtraVIPs = []string{"203.0.113.53"}
	if restartDiffers(&a, &b) {
		t.Fatal("changing the anycast list restarts the gateway")
	}
	if !sameList(nil, []string{}) || sameList(a.ExtraVIPs, b.ExtraVIPs) {
		t.Fatal("sameList")
	}
}

// fakeLo records what the anycast manager does to lo.
type fakeLo struct {
	mu    sync.Mutex
	on    map[string]bool
	adds  int
	dels  int
	failA bool
}

func (f *fakeLo) has(a string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.on[a] }

func hookLo(t *testing.T) *fakeLo {
	ResetAnycast()
	t.Cleanup(ResetAnycast)
	f := &fakeLo{on: map[string]bool{}}
	oa, od := AnycastAddFn, AnycastDelFn
	AnycastAddFn = func(a string) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failA {
			return false
		}
		f.on[a] = true
		f.adds++
		return true
	}
	AnycastDelFn = func(a string) { f.mu.Lock(); delete(f.on, a); f.dels++; f.mu.Unlock() }
	t.Cleanup(func() { AnycastAddFn, AnycastDelFn = oa, od })
	og := AnycastGateFn // these tests are not about BGP: the gate is open unless a test closes it
	AnycastGateFn = func(*BGPConfig, string) string { return "" }
	t.Cleanup(func() { AnycastGateFn = og })
	oc := ServiceUpFn
	ServiceUpFn = func() bool { return true }
	t.Cleanup(func() { ServiceUpFn = oc })
	return f
}

// Pausing an anycast address withdraws it (on this node, or on every node) and resuming announces it again.
func TestAnycastPause(t *testing.T) {
	lo := hookLo(t)
	const addr = "127.0.0.9"
	a := newAnycastSet(1, []string{addr})
	scope := ""
	a.paused = func() map[string]string {
		if scope == "" {
			return nil
		}
		return map[string]string{addr: scope}
	}
	a.step()
	if !lo.has(addr) {
		t.Fatal("not announced")
	}
	scope = "node"
	a.step()
	if lo.has(addr) || a.state()[0].Up || a.state()[0].Reason != pausedHereWhy {
		t.Fatalf("paused on this node but announced: %+v", a.state())
	}
	scope = "all"
	a.step()
	if lo.has(addr) || a.state()[0].Reason != pausedAllWhy {
		t.Fatalf("paused on all nodes but announced: %+v", a.state())
	}
	scope = ""
	a.step()
	if !lo.has(addr) || !a.state()[0].Up {
		t.Fatalf("not announced after resume: %+v", a.state())
	}
	a.cancel = func() {}
	a.done = make(chan struct{})
	close(a.done)
	a.Stop()
}

// The listener stopping withdraws every address; serving again brings them back.
func TestAnycastFollowsServiceHealth(t *testing.T) {
	lo := hookLo(t)
	const addr = "127.0.0.9"
	a := newAnycastSet(1, []string{addr})
	a.step()
	if !lo.has(addr) {
		t.Fatal("not announced while the service is up")
	}
	ServiceUpFn = func() bool { return false }
	a.step()
	if lo.has(addr) || a.state()[0].Up || a.state()[0].Reason == "" {
		t.Fatalf("announced while the service is down: %+v", a.state())
	}
	ServiceUpFn = func() bool { return true }
	a.step()
	if !lo.has(addr) {
		t.Fatal("not announced again once the service is back")
	}
}

// The supervisor holds the addresses with the gateway and drops them when it stops.
func TestSupervisorHoldsAnycastWithGateway(t *testing.T) {
	lo := hookLo(t)
	g := DefaultGroup()
	g.Interface = "netdirnone0"
	g.ExtraVIPs = []string{"127.0.0.9"}
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)
	s.Mu.Lock()
	s.StartGroupLocked(dc.Groups[0])
	s.Mu.Unlock()
	if !lo.has("127.0.0.9") {
		t.Fatalf("not held after the gateway started: %+v", s.AnycastStates(1))
	}
	s.Mu.Lock()
	s.stopGroupLocked(1)
	s.Mu.Unlock()
	if lo.has("127.0.0.9") || s.AnycastStates(1) != nil {
		t.Fatal("still held after the gateway stopped")
	}
	// a paused gateway holds nothing
	g.Paused = true
	s.Mu.Lock()
	s.StartGroupLocked(g)
	s.Mu.Unlock()
	if lo.has("127.0.0.9") {
		t.Fatal("a paused gateway holds its anycast address")
	}
}

// Editing the list through a reload changes the addresses in place: no restart
// of the gateway, the new address appears, the removed one goes.
func TestReloadChangesAnycastInPlace(t *testing.T) {
	lo := hookLo(t)
	g := DefaultGroup()
	g.Interface = "netdirnone0"
	g.ExtraVIPs = []string{"127.0.0.9"}
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)
	s.Mu.Lock()
	s.StartGroupLocked(dc.Groups[0])
	s.Mu.Unlock()
	eng := s.EngineList()
	nu := NewDaemonConfig()
	g2 := g
	g2.ExtraVIPs = []string{"127.0.0.10"}
	nu.Groups = []GroupConfig{g2}
	s.Reload(nu)
	if lo.has("127.0.0.9") || !lo.has("127.0.0.10") {
		t.Fatalf("addresses not swapped: %v", lo.on)
	}
	now := s.EngineList()
	if len(now) != len(eng) || (len(eng) > 0 && now[0] != eng[0]) {
		t.Fatal("the gateway was restarted by an anycast change")
	}
}

// An address is held only while BGP is configured, enabled and at least one neighbor of its family is established;
// otherwise it is off lo and nothing answers on it.
func TestAnycastDownWithoutEstablishedBGP(t *testing.T) {
	lo := hookLo(t)
	AnycastGateFn = anycastBGPGate
	oldDir, oldBGP := FrrDir, VtyshBGP
	FrrDir = t.TempDir()
	t.Cleanup(func() { FrrDir, VtyshBGP = oldDir, oldBGP; BgpLive.At = time.Time{} })
	state := "Established"
	VtyshBGP = func() ([]byte, error) {
		return []byte(`{"ipv4Unicast":{"peers":{"10.0.0.1":{"remoteAs":65001,"state":"` + state + `"}}}}`), nil
	}
	const addr = "127.0.0.9"
	var cfg *BGPConfig
	a := newAnycastSet(1, []string{addr})
	a.bgp = func() (*BGPConfig, bool) { return cfg, true }
	step := func() { BgpLive.At = time.Time{}; a.step() }
	step()
	if lo.has(addr) || a.state()[0].Up || a.state()[0].Reason == "" {
		t.Fatalf("held with BGP not configured: %+v", a.state())
	}
	cfg = &BGPConfig{ASN: 65000, Neighbors: []BGPNeighbor{{Peer: "10.0.0.1", RemoteAS: 65001}}}
	step()
	if !lo.has(addr) {
		t.Fatalf("not held with an established neighbor: %+v", a.state())
	}
	state = "Active"
	step()
	if lo.has(addr) || a.state()[0].Up {
		t.Fatalf("held with no neighbor established: %+v", a.state())
	}
	state = "Established"
	cfg.Disabled = true
	step()
	if lo.has(addr) {
		t.Fatal("held while BGP is disabled")
	}
}
