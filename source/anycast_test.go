package main

import (
	"net"
	"strings"
	"sync"
	"testing"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

func TestAnycastCanvasEdit(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{core.DefaultGroup()}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 1, Anycast: "203.0.113.53, 2001:db8:53::1"}); err != nil {
		t.Fatal(err)
	}
	if len(dc.Groups[0].ExtraVIPs) != 2 {
		t.Fatalf("got %v", dc.Groups[0].ExtraVIPs)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 1, Anycast: "10.0.0.0/24"}); err == nil {
		t.Fatal("a subnet was accepted")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 1, Anycast: "-"}); err != nil || len(dc.Groups[0].ExtraVIPs) != 0 {
		t.Fatalf("not cleared: %v %v", err, dc.Groups[0].ExtraVIPs)
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

func freeUDPPort(t *testing.T) int {
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func TestAnycastCanvasAddDel(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{core.DefaultGroup()}
	ed := func(action, addr string) error {
		_, err := applyCanvasEdit(dc, canvasEdit{Action: action, Kind: "anycast", Group: 1, Address: addr})
		return err
	}
	if err := ed("add", "203.0.113.53"); err != nil {
		t.Fatal(err)
	}
	if err := ed("add", "2001:db8:53::1/128"); err != nil {
		t.Fatal(err)
	}
	if err := ed("add", "203.0.113.53"); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := ed("add", "10.0.0.0/8"); err == nil {
		t.Fatal("subnet accepted")
	}
	if err := ed("add", ""); err == nil {
		t.Fatal("empty address accepted")
	}
	if got := dc.Groups[0].ExtraVIPs; len(got) != 2 || got[1] != "2001:db8:53::1" {
		t.Fatalf("got %v", got)
	}
	if err := ed("del", "203.0.113.99"); err == nil {
		t.Fatal("deleting an unknown address succeeded")
	}
	if err := ed("del", "203.0.113.53"); err != nil || len(dc.Groups[0].ExtraVIPs) != 1 {
		t.Fatalf("not removed: %v %v", err, dc.Groups[0].ExtraVIPs)
	}
}

// The canvas edit, the cluster split between "this node" and "all nodes", and what deleting an address does to its pause.
func TestAnycastPauseConfig(t *testing.T) {
	dc := core.NewDaemonConfig()
	g := core.DefaultGroup()
	g.ExtraVIPs = []string{"203.0.113.53", "203.0.113.54"}
	dc.Groups = []core.GroupConfig{g}
	edit := func(action, scope, addr string) (string, error) {
		return applyCanvasEdit(dc, canvasEdit{Action: action, Kind: "anycast", Group: 1, Address: addr, Scope: scope})
	}
	if _, err := edit("pause", "", "203.0.113.53"); err == nil {
		t.Fatal("pause without a scope accepted")
	}
	if _, err := edit("pause", "node", "203.0.113.99"); err == nil {
		t.Fatal("pausing an address the gateway does not have")
	}
	if _, err := edit("pause", "node", "203.0.113.53"); err != nil {
		t.Fatal(err)
	}
	if _, err := edit("pause", "all", "203.0.113.54"); err != nil {
		t.Fatal(err)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	got := dc.Groups[0].PausedAnycast()
	if got["203.0.113.53"] != "node" || got["203.0.113.54"] != "all" {
		t.Fatalf("paused: %v", got)
	}
	// only "all" is shared: a replica gets that one and keeps its own list
	sh := core.SharedOf(dc)
	if len(sh.Groups[0].PausedVIPs) != 1 || sh.Groups[0].PausedVIPs[0] != "203.0.113.54" {
		t.Fatalf("shared: %+v", sh.Groups[0].PausedVIPs)
	}
	rep := core.NewDaemonConfig()
	rg := core.DefaultGroup()
	rg.PausedVIPsHere = []string{"203.0.113.54"} // its own pause of something else is not touched by a merge
	rep.Groups = []core.GroupConfig{rg}
	if _, err := cluster.MergeShared(rep, sh, nil); err != nil {
		t.Fatal(err)
	}
	if len(rep.Groups[0].PausedVIPs) != 1 || len(rep.Groups[0].PausedVIPsHere) != 1 {
		t.Fatalf("replica: all=%v here=%v", rep.Groups[0].PausedVIPs, rep.Groups[0].PausedVIPsHere)
	}
	// the summary wording, and a hash that does not move for a cluster with nothing paused
	if m, _ := edit("resume", "node", "203.0.113.53"); !strings.Contains(m, "resumed on this node") {
		t.Fatalf("resume: %q", m)
	}
	if m, _ := edit("resume", "node", "203.0.113.53"); !strings.Contains(m, "not paused") {
		t.Fatalf("resume again: %q", m)
	}
	// deleting an address drops its pause
	if _, err := edit("del", "", "203.0.113.54"); err != nil {
		t.Fatal(err)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(dc.Groups[0].PausedVIPs) != 0 || len(dc.Groups[0].PausedAnycast()) != 0 {
		t.Fatalf("pause outlived its address: %v", dc.Groups[0].PausedVIPs)
	}
	plain := core.NewDaemonConfig()
	plain.Groups = []core.GroupConfig{core.DefaultGroup()}
	h0 := core.SharedOf(plain).Hash()
	plain.Groups[0].PausedVIPs = []string{}
	if core.SharedOf(plain).Hash() != h0 {
		t.Fatal("an empty paused list changes the cluster hash")
	}
}

func hookLo(t *testing.T) *fakeLo {
	core.ResetAnycast()
	t.Cleanup(core.ResetAnycast)
	f := &fakeLo{on: map[string]bool{}}
	oa, od := core.AnycastAddFn, core.AnycastDelFn
	core.AnycastAddFn = func(a string) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failA {
			return false
		}
		f.on[a] = true
		f.adds++
		return true
	}
	core.AnycastDelFn = func(a string) { f.mu.Lock(); delete(f.on, a); f.dels++; f.mu.Unlock() }
	t.Cleanup(func() { core.AnycastAddFn, core.AnycastDelFn = oa, od })
	og := core.AnycastGateFn // these tests are not about BGP: the gate is open unless a test closes it
	core.AnycastGateFn = func(*core.BGPConfig, string) string { return "" }
	t.Cleanup(func() { core.AnycastGateFn = og })
	oc := core.ServiceUpFn
	core.ServiceUpFn = func() bool { return true }
	t.Cleanup(func() { core.ServiceUpFn = oc })
	return f
}
