package main

import (
	"context"
	"net"
	"testing"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

func fakeAddrs(cidrs ...string) func(string) ([]net.Addr, error) {
	return func(string) ([]net.Addr, error) {
		var out []net.Addr
		for _, c := range cidrs {
			ip, n, _ := net.ParseCIDR(c)
			n.IP = ip
			out = append(out, n)
		}
		return out, nil
	}
}

// A node on another subnet does not start the gateway, shows it grey, does not
// count as serving it (so it is no cover for a neighbour's update), and starts
// by itself once it has an address in the subnet.
func TestGatewayHeldBackOffSubnet(t *testing.T) {
	oldF, oldE := core.IfaceAddrsFn, core.OffnetEvery
	core.OffnetEvery = 20 * time.Millisecond
	core.IfaceAddrsFn = fakeAddrs("10.5.5.9/24")
	defer func() { core.IfaceAddrsFn, core.OffnetEvery = oldF, oldE }()

	g := core.DefaultGroup()
	g.Interface = "netdirnone0"
	g.VIP4 = "192.168.122.111/24"
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{g}
	s := core.NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)
	s.Mu.Lock()
	s.StartGroupWhenReadyLocked(g)
	s.Mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	if len(s.EngineList()) != 0 {
		t.Fatal("started a gateway on the wrong subnet")
	}
	off := s.OffnetGroups()
	if off[1] == "" {
		t.Fatal("not reported as off-subnet")
	}
	cg := buildCanvas(dc, nil)
	markOffnet(cg, off)
	if cg[0].Status != "idle" || cg[0].Families[0].Status != "idle" {
		t.Fatalf("canvas: %s %s", cg[0].Status, cg[0].Detail)
	}
	// reported as not serving, so a neighbour's update gate does not count it
	st := cluster.GatewayStates(dc, nil)
	if len(st) != 1 || st[0].Serving {
		t.Fatalf("off-subnet node claims to serve: %+v", st)
	}
	if ok, _ := cluster.SafeToTakeDown([]core.GwState{{GroupID: 1, Serving: true}}, []core.PeerGateways{{Known: true, Serving: map[int]bool{1: st[0].Serving}}}); ok {
		t.Fatal("update gate counted the off-subnet node as cover")
	}
	// it gets an address in the subnet
	core.IfaceAddrsFn = fakeAddrs("192.168.122.74/24")
	deadline := time.Now().Add(5 * time.Second)
	for len(s.EngineList()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(s.EngineList()) == 0 || len(s.OffnetGroups()) != 0 {
		t.Fatal("did not start once on the subnet")
	}
}
