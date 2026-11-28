package core

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
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

func TestOnGatewaySubnet(t *testing.T) {
	old := IfaceAddrsFn
	defer func() { IfaceAddrsFn = old }()
	g := DefaultGroup()
	g.VIP4 = "192.168.122.111/24"

	IfaceAddrsFn = fakeAddrs("192.168.122.74/24", "fe80::1/64")
	if ok, why := onGatewaySubnet(g); !ok {
		t.Fatalf("same subnet refused: %s", why)
	}
	IfaceAddrsFn = fakeAddrs("10.5.5.9/24", "fe80::1/64")
	if ok, why := onGatewaySubnet(g); ok || why == "" {
		t.Fatalf("other subnet accepted (%v %q)", ok, why)
	}
	IfaceAddrsFn = func(string) ([]net.Addr, error) { return nil, net.UnknownNetworkError("x") }
	if ok, _ := onGatewaySubnet(g); !ok {
		t.Fatal("a missing interface must be left to the engine's own wait")
	}
	// IPv6-only gateway
	g.VIP4, g.VIP6 = "", "2001:db8:1::1/64"
	IfaceAddrsFn = fakeAddrs("10.5.5.9/24", "fe80::1/64")
	if ok, _ := onGatewaySubnet(g); !ok {
		t.Fatal("link-local only: nothing to compare, must be let through")
	}
	IfaceAddrsFn = fakeAddrs("10.5.5.9/24", "fe80::1/64", "2001:db8:1::74/64")
	if ok, why := onGatewaySubnet(g); !ok {
		t.Fatalf("global address in the VIP prefix refused: %s", why)
	}
	IfaceAddrsFn = fakeAddrs("fe80::1/64", "2001:db8:9::74/64")
	if ok, why := onGatewaySubnet(g); ok || why == "" {
		t.Fatal("global address in another prefix accepted")
	}
	IfaceAddrsFn = fakeAddrs("fd00:1::5/64")
	if ok, _ := onGatewaySubnet(g); ok {
		t.Fatal("a ULA in another prefix accepted")
	}
	// dual stack: every checkable family must match
	g.VIP4 = "10.5.5.1/24"
	IfaceAddrsFn = fakeAddrs("10.5.5.9/24", "2001:db8:9::74/64")
	if ok, _ := onGatewaySubnet(g); ok {
		t.Fatal("v4 matches but v6 does not: must be refused")
	}
	IfaceAddrsFn = fakeAddrs("10.5.5.9/24", "2001:db8:1::74/64")
	if ok, _ := onGatewaySubnet(g); !ok {
		t.Fatal("both families match: refused")
	}
	if !addrsInPrefix(fakeAddrsList(t, "127.0.0.1/8"), netip.MustParsePrefix("127.0.0.9/8")) {
		t.Fatal("loopback config must match its own /8")
	}
}

func fakeAddrsList(t *testing.T, c string) []net.Addr {
	a, _ := fakeAddrs(c)("")
	return a
}

// Pausing the gateway while it is held back cancels the wait.
func TestOffSubnetWaitCancelled(t *testing.T) {
	oldF, oldE := IfaceAddrsFn, OffnetEvery
	OffnetEvery = 20 * time.Millisecond
	IfaceAddrsFn = fakeAddrs("10.5.5.9/24")
	defer func() { IfaceAddrsFn, OffnetEvery = oldF, oldE }()
	g := DefaultGroup()
	g.Interface = "netdirnone0"
	g.VIP4 = "192.168.122.111/24"
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)
	s.Mu.Lock()
	s.StartGroupWhenReadyLocked(g)
	s.stopGroupLocked(1)
	s.Mu.Unlock()
	IfaceAddrsFn = fakeAddrs("192.168.122.74/24")
	time.Sleep(200 * time.Millisecond)
	if len(s.EngineList()) != 0 || len(s.OffnetGroups()) != 0 {
		t.Fatal("a removed gateway started anyway")
	}
}
