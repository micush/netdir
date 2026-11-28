package main

import (
	"strings"
	"testing"
	"time"

	"netdir/internal/core"
	"netdir/internal/web"
)

// bgpEnv is a web environment whose FRR is a fake: saving BGP settings starts the (asynchronous) apply, which must
// not touch the real /etc/frr nor still be running when the next test swaps the fake out.
func bgpEnv(t *testing.T) *webEnv {
	t.Helper()
	fakeFRR(t, nil)
	e := newWebEnv(t)
	t.Cleanup(func() { // runs before fakeFRR's own cleanup puts the real values back
		for i := 0; i < 400; i++ {
			e.mg.bgp.Mu.Lock()
			busy := e.mg.bgp.Running
			e.mg.bgp.Mu.Unlock()
			if !busy {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	return e
}

// A router ID is meaningless without an AS: the settings refuse it, and a stored one next to a cleared AS is dropped
// rather than stopping the config from loading.
func TestBGPRouterIDNeedsASN(t *testing.T) {
	e := bgpEnv(t)
	err := e.mg.BGPSet(core.BGPConfig{RouterID: "192.0.2.10"}, "t")
	if err == nil || !strings.Contains(err.Error(), "router id needs a local AS") {
		t.Fatalf("a router id without an AS was accepted: %v", err)
	}
	if err := e.mg.BGPSet(core.BGPConfig{ASN: 64512, RouterID: "192.0.2.10"}, "t"); err != nil {
		t.Fatal(err)
	}
	// clearing the AS together with the router id is what the page and `--asn off` send
	if err := e.mg.BGPSet(core.BGPConfig{}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ := e.mg.LiveConfig()
	if dc.BGP != nil && (dc.BGP.RouterID != "" || dc.BGP.ASN != 0) {
		t.Fatalf("settings after clearing the AS: %+v", dc.BGP)
	}
	// an old file with a router id and no AS still validates; the router id goes
	old := core.BGPConfig{RouterID: "192.0.2.10", Disabled: true}
	if err := old.Validate(); err != nil || old.RouterID != "" || old.Disabled {
		t.Fatalf("old config not normalised: %+v %v", old, err)
	}
}

func TestBGPOperate(t *testing.T) {
	e := bgpEnv(t)
	if err := e.mg.BGPOperate(core.BGPOperateArgs{Enabled: false}, "t"); err == nil {
		t.Fatal("disabling BGP without an AS should be refused")
	}
	set := core.BGPConfig{ASN: 64512, RouterID: "192.0.2.10", Neighbors: []core.BGPNeighbor{
		{Peer: "192.0.2.1", RemoteAS: 64500}, {Peer: "2001:db8::1", RemoteAS: 64500}}}
	if err := e.mg.BGPSet(set, "t"); err != nil {
		t.Fatal(err)
	}
	get := func() *core.BGPConfig { dc, _, _ := e.mg.LiveConfig(); return dc.BGP }

	if err := e.mg.BGPOperate(core.BGPOperateArgs{Peer: "2001:DB8::1", Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	if c := get(); c.Neighbors[0].Disabled || !c.Neighbors[1].Disabled || c.Disabled || !c.Active() {
		t.Fatalf("after disabling one neighbor: %+v", c)
	}
	if err := e.mg.BGPOperate(core.BGPOperateArgs{Peer: "192.0.2.99", Enabled: false}, "t"); err == nil {
		t.Fatal("an unknown neighbor was accepted")
	}
	if err := e.mg.BGPOperate(core.BGPOperateArgs{Peer: "x", Enabled: false}, "t"); err == nil {
		t.Fatal("a bad address was accepted")
	}

	// editing the settings does not switch anything back on (the page sends the flags it last saw, or none)
	edit := *get()
	edit.Keepalive = 5
	edit.Neighbors = []core.BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}, {Peer: "2001:db8::1", RemoteAS: 64500, Disabled: false}, {Peer: "192.0.2.3", RemoteAS: 64501}}
	if err := e.mg.BGPSet(edit, "t"); err != nil {
		t.Fatal(err)
	}
	if c := get(); !c.Neighbors[1].Disabled || c.Neighbors[0].Disabled || c.Neighbors[2].Disabled || c.Keepalive != 5 {
		t.Fatalf("settings edit changed the neighbors' on/off state: %+v", c.Neighbors)
	}

	if err := e.mg.BGPOperate(core.BGPOperateArgs{Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	c := get()
	if !c.Disabled || c.Active() || c.ASN != 64512 || len(c.Neighbors) != 3 || c.RouterID != "192.0.2.10" {
		t.Fatalf("a disabled process keeps its settings: %+v", c)
	}
	edit = *c
	edit.Disabled = false // the settings path must not be able to switch it on
	if err := e.mg.BGPSet(edit, "t"); err != nil {
		t.Fatal(err)
	}
	if !get().Disabled {
		t.Fatal("the settings edit switched BGP back on")
	}
	if err := e.mg.BGPOperate(core.BGPOperateArgs{Enabled: true}, "t"); err != nil {
		t.Fatal(err)
	}
	if c := get(); c.Disabled || !c.Active() || !c.Neighbors[1].Disabled {
		t.Fatalf("enabled again: %+v", c)
	}
	// clearing the AS forgets the process-level flag
	if err := e.mg.BGPOperate(core.BGPOperateArgs{Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.mg.BGPSet(core.BGPConfig{}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.mg.BGPSet(core.BGPConfig{ASN: 64512}, "t"); err != nil {
		t.Fatal(err)
	}
	if get().Disabled {
		t.Fatal("a fresh AS must start enabled")
	}
}

func TestBGPOperateAPIAndStatus(t *testing.T) {
	e := bgpEnv(t)
	e.login("alice", "pw")
	if r := e.do("PUT", "/api/bgp", core.BGPConfig{ASN: 64512, Neighbors: []core.BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}}}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("set: %d %s", r.code, r.raw)
	}
	r := e.do("POST", "/api/bgp/operate", core.BGPOperateArgs{Peer: "192.0.2.1", Enabled: false}, withAuth(e, true))
	if r.code != 200 {
		t.Fatalf("operate: %d %s", r.code, r.raw)
	}
	if !strings.Contains(string(r.raw), `"disabled":true`) {
		t.Fatalf("the reply does not show the neighbor as disabled: %s", r.raw)
	}
	if r := e.do("POST", "/api/bgp/operate", core.BGPOperateArgs{Enabled: false}, withAuth(e, true)); r.code != 200 || !strings.Contains(string(r.raw), `"disabled":true`) {
		t.Fatalf("operate process: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/bgp/operate", core.BGPOperateArgs{Peer: "198.51.100.1", Enabled: true}, withAuth(e, true)); r.code == 200 {
		t.Fatal("an unknown neighbor was accepted over the API")
	}
	// a router id without an AS is refused over the API too
	if r := e.do("PUT", "/api/bgp", core.BGPConfig{RouterID: "192.0.2.10"}, withAuth(e, true)); r.code == 200 {
		t.Fatal("router id without AS accepted over the API")
	}
	if err := web.ProxyAllowed("POST", "/api/bgp/operate"); err != nil {
		t.Fatalf("the operate call must be relayable to another node: %v", err)
	}
}
