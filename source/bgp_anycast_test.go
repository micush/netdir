package main

import (
	"context"
	"testing"
	"time"

	"netdir/internal/core"
)

// The canvas colours a held address by its BGP sessions, and leaves it alone
// when this node does not manage BGP.
func TestMarkAnycastBGPColour(t *testing.T) {
	og := core.AnycastGateFn
	core.AnycastGateFn = func(*core.BGPConfig, string) string { return "" } // the colour is for the moment before the gate's next tick
	t.Cleanup(func() { core.AnycastGateFn = og })
	hookLo(t)
	g := core.DefaultGroup()
	g.Interface = "netdirnone0"
	g.ExtraVIPs = []string{"127.0.0.9"}
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{g}
	s := core.NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)
	s.Mu.Lock()
	s.StartGroupLocked(dc.Groups[0])
	s.Mu.Unlock()

	oldDir, oldBGP := core.FrrDir, core.VtyshBGP
	core.FrrDir = t.TempDir()
	t.Cleanup(func() { core.FrrDir, core.VtyshBGP = oldDir, oldBGP; core.BgpLive.At = time.Time{} })
	state := ""
	core.VtyshBGP = func() ([]byte, error) {
		return []byte(`{"ipv4Unicast":{"peers":{"10.0.0.1":{"remoteAs":65001,"state":"` + state + `"}}}}`), nil
	}
	ss := &StatusServer{sup: s}
	look := func(st string) string {
		state = st
		core.BgpLive.At = time.Time{}
		gs := []core.CanvasGateway{{GroupID: 1}}
		ss.markAnycast(gs)
		if len(gs[0].Anycast) != 1 || !gs[0].Anycast[0].Up {
			t.Fatalf("%+v", gs[0].Anycast)
		}
		return gs[0].Anycast[0].Status
	}
	if got := look("Established"); got != "" {
		t.Fatalf("BGP not managed here: status %q", got)
	}
	s.Mu.Lock()
	s.Dc.BGP = &core.BGPConfig{ASN: 65000, Neighbors: []core.BGPNeighbor{{Peer: "10.0.0.1", RemoteAS: 65001}}}
	s.Mu.Unlock()
	for st, want := range map[string]string{"Established": "ok", "Connect": "bad", "Idle": "bad"} {
		if got := look(st); got != want {
			t.Errorf("%s: %q, want %q", st, got, want)
		}
	}
	// BGP disabled on this node: red, whatever FRR would say
	s.Mu.Lock()
	s.Dc.BGP.Disabled = true
	s.Mu.Unlock()
	if got := look("Established"); got != "bad" {
		t.Errorf("BGP disabled: %q, want bad", got)
	}
}
