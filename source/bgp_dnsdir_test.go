package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netdir/internal/core"
)

// withDnsdir makes bgpBlocked see a dnsdir install (a marker file in a temp dir) for the test.
func withDnsdir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dnsdir")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(setDnsdir([]string{p}, ""))
	return p
}

func TestBGPCannotBeSetOrEnabledWithDnsdir(t *testing.T) {
	e := bgpEnv(t)
	e.login("alice", "pw")
	set := core.BGPConfig{ASN: 64512, Neighbors: []core.BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}}}
	if r := e.do("PUT", "/api/bgp", set, withAuth(e, true)); r.code != 200 {
		t.Fatalf("set before dnsdir: %d %s", r.code, r.raw)
	}
	withDnsdir(t)

	if r := e.do("PUT", "/api/bgp", set, withAuth(e, true)); r.code == 200 || !strings.Contains(string(r.raw), "AnyName") {
		t.Fatalf("settings accepted with dnsdir installed: %d %s", r.code, r.raw)
	}
	if r := e.do("PUT", "/api/bgp", core.BGPConfig{ASN: 64513}, withAuth(e, true)); r.code == 200 {
		t.Fatal("a new AS was accepted")
	}
	// disabling is fine, enabling is refused
	if r := e.do("POST", "/api/bgp/operate", core.BGPOperateArgs{Enabled: false}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/bgp/operate", core.BGPOperateArgs{Enabled: true}, withAuth(e, true)); r.code == 200 || !strings.Contains(string(r.raw), "AnyName") {
		t.Fatalf("enable accepted: %d %s", r.code, r.raw)
	}
	r := e.do("GET", "/api/bgp", nil, withAuth(e, false))
	if r.code != 200 || !strings.Contains(string(r.raw), `"blocked":"`) {
		t.Fatalf("status does not say BGP is blocked: %d %s", r.code, r.raw)
	}
	// the settings can still be cleared
	if r := e.do("PUT", "/api/bgp", core.BGPConfig{}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("clearing refused: %d %s", r.code, r.raw)
	}
}

// setDnsdir points the dnsdir markers (and, when conf is not "", its configuration) somewhere else and returns what puts them back.
func setDnsdir(markers []string, conf string) func() {
	core.DnsdirMu.Lock()
	om, oc := core.DnsdirMarkers, core.DnsdirConfPath
	core.DnsdirMarkers = markers
	if conf != "" {
		core.DnsdirConfPath = conf
	}
	core.DnsdirMu.Unlock()
	return func() {
		core.DnsdirMu.Lock()
		core.DnsdirMarkers, core.DnsdirConfPath = om, oc
		core.DnsdirMu.Unlock()
	}
}

func setDnsdirConf(conf string) func() {
	core.DnsdirMu.Lock()
	oc := core.DnsdirConfPath
	core.DnsdirConfPath = conf
	core.DnsdirMu.Unlock()
	return func() {
		core.DnsdirMu.Lock()
		core.DnsdirConfPath = oc
		core.DnsdirMu.Unlock()
	}
}
