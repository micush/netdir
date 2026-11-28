package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// A gateway made on the Topology page carries its two names through the save, and they are there when the configuration is read back.
func TestNewGatewayKeepsItsNames(t *testing.T) {
	e := newWebEnv(t)
	e.login("alice", "pw")
	b, _ := json.Marshal(core.DefaultGroup())
	var g map[string]any
	_ = json.Unmarshal(b, &g)
	g["group_id"] = 137
	g["fqdn"], g["anycast_fqdn"] = "files.example.test", "any.example.test"
	cfg := map[string]any{"groups": []any{g}}
	if r := e.do("PUT", "/api/config", map[string]any{"config": cfg, "base": "force"}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("save: %d %v", r.code, r.body)
	}
	cur, _, err := e.mg.LiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, x := range cur.Groups {
		if x.GroupID == 137 {
			found = true
			if x.FQDN != "files.example.test" || x.AnycastFQDN != "any.example.test" {
				t.Fatalf("names after the save: %q %q", x.FQDN, x.AnycastFQDN)
			}
		}
	}
	if !found {
		t.Fatal("the gateway is not there")
	}
	r := e.do("GET", "/api/config", nil, withAuth(e, false))
	raw, _ := json.Marshal(r.body)
	var back struct {
		Config struct{ Groups []core.GroupConfig }
	}
	json.Unmarshal(raw, &back)
	for _, x := range back.Config.Groups {
		if x.GroupID == 137 && (x.FQDN == "" || x.AnycastFQDN == "") {
			t.Fatalf("names read back: %q %q (%s)", x.FQDN, x.AnycastFQDN, raw)
		}
	}
}

// The path a gateway made on a replica takes to the primary: shared document, over JSON, merged into a configuration without it.
func TestNewGatewayNamesReachThePrimary(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups = nil
	g := core.NewGatewayGroup()
	g.GroupID, g.FQDN, g.AnycastFQDN = 137, "files.example.test", "any.example.test"
	dc.Groups = append(dc.Groups, g)
	raw, err := json.Marshal(adminSharedConfig{Shared: core.SharedOf(dc), Seeds: cluster.SeedsOf(dc)})
	if err != nil {
		t.Fatal(err)
	}
	var p adminSharedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	cur := core.NewDaemonConfig()
	cur.Groups = nil
	if _, err := cluster.MergeShared(cur, p.Shared, p.Seeds); err != nil {
		t.Fatal(err)
	}
	for _, x := range cur.Groups {
		if x.GroupID == 137 && (x.FQDN != "files.example.test" || x.AnycastFQDN != "any.example.test") {
			t.Fatalf("lost on the way: %q %q (%s)", x.FQDN, x.AnycastFQDN, raw)
		}
	}
}

// A node that does not know the names would drop them when settings are shared: setting them is refused, naming the node.
func TestGatewayNamesRefusedWhileAnOldNodeIsInTheCluster(t *testing.T) {
	cur := core.NewDaemonConfig()
	next := core.NewDaemonConfig()
	next.Groups[0].FQDN = "files.example.test"
	old, newer := strconv.Itoa(gatewayNamesFromVersion-1), strconv.Itoa(gatewayNamesFromVersion)
	peers := []core.PeerView{{Self: true, Version: strconv.Itoa(gatewayNamesFromVersion + 2)}, {Addr: "10.0.0.2:4451", Hostname: "netdir1", Version: old}}
	if err := gatewayNamesNeedNewNodes(cur, next, peers); err == nil || !strings.Contains(err.Error(), "netdir1") {
		t.Fatalf("an old node did not stop it: %v", err)
	}
	peers[1].Version = newer
	if err := gatewayNamesNeedNewNodes(cur, next, peers); err != nil {
		t.Fatalf("new nodes: %v", err)
	}
	// names that are already there do not block other saves
	cur.Groups[0].FQDN = "files.example.test"
	peers[1].Version = old
	if err := gatewayNamesNeedNewNodes(cur, next, peers); err != nil {
		t.Fatalf("an unchanged name blocked a save: %v", err)
	}
	if err := gatewayNamesNeedNewNodes(nil, core.NewDaemonConfig(), peers); err != nil {
		t.Fatalf("no names: %v", err)
	}
}
