package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClusterOptionsAreAlwaysOn(t *testing.T) {
	var c ClusterConfig
	if err := json.Unmarshal([]byte(`{"enabled": false, "share_cert": false, "listen": ":1234"}`), &c); err != nil {
		t.Fatalf("an older file with the keys must load: %v", err)
	}
	if !c.Enabled || !c.ShareCert || c.Listen != ":1234" {
		t.Fatalf("not forced on: %+v", c)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "enabled") || strings.Contains(string(b), "share_cert") {
		t.Fatalf("options written back: %s", b)
	}
	if err := json.Unmarshal([]byte(`{"bogus": 1}`), &c); err == nil {
		t.Fatal("unknown keys must still be refused")
	}
}

// A configuration that still has the NTP Director's ntp block is refused, so its settings are never dropped in silence.
func TestNTPBlockRefused(t *testing.T) {
	var dc DaemonConfig
	err := dc.UnmarshalJSON([]byte(`{"groups":[],"ntp":{"mcp_acl":["10.0.0.1"]}}`))
	if err == nil || !strings.Contains(err.Error(), `"settings"`) {
		t.Fatalf("an ntp block was accepted: %v", err)
	}
	if err := dc.UnmarshalJSON([]byte(`{"groups":[],"settings":{"mcp_acl":["10.0.0.1"]}}`)); err != nil || len(dc.Settings.MCPACL) != 1 {
		t.Fatalf("the settings block was not read: %v %+v", err, dc.Settings)
	}
}
