package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeviceImportRefusals(t *testing.T) {
	e := newWebEnv(t)
	guiEditConfig(t, e, `{"settings":{"device_credentials":[{"name":"c","token":"tok"}],"devices":[
		{"name":"sw1","platform":"iosxe","address":"10.0.0.1","credential":"c"},
		{"name":"obs-off","platform":"observium","address":"obs.example.com","credential":"c","disabled":true}]}}`)
	for _, tc := range []struct{ dev, want string }{{"nope", "not in the inventory"}, {"sw1", "only an Observium device"}, {"obs-off", "is disabled"}} {
		b, _ := json.Marshal(map[string]any{"device": tc.dev})
		if _, err := e.mg.Op("device.import_observium", b, "alice"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.dev, err)
		}
	}
	// MCP cannot reach it: it is a POST to a route that is not a device change
	if err := mcpWriteGuard("POST", "/api/devices/import"); err == nil {
		t.Error("the import is open to MCP")
	}
}
