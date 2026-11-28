package main

import (
	"strings"
	"testing"

	"netdir/device"
)

// Through the real tool path: a device on a public address is listed by a token, and an error text is scrubbed too.
func TestMCPMasksPublicAddresses(t *testing.T) {
	post := devEnv(t, "127.0.0.1 rw")
	_, m := post(mcpCall("list_devices", `{}`))
	base, _ := toolResult(t, m)
	if strings.Contains(base, "PUBLIC-IP") {
		t.Fatalf("a loopback device was masked: %s", base)
	}
	e, post2 := mcpEnv(t, "127.0.0.1 rw")
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
	sup.Dc.Settings.Devices = []device.Device{{Name: "edge", Platform: "iosxe", Address: "8.8.8.8", Credential: "lab", Insecure: true}}
	attachDevices(sup.Dc)
	sup.Mu.Unlock()
	_, m = post2(mcpCall("list_devices", `{}`))
	txt, _ := toolResult(t, m)
	if strings.Contains(txt, "8.8.8.8") || !strings.Contains(txt, "x.x.x.x") {
		t.Errorf("list_devices: %s", txt)
	}
	if _, m = post2(mcpCall("get_config", `{}`)); m["error"] == nil {
		t.Errorf("get_config answered: %v", m)
	}
}
