package main

import (
	"strings"
	"testing"

	"netdir/device"
	"netdir/internal/core"
)

// Through the real tool path: the level of the address and the default decide what a caller is told.
func TestMCPPrivacyLevels(t *testing.T) {
	setDev := func(e *webEnv, addr string) {
		sup := e.ws.Status.Sup()
		sup.Mu.Lock()
		sup.Dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
		sup.Dc.Settings.Devices = []device.Device{{Name: "edge", Platform: "iosxe", Address: addr, Credential: "lab", Insecure: true}}
		attachDevices(sup.Dc)
		sup.Mu.Unlock()
	}
	list := func(post func(string, ...string) (int, map[string]any)) string {
		_, m := post(mcpCall("list_devices", `{}`))
		txt, _ := toolResult(t, m)
		return txt
	}
	// the default level (standard): a private address is shown, a public one is not
	e, post := mcpEnv(t, "127.0.0.1")
	setDev(e, "10.9.8.7")
	if txt := list(post); !strings.Contains(txt, "10.9.8.7") {
		t.Errorf("standard hid a private address: %s", txt)
	}
	// strict on the source
	e, post = mcpEnv(t, "127.0.0.1 strict")
	setDev(e, "10.9.8.7")
	if txt := list(post); strings.Contains(txt, "10.9.8.7") || !strings.Contains(txt, "x.x.x.x") {
		t.Errorf("strict source: %s", txt)
	}
	// strict as the default, none on the source: the source's own level wins
	e, post = mcpEnv(t, "127.0.0.1 none")
	e.ws.Status.Sup().Mu.Lock()
	e.ws.Status.Sup().Dc.Settings.Privacy = &core.PrivacyConfig{Default: "strict"}
	e.ws.Status.Sup().Mu.Unlock()
	setDev(e, "8.8.8.8")
	if txt := list(post); !strings.Contains(txt, "8.8.8.8") {
		t.Errorf("none on the source was not honoured: %s", txt)
	}
	// a source with no level of its own gets the default
	e, post = mcpEnv(t, "127.0.0.1")
	e.ws.Status.Sup().Mu.Lock()
	e.ws.Status.Sup().Dc.Settings.Privacy = &core.PrivacyConfig{Default: "strict"}
	e.ws.Status.Sup().Mu.Unlock()
	setDev(e, "10.9.8.7")
	if txt := list(post); strings.Contains(txt, "10.9.8.7") {
		t.Errorf("the default level did not apply: %s", txt)
	}
}
