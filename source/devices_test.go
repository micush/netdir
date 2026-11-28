package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"netdir/device"
	"netdir/internal/core"
)

// devEnv is mcpEnv with one stub IOS-XE switch (RESTCONF on loopback) in the inventory.
func devEnv(t *testing.T, acl ...string) func(msg string, hdr ...string) (int, map[string]any) {
	t.Helper()
	sw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "admin" || p != "sw-secret-pw" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/restconf/data/Cisco-IOS-XE-native:native/hostname":
			_, _ = w.Write([]byte(`{"Cisco-IOS-XE-native:hostname":"cat9300"}`))
		case "/restconf/data/Cisco-IOS-XE-native:native":
			_, _ = w.Write([]byte(`{"Cisco-IOS-XE-native:native":{"enable":{"secret":{"secret":"$9$xyz"}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(sw.Close)
	host, port, _ := net.SplitHostPort(sw.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	e, post := mcpEnv(t, acl...)
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "admin", Password: "sw-secret-pw"}}
	sup.Dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: host, Port: p, Credential: "lab", Insecure: true, Tags: []string{"site=home"}}}
	attachDevices(sup.Dc)
	sup.Mu.Unlock()
	return post
}

func TestMCPDeviceTools(t *testing.T) {
	post := devEnv(t, "127.0.0.1")
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	names := strings.Join(toolNames(t, m), ",")
	for _, want := range []string{"list_devices", "device_facts", "device_interfaces", "device_neighbors", "device_ports", "device_neighbor_details", "device_routes", "device_routing", "device_firewall", "device_resources", "device_vlans", "device_api_catalog", "device_api_get", "device_show"} {
		if !strings.Contains(names, want) {
			t.Errorf("tool %s is missing", want)
		}
	}
	_, m = post(mcpCall("list_devices", `{}`))
	txt, isErr := toolResult(t, m)
	if isErr || !strings.Contains(txt, `"sw1"`) || !strings.Contains(txt, "iosxe") || strings.Contains(txt, "sw-secret-pw") {
		t.Errorf("list_devices: %s", txt)
	}
	_, m = post(mcpCall("device_facts", `{"target":"tag:site=home"}`))
	if txt, isErr = toolResult(t, m); isErr || !strings.Contains(txt, "cat9300") || !strings.Contains(txt, `"ok": true`) && !strings.Contains(txt, `"ok":true`) {
		t.Errorf("device_facts: %s", txt)
	}
	// an MCP caller gets a device's configuration with its secrets hidden, by the tool or by the API route
	if !strings.Contains(names, "device_config") {
		t.Error("device_config is not an MCP tool")
	}
	for _, c := range []string{mcpCall("device_config", `{"target":"sw1"}`)} {
		_, m = post(c)
		if txt, isErr = toolResult(t, m); isErr || strings.Contains(txt, "$9$xyz") || !strings.Contains(txt, "(hidden)") || !strings.Contains(txt, "enable") {
			t.Errorf("config, read-only: %s", txt)
		}
	}
	// a write command is refused before any device is asked
	_, m = post(mcpCall("device_show", `{"target":"sw1","command":"reload"}`))
	if _, isErr = toolResult(t, m); !isErr {
		t.Error("device_show reload was not refused")
	}
	// a target that matches nothing is an error, not an empty answer
	_, m = post(mcpCall("device_facts", `{"target":"nosuch"}`))
	if _, isErr = toolResult(t, m); !isErr {
		t.Error("an unknown target was not refused")
	}
	// there is no tool that reads netdir's own configuration, so the credentials cannot reach the caller that way
	_, m = post(mcpCall("get_config", `{}`))
	if m["error"] == nil {
		t.Error("get_config answered")
	}
}

// Not even a read-write MCP caller is handed a device's secrets: the configuration comes filtered, a text answer or a secret-bearing path is refused.
func TestMCPNeverGetsDeviceSecrets(t *testing.T) {
	post := devEnv(t, "127.0.0.1 rw")
	_, m0 := post(mcpCall("device_config", `{"target":"sw1"}`))
	if txt, isErr := toolResult(t, m0); isErr || strings.Contains(txt, "$9$xyz") {
		t.Errorf("device_config, read-write: %s", txt)
	}
	for _, path := range []string{
		"/restconf/data/Cisco-IOS-XE-native:native",
		"/restconf/data/Cisco-IOS-XE-native:native/snmp-server",
		"/restconf/data/Cisco-IOS-XE-native:native/username"} {
		_, m := post(mcpCall("device_api_get", `{"target":"sw1","path":"`+path+`"}`))
		if txt, _ := toolResult(t, m); strings.Contains(txt, "$9$xyz") || strings.Contains(txt, "sw-secret-pw") {
			t.Errorf("%s gave a secret: %s", path, txt)
		}
	}
	// a device query cannot be sent through another node
	_, m := post(mcpCall("device_config", `{"target":"sw1","node":"somenode"}`))
	if _, isErr := toolResult(t, m); !isErr {
		t.Error("a device query went through another node")
	}
}

// The canvas edits for a gateway's devices, and gateway:N as a target.
func TestGatewayDeviceEditsAndTarget(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups[0].GroupID = 100
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: "10.0.0.2", Credential: "lab"}, {Name: "sw2", Platform: "iosxe", Address: "10.0.0.3", Credential: "lab"}}
	for _, e := range []canvasEdit{{Action: "add", Kind: "device", Group: 100, Device: "sw1"}, {Action: "add", Kind: "device", Group: 100, Device: "sw2"},
		{Action: "move", Kind: "device", Group: 100, Device: "sw2", Pos: 1}} {
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	if strings.Join(dc.Groups[0].Devices, ",") != "sw2,sw1" {
		t.Fatalf("devices: %v", dc.Groups[0].Devices)
	}
	for _, e := range []canvasEdit{{Action: "add", Kind: "device", Group: 100, Device: "sw1"}, {Action: "add", Kind: "device", Group: 100, Device: "nosuch"},
		{Action: "del", Kind: "device", Group: 100, Device: "sw9"}, {Action: "add", Kind: "device", Group: 7, Device: "sw1"}} {
		if _, err := applyCanvasEdit(dc, e); err == nil {
			t.Errorf("%+v was accepted", e)
		}
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	s := &core.Supervisor{Dc: dc}
	if got, err := s.ExpandGatewayTargets("gateway:100, fw9"); err != nil || got != "sw2,sw1,fw9" {
		t.Fatalf("expand: %q %v", got, err)
	}
	for _, bad := range []string{"gateway:7", "gateway:x"} {
		if _, err := s.ExpandGatewayTargets(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "del", Kind: "device", Group: 100, Device: "sw2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "del", Kind: "device", Group: 100, Device: "sw1"}); err != nil || dc.Groups[0].Devices != nil {
		t.Fatalf("the last device off: %v %v", err, dc.Groups[0].Devices)
	}
	if _, err := s.ExpandGatewayTargets("gateway:100"); err == nil {
		t.Error("a gateway with no devices was taken as a target")
	}
}

// The canvas draws a gateway's devices in its order, each with this node's health of it (grey before the first check).
func TestCanvasDrawsGatewayDevices(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: "10.0.0.2", Credential: "lab"}, {Name: "old", Platform: "iosxe", Address: "10.0.0.9", Credential: "lab", Disabled: true}}
	attachDevices(dc)
	dc.Groups[0].Devices = []string{"old", "sw1"}
	cv := buildCanvas(dc, nil)[0]
	if len(cv.Devices) != 2 || cv.Devices[0].Name != "old" || cv.Devices[0].Status != "paused" || cv.Devices[1].Status != "idle" {
		t.Fatalf("devices: %+v", cv.Devices)
	}
	if b, _ := json.Marshal(buildCanvas(core.NewDaemonConfig(), nil)); !strings.Contains(string(b), `"devices":[]`) {
		t.Fatalf("a gateway with no devices must say [] (the page maps over it): %s", b)
	}
}

// Privacy none means none for what a device says: the configuration comes as the device has it.  netdir's own logins stay hidden.
func TestMCPPrivacyNoneGivesDeviceAnswersAsTheyAre(t *testing.T) {
	post := devEnv(t, "127.0.0.1 rw none")
	_, m := post(mcpCall("device_config", `{"target":"sw1"}`))
	if txt, isErr := toolResult(t, m); isErr || !strings.Contains(txt, "$9$xyz") {
		t.Errorf("device_config at none: %s", txt)
	}
	_, m = post(mcpCall("get_config", `{}`))
	if m["error"] == nil {
		t.Error("get_config answered at none")
	}
	_, m = post(mcpCall("list_devices", `{}`))
	if txt, _ := toolResult(t, m); strings.Contains(txt, "sw-secret-pw") {
		t.Error("list_devices showed a device login at none")
	}
	// the same key at standard still gets it filtered
	post2 := devEnv(t, "127.0.0.1 rw standard")
	_, m = post2(mcpCall("device_config", `{"target":"sw1"}`))
	if txt, _ := toolResult(t, m); strings.Contains(txt, "$9$xyz") {
		t.Errorf("device_config at standard: %s", txt)
	}
}
