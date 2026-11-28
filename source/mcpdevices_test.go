package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

func TestSourceDevicesAndScope(t *testing.T) {
	e := newWebEnv(t)
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPACL = []string{"10.1.0.50 rw devices=sw1", "10.1.0.0/24 devices=sw2,tag:site=lab", "10.2.0.0/24", "10.3.0.0/24 devices=none"}
	sup.Mu.Unlock()
	for from, want := range map[string]string{
		"10.1.0.50": "sw1,sw2,tag:site=lab", // two entries match: added up
		"10.1.0.7":  "sw2,tag:site=lab",
		"10.2.0.9":  "", // no limit
		"10.3.0.4":  "none",
		"192.0.2.1": "", // no entry: the address limits nothing
	} {
		if got := strings.Join(sup.McpSourceDevices(netip.MustParseAddr(from)), ","); got != want {
			t.Errorf("%s: %q, want %q", from, got, want)
		}
	}
	sc := devices.NewDevScope([]string{"sw1", "tag:site=lab"}, []string{"sw1", "sw3"})
	for name, want := range map[string]bool{"sw1": true, "SW1": true, "sw3": false, "sw2": false} {
		if sc.Allows(name, nil) != want {
			t.Errorf("%s: %v, want %v", name, !want, want)
		}
	}
	if !devices.NewDevScope([]string{"tag:site=lab"}).Allows("x", []string{"site=lab"}) || devices.NewDevScope([]string{"tag:site=lab"}).Allows("x", []string{"site=dc1"}) {
		t.Error("tags")
	}
	if devices.NewDevScope(nil, nil) != nil || devices.NewDevScope([]string{"none"}).Allows("sw1", nil) {
		t.Error("all and none")
	}
	// both lists must allow: a narrow key is not widened by its address
	if devices.NewDevScope([]string{"sw1"}, []string{"sw2"}).Allows("sw1", nil) {
		t.Error("the stricter list did not win")
	}
}

// the end to end: what a key limited to some devices sees and may do
func TestMCPKeyLimitedToDevices(t *testing.T) {
	sw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/restconf/data/Cisco-IOS-XE-native:native/hostname" {
			_, _ = w.Write([]byte(`{"Cisco-IOS-XE-native:hostname":"cat9300"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(sw.Close)
	host, port, _ := net.SplitHostPort(sw.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	e, post := mcpEnv(t, "127.0.0.1")
	k1, k2, k3, k4 := testMCPKey(), testMCPKey(), testMCPKey(), testMCPKey()
	keys, err := core.NormMCPKeys([]core.MCPKey{
		{Name: "one", Access: "rw", Key: k1, Devices: []string{"sw1"}},
		{Name: "lab", Access: "ro", Key: k2, Devices: []string{"tag:site=lab"}},
		{Name: "nothing", Access: "ro", Key: k3, Devices: []string{"none"}},
		{Name: "everything", Access: "rw", Key: k4},
	})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPKeys = keys
	sup.Dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "admin", Password: "pw"}}
	mk := func(n string, tag string) device.Device {
		return device.Device{Name: n, Platform: "iosxe", Address: host, Port: p, Credential: "lab", Insecure: true, Tags: []string{tag}}
	}
	sup.Dc.Settings.Devices = []device.Device{mk("sw1", "site=home"), mk("sw2", "site=lab"), mk("sw3", "site=lab")}
	attachDevices(sup.Dc)
	sup.Mu.Unlock()
	auth := func(k string) []string { return []string{"Authorization", "Bearer " + k} }
	call := func(k, tool, args string) (string, bool) {
		_, m := post(mcpCall(tool, args), auth(k)...)
		return toolResult(t, m)
	}
	names := func(txt string) string {
		var out []string
		for _, n := range []string{"sw1", "sw2", "sw3"} {
			if strings.Contains(txt, `"`+n+`"`) {
				out = append(out, n)
			}
		}
		return strings.Join(out, ",")
	}
	// list_devices shows only what the key may use
	for k, want := range map[string]string{k1: "sw1", k2: "sw2,sw3", k3: "", k4: "sw1,sw2,sw3"} {
		txt, isErr := call(k, "list_devices", `{}`)
		if isErr || names(txt) != want {
			t.Errorf("list_devices: %q (%v), want %q: %s", names(txt), isErr, want, txt)
		}
	}
	// a target picks the devices the key may use; a name it may not use is as if it did not exist
	if txt, isErr := call(k2, "device_facts", `{"target":"all"}`); isErr || names(txt) != "sw2,sw3" {
		t.Errorf("all: %q %v", names(txt), isErr)
	}
	if txt, isErr := call(k2, "device_facts", `{"target":"tag:site=lab"}`); isErr || names(txt) != "sw2,sw3" {
		t.Errorf("tag: %q %v", names(txt), isErr)
	}
	for k, target := range map[string]string{k1: "sw2", k2: "sw1", k3: "all"} {
		if txt, isErr := call(k, "device_facts", `{"target":"`+target+`"}`); !isErr || strings.Contains(txt, "cat9300") {
			t.Errorf("target %s was answered: %s", target, txt)
		}
	}
	if txt, isErr := call(k1, "device_facts", `{"target":"sw1"}`); isErr || !strings.Contains(txt, "cat9300") {
		t.Errorf("sw1 for its own key: %v %s", isErr, txt)
	}
	// a change that picks even one device it may not use is refused whole
	for _, target := range []string{"all", "tag:site=lab", "sw1,sw2", "sw2"} {
		if txt, isErr := call(k1, "device_change", `{"target":"`+target+`","text":"shut down gi1/0/5","dry_run":true}`); !isErr || !strings.Contains(txt, "may not use") && !strings.Contains(txt, "matches no device") {
			t.Errorf("change of %s: %v %s", target, isErr, txt)
		}
	}
	// the tools and routes that hold every device and every key are not for it
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, auth(k1)...)
	have := strings.Join(toolNames(t, m), ",")
	for _, gone := range []string{"device_troubleshoot_user"} {
		if strings.Contains(have, gone) {
			t.Errorf("%s is offered to a limited key", gone)
		}
	}
	if _, m := post(mcpCall("device_troubleshoot_user", `{}`), auth(k1)...); m["error"] == nil {
		t.Errorf("device_troubleshoot_user was called: %v", m)
	}
	requireGateTools(t, post, auth(k1)...)
	// the key with no limit has all of it
	_, m = post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, auth(k4)...)
	if have = strings.Join(toolNames(t, m), ","); !strings.Contains(have, "device_troubleshoot_user") {
		t.Errorf("an unlimited key lost tools: %s", have)
	}
	// a source with its own limit narrows a key that has none: the stricter wins
	sup.Mu.Lock()
	sup.Dc.Settings.MCPACL = []string{"127.0.0.1 devices=sw3"}
	sup.Mu.Unlock()
	if txt, isErr := call(k4, "list_devices", `{}`); isErr || names(txt) != "sw3" {
		t.Errorf("source limit: %q %v", names(txt), isErr)
	}
	if txt, isErr := call(k2, "list_devices", `{}`); isErr || names(txt) != "sw3" {
		t.Errorf("key and source: %q %v", names(txt), isErr)
	}
}

func TestMCPGatewaysFollowTheScope(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1")
	k1, k2 := testMCPKey(), testMCPKey()
	keys, err := core.NormMCPKeys([]core.MCPKey{{Name: "gw", Access: "ro", Key: k1, Devices: []string{"gateway:7"}}, {Name: "dev", Access: "ro", Key: k2, Devices: []string{"sw1"}}})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPKeys = keys
	sup.Dc.Groups = []core.GroupConfig{{GroupID: 7, Name: "seven", Interface: "lo", VIP4: "127.0.0.7/8", Devices: []string{"sw1"}}, {GroupID: 8, Name: "eight", Interface: "lo", VIP4: "127.0.0.8/8"}}
	sup.Mu.Unlock()
	for _, tc := range []struct {
		key  string
		tool string
		want bool // gateway 7 is shown
		not8 bool
	}{{k1, "get_topology", true, true}, {k2, "get_topology", false, true}} {
		_, m := post(mcpCall(tc.tool, `{}`), "Authorization", "Bearer "+tc.key)
		txt, isErr := toolResult(t, m)
		if isErr {
			t.Fatalf("%s: %s", tc.tool, txt)
		}
		if strings.Contains(txt, `"group_id":8`) {
			t.Errorf("%s shows gateway 8: %s", tc.tool, txt)
		}
		if got := strings.Contains(txt, `"group_id":7`); got != tc.want {
			t.Errorf("%s with %s: gateway 7 shown=%v: %s", tc.tool, tc.key[:4], got, txt)
		}
	}
}
