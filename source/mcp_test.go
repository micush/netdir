package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"netdir/device"
)

func TestMCPACLNormalised(t *testing.T) {
	got, err := normMCPACL([]string{" 10.1.1.50  RW", "10.1.0.0/24", "10.1.1.50", "Mon.Example.com.", "2001:db8::5 ro", "192.0.2.9 read-write"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "10.1.1.50 rw|10.1.0.0/24|mon.example.com|2001:db8::5|192.0.2.9 rw" {
		t.Fatalf("%q", got)
	}
	for _, bad := range []string{"10.1.0.0/24 rw", "mon.example.com rw", "10.1.1.50 admin", "10.1.1.50 rw extra", "not an address"} {
		if _, err := normMCPACL([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// mcpEnv is a web server whose MCP access list is acl; post sends one JSON-RPC message and returns the HTTP status and body.
func mcpEnv(t *testing.T, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any)) {
	t.Helper()
	e := newWebEnv(t)
	e.mg.webH = e.ws.Handler()
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.MCPACL = acl
	sup.mu.Unlock()
	return e, func(msg string, hdr ...string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(msg))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return res.StatusCode, m
	}
}

func mcpCall(name, args string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

// toolResult is the text of a tools/call answer and whether it is an error.
func toolResult(t *testing.T, m map[string]any) (string, bool) {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	c := r["content"].([]any)[0].(map[string]any)
	return c["text"].(string), r["isError"] == true
}

func toolNames(t *testing.T, m map[string]any) []string {
	var out []string
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return out
}

func TestMCPNobodyUntilListed(t *testing.T) {
	_, post := mcpEnv(t)
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 403 {
		t.Fatalf("empty list: %d", code)
	}
	_, post = mcpEnv(t, "192.0.2.1 rw", "10.0.0.0/8")
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 403 {
		t.Fatalf("not listed: %d", code)
	}
}

func TestMCPReadOnly(t *testing.T) {
	_, post := mcpEnv(t, "127.0.0.0/8")
	code, m := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	if code != 200 || m["result"].(map[string]any)["protocolVersion"] != "2025-03-26" {
		t.Fatalf("%d %v", code, m)
	}
	if code, _ := post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 202 {
		t.Fatalf("notification: %d", code)
	}
	_, m = post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	names := strings.Join(toolNames(t, m), " ")
	if !strings.Contains(names, "list_devices") || strings.Contains(names, "set_node_paused") || strings.Contains(names, "schedule_set") || strings.Contains(names, "api_request") || strings.Contains(names, "edit_config") {
		t.Fatalf("read-only tools: %s", names)
	}
	if txt, isErr := toolResult(t, func() map[string]any { _, m := post(mcpCall("list_nodes", `{}`)); return m }()); isErr || !strings.Contains(txt, `"this_node":true`) {
		t.Fatalf("list_nodes: %s", txt)
	}
	requireGateTools(t, post)
	// a write is refused, whatever the client sends
	_, m = post(mcpCall("set_node_paused", `{"node":"this","paused":true}`))
	if m["error"] == nil {
		t.Fatalf("a tool that changes netdir is gone, yet it answered: %v", m)
	}
	_, m = post(mcpCall("no_such_tool", `{}`))
	if m["error"] == nil {
		t.Fatalf("unknown tool: %v", m)
	}
}

func TestMCPRefusesBrowsersAndGET(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "Origin", "https://evil.example"); code != 403 {
		t.Fatalf("foreign origin: %d", code)
	}
	res, err := http.Get(e.ts.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 405 {
		t.Fatalf("GET: %d", res.StatusCode)
	}
	// a batch
	res, err = http.Post(e.ts.URL+"/mcp", "application/json", bytes.NewBufferString(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(string(b), "[") || strings.Count(string(b), `"id"`) != 1 {
		t.Fatalf("batch: %d %s", res.StatusCode, b)
	}
}

func TestMCPResultLimitSetting(t *testing.T) {
	e, _ := mcpEnv(t, "127.0.0.1")
	sup := e.ws.status.sup
	if sup.mcpResultLimit() != 1<<20 {
		t.Fatalf("default %d", sup.mcpResultLimit())
	}
	sup.mu.Lock()
	sup.dc.Settings.MCPMaxResultMB = 4
	sup.mu.Unlock()
	if sup.mcpResultLimit() != 4<<20 {
		t.Fatalf("4 MB: %d", sup.mcpResultLimit())
	}
	for _, n := range []int{-1, 9} {
		dc := newDaemonConfig()
		dc.Settings.MCPMaxResultMB = n
		if err := dc.Validate(); err == nil {
			t.Errorf("accepted %d MB", n)
		}
	}
	dc := newDaemonConfig()
	dc.Settings.MCPMaxResultMB = 1
	if err := dc.Validate(); err != nil || dc.Settings.MCPMaxResultMB != 0 {
		t.Errorf("1 MB is the default and is not written: %v %d", err, dc.Settings.MCPMaxResultMB)
	}
}

func TestDeviceCheckSettings(t *testing.T) {
	e, _ := mcpEnv(t, "127.0.0.1")
	sup := e.ws.status.sup
	if tu := sup.deviceTuning(); tu != (device.Tuning{}) {
		t.Fatalf("default tuning %+v", tu)
	}
	sup.mu.Lock()
	st := &sup.dc.Settings
	st.DeviceCheckSec, st.DeviceFactsMin, st.DeviceLiveCheckSec, st.DeviceLiveFactsMin = 600, 120, 20, 2
	sup.mu.Unlock()
	if tu := sup.deviceTuning(); tu != (device.Tuning{Reach: 10 * time.Minute, Facts: 2 * time.Hour, LiveReach: 20 * time.Second, LiveFacts: 2 * time.Minute}) {
		t.Errorf("tuning %+v", tu)
	}
	for _, c := range []struct{ sec, min, lsec, lmin int }{{29, 0, 0, 0}, {3601, 0, 0, 0}, {-1, 0, 0, 0}, {0, 4, 0, 0}, {0, 1441, 0, 0}, {0, -5, 0, 0},
		{0, 0, 9, 0}, {0, 0, 601, 0}, {0, 0, 0, 61}, {0, 0, 0, -1}} {
		dc := newDaemonConfig()
		dc.Settings.DeviceCheckSec, dc.Settings.DeviceFactsMin, dc.Settings.DeviceLiveCheckSec, dc.Settings.DeviceLiveFactsMin = c.sec, c.min, c.lsec, c.lmin
		if err := dc.Validate(); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	dc := newDaemonConfig()
	dc.Settings.DeviceCheckSec, dc.Settings.DeviceFactsMin, dc.Settings.DeviceLiveCheckSec, dc.Settings.DeviceLiveFactsMin = 30, 1440, 10, 60
	if err := dc.Validate(); err != nil {
		t.Errorf("the limits themselves: %v", err)
	}
}

// mcpClusterGone are the tools an MCP caller no longer has: anything about netdir's own cluster, configuration, alerts, schedules,
// updates or host, and the raw route of the GUI's API.  What is left is the devices, the device list and status, the cluster
// status (list_nodes, get_topology) and the network tools.
var mcpClusterGone = []string{"get_gateways", "get_alerts", "get_lldp", "get_host_stats", "get_schedule", "get_updates", "get_node_status", "get_config", "list_api", "api_get", "get_log"}

// requireGateTools checks that the tool list has the device and status tools and none of mcpClusterGone, that each of those
// answers "unknown tool", and that a node cannot be picked.
func requireGateTools(t *testing.T, post func(string, ...string) (int, map[string]any), hdr ...string) {
	t.Helper()
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, hdr...)
	have := toolNames(t, m)
	for _, want := range []string{"list_nodes", "get_topology", "list_devices", "device_facts", "device_show"} {
		if !containsStr(have, want) {
			t.Errorf("%s is not offered: %v", want, have)
		}
	}
	for _, gone := range mcpClusterGone {
		if containsStr(have, gone) {
			t.Errorf("%s is offered", gone)
		}
		if _, m := post(mcpCall(gone, `{}`), hdr...); m["error"] == nil {
			t.Errorf("%s answered: %v", gone, m)
		}
	}
	for _, name := range have {
		if strings.HasPrefix(name, "device_") || strings.HasPrefix(name, "net_") || name == "list_nodes" || name == "get_topology" || name == "list_devices" {
			continue
		}
		t.Errorf("unexpected tool %s", name)
	}
	for _, name := range []string{"list_nodes", "get_topology", "device_facts"} {
		_, m := post(mcpCall(name, `{"node":"other","target":"all"}`), hdr...)
		if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "no node argument") {
			t.Errorf("%s with a node: %v %s", name, isErr, txt)
		}
	}
}
