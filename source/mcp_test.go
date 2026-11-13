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
	if !strings.Contains(names, "api_get") || strings.Contains(names, "set_node_paused") || strings.Contains(names, "schedule_set") || strings.Contains(names, "api_request") || strings.Contains(names, "edit_config") {
		t.Fatalf("read-only tools: %s", names)
	}
	if txt, isErr := toolResult(t, func() map[string]any { _, m := post(mcpCall("list_nodes", `{}`)); return m }()); isErr || !strings.Contains(txt, `"this_node":true`) {
		t.Fatalf("list_nodes: %s", txt)
	}
	if txt, isErr := toolResult(t, func() map[string]any { _, m := post(mcpCall("get_alerts", `{"node":"all"}`)); return m }()); isErr || !strings.Contains(txt, `"alerts"`) {
		t.Fatalf("get_alerts: %s", txt)
	}
	// a write is refused, whatever the client sends
	_, m = post(mcpCall("set_node_paused", `{"node":"this","paused":true}`))
	if m["error"] == nil {
		t.Fatalf("a tool that changes netdir is gone, yet it answered: %v", m)
	}
	if txt, isErr := toolResult(t, func() map[string]any { _, m := post(mcpCall("api_get", `{"path":"/api/config"}`)); return m }()); isErr && strings.Contains(txt, "cannot be changed") {
		t.Fatalf("a read was refused: %s", txt)
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
