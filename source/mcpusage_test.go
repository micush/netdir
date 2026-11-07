package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMCPUsage(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 12, 30, 0, 0, time.UTC)
	u := newMCPUsage(dir)
	u.now = func() time.Time { return now }
	rec := func(ago time.Duration, caller, addr, tool, target, res string, write bool) {
		u.Record(mcpUseCall{Time: now.Add(-ago), Caller: caller, Addr: addr, Tool: tool, Target: target, Ms: 20, Bytes: 100, Result: res, Write: write})
	}
	rec(time.Minute, "claude", "10.0.0.5", "device_facts", "sw1,sw2", "ok", false)
	rec(2*time.Minute, "claude", "10.0.0.5", "device_facts", "sw1", "error", false)
	rec(3*time.Minute, "(address list)", "10.0.0.9", "list_devices", "", "ok", false)
	rec(4*time.Minute, "bot", "10.0.0.7", "device_change_raw", "sw1", "ok", true)
	rec(5*time.Minute, "bot", "10.0.0.7", "device_change_raw", "sw1", "refused", true)
	rec(30*time.Hour, "claude", "10.0.0.5", "device_facts", "sw3", "ok", false)
	rec(9*24*time.Hour, "old", "10.0.0.1", "get_log", "", "ok", false) // older than the 8 days kept

	r := u.Report(24 * time.Hour)
	tot := r["totals"].(mcpUseSum)
	if tot.Calls != 5 || tot.Errors != 1 || tot.Writes != 1 || tot.Refused != 1 || tot.Bytes != 500 || tot.AvgMs != 20 {
		t.Errorf("totals %+v", tot)
	}
	keys := r["by_key"].([]mcpUseSum)
	if len(keys) != 3 || keys[0].Name != "claude" && keys[0].Name != "bot" || keys[0].Calls != 2 {
		t.Errorf("by key %+v", keys)
	}
	tg := map[string]int64{}
	for _, s := range r["by_target"].([]mcpUseSum) {
		tg[s.Name] = s.Calls
	}
	if tg["sw1"] != 4 || tg["sw2"] != 1 || tg["(none)"] != 1 || tg["sw3"] != 0 {
		t.Errorf("by target %v (a target list counts for each device)", tg)
	}
	if r2 := u.Report(7 * 24 * time.Hour); r2["totals"].(mcpUseSum).Calls != 6 {
		t.Errorf("7 days: %+v", r2["totals"])
	}
	if h := r["hours"].([]mcpUseHour); len(h) != 25 && len(h) != 24 || h[len(h)-1].Calls != 5 || h[len(h)-1].Bytes != 500 {
		t.Errorf("hours %+v", h)
	}
	if rc := r["recent"].([]mcpUseCall); len(rc) != 7 || rc[0].Tool != "get_log" {
		t.Errorf("recent has %d", len(rc))
	}

	// it is written, and read again by the next daemon; the old bucket is not kept
	u.Flush()
	if _, err := os.Stat(filepath.Join(dir, "mcpusage.json")); err != nil {
		t.Fatal(err)
	}
	u2 := newMCPUsage(dir)
	u2.now = u.now
	if got := u2.Report(7 * 24 * time.Hour)["totals"].(mcpUseSum); got.Calls != 6 || got.Writes != 1 {
		t.Errorf("after a restart %+v", got)
	}
	if len(u2.Report(time.Hour)["recent"].([]mcpUseCall)) != 0 {
		t.Error("recent calls are not kept across a restart")
	}
}

func TestMCPUsageCapAndNil(t *testing.T) {
	u := newMCPUsage("")
	now := time.Now()
	for i := 0; i < mcpUsageRows+50; i++ {
		u.Record(mcpUseCall{Time: now, Caller: "k", Addr: "a", Tool: "t", Target: "d" + string(rune('a'+i%26)) + time.Duration(i).String(), Result: "ok"})
	}
	if n := len(u.hours[now.Truncate(time.Hour).Unix()]); n > mcpUsageRows+1 {
		t.Errorf("%d rows in a bucket", n)
	}
	if u.Report(time.Hour)["totals"].(mcpUseSum).Calls != int64(mcpUsageRows+50) {
		t.Error("a call was lost over the cap")
	}
	var nilU *mcpUsage
	nilU.Record(mcpUseCall{})
	nilU.Flush()
	if got := mcpCallerOf("k@1.2.3.4", "1.2.3.4"); got != "k" {
		t.Errorf("caller %q", got)
	}
	if got := mcpCallerOf("1.2.3.4", "1.2.3.4"); got != "(address list)" {
		t.Errorf("caller %q", got)
	}
	if got := mcpTarget(map[string]any{"target": " tag:site=dc1 "}); got != "tag:site=dc1" {
		t.Errorf("target %q", got)
	}
}

func TestMCPUsageHandler(t *testing.T) {
	w := &WebServer{usage: newMCPUsage("")}
	w.usage.Record(mcpUseCall{Time: time.Now(), Caller: "k", Addr: "a", Tool: "t", Result: "ok"})
	for _, win := range []string{"", "1h", "24h", "7d"} {
		rw := httptest.NewRecorder()
		w.handleMCPUsage(rw, httptest.NewRequest("GET", "/api/mcpusage?window="+win, nil), nil)
		var out map[string]any
		if rw.Code != 200 || json.Unmarshal(rw.Body.Bytes(), &out) != nil || out["by_tool"] == nil {
			t.Errorf("window %q: %d %s", win, rw.Code, rw.Body.String())
		}
	}
	rw := httptest.NewRecorder()
	w.handleMCPUsage(rw, httptest.NewRequest("GET", "/api/mcpusage?window=9y", nil), nil)
	if rw.Code != 400 {
		t.Errorf("a bad window: %d", rw.Code)
	}
}

// a call through the endpoint is counted: the caller, the tool, a refusal, and the page's answer
func TestMCPUsageEndToEnd(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.0/8")
	post(mcpCall("list_nodes", `{}`))
	post(mcpCall("set_node_paused", `{"node":"this","paused":true}`)) // refused: read-only
	r := e.ws.usage.Report(time.Hour)
	tot := r["totals"].(mcpUseSum)
	if tot.Calls != 2 || tot.Refused != 1 {
		t.Fatalf("totals %+v", tot)
	}
	tools := map[string]int64{}
	for _, s := range r["by_tool"].([]mcpUseSum) {
		tools[s.Name] = s.Calls
	}
	if tools["list_nodes"] != 1 || tools["set_node_paused"] != 1 {
		t.Errorf("by tool %v", tools)
	}
	if k := r["by_key"].([]mcpUseSum); len(k) != 1 || k[0].Name != "(address list)" {
		t.Errorf("by key %+v", k)
	}
	if s := r["by_source"].([]mcpUseSum); len(s) != 1 || s[0].Name != "127.0.0.1" {
		t.Errorf("by source %+v", s)
	}
}
