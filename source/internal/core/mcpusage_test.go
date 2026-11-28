package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMCPUsage(t *testing.T) {
	dir := t.TempDir()
	// near the real clock: the next daemon (below) drops what is older than the 8 days kept, by the real clock
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)
	u := NewMCPUsage(dir)
	u.now = func() time.Time { return now }
	rec := func(ago time.Duration, caller, addr, tool, target, res string, write bool) {
		u.Record(McpUseCall{Time: now.Add(-ago), Caller: caller, Addr: addr, Tool: tool, Target: target, Ms: 20, Bytes: 100, Result: res, Write: write})
	}
	rec(time.Minute, "claude", "10.0.0.5", "device_facts", "sw1,sw2", "ok", false)
	rec(2*time.Minute, "claude", "10.0.0.5", "device_facts", "sw1", "error", false)
	rec(3*time.Minute, "(address list)", "10.0.0.9", "list_devices", "", "ok", false)
	rec(4*time.Minute, "bot", "10.0.0.7", "device_change_raw", "sw1", "ok", true)
	rec(5*time.Minute, "bot", "10.0.0.7", "device_change_raw", "sw1", "refused", true)
	rec(30*time.Hour, "claude", "10.0.0.5", "device_facts", "sw3", "ok", false)
	rec(9*24*time.Hour, "old", "10.0.0.1", "get_log", "", "ok", false) // older than the 8 days kept

	r := u.Report(24 * time.Hour)
	tot := r["totals"].(McpUseSum)
	if tot.Calls != 5 || tot.Errors != 1 || tot.Writes != 1 || tot.Refused != 1 || tot.Bytes != 500 || tot.AvgMs != 20 {
		t.Errorf("totals %+v", tot)
	}
	keys := r["by_key"].([]McpUseSum)
	if len(keys) != 3 || keys[0].Name != "claude" && keys[0].Name != "bot" || keys[0].Calls != 2 {
		t.Errorf("by key %+v", keys)
	}
	tg := map[string]int64{}
	for _, s := range r["by_target"].([]McpUseSum) {
		tg[s.Name] = s.Calls
	}
	if tg["sw1"] != 4 || tg["sw2"] != 1 || tg["(none)"] != 1 || tg["sw3"] != 0 {
		t.Errorf("by target %v (a target list counts for each device)", tg)
	}
	if r2 := u.Report(7 * 24 * time.Hour); r2["totals"].(McpUseSum).Calls != 6 {
		t.Errorf("7 days: %+v", r2["totals"])
	}
	if h := r["hours"].([]mcpUseHour); len(h) != 25 && len(h) != 24 || h[len(h)-1].Calls != 5 || h[len(h)-1].Bytes != 500 {
		t.Errorf("hours %+v", h)
	}
	if rc := r["recent"].([]McpUseCall); len(rc) != 7 || rc[0].Tool != "get_log" {
		t.Errorf("recent has %d", len(rc))
	}

	// it is written, and read again by the next daemon; the old bucket is not kept
	u.Flush()
	if _, err := os.Stat(filepath.Join(dir, "mcpusage.json")); err != nil {
		t.Fatal(err)
	}
	u2 := NewMCPUsage(dir)
	u2.now = u.now
	if got := u2.Report(7 * 24 * time.Hour)["totals"].(McpUseSum); got.Calls != 6 || got.Writes != 1 {
		t.Errorf("after a restart %+v", got)
	}
	if len(u2.Report(time.Hour)["recent"].([]McpUseCall)) != 0 {
		t.Error("recent calls are not kept across a restart")
	}
}
