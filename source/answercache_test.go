package main

import (
	"testing"
	"time"

	"netdir/device"
)

// A facts read is answered from what the health monitor holds when that is recent and good.
func TestFactsFromMonitor(t *testing.T) {
	d := device.Device{Name: "sw1", Platform: "iosxe"}
	now := time.Now()
	f := &device.Facts{Hostname: "sw1", UptimeS: 1000}
	good := device.Health{Status: "ok", Facts: f, FactsAt: now.Add(-60 * time.Second).Unix()}
	r, ok := factsFromMonitor(d, map[string]device.Health{"sw1": good})
	if !ok || !r.OK || !r.FromMonitor || r.CachedSecs == nil || *r.CachedSecs < 59 || r.Data.(device.Facts).UptimeS < 1059 {
		t.Fatalf("recent facts: %v %+v", ok, r)
	}
	if f.UptimeS != 1000 {
		t.Error("the monitor's copy was changed")
	}
	for name, h := range map[string]device.Health{
		"old":     {Status: "ok", Facts: f, FactsAt: now.Add(-10 * time.Minute).Unix()},
		"failed":  {Status: "warn", Facts: f, FactsAt: now.Unix(), FactsErr: "401"},
		"down":    {Status: "bad", Facts: f, FactsAt: now.Unix()},
		"paused":  {Status: "paused", Facts: f, FactsAt: now.Unix()},
		"never":   {Status: "ok", Facts: f},
		"nofacts": {Status: "ok", FactsAt: now.Unix()},
	} {
		if _, ok := factsFromMonitor(d, map[string]device.Health{"sw1": h}); ok {
			t.Errorf("%s: answered from the monitor", name)
		}
	}
	if _, ok := factsFromMonitor(d, nil); ok {
		t.Error("no monitor data: answered")
	}
}
