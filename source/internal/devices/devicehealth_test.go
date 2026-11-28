package devices

import (
	"strings"
	"testing"
	"time"

	"netdir/device"
	"netdir/internal/core"
)

func TestDeviceHealthStandaloneChecksHere(t *testing.T) {
	core.HealthCl = nil
	if core.ClusterOn() || !core.IsPrimaryHere() {
		t.Fatal("a node without a cluster must do its own checks")
	}
	if DeviceHealth(true) == nil {
		t.Fatal("deviceHealth returned nil")
	}
	LookAtDevices()
}

func stubCluster(t *testing.T, primary bool, peers []core.PeerView, ask func(string, bool) (map[string]device.Health, bool)) {
	t.Helper()
	oc, op, oh, oa := core.ClusterOn, core.IsPrimaryHere, core.HealthPeers, core.AskPeerHealth
	core.ClusterOn = func() bool { return true }
	core.IsPrimaryHere = func() bool { return primary }
	core.HealthPeers = func() []core.PeerView { return peers }
	if ask != nil {
		core.AskPeerHealth = ask
	}
	core.PeerHealth.Mu.Lock()
	core.PeerHealth.M = map[string]*core.PeerHealthEntry{}
	core.PeerHealth.Mu.Unlock()
	core.ControlHold.Mu.Lock()
	core.ControlHold.Until = map[int]time.Time{}
	core.ControlHold.Mu.Unlock()
	t.Cleanup(func() {
		core.ClusterOn, core.IsPrimaryHere, core.HealthPeers, core.AskPeerHealth = oc, op, oh, oa
		core.PeerHealth.Mu.Lock()
		core.PeerHealth.M = map[string]*core.PeerHealthEntry{}
		core.PeerHealth.Mu.Unlock()
		core.HealthCfg, core.HealthRows = nil, nil
	})
}

// Every node shows every device: its own checks, the other nodes' reports, the newest report of a device wins, and a report that is too
// old reads "not checked" instead of a colour.
func TestDeviceHealthMergesReports(t *testing.T) {
	now := time.Now()
	peers := []core.PeerView{{Addr: "n2", Reachable: true, Hostname: "site-b"}, {Addr: "n3", Reachable: true}}
	stubCluster(t, false, peers, func(addr string, look bool) (map[string]device.Health, bool) {
		switch addr {
		case "n2":
			return map[string]device.Health{"b1": {Status: "ok", Checked: now.Unix()}, "shared": {Status: "ok", Checked: now.Unix() - 5}}, true
		default:
			return map[string]device.Health{"c1": {Status: "bad", Detail: "down", Checked: now.Unix()}, "dead": {Status: "ok", Checked: now.Add(-time.Hour).Unix()},
				"shared": {Status: "bad", Checked: now.Unix()}, "off": {Status: "paused", Detail: "disabled"}}, true
		}
	})
	old := core.DevHealth
	core.DevHealth = device.NewMonitor()
	t.Cleanup(func() { core.DevHealth = old })
	m := DeviceHealth(false)
	if m["b1"].Status != "ok" || m["b1"].By != "site-b" {
		t.Errorf("b1: %+v (a node's report, said by that node's name)", m["b1"])
	}
	if m["c1"].Status != "bad" || m["c1"].By != "n3" {
		t.Errorf("c1: %+v (a node with no host name is named by its address)", m["c1"])
	}
	if m["shared"].Status != "bad" || m["shared"].By != "n3" {
		t.Errorf("shared: %+v, want the newest report", m["shared"])
	}
	if d := m["dead"]; d.Status != "idle" || !strings.Contains(d.Detail, "not checked") {
		t.Errorf("a report an hour old must not show a colour: %+v", d)
	}
	if m["off"].Status != "paused" {
		t.Errorf("a disabled device stays paused, not 'not checked': %+v", m["off"])
	}
}

// ── reading another node's report ───────────────────────────────────────────

func peerOf(addr string) core.PeerView { return core.PeerView{Addr: addr, Reachable: true} }

// A node that is slow to answer must not hold a request longer than healthColdWait: the devices read "not checked" for a poll.
func TestDeviceHealthColdWaitIsBounded(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubCluster(t, false, []core.PeerView{peerOf("n2"), peerOf("n3"), peerOf("n4")}, func(string, bool) (map[string]device.Health, bool) { <-release; return nil, false })
	old, oh := core.HealthColdWait, core.DevHealth
	core.HealthColdWait = 150 * time.Millisecond
	core.DevHealth = device.NewMonitor()
	t.Cleanup(func() { core.HealthColdWait, core.DevHealth = old, oh })
	t0 := time.Now()
	m := DeviceHealth(true)
	if took := time.Since(t0); took > time.Second { // three slow nodes are waited for together, not one after the other
		t.Fatalf("waited %s for nodes that do not answer", took)
	}
	if m == nil || len(m) != 0 {
		t.Fatalf("want an empty map, got %v", m)
	}
}

// The node that checks a device is the one asked to check it again.
func TestRecheckTargetIsTheNodeThatChecks(t *testing.T) {
	stubCluster(t, false, nil, nil)
	old := core.DevHealth
	core.DevHealth = device.NewMonitor()
	t.Cleanup(func() { core.DevHealth = old })
	if got := RecheckTarget("x"); got != "" && core.HealthCl == nil {
		// no cluster handle: the primary lookup is skipped below
	}
	core.PeerHealth.Mu.Lock()
	core.PeerHealth.M["n2"] = &core.PeerHealthEntry{Data: map[string]device.Health{"x": {Status: "ok", Checked: time.Now().Unix()}}}
	core.PeerHealth.M["n3"] = &core.PeerHealthEntry{Data: map[string]device.Health{"x": {Status: "ok", Checked: time.Now().Unix() - 60}}}
	core.PeerHealth.Mu.Unlock()
	if got := RecheckTarget("x"); got != "n2" {
		t.Fatalf("recheck goes to %q, want n2 (the newest report)", got)
	}
}

// A report that is too old does not send the request away: the node that checked may be gone.
func TestCheckerOfIgnoresAStaleReport(t *testing.T) {
	stubCluster(t, false, []core.PeerView{peerOf("n2")}, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"far": {Status: "ok", Checked: time.Now().Add(-time.Hour).Unix()}}, true
	})
	core.PeerReport(peerOf("n2"), false)
	time.Sleep(100 * time.Millisecond)
	if got := CheckerOf("far"); got != "" {
		t.Fatalf("an hour-old report sends the request to %q", got)
	}
}
