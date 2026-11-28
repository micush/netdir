package core

import (
	"strings"
	"sync"
	"testing"
	"time"

	"netdir/device"
)

// ── ownership: each device is checked by the controller of its gateway ────────

func twoGateways() *DaemonConfig {
	dc := &DaemonConfig{}
	dc.Settings.Devices = []device.Device{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "lonely"}}
	dc.Groups = []GroupConfig{
		{GroupID: 5, VIP4: "10.0.5.1/24", Devices: []string{"b", "c"}},
		{GroupID: 3, VIP4: "10.0.3.1/24", Devices: []string{"a", "b"}},
		{GroupID: 9, VIP4: "10.0.9.1/24", PausedAll: true, Devices: []string{"c", "lonely"}},
	}
	return dc
}

func TestDeviceOwnerGroup(t *testing.T) {
	dc := twoGateways()
	for name, want := range map[string]int{"a": 3, "b": 3, "c": 5, "lonely": 0} {
		g, ok := deviceOwnerGroup(dc, name)
		if want == 0 {
			if ok {
				t.Errorf("%s (only on a gateway paused on every node) has an owner: %d", name, g.GroupID)
			}
			continue
		}
		if !ok || g.GroupID != want {
			t.Errorf("%s: owner %v %v, want gateway %d (the lowest ID that is not paused everywhere)", name, g, ok, want)
		}
	}
	if _, ok := deviceOwnerGroup(dc, "nobody"); ok {
		t.Error("a device on no gateway has an owner")
	}
}

func TestControllerHere(t *testing.T) {
	g4 := &GroupConfig{GroupID: 3, VIP4: "10.0.3.1/24", VIP6: "fd00::1/64"}
	g6 := &GroupConfig{GroupID: 4, VIP6: "fd00::2/64"}
	rows := []SnapshotRow{
		{GroupID: 3, AF: "v4", Local: true, PeerIP: "10.0.3.10", AGCIP: "10.0.3.10"}, // this node controls the v4 side
		{GroupID: 3, AF: "v6", Local: true, PeerIP: "fd00::10", AGCIP: "fd00::11"},   // another node controls the v6 side
		{GroupID: 3, AF: "v4", Local: false, PeerIP: "10.0.3.11", AGCIP: "10.0.3.10"},
		{GroupID: 4, AF: "v6", Local: true, PeerIP: "fd00::10", AGCIP: "fd00::11"}, // not the controller of gateway 4
	}
	if !controllerHere(rows, g4) {
		t.Error("the v4 controller of a dual-stack gateway is its controller")
	}
	if controllerHere(rows, g6) {
		t.Error("not the controller of gateway 4")
	}
	rows[3].AGCIP = "fd00::10"
	if !controllerHere(rows, g6) {
		t.Error("a gateway with no IPv4 address is controlled by its IPv6 controller")
	}
	// the IPv6 side alone does not count on a dual-stack gateway: the IPv4 controller stands for it
	if controllerHere([]SnapshotRow{{GroupID: 3, AF: "v6", Local: true, PeerIP: "fd00::10", AGCIP: "fd00::10"}}, g4) {
		t.Error("the IPv6 controller of a gateway that has IPv4 is not its controller")
	}
	if controllerHere(nil, g4) {
		t.Error("no engine here: not the controller")
	}
}

// A node that was a gateway's controller goes on checking for controllerHold after it stops: a flapping election does not move the checks.
func TestHoldControl(t *testing.T) {
	ControlHold.Mu.Lock()
	ControlHold.Until = map[int]time.Time{}
	ControlHold.Mu.Unlock()
	now := time.Now()
	if holdControl(7, now, false) {
		t.Fatal("never a controller, yet it checks")
	}
	if !holdControl(7, now, true) {
		t.Fatal("the controller does not check")
	}
	if !holdControl(7, now.Add(controllerHold-time.Second), false) {
		t.Fatal("dropped the checks the moment it stopped being the controller")
	}
	if holdControl(7, now.Add(controllerHold+time.Second), false) {
		t.Fatal("still checking long after it stopped being the controller")
	}
}

func stubCluster(t *testing.T, primary bool, peers []PeerView, ask func(string, bool) (map[string]device.Health, bool)) {
	t.Helper()
	oc, op, oh, oa := ClusterOn, IsPrimaryHere, HealthPeers, AskPeerHealth
	ClusterOn = func() bool { return true }
	IsPrimaryHere = func() bool { return primary }
	HealthPeers = func() []PeerView { return peers }
	if ask != nil {
		AskPeerHealth = ask
	}
	PeerHealth.Mu.Lock()
	PeerHealth.M = map[string]*PeerHealthEntry{}
	PeerHealth.Mu.Unlock()
	ControlHold.Mu.Lock()
	ControlHold.Until = map[int]time.Time{}
	ControlHold.Mu.Unlock()
	t.Cleanup(func() {
		ClusterOn, IsPrimaryHere, HealthPeers, AskPeerHealth = oc, op, oh, oa
		PeerHealth.Mu.Lock()
		PeerHealth.M = map[string]*PeerHealthEntry{}
		PeerHealth.Mu.Unlock()
		HealthCfg, HealthRows = nil, nil
	})
}

func names(devs []device.Device) string {
	var out []string
	for _, d := range devs {
		out = append(out, d.Name)
	}
	return strings.Join(out, ",")
}

// In a cluster a node checks the devices of the gateways it controls and nothing else; the primary also takes what nobody else reports.
func TestOwnedInventoryIsTheControlledGateways(t *testing.T) {
	dc := twoGateways()
	dc.Settings.Devices = append(dc.Settings.Devices, device.Device{Name: "unlisted"})
	rows := []SnapshotRow{{GroupID: 5, AF: "v4", Local: true, PeerIP: "10.0.5.10", AGCIP: "10.0.5.10"}} // controller of gateway 5 only
	stubCluster(t, false, nil, nil)
	HealthCfg, HealthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	sup := &Supervisor{Dc: dc}
	devs, _ := sup.OwnedInventory()
	if got := names(devs); got != "c" { // c's owner is gateway 5; a and b belong to gateway 3, which another node controls
		t.Fatalf("a non-primary that controls gateway 5 checks %q, want c", got)
	}
	// the primary, hearing nothing from the other nodes, takes the rest (but not what is on no gateway's checks... it takes everything unreported)
	stubCluster(t, true, nil, nil)
	HealthCfg, HealthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	devs, _ = sup.OwnedInventory()
	if got := names(devs); got != "a,b,c,lonely,unlisted" {
		t.Fatalf("the primary with no reports checks %q, want every device", got)
	}
	// another node reports a and b lately: the primary leaves them (and takes the rest)
	peers := []PeerView{{Addr: "n2", Reachable: true, Hostname: "node2"}}
	fresh := time.Now().Unix()
	stubCluster(t, true, peers, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"a": {Status: "ok", Checked: fresh}, "b": {Status: "ok", Checked: fresh}}, true
	})
	HealthCfg, HealthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	devs, _ = sup.OwnedInventory()
	if got := names(devs); got != "c,lonely,unlisted" {
		t.Fatalf("the primary checks %q, want only what nobody reports", got)
	}
	// a report that is too old does not count: the primary takes the device over
	stubCluster(t, true, peers, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"a": {Status: "ok", Checked: time.Now().Add(-time.Hour).Unix()}}, true
	})
	HealthCfg, HealthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	devs, _ = sup.OwnedInventory()
	if !strings.Contains(","+names(devs)+",", ",a,") {
		t.Fatalf("an hour-old report still keeps the primary away from a: %q", names(devs))
	}
}

// ── reading another node's report ───────────────────────────────────────────

func peerOf(addr string) PeerView { return PeerView{Addr: addr, Reachable: true} }

// The Topology page asks for the health twice at once (the canvas and the devices): the second asker used to get an empty answer while the
// first was still fetching, and every device was drawn "not checked".
func TestPeerReportSecondAskerWaitsForTheFetch(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	fetches := 0
	stubCluster(t, false, nil, func(string, bool) (map[string]device.Health, bool) {
		fetches++
		close(started)
		<-release
		return map[string]device.Health{"sw1": {Status: "ok", Checked: time.Now().Unix()}}, true
	})
	p := peerOf("n2")
	got := make(chan map[string]device.Health, 2)
	go func() { _, done := PeerReport(p, true); <-done; d, _ := PeerReport(p, true); got <- d }()
	<-started
	if d, done := PeerReport(p, true); d != nil || done == nil {
		t.Fatalf("the second asker got %v, done=%v while the fetch is in flight", d, done)
	}
	close(release)
	select {
	case d := <-got:
		if d["sw1"].Status != "ok" {
			t.Fatalf("got %v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never answered")
	}
	if fetches != 1 {
		t.Fatalf("%d fetches for two askers", fetches)
	}
}

// With an older answer in hand a request uses it at once; the new one is fetched in the background and used by the next request.
func TestPeerReportStaleAnswerIsUsedWhileRefreshing(t *testing.T) {
	release, fetched := make(chan struct{}), make(chan struct{})
	stubCluster(t, false, nil, func(string, bool) (map[string]device.Health, bool) {
		<-release
		defer close(fetched)
		return map[string]device.Health{"sw1": {Status: "bad"}}, true
	})
	PeerHealth.Mu.Lock()
	PeerHealth.M["n2"] = &PeerHealthEntry{Data: map[string]device.Health{"sw1": {Status: "ok"}}, At: time.Now().Add(-time.Minute), tried: true}
	PeerHealth.Mu.Unlock()
	p := peerOf("n2")
	t0 := time.Now()
	if d, _ := PeerReport(p, false); d["sw1"].Status != "ok" || time.Since(t0) > time.Second {
		t.Fatalf("want the older answer at once, got %v after %s", d, time.Since(t0))
	}
	close(release)
	<-fetched
	time.Sleep(50 * time.Millisecond)
	if d, _ := PeerReport(p, false); d["sw1"].Status != "bad" {
		t.Fatalf("the refreshed answer was not used: %v", d)
	}
}

// A fetch that failed with nothing yet is tried again in about 2 s, not after a long wait.
func TestPeerReportRetriesSoonAfterAFailedFirstFetch(t *testing.T) {
	calls := 0
	stubCluster(t, false, nil, func(string, bool) (map[string]device.Health, bool) {
		calls++
		if calls == 1 {
			return nil, false
		}
		return map[string]device.Health{"sw1": {Status: "ok"}}, true
	})
	p := peerOf("n2")
	if _, done := PeerReport(p, false); done != nil {
		<-done
	}
	if d, _ := PeerReport(p, false); len(d) != 0 {
		t.Fatalf("first answer %v", d)
	}
	time.Sleep(2500 * time.Millisecond)
	PeerReport(p, false) // starts the retry
	time.Sleep(200 * time.Millisecond)
	if d, _ := PeerReport(p, false); d["sw1"].Status != "ok" {
		t.Fatalf("not retried after a failed first fetch: %v (calls %d)", d, calls)
	}
}

// Someone looking tells the node that checks: a fetch that carries look=1 is sent again when the last one did not, even with a fresh answer.
func TestPeerReportLookIsPassedOn(t *testing.T) {
	var looks []bool
	var mu sync.Mutex
	stubCluster(t, false, nil, func(_ string, look bool) (map[string]device.Health, bool) {
		mu.Lock()
		looks = append(looks, look)
		mu.Unlock()
		return map[string]device.Health{}, true
	})
	p := peerOf("n2")
	_, done := PeerReport(p, false) // the priming ask: nobody is looking
	<-done
	time.Sleep(50 * time.Millisecond)
	_, done = PeerReport(p, true) // a page is opened: the answer is fresh, but the node must hear about it
	if done != nil {
		<-done
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(looks) != 2 || looks[0] || !looks[1] {
		t.Fatalf("fetches %v, want [false true]", looks)
	}
}
