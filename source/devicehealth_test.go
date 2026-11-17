package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netdir/device"
)

func TestDeviceHealthStandaloneChecksHere(t *testing.T) {
	healthMg = nil
	if clusterOn() || !isPrimaryHere() {
		t.Fatal("a node without a cluster must do its own checks")
	}
	if deviceHealth(true) == nil {
		t.Fatal("deviceHealth returned nil")
	}
	lookAtDevices()
}

func TestHandleDeviceHealth(t *testing.T) {
	healthMg = nil
	w := &WebServer{}
	rec := httptest.NewRecorder()
	w.handleDeviceHealth(rec, httptest.NewRequest(http.MethodGet, "/api/devices/health?look=1", nil), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"health"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// POST /api/devices/recheck asks one device again now and says what it found.
func TestHandleDeviceRecheck(t *testing.T) {
	healthMg = nil
	port := func() int { // a port nothing listens on
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}()
	dc := newDaemonConfig()
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "secret-pw"}}
	dc.Settings.Devices = []device.Device{
		{Name: "dead", Platform: "iosxe", Address: "127.0.0.1", Port: port, Credential: "lab"},
		{Name: "off", Platform: "iosxe", Address: "127.0.0.1", Port: port, Credential: "lab", Disabled: true},
		{Name: "other", Platform: "iosxe", Address: "127.0.0.1", Port: port, Credential: "lab"},
	}
	attachDevices(dc)
	w := &WebServer{status: &StatusServer{sup: &Supervisor{dc: dc}}}
	post := func(s *session, body string) (int, string) {
		rec := httptest.NewRecorder()
		w.handleDeviceRecheck(rec, httptest.NewRequest(http.MethodPost, "/api/devices/recheck", strings.NewReader(body)), s)
		return rec.Code, rec.Body.String()
	}
	if code, _ := post(&session{}, `{}`); code != http.StatusBadRequest {
		t.Fatalf("no name: %d", code)
	}
	if code, _ := post(&session{}, `not json`); code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", code)
	}
	if code, body := post(&session{}, `{"name":"nope"}`); code != http.StatusNotFound || !strings.Contains(body, "no such device") {
		t.Fatalf("unknown device: %d %s", code, body)
	}
	// a device whose port does not answer: unreachable, said at once, and it is the state from then on
	code, body := post(&session{}, `{"name":"dead"}`)
	var out struct {
		Data struct {
			Name   string
			Health device.Health
		}
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || out.Data.Name != "dead" || out.Data.Health.Status != "bad" || !strings.Contains(out.Data.Health.Detail, "does not answer") || out.Data.Health.Checked == 0 {
		t.Fatalf("dead: %d %s", code, body)
	}
	if strings.Contains(body, "secret-pw") || strings.Contains(body, `"facts"`) {
		t.Fatalf("the answer carries more than the state: %s", body)
	}
	if h := devHealth.Snapshot()["dead"]; h.Status != "bad" {
		t.Fatalf("the monitor does not hold the answer: %+v", h)
	}
	// a disabled device is not contacted
	if code, body = post(&session{}, `{"name":"off"}`); code != http.StatusOK || !strings.Contains(body, `"paused"`) {
		t.Fatalf("off: %d %s", code, body)
	}
	// a caller limited to some devices cannot ask for the others, and is told no more than for a device that is not there
	limited := &session{devs: newDevScope([]string{"dead"})}
	if code, body = post(limited, `{"name":"other"}`); code != http.StatusNotFound || !strings.Contains(body, "no such device") {
		t.Fatalf("a device out of scope: %d %s", code, body)
	}
	if code, _ = post(limited, `{"name":"dead"}`); code != http.StatusOK {
		t.Fatalf("a device in scope: %d", code)
	}
}

// A read-only account may not ask (the one gate refuses every POST): the route is not an exception.
func TestRecheckIsAPostRefusedToReadOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/devices/recheck", nil)
	if !readOnlyDenied(r) {
		t.Fatal("a read-only account can ask a device again")
	}
}

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
	controlHold.mu.Lock()
	controlHold.until = map[int]time.Time{}
	controlHold.mu.Unlock()
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
	oc, op, oh, oa := clusterOn, isPrimaryHere, healthPeers, askPeerHealth
	clusterOn = func() bool { return true }
	isPrimaryHere = func() bool { return primary }
	healthPeers = func() []PeerView { return peers }
	if ask != nil {
		askPeerHealth = ask
	}
	peerHealth.mu.Lock()
	peerHealth.m = map[string]*peerHealthEntry{}
	peerHealth.mu.Unlock()
	controlHold.mu.Lock()
	controlHold.until = map[int]time.Time{}
	controlHold.mu.Unlock()
	t.Cleanup(func() {
		clusterOn, isPrimaryHere, healthPeers, askPeerHealth = oc, op, oh, oa
		peerHealth.mu.Lock()
		peerHealth.m = map[string]*peerHealthEntry{}
		peerHealth.mu.Unlock()
		healthCfg, healthRows = nil, nil
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
	healthCfg, healthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	sup := &Supervisor{dc: dc}
	devs, _ := sup.ownedInventory()
	if got := names(devs); got != "c" { // c's owner is gateway 5; a and b belong to gateway 3, which another node controls
		t.Fatalf("a non-primary that controls gateway 5 checks %q, want c", got)
	}
	// the primary, hearing nothing from the other nodes, takes the rest (but not what is on no gateway's checks... it takes everything unreported)
	stubCluster(t, true, nil, nil)
	healthCfg, healthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	devs, _ = sup.ownedInventory()
	if got := names(devs); got != "a,b,c,lonely,unlisted" {
		t.Fatalf("the primary with no reports checks %q, want every device", got)
	}
	// another node reports a and b lately: the primary leaves them (and takes the rest)
	peers := []PeerView{{Addr: "n2", Reachable: true, Hostname: "node2"}}
	fresh := time.Now().Unix()
	stubCluster(t, true, peers, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"a": {Status: "ok", Checked: fresh}, "b": {Status: "ok", Checked: fresh}}, true
	})
	healthCfg, healthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	devs, _ = sup.ownedInventory()
	if got := names(devs); got != "c,lonely,unlisted" {
		t.Fatalf("the primary checks %q, want only what nobody reports", got)
	}
	// a report that is too old does not count: the primary takes the device over
	stubCluster(t, true, peers, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"a": {Status: "ok", Checked: time.Now().Add(-time.Hour).Unix()}}, true
	})
	healthCfg, healthRows = func() *DaemonConfig { return dc }, func() []SnapshotRow { return rows }
	devs, _ = sup.ownedInventory()
	if !strings.Contains(","+names(devs)+",", ",a,") {
		t.Fatalf("an hour-old report still keeps the primary away from a: %q", names(devs))
	}
}

// Every node shows every device: its own checks, the other nodes' reports, the newest report of a device wins, and a report that is too
// old reads "not checked" instead of a colour.
func TestDeviceHealthMergesReports(t *testing.T) {
	now := time.Now()
	peers := []PeerView{{Addr: "n2", Reachable: true, Hostname: "site-b"}, {Addr: "n3", Reachable: true}}
	stubCluster(t, false, peers, func(addr string, look bool) (map[string]device.Health, bool) {
		switch addr {
		case "n2":
			return map[string]device.Health{"b1": {Status: "ok", Checked: now.Unix()}, "shared": {Status: "ok", Checked: now.Unix() - 5}}, true
		default:
			return map[string]device.Health{"c1": {Status: "bad", Detail: "down", Checked: now.Unix()}, "dead": {Status: "ok", Checked: now.Add(-time.Hour).Unix()},
				"shared": {Status: "bad", Checked: now.Unix()}, "off": {Status: "paused", Detail: "disabled"}}, true
		}
	})
	old := devHealth
	devHealth = device.NewMonitor()
	t.Cleanup(func() { devHealth = old })
	m := deviceHealth(false)
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
	go func() { _, done := peerReport(p, true); <-done; d, _ := peerReport(p, true); got <- d }()
	<-started
	if d, done := peerReport(p, true); d != nil || done == nil {
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

// A node that is slow to answer must not hold a request longer than healthColdWait: the devices read "not checked" for a poll.
func TestDeviceHealthColdWaitIsBounded(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubCluster(t, false, []PeerView{peerOf("n2"), peerOf("n3"), peerOf("n4")}, func(string, bool) (map[string]device.Health, bool) { <-release; return nil, false })
	old, oh := healthColdWait, devHealth
	healthColdWait = 150 * time.Millisecond
	devHealth = device.NewMonitor()
	t.Cleanup(func() { healthColdWait, devHealth = old, oh })
	t0 := time.Now()
	m := deviceHealth(true)
	if took := time.Since(t0); took > time.Second { // three slow nodes are waited for together, not one after the other
		t.Fatalf("waited %s for nodes that do not answer", took)
	}
	if m == nil || len(m) != 0 {
		t.Fatalf("want an empty map, got %v", m)
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
	peerHealth.mu.Lock()
	peerHealth.m["n2"] = &peerHealthEntry{data: map[string]device.Health{"sw1": {Status: "ok"}}, at: time.Now().Add(-time.Minute), tried: true}
	peerHealth.mu.Unlock()
	p := peerOf("n2")
	t0 := time.Now()
	if d, _ := peerReport(p, false); d["sw1"].Status != "ok" || time.Since(t0) > time.Second {
		t.Fatalf("want the older answer at once, got %v after %s", d, time.Since(t0))
	}
	close(release)
	<-fetched
	time.Sleep(50 * time.Millisecond)
	if d, _ := peerReport(p, false); d["sw1"].Status != "bad" {
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
	if _, done := peerReport(p, false); done != nil {
		<-done
	}
	if d, _ := peerReport(p, false); len(d) != 0 {
		t.Fatalf("first answer %v", d)
	}
	time.Sleep(2500 * time.Millisecond)
	peerReport(p, false) // starts the retry
	time.Sleep(200 * time.Millisecond)
	if d, _ := peerReport(p, false); d["sw1"].Status != "ok" {
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
	_, done := peerReport(p, false) // the priming ask: nobody is looking
	<-done
	time.Sleep(50 * time.Millisecond)
	_, done = peerReport(p, true) // a page is opened: the answer is fresh, but the node must hear about it
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

// The node that checks a device is the one asked to check it again.
func TestRecheckTargetIsTheNodeThatChecks(t *testing.T) {
	stubCluster(t, false, nil, nil)
	old := devHealth
	devHealth = device.NewMonitor()
	t.Cleanup(func() { devHealth = old })
	if got := recheckTarget("x"); got != "" && healthMg == nil {
		// no cluster handle: the primary lookup is skipped below
	}
	peerHealth.mu.Lock()
	peerHealth.m["n2"] = &peerHealthEntry{data: map[string]device.Health{"x": {Status: "ok", Checked: time.Now().Unix()}}}
	peerHealth.m["n3"] = &peerHealthEntry{data: map[string]device.Health{"x": {Status: "ok", Checked: time.Now().Unix() - 60}}}
	peerHealth.mu.Unlock()
	if got := recheckTarget("x"); got != "n2" {
		t.Fatalf("recheck goes to %q, want n2 (the newest report)", got)
	}
}

// A device request goes to the node that checks the device, as the caller made it, and a node that does not answer is skipped.
func TestDeviceQueryGoesToTheNodeThatChecks(t *testing.T) {
	now := time.Now().Unix()
	stubCluster(t, false, []PeerView{peerOf("n2")}, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"far": {Status: "ok", Checked: now}}, true
	})
	oldLook := lookAtDevices // a request starts a look at the devices in the background: not here, it would outlive the stand-in cluster
	lookAtDevices = func() {}
	t.Cleanup(func() { lookAtDevices = oldLook })
	peerReport(peerOf("n2"), false)
	time.Sleep(100 * time.Millisecond)
	if got := checkerOf("far"); got != "n2" {
		t.Fatalf("checker of far: %q, want n2", got)
	}
	if got := checkerOf("near"); got != "" {
		t.Fatalf("a device no other node reports is asked from here, got %q", got)
	}
	dc := newDaemonConfig()
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "pw"}}
	dc.Settings.Devices = []device.Device{{Name: "far", Platform: "iosxe", Address: "127.0.0.1", Port: 1, Credential: "lab"}}
	attachDevices(dc)
	w := &WebServer{status: &StatusServer{sup: &Supervisor{dc: dc}}}
	ask := func(s *session) (map[string]any, string) {
		rec := httptest.NewRecorder()
		w.handleDeviceQuery(rec, httptest.NewRequest(http.MethodGet, "/api/devices/query?op=facts&target=all", nil), s)
		var out struct{ Data map[string]any }
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Data, rec.Body.String()
	}
	oldRelay := relayDevices
	t.Cleanup(func() { relayDevices = oldRelay })
	var seen proxyReq
	var seenAddr string
	relayDevices = func(_ context.Context, addr string, req proxyReq) (*proxyResp, error) {
		seen, seenAddr = req, addr
		return &proxyResp{Status: 200, Body: []byte(`{"ok":true,"data":{"op":"facts","results":[{"device":"far","ok":true,"data":{"from":"n2"}}]}}`)}, nil
	}
	data, body := ask(&session{user: "ann", mcp: true, readOnly: true})
	if seenAddr != "n2" || !seen.MCP || !seen.RO || seen.Raw || !strings.Contains(seen.Path, "target=far") || !strings.Contains(seen.Path, "op=facts") {
		t.Fatalf("relayed to %q: %+v", seenAddr, seen)
	}
	if !strings.Contains(body, `"from":"n2"`) || data["asked"].(float64) != 1 {
		t.Fatalf("the node's answer is not the result: %s", body)
	}
	// handed over by another node: not handed on again, whatever the reports say
	seenAddr = ""
	ask(&session{user: "ann via n3", hop: true})
	if seenAddr != "" {
		t.Fatalf("a request handed over by a node was handed on to %s", seenAddr)
	}
	// the node does not answer: this node asks the device itself (nothing listens on port 1: the answer is a failure, not the node's)
	relayDevices = func(context.Context, string, proxyReq) (*proxyResp, error) { return nil, errors.New("down") }
	_, body = ask(&session{user: "ann"})
	if strings.Contains(body, `"from":"n2"`) || !strings.Contains(body, `"asked":1`) {
		t.Fatalf("no fallback to this node: %s", body)
	}
}

// A report that is too old does not send the request away: the node that checked may be gone.
func TestCheckerOfIgnoresAStaleReport(t *testing.T) {
	stubCluster(t, false, []PeerView{peerOf("n2")}, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"far": {Status: "ok", Checked: time.Now().Add(-time.Hour).Unix()}}, true
	})
	peerReport(peerOf("n2"), false)
	time.Sleep(100 * time.Millisecond)
	if got := checkerOf("far"); got != "" {
		t.Fatalf("an hour-old report sends the request to %q", got)
	}
}

// A change is made by the node that checks each device; a node that does not answer is reported, never replaced by this node.
func TestWritesGoToTheNodeThatChecks(t *testing.T) {
	now := time.Now().Unix()
	stubCluster(t, false, []PeerView{peerOf("n2")}, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"far": {Status: "ok", Checked: now}}, true
	})
	peerReport(peerOf("n2"), false)
	time.Sleep(100 * time.Millisecond)
	dc := newDaemonConfig()
	dc.Settings.Devices = []device.Device{{Name: "far", Platform: "iosxe"}, {Name: "near", Platform: "iosxe"}, {Name: "off", Platform: "iosxe", Disabled: true}}
	attachDevices(dc)
	var hereGot []string
	here := func(raw json.RawMessage, actor string) (any, error) {
		var a struct{ Target string }
		json.Unmarshal(raw, &a)
		hereGot = append(hereGot, a.Target)
		var rs []map[string]any
		for _, n := range strings.Split(a.Target, ",") {
			rs = append(rs, map[string]any{"device": n, "ok": true})
		}
		return map[string]any{"op": "change", "dry_run": true, "asked": len(rs), "failed": 0, "results": rs}, nil
	}
	oldRelay := relayDevices
	t.Cleanup(func() { relayDevices = oldRelay })
	var seenAddr, seenPath, seenBody string
	relayDevices = func(_ context.Context, addr string, req proxyReq) (*proxyResp, error) {
		seenAddr, seenPath, seenBody = addr, req.Path, string(req.Body)
		return &proxyResp{Status: 200, Body: []byte(`{"ok":true,"data":{"op":"change","dry_run":true,"asked":1,"failed":0,"results":[{"device":"far","ok":true,"data":"by n2"}]}}`)}, nil
	}
	v, err := routeByChecker(dc, "change", json.RawMessage(`{"target":"far,near","text":"x","dry_run":true}`), "ann", here)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(v)
	if seenAddr != "n2" || seenPath != "/api/devices/change" || !strings.Contains(seenBody, `"target":"far"`) || !strings.Contains(seenBody, `"text":"x"`) {
		t.Fatalf("relayed to %q %s %s", seenAddr, seenPath, seenBody)
	}
	if len(hereGot) != 1 || hereGot[0] != "near" {
		t.Fatalf("this node made %v, want only near", hereGot)
	}
	if !strings.Contains(string(out), `"asked":2`) || !strings.Contains(string(out), `by n2`) || !strings.Contains(string(out), `"dry_run":true`) {
		t.Fatalf("answers not put together: %s", out)
	}
	// the node does not answer: the device is reported and never changed from here
	hereGot = nil
	relayDevices = func(context.Context, string, proxyReq) (*proxyResp, error) { return nil, errors.New("down") }
	v, _ = routeByChecker(dc, "change", json.RawMessage(`{"target":"far","text":"x"}`), "ann", here)
	out, _ = json.Marshal(v)
	if len(hereGot) != 0 || !strings.Contains(string(out), `"failed":1`) || !strings.Contains(string(out), "did not confirm") {
		t.Fatalf("a change was made from here, or not reported: %v %s", hereGot, out)
	}
	// a disabled device refuses the whole request, as before; a request handed over by a node is not handed on
	hereGot, seenAddr = nil, ""
	routeByChecker(dc, "change", json.RawMessage(`{"target":"far,off"}`), "ann", here)
	(&Mgmt{}).viaCheckers("change", here)(json.RawMessage(`{"target":"far"}`), "ann via n3")
	if seenAddr != "" || len(hereGot) != 2 {
		t.Fatalf("handed on: %q %v", seenAddr, hereGot)
	}
}
