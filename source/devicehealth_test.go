package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
	"netdir/internal/web"
)

// POST /api/devices/recheck asks one device again now and says what it found.
func TestHandleDeviceRecheck(t *testing.T) {
	core.HealthCl = nil
	port := func() int { // a port nothing listens on
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}()
	dc := core.NewDaemonConfig()
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "secret-pw"}}
	dc.Settings.Devices = []device.Device{
		{Name: "dead", Platform: "iosxe", Address: "127.0.0.1", Port: port, Credential: "lab"},
		{Name: "off", Platform: "iosxe", Address: "127.0.0.1", Port: port, Credential: "lab", Disabled: true},
		{Name: "other", Platform: "iosxe", Address: "127.0.0.1", Port: port, Credential: "lab"},
	}
	attachDevices(dc)
	w := &web.WebServer{Status: &StatusServer{sup: &core.Supervisor{Dc: dc}}}
	post := func(s *core.Session, body string) (int, string) {
		rec := httptest.NewRecorder()
		w.HandleDeviceRecheck(rec, httptest.NewRequest(http.MethodPost, "/api/devices/recheck", strings.NewReader(body)), s)
		return rec.Code, rec.Body.String()
	}
	if code, _ := post(&core.Session{}, `{}`); code != http.StatusBadRequest {
		t.Fatalf("no name: %d", code)
	}
	if code, _ := post(&core.Session{}, `not json`); code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", code)
	}
	if code, body := post(&core.Session{}, `{"name":"nope"}`); code != http.StatusNotFound || !strings.Contains(body, "no such device") {
		t.Fatalf("unknown device: %d %s", code, body)
	}
	// a device whose port does not answer: unreachable, said at once, and it is the state from then on
	code, body := post(&core.Session{}, `{"name":"dead"}`)
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
	if h := core.DevHealth.Snapshot()["dead"]; h.Status != "bad" {
		t.Fatalf("the monitor does not hold the answer: %+v", h)
	}
	// a disabled device is not contacted
	if code, body = post(&core.Session{}, `{"name":"off"}`); code != http.StatusOK || !strings.Contains(body, `"paused"`) {
		t.Fatalf("off: %d %s", code, body)
	}
	// a caller limited to some devices cannot ask for the others, and is told no more than for a device that is not there
	limited := &core.Session{Devs: devices.NewDevScope([]string{"dead"})}
	if code, body = post(limited, `{"name":"other"}`); code != http.StatusNotFound || !strings.Contains(body, "no such device") {
		t.Fatalf("a device out of scope: %d %s", code, body)
	}
	if code, _ = post(limited, `{"name":"dead"}`); code != http.StatusOK {
		t.Fatalf("a device in scope: %d", code)
	}
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

// ── reading another node's report ───────────────────────────────────────────

func peerOf(addr string) core.PeerView { return core.PeerView{Addr: addr, Reachable: true} }

// A device request goes to the node that checks the device, as the caller made it, and a node that does not answer is skipped.
func TestDeviceQueryGoesToTheNodeThatChecks(t *testing.T) {
	now := time.Now().Unix()
	stubCluster(t, false, []core.PeerView{peerOf("n2")}, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"far": {Status: "ok", Checked: now}}, true
	})
	oldLook := devices.LookAtDevices // a request starts a look at the devices in the background: not here, it would outlive the stand-in cluster
	devices.LookAtDevices = func() {}
	t.Cleanup(func() { devices.LookAtDevices = oldLook })
	core.PeerReport(peerOf("n2"), false)
	time.Sleep(100 * time.Millisecond)
	if got := devices.CheckerOf("far"); got != "n2" {
		t.Fatalf("checker of far: %q, want n2", got)
	}
	if got := devices.CheckerOf("near"); got != "" {
		t.Fatalf("a device no other node reports is asked from here, got %q", got)
	}
	dc := core.NewDaemonConfig()
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "pw"}}
	dc.Settings.Devices = []device.Device{{Name: "far", Platform: "iosxe", Address: "127.0.0.1", Port: 1, Credential: "lab"}}
	attachDevices(dc)
	w := &web.WebServer{Status: &StatusServer{sup: &core.Supervisor{Dc: dc}}}
	ask := func(s *core.Session) (map[string]any, string) {
		rec := httptest.NewRecorder()
		w.HandleDeviceQuery(rec, httptest.NewRequest(http.MethodGet, "/api/devices/query?op=facts&target=all", nil), s)
		var out struct{ Data map[string]any }
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Data, rec.Body.String()
	}
	oldRelay := devices.RelayDevices
	t.Cleanup(func() { devices.RelayDevices = oldRelay })
	var seen core.ProxyReq
	var seenAddr string
	devices.RelayDevices = func(_ context.Context, addr string, req core.ProxyReq) (*core.ProxyResp, error) {
		seen, seenAddr = req, addr
		return &core.ProxyResp{Status: 200, Body: []byte(`{"ok":true,"data":{"op":"facts","results":[{"device":"far","ok":true,"data":{"from":"n2"}}]}}`)}, nil
	}
	data, body := ask(&core.Session{User: "ann", Mcp: true, ReadOnly: true})
	if seenAddr != "n2" || !seen.MCP || !seen.RO || seen.Raw || !strings.Contains(seen.Path, "target=far") || !strings.Contains(seen.Path, "op=facts") {
		t.Fatalf("relayed to %q: %+v", seenAddr, seen)
	}
	if !strings.Contains(body, `"from":"n2"`) || data["asked"].(float64) != 1 {
		t.Fatalf("the node's answer is not the result: %s", body)
	}
	// handed over by another node: not handed on again, whatever the reports say
	seenAddr = ""
	ask(&core.Session{User: "ann via n3", Hop: true})
	if seenAddr != "" {
		t.Fatalf("a request handed over by a node was handed on to %s", seenAddr)
	}
	// the node does not answer: this node asks the device itself (nothing listens on port 1: the answer is a failure, not the node's)
	devices.RelayDevices = func(context.Context, string, core.ProxyReq) (*core.ProxyResp, error) { return nil, errors.New("down") }
	_, body = ask(&core.Session{User: "ann"})
	if strings.Contains(body, `"from":"n2"`) || !strings.Contains(body, `"asked":1`) {
		t.Fatalf("no fallback to this node: %s", body)
	}
}

// A change is made by the node that checks each device; a node that does not answer is reported, never replaced by this node.
func TestWritesGoToTheNodeThatChecks(t *testing.T) {
	now := time.Now().Unix()
	stubCluster(t, false, []core.PeerView{peerOf("n2")}, func(string, bool) (map[string]device.Health, bool) {
		return map[string]device.Health{"far": {Status: "ok", Checked: now}}, true
	})
	core.PeerReport(peerOf("n2"), false)
	time.Sleep(100 * time.Millisecond)
	dc := core.NewDaemonConfig()
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
	oldRelay := devices.RelayDevices
	t.Cleanup(func() { devices.RelayDevices = oldRelay })
	var seenAddr, seenPath, seenBody string
	devices.RelayDevices = func(_ context.Context, addr string, req core.ProxyReq) (*core.ProxyResp, error) {
		seenAddr, seenPath, seenBody = addr, req.Path, string(req.Body)
		return &core.ProxyResp{Status: 200, Body: []byte(`{"ok":true,"data":{"op":"change","dry_run":true,"asked":1,"failed":0,"results":[{"device":"far","ok":true,"data":"by n2"}]}}`)}, nil
	}
	v, err := devices.RouteByChecker(dc, "change", json.RawMessage(`{"target":"far,near","text":"x","dry_run":true}`), "ann", here)
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
	devices.RelayDevices = func(context.Context, string, core.ProxyReq) (*core.ProxyResp, error) { return nil, errors.New("down") }
	v, _ = devices.RouteByChecker(dc, "change", json.RawMessage(`{"target":"far","text":"x"}`), "ann", here)
	out, _ = json.Marshal(v)
	if len(hereGot) != 0 || !strings.Contains(string(out), `"failed":1`) || !strings.Contains(string(out), "did not confirm") {
		t.Fatalf("a change was made from here, or not reported: %v %s", hereGot, out)
	}
	// a disabled device refuses the whole request, as before; a request handed over by a node is not handed on
	hereGot, seenAddr = nil, ""
	devices.RouteByChecker(dc, "change", json.RawMessage(`{"target":"far,off"}`), "ann", here)
	(&Mgmt{}).viaCheckers("change", here)(json.RawMessage(`{"target":"far"}`), "ann via n3")
	if seenAddr != "" || len(hereGot) != 2 {
		t.Fatalf("handed on: %q %v", seenAddr, hereGot)
	}
}
