package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netdir/device"
)

func TestDeviceHealthStandaloneChecksHere(t *testing.T) {
	healthMg = nil
	if !checksHere() {
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
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"health"`) || !strings.Contains(rec.Body.String(), `"checks_here":true`) {
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
