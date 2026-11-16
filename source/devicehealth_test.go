package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// A node that is not the primary hears the health from the primary.  The Topology page asks for it twice at once (the canvas and the
// devices): the second asker used to get an empty answer while the first was still fetching, and every device was drawn "not checked".
func TestReplicaHealthSecondAskerWaitsForTheFetch(t *testing.T) {
	healthCache.mu.Lock()
	healthCache.data, healthCache.at, healthCache.fetching = nil, time.Time{}, false
	healthCache.mu.Unlock()
	t.Cleanup(func() {
		healthCache.mu.Lock()
		healthCache.data, healthCache.at, healthCache.fetching = nil, time.Time{}, false
		healthCache.mu.Unlock()
	})
	started, release := make(chan struct{}), make(chan struct{})
	fetches := 0
	fetch := func(bool) (map[string]device.Health, bool) {
		fetches++
		close(started)
		<-release
		return map[string]device.Health{"sw1": {Status: "ok"}}, true
	}
	first := make(chan map[string]device.Health)
	go func() { first <- replicaHealth(true, fetch) }()
	<-started // the first asker is now fetching
	second := make(chan map[string]device.Health)
	go func() { second <- replicaHealth(true, fetch) }()
	select {
	case m := <-second:
		t.Fatalf("the second asker returned %v before the fetch ended", m)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	for i, ch := range []chan map[string]device.Health{first, second} {
		select {
		case m := <-ch:
			if m["sw1"].Status != "ok" {
				t.Fatalf("asker %d got %v", i+1, m)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("asker %d never answered", i+1)
		}
	}
	if fetches != 1 {
		t.Fatalf("%d fetches for two askers", fetches)
	}
}

func resetHealthCache(t *testing.T) {
	t.Helper()
	reset := func() {
		healthCache.mu.Lock()
		healthCache.data, healthCache.at, healthCache.fetching = nil, time.Time{}, false
		healthCache.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// A primary that is slow to answer must not hold a request longer than healthColdWait: the page is answered without the health (the
// devices read "not checked" for a poll) instead of staying blank until the primary has answered.
func TestReplicaHealthColdWaitIsBounded(t *testing.T) {
	resetHealthCache(t)
	old := healthColdWait
	healthColdWait = 100 * time.Millisecond
	t.Cleanup(func() { healthColdWait = old })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fetch := func(bool) (map[string]device.Health, bool) { <-release; return nil, false }
	t0 := time.Now()
	m := replicaHealth(true, fetch)
	if took := time.Since(t0); took > time.Second {
		t.Fatalf("waited %s for a primary that does not answer", took)
	}
	if m == nil || len(m) != 0 {
		t.Fatalf("want an empty map, got %v", m)
	}
}

// With an older answer in hand a request uses it at once; the new one is fetched in the background and used by the next request.
func TestReplicaHealthStaleAnswerIsUsedWhileRefreshing(t *testing.T) {
	resetHealthCache(t)
	healthCache.mu.Lock()
	healthCache.data = map[string]device.Health{"sw1": {Status: "ok"}}
	healthCache.at = time.Now().Add(-time.Minute)
	healthCache.mu.Unlock()
	release, fetched := make(chan struct{}), make(chan struct{})
	fetch := func(bool) (map[string]device.Health, bool) {
		<-release
		defer close(fetched)
		return map[string]device.Health{"sw1": {Status: "bad"}}, true
	}
	t0 := time.Now()
	if m := replicaHealth(true, fetch); m["sw1"].Status != "ok" || time.Since(t0) > time.Second {
		t.Fatalf("want the older answer at once, got %v after %s", m, time.Since(t0))
	}
	close(release)
	<-fetched
	time.Sleep(50 * time.Millisecond)
	if m := replicaHealth(true, fetch); m["sw1"].Status != "bad" {
		t.Fatalf("the refreshed answer was not used: %v", m)
	}
}

// A fetch that failed on a node with nothing yet is tried again in about 2 s, not after the 18 s it was once set to.
func TestReplicaHealthRetriesSoonAfterAFailedFirstFetch(t *testing.T) {
	resetHealthCache(t)
	healthColdWait = 500 * time.Millisecond
	t.Cleanup(func() { healthColdWait = 2 * time.Second })
	calls := 0
	fetch := func(bool) (map[string]device.Health, bool) {
		calls++
		if calls == 1 {
			return nil, false
		}
		return map[string]device.Health{"sw1": {Status: "ok"}}, true
	}
	if m := replicaHealth(true, fetch); len(m) != 0 {
		t.Fatalf("first answer %v", m)
	}
	time.Sleep(2500 * time.Millisecond)
	replicaHealth(true, fetch) // starts the retry (the old answer is used at once)
	time.Sleep(200 * time.Millisecond)
	if m := replicaHealth(true, fetch); m["sw1"].Status != "ok" {
		t.Fatalf("not retried after a failed first fetch: %v (calls %d)", m, calls)
	}
}
