package device

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitor(t *testing.T) {
	calls := 0
	d, srv := stub(t, func(r *http.Request) bool { u, p, _ := r.BasicAuth(); return u == "admin" && p == "pw" }, map[string]string{
		"/restconf/data/Cisco-IOS-XE-native:native/hostname": `{"x:hostname":"sw1"}`,
	})
	srv.Config.Handler = countCalls(srv.Config.Handler, &calls)
	d.Name, d.Platform, d.Credential = "sw1", "iosxe", "lab"
	off := d
	off.Name, off.Disabled = "off", true
	dead := d
	dead.Name, dead.Address, dead.Port = "dead", "127.0.0.1", freePort(t)
	creds := []Credential{{Name: "lab", Username: "admin", Password: "pw"}}
	m := NewMonitor()
	m.Timeout = time.Second
	m.IdleReach, m.IdleFacts = 0, 0 // this test is about what a check finds, not how often
	now := time.Unix(1_800_000_000, 0)
	m.Check(context.Background(), []Device{d, off, dead}, creds, now)
	s := m.Snapshot()
	if h := s["sw1"]; h.Status != "ok" || h.Facts == nil || h.Facts.Hostname != "sw1" || h.LastOK != now.Unix() {
		t.Fatalf("sw1: %+v", h)
	}
	if h := s["off"]; h.Status != "paused" {
		t.Fatalf("a disabled device is contacted: %+v", h)
	}
	if h := s["dead"]; h.Status != "bad" || !strings.Contains(h.Detail, "does not answer") {
		t.Fatalf("dead: %+v", h)
	}
	// the facts are not asked again before FactsEvery
	before := calls
	m.Check(context.Background(), []Device{d}, creds, now.Add(time.Minute))
	if calls != before {
		t.Fatalf("facts asked again after a minute (%d requests)", calls-before)
	}
	if _, ok := m.Snapshot()["dead"]; ok {
		t.Fatal("a device that left the inventory is still kept")
	}
	// a wrong password: the port answers, the request does not; the last facts are kept, the password never shows
	bad := []Credential{{Name: "lab", Username: "admin", Password: "wrong-secret"}}
	m.Check(context.Background(), []Device{d}, bad, now.Add(10*time.Minute))
	if h := m.Snapshot()["sw1"]; h.Status != "warn" || h.Facts == nil || strings.Contains(h.Detail, "wrong-secret") || h.LastOK != now.Unix() {
		t.Fatalf("wrong password: %+v", h)
	}
}

func TestMonitorUnreachableWhenDialFails(t *testing.T) {
	od := dialFn
	dialFn = func(context.Context, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	}
	defer func() { dialFn = od }()
	m := NewMonitor()
	m.Check(context.Background(), []Device{{Name: "a", Platform: "iosxe", Address: "192.0.2.1", Credential: "c"}}, nil, time.Now())
	if h := m.Snapshot()["a"]; h.Status != "bad" || h.Detail != "the API port does not answer: connection refused" {
		t.Fatalf("%+v", h)
	}
}

func countCalls(h http.Handler, n *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { *n++; h.ServeHTTP(w, r) })
}

// freePort is a TCP port on loopback that nothing listens on.
func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

// while nobody is looking the facts are asked rarely; looking (Touch) brings back the short interval
func TestMonitorQuietWhenNobodyLooks(t *testing.T) {
	calls := 0
	d, srv := stub(t, func(r *http.Request) bool { return true }, map[string]string{
		"/restconf/data/Cisco-IOS-XE-native:native/hostname": `{"x:hostname":"sw1"}`,
	})
	srv.Config.Handler = countCalls(srv.Config.Handler, &calls)
	d.Name, d.Platform, d.Credential = "sw1", "iosxe", "lab"
	creds := []Credential{{Name: "lab", Username: "admin", Password: "pw"}}
	m := NewMonitor()
	m.Timeout = time.Second
	now := time.Now()
	if r, f := m.intervals(now); r != 3*time.Minute || f != 6*time.Hour {
		t.Fatalf("quiet intervals %v %v", r, f)
	}
	m.Check(context.Background(), []Device{d}, creds, now) // first sight: the facts are asked
	first := calls
	if first == 0 {
		t.Fatal("the facts were not asked at first sight")
	}
	m.Check(context.Background(), []Device{d}, creds, now.Add(30*time.Minute))
	if calls != first {
		t.Errorf("facts asked after 30 minutes with nobody looking (%d requests)", calls-first)
	}
	m.Tune = func() Tuning { return Tuning{Reach: 10 * time.Minute, Facts: 45 * time.Minute} }
	if r, f := m.intervals(now); r != 10*time.Minute || f != 45*time.Minute {
		t.Errorf("tuned intervals %v %v", r, f)
	}
	m.Tune = func() Tuning { return Tuning{Reach: time.Second, Facts: time.Second} } // never shorter than while looking
	if r, f := m.intervals(now); r != 30*time.Second || f != 5*time.Minute {
		t.Errorf("a tuned interval shorter than the watched one: %v %v", r, f)
	}
	m.Tune = func() Tuning { return Tuning{LiveReach: 15 * time.Second, LiveFacts: 2 * time.Minute} }
	m.Touch()
	if r, f := m.intervals(time.Now()); r != 15*time.Second || f != 2*time.Minute {
		t.Errorf("tuned watched intervals %v %v", r, f)
	}
	if r, f := m.intervals(time.Now().Add(time.Hour)); r != 3*time.Minute || f != 6*time.Hour {
		t.Errorf("quiet intervals with a tuned watched pair %v %v", r, f)
	}
	m.Tune = nil
	if !m.watched(time.Now()) {
		t.Fatal("not watched after a Touch")
	}
	if r, f := m.intervals(time.Now()); r != 30*time.Second || f != 5*time.Minute {
		t.Errorf("watched intervals %v %v", r, f)
	}
	m.Check(context.Background(), []Device{d}, creds, time.Now().Add(6*time.Minute))
	if calls == first {
		t.Error("facts not asked again 6 minutes after a look")
	}
	// a Touch after a quiet time wakes the loop once
	m2 := NewMonitor()
	m2.Touch()
	select {
	case <-m2.wake:
	default:
		t.Error("the first look after a quiet time did not wake the checks")
	}
	m2.Touch()
	select {
	case <-m2.wake:
		t.Error("a second look woke the checks again")
	default:
	}
}

func TestMonitorInactiveDoesNotCheck(t *testing.T) {
	m := NewMonitor()
	var active atomic.Bool
	m.Active = active.Load
	m.InactiveWait = 10 * time.Millisecond
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx, func() ([]Device, []Credential) {
		calls.Add(1)
		return nil, nil
	})
	time.Sleep(80 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("inactive node listed devices %d times", n)
	}
	active.Store(true)
	time.Sleep(80 * time.Millisecond)
	if calls.Load() == 0 {
		t.Fatal("node did not start checking once active")
	}
}
