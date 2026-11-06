package device

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
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
