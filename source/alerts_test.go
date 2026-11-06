package main

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type alertRig struct {
	t    *testing.T
	e    *AlertEngine
	cfg  *AlertsConfig
	now  time.Time
	bad  bool
	val  float64
	rule string
	mu   sync.Mutex
	sent []string
}

func newAlertRig(t *testing.T, rule string, r AlertRule) *alertRig {
	g := &alertRig{t: t, rule: rule, now: time.Unix(1_700_000_000, 0)}
	g.cfg = &AlertsConfig{Webhook: "http://hook.example/x", Rules: map[string]AlertRule{rule: r}}
	if err := g.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g.e = NewAlertEngine(t.TempDir(), "node1", func() *AlertsConfig { return g.cfg })
	g.e.now = func() time.Time { return g.now }
	g.e.send = func(u string, b []byte) error {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		g.mu.Lock()
		g.sent = append(g.sent, m["event"].(string))
		g.mu.Unlock()
		return nil
	}
	g.e.sample = func(time.Time) []alertSample {
		return []alertSample{{Rule: g.rule, Subject: "s1", Bad: g.bad, Value: g.val, Message: "msg"}}
	}
	return g
}

// step makes n checks, alertTick apart, with the condition bad or good.
func (g *alertRig) step(bad bool, n int) {
	g.bad = bad
	for i := 0; i < n; i++ {
		g.now = g.now.Add(alertTick)
		g.e.Tick()
	}
	time.Sleep(10 * time.Millisecond) // the webhook goes out in a goroutine
}

func (g *alertRig) open() int {
	n := 0
	for _, a := range g.e.View().Alerts {
		if a.Closed == 0 {
			n++
		}
	}
	return n
}

func (g *alertRig) events() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.Join(g.sent, ",")
}

func TestAlertValueNeedsToStayPastTheThreshold(t *testing.T) {
	forMin := 1
	g := newAlertRig(t, "cpu_high", AlertRule{Threshold: 80, ForMin: &forMin})
	g.val = 95
	g.step(true, 3) // 45 s
	if g.open() != 0 {
		t.Fatal("opened before the minute")
	}
	g.step(true, 2)
	if g.open() != 1 {
		t.Fatal("not open after the minute")
	}
	g.val = 10
	g.step(false, 19) // 4m45s of good, the default clear is 5 minutes
	if g.open() != 1 {
		t.Fatal("closed before 5 minutes of good")
	}
	g.step(false, 2)
	if g.open() != 0 {
		t.Fatal("not closed after 5 minutes of good")
	}
}

// The alerts of any node can be seen and handled from the GUI of another one.
func TestAlertsCanBeRelayedToAnotherNode(t *testing.T) {
	for _, c := range [][2]string{{"GET", "/api/alerts"}, {"POST", "/api/alerts/ack"}, {"POST", "/api/alerts/silence"}, {"POST", "/api/alerts/resolve"}, {"POST", "/api/alerts/fix"}, {"POST", "/api/alerts/test"}} {
		if err := proxyAllowed(c[0], c[1]); err != nil {
			t.Errorf("%s %s: %v", c[0], c[1], err)
		}
	}
}

// Alerts opened in the same second must come out in one fixed order on every View, not in the
// map's order: the Alerts page polls, and rows that swap places look like values changing.
func TestAlertViewOrderStableForSameSecond(t *testing.T) {
	e := NewAlertEngine(t.TempDir(), "node1", func() *AlertsConfig { return &AlertsConfig{} })
	e.now = func() time.Time { return time.Unix(1_700_000_100, 0) }
	add := func(id, rule, subject string, opened, closed int64) {
		e.alerts[id] = &Alert{ID: id, Rule: rule, Subject: subject, Node: "node1", Opened: opened, Closed: closed}
	}
	add("c3", "upstream_down", "203.0.113.3", 1000, 1360)
	add("a1", "upstream_falseticker", "203.0.113.1", 1000, 1360)
	add("b2", "upstream_down", "203.0.113.2", 1000, 1360)
	add("d4", "listener_down", "gateway 100 v4", 2000, 2180)
	add("e5", "upstream_down", "203.0.113.2", 1000, 1360) // same subject too: the ID decides
	want := []string{"d4", "b2", "e5", "c3", "a1"}
	for i := 0; i < 200; i++ {
		var got []string
		for _, a := range e.View().Alerts {
			got = append(got, a.ID)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("view %d: order %v, want %v", i, got, want)
		}
	}
}
