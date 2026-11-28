package main

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netdir/internal/core"
)

type powerCalls struct {
	mu    sync.Mutex
	calls []string
}

func (p *powerCalls) add(n string, a ...string) error {
	p.mu.Lock()
	p.calls = append(p.calls, n+" "+strings.Join(a, " "))
	p.mu.Unlock()
	return nil
}
func (p *powerCalls) get() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func fakePower(t *testing.T) *powerCalls {
	pc := &powerCalls{}
	or, os_, od := core.PowerRun, core.PowerStart, core.PowerDelay
	core.PowerRun = func(n string, a ...string) error { return pc.add(n, a...) }
	core.PowerStart = func(n string, a ...string) error { return pc.add(n, a...) }
	core.PowerDelay = time.Millisecond
	t.Cleanup(func() { core.PowerRun, core.PowerStart, core.PowerDelay = or, os_, od })
	return pc
}

func newPowerMgmt(t *testing.T) *Mgmt {
	mg, err := NewMgmt(filepath.Join(t.TempDir(), "netdir.conf"), filepath.Join(t.TempDir(), "state"), core.NewDaemonConfig())
	if err != nil {
		t.Fatal(err)
	}
	return mg
}

func waitCalls(t *testing.T, pc *powerCalls, n int) []string {
	t.Helper()
	for i := 0; i < 200 && len(pc.get()) < n; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	return pc.get()
}

func TestPowerRequests(t *testing.T) {
	pc := fakePower(t)
	m := newPowerMgmt(t)
	cases := []struct {
		r    core.PowerReq
		want string
	}{
		{core.PowerReq{Action: "restart"}, "systemctl reboot"},
		{core.PowerReq{Action: "shutdown", When: "now"}, "systemctl poweroff"},
		{core.PowerReq{Action: "restart", When: "in", Minutes: 5}, "shutdown -r +5"},
		{core.PowerReq{Action: "shutdown", When: "at", Time: "02:30"}, "shutdown -h 02:30"},
	}
	for _, c := range cases {
		before := len(pc.get())
		if _, err := m.Power(c.r, "tester"); err != nil {
			t.Fatalf("%+v: %v", c.r, err)
		}
		got := waitCalls(t, pc, before+1)
		if len(got) != before+1 || got[before] != c.want {
			t.Errorf("%+v ran %v, want %q", c.r, got[before:], c.want)
		}
	}
	for _, bad := range []core.PowerReq{
		{Action: "explode"}, {Action: "restart", When: "in"}, {Action: "restart", When: "in", Minutes: core.MaxPowerMinutes + 1},
		{Action: "restart", When: "at", Time: "25:00"}, {Action: "restart", When: "tomorrow"},
	} {
		if _, err := m.Power(bad, "tester"); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	n := len(pc.get())
	if _, err := m.Power(core.PowerReq{Action: "cancel"}, "tester"); err != nil {
		t.Fatal(err)
	}
	if got := pc.get(); len(got) != n+1 || got[n] != "shutdown -c" {
		t.Fatalf("cancel ran %v", got[n:])
	}
}

// An immediate action must not take the last serving member of a gateway down.
func TestPowerRefusesLastServingMember(t *testing.T) {
	pc := fakePower(t)
	m := newPowerMgmt(t)
	m.gwFn = func() []core.GwState { return []core.GwState{{GroupID: 1, Serving: true}} }
	if _, err := m.Power(core.PowerReq{Action: "restart"}, "tester"); err == nil || !strings.HasPrefix(err.Error(), "not safe to restart") {
		t.Fatalf("expected the safety refusal, got %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	if len(pc.get()) != 0 {
		t.Fatalf("ran %v although refused", pc.get())
	}
	// a scheduled action is not gated; forcing goes ahead
	if _, err := m.Power(core.PowerReq{Action: "restart", When: "in", Minutes: 5}, "tester"); err != nil {
		t.Fatalf("scheduled: %v", err)
	}
	if _, err := m.Power(core.PowerReq{Action: "restart", Force: true}, "tester"); err != nil {
		t.Fatalf("forced: %v", err)
	}
	if got := waitCalls(t, pc, 2); len(got) != 2 {
		t.Fatalf("calls: %v", got)
	}
}
