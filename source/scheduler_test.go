package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func mustTask(t *testing.T, s SchedTask) SchedTask {
	t.Helper()
	if s.Name == "" {
		s.Name = "t"
	}
	if s.Action == "" {
		s.Action = "stats_clear"
	}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func dates(l []time.Time) string {
	var p []string
	for _, x := range l {
		p = append(p, x.Format("01-02 15:04"))
	}
	return strings.Join(p, ",")
}

func TestScheduleOffsetStaysInTheWindow(t *testing.T) {
	base := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if schedOffset("n1", "a", base, 0) != 0 {
		t.Fatal("no window, but an offset")
	}
	seen := map[time.Duration]bool{}
	for _, n := range []string{"n1", "n2", "n3", "n4", "n5", "n6"} {
		o := schedOffset(n, "a", base, 3600)
		if o < 0 || o > time.Hour {
			t.Fatalf("%s: offset %v is outside the window", n, o)
		}
		if o != schedOffset(n, "a", base, 3600) {
			t.Fatal("the offset changed between calls")
		}
		seen[o] = true
	}
	if len(seen) < 4 {
		t.Fatalf("the nodes were not spread over the window: %v", seen)
	}
}

type schedHarness struct {
	s   *Scheduler
	now time.Time
	mu  sync.Mutex
	ran []string
}

func newHarness(t *testing.T, tasks ...SchedTask) *schedHarness {
	h := &schedHarness{now: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}
	h.s = newScheduler(nil, t.TempDir())
	h.s.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now }
	h.s.act = func(action, actor string) (string, error) {
		h.mu.Lock()
		h.ran = append(h.ran, action)
		h.mu.Unlock()
		return "done", nil
	}
	h.s.SetTasks(tasks)
	return h
}

func (h *schedHarness) at(tm time.Time) { h.mu.Lock(); h.now = tm; h.mu.Unlock() }
func (h *schedHarness) count() int      { h.mu.Lock(); defer h.mu.Unlock(); return len(h.ran) }

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestSchedulerShellCommand(t *testing.T) {
	h := newHarness(t)
	ok := mustTask(t, SchedTask{ID: "s1", Name: "echo", Action: "shell", Command: "echo hello; echo oops >&2", Freq: "daily"})
	slow := mustTask(t, SchedTask{ID: "s2", Name: "slow", Action: "shell", Command: "sleep 30", TimeoutSec: 1, Freq: "daily"})
	bad := mustTask(t, SchedTask{ID: "s3", Name: "bad", Action: "shell", Command: "exit 3", Freq: "daily"})
	ign := mustTask(t, SchedTask{ID: "s4", Name: "ign", Action: "shell", Command: "echo stopped; exit 3", IgnoreExit: true, Freq: "daily"})
	ignSlow := mustTask(t, SchedTask{ID: "s5", Name: "ignslow", Action: "shell", Command: "sleep 30", TimeoutSec: 1, IgnoreExit: true, Freq: "daily"})
	h.s.SetTasks([]SchedTask{ok, slow, bad, ign, ignSlow})
	idle := func() bool {
		for _, r := range h.s.Status().History {
			if r.Status == "running" {
				return false
			}
		}
		return true
	}
	for _, id := range []string{"s1", "s2", "s3", "s4", "s5"} { // one at a time
		if err := h.s.RunNow(id, "test"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, idle)
	}
	by := map[string]SchedRun{}
	for _, r := range h.s.Status().History {
		by[r.Task] = r
	}
	if by["s1"].Status != "ok" || !strings.Contains(by["s1"].Output, "hello") || !strings.Contains(by["s1"].Output, "oops") {
		t.Errorf("echo: %+v", by["s1"])
	}
	if by["s2"].Status != "failed" || !strings.Contains(by["s2"].Output, "stopped after") {
		t.Errorf("a command over its limit: %+v", by["s2"])
	}
	if by["s3"].Status != "failed" {
		t.Errorf("exit 3: %+v", by["s3"])
	}
	if by["s4"].Status != "ok" || !strings.Contains(by["s4"].Output, "stopped") || !strings.Contains(by["s4"].Output, "exit status 3, ignored") {
		t.Errorf("exit 3 with the status ignored: %+v", by["s4"])
	}
	if by["s5"].Status != "failed" {
		t.Errorf("a command over its limit fails even when the status is ignored: %+v", by["s5"])
	}
}

func TestSchedEnvHasTheUsualPaths(t *testing.T) {
	env := schedEnv([]string{"PATH=/opt/x/bin", "LANG=C"}, "job")
	m := map[string]string{}
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i > 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	for _, p := range []string{"/opt/x/bin", "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if !strings.Contains(":"+m["PATH"]+":", ":"+p+":") {
			t.Errorf("PATH %q lacks %s", m["PATH"], p)
		}
	}
	if m["HOME"] != "/root" || m["LANG"] != "C" {
		t.Errorf("env %v", m)
	}
	if got := schedEnv(nil, "job"); len(got) < 2 {
		t.Errorf("empty base: %v", got)
	}
}

// With auto-update on, the online update task is for one node of a cluster; alone, or with auto-update off, it is not asked.
func TestOnlineUpdateNeedsOneNode(t *testing.T) {
	every := SchedTask{Action: "update_online"}
	one := SchedTask{Action: "update_online", Nodes: []string{"a"}}
	two := SchedTask{Action: "update_online", Nodes: []string{"a", "b"}}
	other := SchedTask{Action: "stats_clear"}
	for _, c := range []struct {
		t       SchedTask
		auto    bool
		cluster bool
		want    bool
	}{
		{every, true, true, true}, {two, true, true, true}, {one, true, true, false},
		{every, false, true, false}, {every, true, false, false}, {other, true, true, false},
	} {
		if got := onlineUpdateNeedsOneNode(c.t, c.auto, c.cluster); got != c.want {
			t.Errorf("%+v auto=%v cluster=%v: got %v", c.t, c.auto, c.cluster, got)
		}
	}
	mg := newPowerMgmt(t)
	if st := mg.sched.Status(); st.AutoUpdate != mg.upd.Intent().AutoAll {
		t.Errorf("status says auto-update %v, the intent %v", st.AutoUpdate, mg.upd.Intent().AutoAll)
	}
}
