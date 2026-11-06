package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSchedulerUpdateOnlineWhenAlreadyNewest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			w.Write([]byte(`{"tag_name":"v1"}`))
			return
		}
		t.Errorf("nothing else may be fetched, got %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	oa, oh := ghAPI, ghHost
	ghAPI, ghHost = srv.URL, srv.URL
	defer func() { ghAPI, ghHost = oa, oh }()
	mg := newPowerMgmt(t)
	out, err := mg.sched.builtin("update_online", "test")
	if err != nil || !strings.Contains(out, "up to date") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestSchedulerUpdateOnlineCannotReach(t *testing.T) {
	oa := ghAPI
	ghAPI = "http://127.0.0.1:1"
	defer func() { ghAPI = oa }()
	mg := newPowerMgmt(t)
	if _, err := mg.sched.builtin("update_online", "test"); err == nil {
		t.Fatal("an unreachable GitHub must fail the task")
	}
}

func TestSchedulerRebootsTheHost(t *testing.T) {
	pc := fakePower(t)
	od := schedActionDelay
	schedActionDelay = 1
	defer func() { schedActionDelay = od }()
	mg := newPowerMgmt(t)
	out, err := mg.sched.builtin("node_reboot", "test")
	if err != nil || !strings.Contains(out, "reboot") {
		t.Fatalf("%q %v", out, err)
	}
	calls := waitCalls(t, pc, 1)
	if len(calls) == 0 || !strings.Contains(strings.Join(calls, " "), "reboot") {
		t.Fatalf("calls %v", calls)
	}
}

func TestSchedRunAllOnAMemberlessNode(t *testing.T) {
	mg := newPowerMgmt(t)
	mg.sched.SetTasks([]SchedTask{mustTask(t, SchedTask{ID: "a1", Name: "a", Action: "shell", Command: "true", Freq: "daily"})})
	out, err := mg.SchedRunAll("a1", "me")
	if err != nil || len(out) != 1 {
		t.Fatalf("%v %v", out, err)
	}
	for _, v := range out {
		if v != "started" {
			t.Fatalf("%q", v)
		}
	}
	if _, err := mg.SchedRunAll("nope", "me"); err == nil {
		t.Fatal("unknown task")
	}
	waitFor(t, func() bool {
		for _, r := range mg.sched.Status().History {
			if r.Status == "running" {
				return false
			}
		}
		return len(mg.sched.Status().History) > 0
	})
}

func TestReleaseNameSaysItOnce(t *testing.T) {
	if got := releaseName("v80", "80"); got != "v80" {
		t.Fatalf("same tag and version: %q", got)
	}
	if got := releaseName("v80-rc1", "80"); got != "v80-rc1 (v80)" {
		t.Fatalf("different: %q", got)
	}
}
