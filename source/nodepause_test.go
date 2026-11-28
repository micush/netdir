package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestNodePauseThroughMgmt(t *testing.T) {
	mg := newPowerMgmt(t)
	if err := core.NewDaemonConfig().Save(mg.confPath); err != nil {
		t.Fatal(err)
	}
	if st, err := mg.NodePauseStatus(); err != nil || st.Paused {
		t.Fatalf("fresh node: %+v %v", st, err)
	}
	// the only node in service cannot be paused: nothing would answer
	mg.othersFn = func() int { return 0 }
	if _, err := mg.NodePause(true, "test"); err == nil || !strings.Contains(err.Error(), "only node in service") {
		t.Fatalf("pausing the only node: %v", err)
	}
	if st, _ := mg.NodePauseStatus(); st.Paused {
		t.Fatal("the refused pause was saved")
	}
	// other nodes exist, but this one is the last to serve a gateway: refused, and not saved
	mg.othersFn = func() int { return 2 }
	mg.lastFn = func() string { return "this is the only node serving gateway 1" }
	if _, err := mg.NodePause(true, "test"); err == nil || !strings.Contains(err.Error(), "only node serving gateway 1") {
		t.Fatalf("pausing the last node of a gateway: %v", err)
	}
	if st, _ := mg.NodePauseStatus(); st.Paused {
		t.Fatal("the refused pause was saved")
	}
	mg.lastFn = nil
	mg.othersFn = func() int { return 1 } // another node carries on
	if msg, err := mg.NodePause(true, "test"); err != nil || !strings.Contains(msg, "paused") {
		t.Fatalf("pause: %q %v", msg, err)
	}
	if st, _ := mg.NodePauseStatus(); !st.Paused {
		t.Fatal("not paused in the file")
	}
	if msg, _ := mg.NodePause(true, "test"); !strings.Contains(msg, "already paused") {
		t.Fatalf("second pause: %q", msg)
	}
	if _, err := mg.Op("node.pause", json.RawMessage(`{"paused":false}`), "test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := mg.NodePauseStatus(); st.Paused {
		t.Fatal("still paused after resume")
	}
}

func TestPausingThePrimaryMovesTheRole(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	a.sync()
	b.sync()
	paused := false
	a.mg.pausedFn = func() bool { return paused }
	a.mg.othersFn = func() int { return 1 }
	a.mg.lastFn = func() string { return "" }
	if a.mg.cl.Snapshot().Role != core.RolePrimary {
		t.Fatal("A should start as the primary")
	}
	msg, err := a.mg.NodePause(true, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, b.addr+" is now the primary") {
		t.Fatalf("message %q", msg)
	}
	if b.mg.cl.Snapshot().Role != core.RolePrimary || a.mg.cl.Snapshot().Role == core.RolePrimary {
		t.Fatalf("roles after the pause: A=%s B=%s", a.mg.cl.Snapshot().Role, b.mg.cl.Snapshot().Role)
	}
}

func TestPausedNodeCannotBePromoted(t *testing.T) {
	a := newTNode(t, "A")
	a.mg.pausedFn = func() bool { return true }
	if _, err := a.mg.Op("cluster.promote", nil, "tester"); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("a paused node must refuse to become the primary: %v", err)
	}
}

func TestNodePauseStartsNothingAndShowsOnTheCanvas(t *testing.T) {
	g := core.DefaultGroup()
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{g}
	dc.NodePaused = true

	sup := core.NewSupervisor(context.Background(), dc)
	sup.StartAll()
	if n := len(sup.EngineList()); n != 0 {
		t.Fatalf("a paused node must start no engines, got %d", n)
	}
	cv := buildCanvas(sup.Config(), nil)[0]
	if cv.Status != "paused" || !cv.Paused || !cv.NodePaused || !strings.Contains(cv.Detail, "This node is paused") {
		t.Fatalf("canvas: %+v", cv)
	}
	// a reload that keeps the node paused changes nothing
	nu := *dc
	sup.Reload(&nu)
	if n := len(sup.EngineList()); n != 0 {
		t.Fatalf("still paused after a reload, got %d engines", n)
	}
	sup.StopAll()
}
