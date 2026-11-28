package core

import (
	"context"
	"testing"
	"time"
)

// A gateway that is paused or restarted has its engines stopped without s.mu held: the stop says goodbye to the group
// and tears interfaces down, and every status request needs s.mu, so a slow stop used to leave the whole node unable
// to answer the cluster (and the web pages) until it was over.
func TestRestartStopsEnginesOutsideTheLock(t *testing.T) {
	old := leaveGrace
	leaveGrace = 700 * time.Millisecond
	defer func() { leaveGrace = old }()

	g := DefaultGroup()
	g.Interface = "netdirnone0"
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)

	e := newTestEngine() // a controller that says goodbye for leaveGrace when it stops
	e.cfg.GroupID = g.GroupID
	e.cfg.Neighbors = []string{"10.0.0.9"}
	e.conn = &capConn{}
	e.state = stateSpeak
	e.Mu.Lock()
	e.runElectionLocked()
	e.Mu.Unlock()
	s.Mu.Lock()
	s.engines[engineKey{g.GroupID, AfIPv4}] = e
	s.Mu.Unlock()

	nu := *dc
	nu.Groups = []GroupConfig{g}
	nu.Groups[0].Paused = true // restartDiffers: the engines are stopped
	done := make(chan struct{})
	go func() { s.Reload(&nu); close(done) }()
	time.Sleep(150 * time.Millisecond) // the stop is under way and sleeping

	got := make(chan struct{})
	go func() { s.EngineList(); close(got) }()
	select {
	case <-got:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("s.mu was held while the engines were stopping")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reload did not finish")
	}
	if s.EngineList() != nil && len(s.EngineList()) != 0 {
		t.Fatalf("the paused gateway still has engines: %d", len(s.EngineList()))
	}
}
