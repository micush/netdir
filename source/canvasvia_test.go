package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"netdir/internal/core"
)

// A gateway this node does not run is added from a serving node's answer, nobody starred, in group order.
func TestTakeGatewayRowsAddsTheOtherGroupsWithoutStars(t *testing.T) {
	mine := []core.GatewayGroup{{GroupID: 2, AF: "v4", Members: []core.GatewayMember{{IP: "10.2.0.1", Local: true}}}}
	theirs := []core.GatewayGroup{
		{GroupID: 1, AF: "v6", Members: []core.GatewayMember{{IP: "fd00::1", Local: true}}},
		{GroupID: 1, AF: "v4", Members: []core.GatewayMember{{IP: "10.1.0.1", Local: true}, {IP: "10.1.0.2"}}},
		{GroupID: 2, AF: "v4", Members: []core.GatewayMember{{IP: "10.2.0.9"}}},
	}
	got := takeGatewayRows(mine, theirs, 1)
	if len(got) != 3 || got[0].GroupID != 1 || got[0].AF != "v4" || got[1].AF != "v6" || got[2].GroupID != 2 {
		t.Fatalf("wrong rows or order: %+v", got)
	}
	for _, g := range got[:2] {
		for _, m := range g.Members {
			if m.Local {
				t.Errorf("group %d: %s starred", g.GroupID, m.IP)
			}
		}
	}
	if !got[2].Members[0].Local || got[2].Members[0].IP != "10.2.0.1" {
		t.Errorf("this node's own group changed: %+v", got[2])
	}
	if !theirs[0].Members[0].Local {
		t.Errorf("the answer was modified in place")
	}
}

// A node that does not answer is waited for once (the first look), then never again: it used to cost the page 2 s on every poll.
func TestPeerCanvasOfDoesNotWaitForADeadNodeTwice(t *testing.T) {
	peerCanvasMu.Lock()
	peerCanvases = map[string]*peerCanvas{}
	peerCanvasMu.Unlock()
	oldAsk, oldWait := askPeerCanvas, viaColdWait
	viaColdWait = 300 * time.Millisecond
	asks := 0
	var mu sync.Mutex
	askPeerCanvas = func(*StatusServer, context.Context, string) ([]core.CanvasGateway, bool) {
		mu.Lock()
		asks++
		mu.Unlock()
		time.Sleep(600 * time.Millisecond) // slower than anyone waits
		return nil, false
	}
	t.Cleanup(func() { askPeerCanvas, viaColdWait = oldAsk, oldWait })
	s := &StatusServer{}
	n := core.CanvasNode{Addr: "10.9.9.9:1"}
	t0 := time.Now()
	if d := s.peerCanvasOf(n); d != nil {
		t.Fatalf("got %v from a node that did not answer", d)
	}
	if took := time.Since(t0); took < 250*time.Millisecond || took > 550*time.Millisecond {
		t.Fatalf("the first ask waited %s, want about the cold wait", took)
	}
	time.Sleep(450 * time.Millisecond) // the background ask has ended (failed)
	for i := 0; i < 5; i++ {
		t0 = time.Now()
		s.peerCanvasOf(n)
		if took := time.Since(t0); took > 100*time.Millisecond {
			t.Fatalf("ask %d waited %s for a node already known not to answer", i+2, took)
		}
	}
	time.Sleep(peerCanvasFor) // the retry window has passed: the next ask starts a new background fetch, and still does not wait for it
	t0 = time.Now()
	s.peerCanvasOf(n)
	if took := time.Since(t0); took > 100*time.Millisecond {
		t.Fatalf("a retry of a dead node held the request %s", took)
	}
	for i := 0; i < 100; i++ { // the retry's background ask has started (it reads the stubs): only then are they put back
		mu.Lock()
		n := asks
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}
