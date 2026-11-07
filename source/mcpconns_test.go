package main

import (
	"strings"
	"testing"
	"time"
)

func TestMCPClientsCountsCallersInTheWindow(t *testing.T) {
	now := time.Now()
	s := &mcpSeenSet{at: map[mcpSeenKey]time.Time{}, now: func() time.Time { return now }}
	s.record("10.0.0.1", "laptop")
	s.record("10.0.0.1", "laptop") // the same caller again is one
	s.record("10.0.0.1", "10.0.0.51")
	s.record("10.0.0.9", "ci")
	if n := len(s.callers("10.0.0.1/24")); n != 2 {
		t.Fatalf("clients on 10.0.0.1 = %d, want 2", n)
	}
	if n := len(s.callers("10.0.0.1", "10.0.0.9")); n != 3 {
		t.Fatalf("clients on both addresses = %d, want 3", n)
	}
	for _, c := range s.callers("10.0.0.1", "10.0.0.9") {
		if strings.Contains(c, "laptop") || strings.Contains(c, "10.0.0.51") {
			t.Fatalf("a caller is shown as %q: only a hash may leave the node", c)
		}
	}
	now = now.Add(mcpClientWindow - time.Second)
	s.record("10.0.0.1", "laptop")
	now = now.Add(2 * time.Second) // the others are now past the window, laptop is not
	if n := len(s.callers("10.0.0.1", "10.0.0.9")); n != 1 {
		t.Fatalf("after the window: %d, want 1", n)
	}
}

func TestMCPRequestsCountAsClients(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1")
	_ = e
	mcpSeen.at = map[mcpSeenKey]time.Time{}
	if n := len(mcpSeen.callers("127.0.0.1")); n != 0 {
		t.Fatalf("%d clients before any request", n)
	}
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`) // the handshake alone is a client
	if n := len(mcpSeen.callers("127.0.0.1")); n != 1 {
		t.Fatalf("clients after initialize = %d, want 1", n)
	}
}

func TestMCPRefusedRequestIsNotAClient(t *testing.T) {
	_, post := mcpEnv(t) // an empty access list: nobody may use it
	mcpSeen.at = map[mcpSeenKey]time.Time{}
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 403 {
		t.Fatalf("status %d, want 403", code)
	}
	if n := len(mcpSeen.callers("127.0.0.1")); n != 0 {
		t.Fatalf("a refused request counted as a client")
	}
}
