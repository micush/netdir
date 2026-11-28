package main

import (
	"testing"
	"time"

	"netdir/internal/mcp"
)

func TestMCPRequestsCountAsClients(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1")
	_ = e
	mcp.McpSeen.At = map[mcp.McpSeenKey]time.Time{}
	if n := len(mcp.McpSeen.Callers("127.0.0.1")); n != 0 {
		t.Fatalf("%d clients before any request", n)
	}
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`) // the handshake alone is a client
	if n := len(mcp.McpSeen.Callers("127.0.0.1")); n != 1 {
		t.Fatalf("clients after initialize = %d, want 1", n)
	}
}

func TestMCPRefusedRequestIsNotAClient(t *testing.T) {
	_, post := mcpEnv(t) // an empty access list: nobody may use it
	mcp.McpSeen.At = map[mcp.McpSeenKey]time.Time{}
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 403 {
		t.Fatalf("status %d, want 403", code)
	}
	if n := len(mcp.McpSeen.Callers("127.0.0.1")); n != 0 {
		t.Fatalf("a refused request counted as a client")
	}
}
