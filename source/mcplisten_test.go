package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"netdir/internal/core"
	"netdir/internal/mcp"
)

// A listener per gateway address serves /mcp and nothing else; the set follows the configuration.
func TestMCPListenersFollowTheConfig(t *testing.T) {
	e, _ := mcpEnv(t, "127.0.0.1 rw")
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Groups = []core.GroupConfig{{GroupID: 7, VIP4: "127.0.0.77/8"}}
	sup.Dc.Settings.MCPPort = port
	sup.Mu.Unlock()
	m := mcp.NewMCPListeners(e.ws)
	m.Start()
	defer m.Stop()
	if !core.McpServing.Load() {
		t.Fatal("not serving")
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}
	base := "https://127.0.0.77:" + strconv.Itoa(port)
	res, err := cl.Post(base+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == 404 {
		t.Fatalf("/mcp: %d", res.StatusCode)
	}
	for _, p := range []string{"/", "/api/session", "/metrics"} {
		r, err := cl.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatalf("%s on a gateway address: %d, want 404", p, r.StatusCode)
		}
	}
	// the gateway is paused here: its listener goes
	sup.Mu.Lock()
	sup.Dc.Groups[0].Paused = true
	sup.Mu.Unlock()
	m.Reconcile()
	if _, err := cl.Get(base + "/mcp"); err == nil {
		t.Fatal("a paused gateway still answers /mcp")
	}
}
