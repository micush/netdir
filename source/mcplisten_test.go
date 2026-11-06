package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGatewayAddrs(t *testing.T) {
	dc := newDaemonConfig()
	g := &dc.Groups[0]
	g.GroupID, g.VIP4, g.VIP6 = 7, "10.0.0.1/24", "2001:db8::1/64"
	g.MoreVIP4 = []string{"10.0.0.2"}
	g.ExtraVIPs = []string{"203.0.113.5"}
	dc.Groups = append(dc.Groups, GroupConfig{GroupID: 8, VIP4: "10.9.0.1/24", Paused: true})
	got := func(serving bool) string {
		var s []string
		for _, a := range gatewayAddrs(dc, serving) {
			s = append(s, a.String())
		}
		return strings.Join(s, " ")
	}
	if all := got(false); all != "10.0.0.1 10.0.0.2 10.9.0.1 203.0.113.5 2001:db8::1" {
		t.Fatalf("all addresses: %s", all)
	}
	if now := got(true); strings.Contains(now, "10.9.0.1") || !strings.Contains(now, "203.0.113.5") {
		t.Fatalf("a paused gateway has no listener: %s", now)
	}
	if gatewayAddrs(nil, true) != nil {
		t.Fatal("no configuration, no addresses")
	}
}

func TestMCPPortSetting(t *testing.T) {
	dc := newDaemonConfig()
	if dc.Settings.mcpPort() != 443 {
		t.Fatalf("default port %d", dc.Settings.mcpPort())
	}
	dc.Settings.MCPPort = 70000
	if err := dc.Validate(); err == nil {
		t.Fatal("port 70000 accepted")
	}
	dc.Settings.MCPPort = 22161 // the GUI's port
	if err := dc.Validate(); err == nil {
		t.Fatal("the GUI's port accepted for MCP")
	}
	dc.Settings.MCPPort = 8443
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The GUI refuses a connection that arrived on a gateway address.
func TestNoGatewayListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	blocked := netip.MustParseAddr("127.0.0.1")
	nl := noGatewayListener{Listener: ln, blocked: func(a netip.Addr) bool { return a == blocked }}
	done := make(chan error, 1)
	go func() { _, err := nl.Accept(); done <- err }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("a blocked connection should be closed: %v", err)
	}
	ln.Close()
	<-done
}

// A listener per gateway address serves /mcp and nothing else; the set follows the configuration.
func TestMCPListenersFollowTheConfig(t *testing.T) {
	e, _ := mcpEnv(t, "127.0.0.1 rw")
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Groups = []GroupConfig{{GroupID: 7, VIP4: "127.0.0.77/8"}}
	sup.dc.Settings.MCPPort = port
	sup.mu.Unlock()
	m := newMCPListeners(e.ws)
	m.Start()
	defer m.Stop()
	if !mcpServing.Load() {
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
	sup.mu.Lock()
	sup.dc.Groups[0].Paused = true
	sup.mu.Unlock()
	m.reconcile()
	if _, err := cl.Get(base + "/mcp"); err == nil {
		t.Fatal("a paused gateway still answers /mcp")
	}
}
