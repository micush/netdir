package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netdir/device"
)

// toolsEnv is an MCP endpoint with two gateways, paris and london; the network tools device is on the gateways named in on.
func toolsEnv(t *testing.T, on ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any), map[string]string) {
	t.Helper()
	e, post := mcpEnv(t, "127.0.0.1")
	kro, klim := testMCPKey(), testMCPKey()
	keys, err := normMCPKeys([]MCPKey{{Name: "ro", Access: "ro", Key: kro}, {Name: "lim", Access: "rw", Key: klim, Devices: []string{"none"}}})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.MCPKeys = keys
	sup.dc.Settings.Devices = []device.Device{{Name: "tools", Platform: "tools", Address: "localhost"}}
	for i := range sup.dc.Groups {
		sup.dc.Groups[i].Devices = nil
	}
	sup.dc.Groups = []GroupConfig{{GroupID: 161, Name: "paris"}, {GroupID: 162, Name: "london"}}
	for i := range sup.dc.Groups {
		for _, n := range on {
			if strings.EqualFold(sup.dc.Groups[i].Name, n) {
				sup.dc.Groups[i].Devices = []string{"tools"}
			}
		}
	}
	sup.mu.Unlock()
	return e, post, map[string]string{"ro": kro, "lim": klim}
}

// The network tools: who is offered them, what is refused before anything runs, and that they are only for a gateway that has them.
func TestMCPNetTools(t *testing.T) {
	_, post, k := toolsEnv(t)
	auth := func(k string) []string { return []string{"Authorization", "Bearer " + k} }
	has := func(k string) map[string]bool {
		_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, auth(k)...)
		got := map[string]bool{}
		for _, n := range toolNames(t, m) {
			got[n] = true
		}
		return got
	}
	all := []string{"net_ping", "net_mtr", "net_dig", "net_curl", "net_whois", "net_scan"}
	g := has(k["ro"])
	for _, n := range all {
		if !g[n] {
			t.Errorf("a read-only key is not offered %s", n)
		}
	}
	g = has(k["lim"])
	for _, n := range all {
		if g[n] {
			t.Errorf("a key limited to devices is offered %s", n)
		}
	}
	call := func(tool, args string) (string, bool) {
		_, m := post(mcpCall(tool, args), auth(k["ro"])...)
		return toolResult(t, m)
	}
	// no gateway has the tools yet
	if txt, isErr := call("net_ping", `{"host":"10.1.1.1"}`); !isErr || !strings.Contains(txt, "no gateway has the network tools") {
		t.Errorf("without the device: %v %s", isErr, txt)
	}
}

func TestMCPNetToolsGateways(t *testing.T) {
	e, post, k := toolsEnv(t, "paris")
	call := func(tool, args string) (string, bool) {
		_, m := post(mcpCall(tool, args), "Authorization", "Bearer "+k["ro"])
		return toolResult(t, m)
	}
	for _, c := range []struct{ tool, args, want string }{
		{"net_ping", `{"host":"10.1.1.1","gateway":"london"}`, "not enabled on gateway \"london\""},
		{"net_scan", `{"host":"10.1.1.1","gateway":"nosuch"}`, "paris (161)"},
		{"net_dig", `{"name":"example.com","gateway":"162"}`, "not enabled"},
		{"net_scan", `{"host":"10.1.1.0/24","gateway":"paris"}`, "not an IP address or a host name"},
		{"net_scan", `{"host":"-oN x"}`, "not an IP address or a host name"},
		{"net_scan", `{"host":"a b"}`, "not an IP address or a host name"},
		{"net_scan", `{"host":"224.0.0.1"}`, "not an address of one host"},
		{"net_ping", `{"host":"a b; rm -rf /"}`, "not an IP address or a host name"},
		{"net_mtr", `{"host":"-c1"}`, "not an IP address or a host name"},
		{"net_dig", `{"name":"a b"}`, "not a host or domain name"},
		{"net_dig", `{"name":"example.com","type":"ANY"}`, "type:"},
		{"net_dig", `{"name":"example.com","server":"-x"}`, "server: an IP address"},
		{"net_dig", `{"name":"-x"}`, "not a host or domain name"},
		{"net_dig", `{"name":"example.com;id"}`, "not a host or domain name"},
		{"net_curl", `{"url":"file:///etc/passwd"}`, "an http or https address"},
		{"net_curl", `{"url":"ftp://example.com/"}`, "an http or https address"},
		{"net_curl", `{"url":"http://user:pw@example.com/"}`, "no user name or password"},
		{"net_curl", `{"url":"http://exa mple.com/"}`, "an http or https address"},
		{"net_curl", `{"url":"http://-x/"}`, "not a host name"},
		{"net_curl", `{"url":"https://example.com/","method":"POST"}`, "method:"},
	} {
		if txt, isErr := call(c.tool, c.args); !isErr || !strings.Contains(txt, c.want) {
			t.Errorf("%s %s: %v %q, want %q", c.tool, c.args, isErr, txt, c.want)
		}
	}
	// with the tools on both, a gateway has to be named
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Groups[1].Devices = []string{"tools"}
	sup.mu.Unlock()
	if txt, isErr := call("net_ping", `{"host":"10.1.1.1"}`); !isErr || !strings.Contains(txt, "from which gateway") || !strings.Contains(txt, "london (162)") {
		t.Errorf("two gateways, none named: %v %s", isErr, txt)
	}
}

// With the programs there (stand-ins here), the tools start the job, wait for it and return its text.
func TestMCPNetToolsRun(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"ping": "echo '4 packets transmitted, 4 received, 0% packet loss'",
		"nmap": "echo 'Nmap scan report for 10.1.1.1'; echo '22/tcp open ssh'",
		"dig":  "echo \"args: $*\"; echo 'example.com. 300 IN A 93.184.216.34'",
		"curl": "echo \"args: $*\"; echo 'HTTP/2 200'",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	_, post, k := toolsEnv(t, "paris")
	call := func(tool, args string) string {
		_, m := post(mcpCall(tool, args), "Authorization", "Bearer "+k["ro"])
		txt, isErr := toolResult(t, m)
		if isErr {
			t.Fatalf("%s: %s", tool, txt)
		}
		return strings.ReplaceAll(txt, `&`, "&")
	}
	if txt := call("net_ping", `{"host":"10.1.1.1","gateway":"paris"}`); !strings.Contains(txt, `"state":"done"`) || !strings.Contains(txt, "0% packet loss") {
		t.Errorf("net_ping: %s", txt)
	}
	if txt := call("net_scan", `{"host":"10.1.1.1"}`); !strings.Contains(txt, `"state":"done"`) || !strings.Contains(txt, "22/tcp") {
		t.Errorf("net_scan: %s", txt)
	}
	if txt := call("net_dig", `{"name":"example.com","type":"mx","server":"10.0.0.53","gateway":"161"}`); !strings.Contains(txt, "+time=3 +tries=1 @10.0.0.53 -- example.com MX") || !strings.Contains(txt, "x.x.x.x") {
		t.Errorf("net_dig: %s", txt)
	}
	if txt := call("net_dig", `{"name":"10.1.1.1"}`); !strings.Contains(txt, "-x 10.1.1.1") {
		t.Errorf("net_dig of an address: %s", txt)
	}
	txt := call("net_curl", `{"url":"https://example.com/x"}`)
	for _, w := range []string{"--proto =http,https", "--proto-redir =http,https", "--max-time 15", "-I", "-- https://example.com/x", "HTTP/2 200"} {
		if !strings.Contains(txt, w) {
			t.Errorf("net_curl lacks %q: %s", w, txt)
		}
	}
	if strings.Contains(txt, " -L") || strings.Contains(txt, " -k") {
		t.Errorf("net_curl followed or skipped the check without being asked: %s", txt)
	}
	txt = call("net_curl", `{"url":"https://example.com/","method":"get","follow":true,"insecure":true}`)
	if !strings.Contains(txt, "-i") || strings.Contains(txt, " -I") || !strings.Contains(txt, "-L --max-redirs 3") || !strings.Contains(txt, "-k") {
		t.Errorf("net_curl GET: %s", txt)
	}
}

// Where a gateway's tools run: here when this node serves it, otherwise on a reachable node that does (the one the Topology page asks).
func TestToolsNodeFor(t *testing.T) {
	n := func(addr, gw string, self bool) CanvasNode {
		return CanvasNode{Addr: addr, Gw: gw, Self: self, Reachable: true}
	}
	g := func(nodes ...CanvasNode) CanvasGateway { return CanvasGateway{GroupID: 162, Name: "phx", Nodes: nodes} }
	for _, c := range []struct {
		name, want string
		gw         CanvasGateway
		fail       bool
	}{
		{"served here", "", g(n("a", "ok", true), n("b", "ok", false)), false},
		{"degraded here", "", g(n("a", "degraded", true), n("b", "ok", false)), false},
		{"served by a peer", "b", g(n("a", "notserving", true), n("c", "degraded", false), n("b", "ok", false)), false},
		{"paused here", "b", g(n("a", "paused", true), n("b", "ok", false)), false},
		{"nobody", "", g(n("a", "notserving", true), n("b", "notserving", false), n("c", "down", false)), true},
		{"a single node", "", g(), false},
	} {
		got, err := toolsNodeFor(c.gw)
		if (err != nil) != c.fail || got != c.want {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
}

// A read-only caller may start the look jobs, here or through /api/proxy on another node, and nothing else.
func TestReadOnlyJob(t *testing.T) {
	req := func(method, target string) *http.Request { return httptest.NewRequest(method, target, nil) }
	for target, want := range map[string]bool{
		"/api/nettool": true, "/api/scan": true,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fnettool": true,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fscan":    true,
		"/api/wake": false, "/api/proxy?node=10.0.0.2&path=%2Fapi%2Fwake": false,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fconfig":                false,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fdevices%2Fchange":      false,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fnettool%2F..%2Fconfig": false,
		"/api/devices/change": false,
	} {
		if got := readOnlyJob(req("POST", target)); got != want {
			t.Errorf("POST %s: %v, want %v", target, got, want)
		}
	}
	if readOnlyJob(req("PUT", "/api/nettool")) {
		t.Error("a PUT was let through")
	}
}
