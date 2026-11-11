package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPortCheck(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	dead, _ := net.Listen("tcp4", "127.0.0.1:0") // a port that was free a moment ago: refused
	closed := strconv.Itoa(dead.Addr().(*net.TCPAddr).Port)
	dead.Close()
	v, err := portCheck("127.0.0.1", open+", "+closed, "")
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(v)
	var back struct {
		Results []struct {
			Port  int
			State string
		}
	}
	_ = json.Unmarshal(j, &back)
	rs := back.Results
	if len(rs) != 2 || rs[0].State != "open" || rs[1].State != "closed" {
		t.Errorf("results %s", j)
	}
	for _, bad := range []struct{ host, ports, fam string }{
		{"127.0.0.1", "", ""}, {"127.0.0.1", "0", ""}, {"127.0.0.1", "65536", ""}, {"127.0.0.1", "80;id", ""},
		{"127.0.0.1", "1,2,3,4,5,6,7,8,9,10,11", ""}, {"a b", "80", ""}, {"127.0.0.1", "80", "5"}, {"127.0.0.1", "80", "6"}, {"224.0.0.1", "80", ""},
	} {
		if _, err := portCheck(bad.host, bad.ports, bad.fam); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestTLSCheck(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	v, err := tlsCheck("127.0.0.1", port, "", "")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["protocol"] != "TLS 1.3" || m["trusted"] != false || m["verify_error"] == nil {
		t.Errorf("answer %+v", m)
	}
	if m["warning"] != nil { // the test certificate is valid for a long time
		t.Errorf("warning %v", m["warning"])
	}
	if _, err := tlsCheck("127.0.0.1", "0", "", ""); err == nil {
		t.Error("port 0 accepted")
	}
	if _, err := tlsCheck("127.0.0.1", port, "a b", ""); err == nil {
		t.Error("a bad sni was accepted")
	}
	// a plain-text port is not TLS
	pl, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer pl.Close()
	go func() {
		c, err := pl.Accept()
		if err == nil {
			c.Write([]byte("SSH-2.0-x\r\n"))
			c.Close()
		}
	}()
	_, pp, _ := net.SplitHostPort(pl.Addr().String())
	if _, err := tlsCheck("127.0.0.1", pp, "", ""); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Errorf("plain port: %v", err)
	}
}

func TestARPAndWake(t *testing.T) {
	for _, bad := range []string{"", "a b", "127.0.0.1", "0.0.0.0", "224.0.0.1"} {
		if _, err := arpLookup(bad); err == nil {
			t.Errorf("arp %q accepted", bad)
		}
	}
	v, err := arpLookup("192.0.2.77") // not on a subnet of the sandbox: nothing sent, not found
	if err != nil || v.(map[string]any)["found"] != false {
		t.Errorf("arp: %v %v", v, err)
	}
	for _, c := range []struct{ mac, bc string }{{"", ""}, {"aa:bb", ""}, {"aa:bb:cc:dd:ee:ff:00:11", ""}, {"aa:bb:cc:dd:ee:ff", "224.0.0.1"}, {"aa:bb:cc:dd:ee:ff", "::1"}, {"aa:bb:cc:dd:ee:ff", "10.0.0.1;id"}} {
		if _, err := wakeSend(c.mac, c.bc, "t"); err == nil {
			t.Errorf("wake %+v accepted", c)
		}
	}
}

func TestNetOptions(t *testing.T) {
	o, err := netOptsParse("ping", "10", "1472", "true", "6")
	if err != nil || o != (NetOpts{Count: 10, Size: 1472, Df: true, Family: 6}) {
		t.Fatalf("%+v %v", o, err)
	}
	_, args, lim, _ := netToolSpecOpts("ping", netip.MustParseAddr("2001:db8::1"), o)
	if got := strings.Join(args, " "); got != "-n -c 10 -W 2 -s 1472 -M do -6 -- 2001:db8::1" || lim.Seconds() != 21 {
		t.Errorf("args %q %v", got, lim)
	}
	if _, a, _, _ := netToolSpecOpts("ping", netip.MustParseAddr("10.1.1.1"), NetOpts{}); strings.Join(a, " ") != "-n -c 4 -W 2 -- 10.1.1.1" {
		t.Errorf("default %v", a)
	}
	for _, bad := range [][5]string{{"ping", "0", "", "", ""}, {"ping", "21", "", "", ""}, {"ping", "", "7", "", ""}, {"ping", "", "65501", "", ""}, {"ping", "x", "", "", ""}, {"ping", "", "", "", "5"}, {"trace", "3", "", "", ""}, {"trace", "", "", "true", ""}} {
		if _, err := netOptsParse(bad[0], bad[1], bad[2], bad[3], bad[4]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if o, err := netOptsParse("trace", "", "", "", "4"); err != nil || o.Family != 4 {
		t.Errorf("mtr family: %+v %v", o, err)
	}
	if _, err := netToolStartOpts("ping", "10.1.1.1", "t", NetOpts{Family: 6}); err == nil {
		t.Error("an IPv4 address with family 6 was accepted")
	}
}

func TestDigWithoutDig(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	v, err := digRun("127.0.0.1", "", "")
	if err != nil {
		t.Skip("no resolver here:", err)
	}
	if m := v; !strings.Contains(m["text"].(string), "PTR") || m["note"] == nil {
		t.Errorf("answer %+v", m)
	}
	if _, err := digRun("example.com", "SOA", ""); err == nil || !strings.Contains(err.Error(), "dig is not installed") {
		t.Errorf("SOA without dig: %v", err)
	}
}

// ping gets its options on the command line, from the tool through the node.
func TestMCPNetToolsPingOptions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ping"), []byte("#!/bin/sh\necho \"ping $*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	_, post, k := toolsEnv(t, "paris")
	call := func(key, tool, args string) (string, bool) {
		_, m := post(mcpCall(tool, args), "Authorization", "Bearer "+key)
		return toolResult(t, m)
	}
	txt, isErr := call(k["ro"], "net_ping", `{"host":"10.1.1.1","count":3,"size":1472,"df":true,"family":4}`)
	if isErr || !strings.Contains(txt, "ping -n -c 3 -W 2 -s 1472 -M do -- 10.1.1.1") {
		t.Errorf("ping options: %v %s", isErr, txt)
	}
	for _, bad := range []string{`{"host":"10.1.1.1","count":99}`, `{"host":"10.1.1.1","size":1}`, `{"host":"10.1.1.1","family":"7"}`, `{"host":"10.1.1.1","family":6}`} {
		if txt, isErr := call(k["ro"], "net_ping", bad); !isErr {
			t.Errorf("%s: %s", bad, txt)
		}
	}
	// the new tools: a read-only key has the lookups, not the one that powers a machine on; a refused argument stops before the node is asked
	for _, c := range []struct{ tool, args, want string }{
		{"net_port", `{"host":"10.1.1.1","ports":"0"}`, "ports:"},
		{"net_tls", `{"host":"10.1.1.1","port":"99999"}`, "port:"},
		{"net_arp", `{"ip":"nope"}`, "ip:"},
	} {
		if txt, isErr := call(k["ro"], c.tool, c.args); !isErr || !strings.Contains(txt, c.want) {
			t.Errorf("%s: %v %s", c.tool, isErr, txt)
		}
	}
	if txt, isErr := call(k["ro"], "net_wake", `{"mac":"aa:bb:cc:dd:ee:ff"}`); !isErr || !strings.Contains(strings.ToLower(txt), "read") {
		t.Errorf("a read-only key woke a machine: %v %s", isErr, txt)
	}
	if txt, isErr := call(k["ro"], "net_arp", `{"ip":"192.0.2.77"}`); isErr || !strings.Contains(txt, `"found":false`) {
		t.Errorf("net_arp: %v %s", isErr, txt)
	}
}
