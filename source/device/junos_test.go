package device

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type junState struct {
	mu        sync.Mutex
	committed []string
	candidate []string
	rpcs      []string
	confirmed int // commits confirmed
	pending   bool
	loadErr   bool
	checkErr  bool
	dead      bool // the device stops answering reads once a commit is made
	rebooted  bool
}

func (s *junState) has(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rpcs {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func jd(s string) []J { return []J{{"data": s}} }

// junStub is a Junos REST: GET /rpc/<name> and POST /rpc with XML, answered in JSON with the [{"data": ...}] wrappers.
func junStub(t *testing.T, st *junState) Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
			w.WriteHeader(401)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			t.Errorf("request without Accept JSON: %s %s", r.Method, r.URL)
		}
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		st.mu.Lock()
		st.rpcs = append(st.rpcs, r.Method+" "+r.URL.Path+" "+body)
		dead := st.dead && st.pending
		st.mu.Unlock()
		send := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		rpcErr := func(msg string) {
			send(J{"rpc-reply": []J{{"load-configuration-results": []J{{"rpc-error": []J{{"error-severity": jd("error"), "error-message": jd(msg), "error-path": jd("[edit interfaces]")}}}}}}})
		}
		if dead && r.Method == "GET" {
			w.WriteHeader(503)
			return
		}
		if r.Method == "GET" {
			switch r.URL.Path {
			case "/rpc/get-software-information":
				send(J{"software-information": []J{{"host-name": jd("vsrx1"), "product-model": jd("vsrx"), "junos-version": jd("20.4R3.8")}}})
			case "/rpc/get-chassis-inventory":
				send(J{"chassis-inventory": []J{{"chassis": []J{{"name": jd("Chassis"), "serial-number": jd("SN123456")}}}}})
			case "/rpc/get-system-uptime-information":
				send(J{"system-uptime-information": []J{{"uptime-information": []J{{"up-time": []J{{"data": "3 days", "attributes": J{"junos:seconds": "259200"}}}}}}}})
			case "/rpc/get-interface-information":
				send(J{"interface-information": []J{{"physical-interface": []J{
					{"name": jd("\nge-0/0/0\n"), "admin-status": jd("up"), "oper-status": jd("up"), "description": jd("uplink"), "speed": jd("1000mbps"), "current-physical-address": jd("aa:bb:cc:00:00:01"),
						"logical-interface": []J{{"name": jd("ge-0/0/0.0"), "address-family": []J{{"address-family-name": jd("inet"), "interface-address": []J{{"ifa-local": jd("10.0.0.1"), "ifa-destination": jd("10.0.0.0/24")}}}}}}},
					{"name": jd("ge-0/0/1"), "admin-status": jd("down"), "oper-status": jd("down"), "speed": jd("10Gbps")}}}}})
			case "/rpc/get-lldp-neighbors-information":
				send(J{"lldp-neighbors-information": []J{{"lldp-neighbor-information": []J{{"lldp-local-port-id": jd("ge-0/0/0"), "lldp-remote-system-name": jd("sw2"), "lldp-remote-port-id": jd("Gi1/0/1"), "lldp-remote-port-description": jd("to vsrx1")}}}}})
			case "/rpc/get-route-information":
				send(J{"route-information": []J{{"route-table": []J{{"table-name": jd("inet.0"), "snmp-community": jd("SECRETCOMM")}}}}})
			default:
				w.WriteHeader(404)
				send(J{"rpc-reply": []J{{"rpc-error": []J{{"error-severity": jd("error"), "error-message": jd("syntax error, unknown rpc")}}}}})
			}
			return
		}
		switch {
		case strings.HasPrefix(body, `<get-configuration compare="rollback"`):
			st.mu.Lock()
			var d []string
			for _, l := range st.candidate {
				found := false
				for _, c := range st.committed {
					found = found || c == l
				}
				if !found {
					d = append(d, "+  "+l)
				}
			}
			st.mu.Unlock()
			out := "\n"
			if len(d) > 0 {
				out = "\n[edit]\n" + strings.Join(d, "\n") + "\n"
			}
			send(J{"configuration-information": []J{{"configuration-output": jd(out)}}})
		case strings.HasPrefix(body, `<get-configuration database="committed"`):
			send(J{"configuration": []J{{"configuration-text": jd("system {\n    host-name vsrx1;\n}\n")}}})
		case strings.HasPrefix(body, `<load-configuration action="set"`):
			var in struct {
				Set string `xml:"configuration-set"`
			}
			_ = xml.Unmarshal(b, &in)
			if st.loadErr {
				rpcErr("statement not found")
				return
			}
			st.mu.Lock()
			st.candidate = append(st.candidate, strings.Split(strings.TrimSpace(in.Set), "\n")...)
			st.mu.Unlock()
			send(J{"load-configuration-results": []J{{"load-success": []J{{}}}}})
		case strings.HasPrefix(body, `<load-configuration rollback="0"`):
			st.mu.Lock()
			st.candidate = append([]string(nil), st.committed...)
			st.mu.Unlock()
			send(J{"load-configuration-results": []J{{"load-success": []J{{}}}}})
		case strings.HasPrefix(body, `<commit-configuration><check/>`):
			if st.checkErr {
				rpcErr("commit check failed: missing mandatory statement")
				return
			}
			send(J{"commit-results": []J{{"routing-engine": []J{{"commit-check-success": []J{{}}}}}}})
		case strings.HasPrefix(body, `<commit-configuration><confirmed/>`):
			st.mu.Lock()
			st.committed = append([]string(nil), st.candidate...)
			st.pending = true
			st.mu.Unlock()
			send(J{"commit-results": []J{{}}})
		case strings.HasPrefix(body, `<commit-configuration><log>`):
			st.mu.Lock()
			st.pending = false
			st.confirmed++
			st.mu.Unlock()
			send(J{"commit-results": []J{{}}})
		case strings.HasPrefix(body, `<command format="text">`):
			var in struct {
				C string `xml:",chardata"`
			}
			_ = xml.Unmarshal(b, &in)
			send(J{"output": "ran: " + in.C + "\n"})
		case strings.HasPrefix(body, `<request-reboot`):
			st.mu.Lock()
			st.rebooted = true
			st.mu.Unlock()
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
		case strings.HasPrefix(body, `<clear-bgp-neighbor>`):
			send(J{"output": ""})
		default:
			w.WriteHeader(400)
			rpcErr("unknown rpc")
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "jun", Platform: "junos", Address: h, Port: pn, Insecure: true}
}

func junOpen(t *testing.T, st *junState) Driver {
	st.committed = []string{"set system host-name vsrx1"}
	st.candidate = append([]string(nil), st.committed...)
	return open(t, junStub(t, st), Credential{Username: "admin", Password: "pw"})
}

func TestJunos(t *testing.T) {
	st := &junState{}
	drv := junOpen(t, st)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Juniper" || f.Hostname != "vsrx1" || f.Model != "vsrx" || f.OSVersion != "20.4R3.8" || f.Serial != "SN123456" || f.UptimeS != 259200 {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "ge-0/0/0" || ifs[0].SpeedMbps != 1000 || ifs[0].MAC != "aa:bb:cc:00:00:01" || ifs[0].Description != "uplink" ||
		len(ifs[0].Addresses) != 1 || ifs[0].Addresses[0] != "10.0.0.1" || !*ifs[0].OperUp || *ifs[1].AdminUp || ifs[1].SpeedMbps != 10000 {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	ns, err := drv.Neighbors(ctx)
	if err != nil || len(ns) != 1 || ns[0].LocalPort != "ge-0/0/0" || ns[0].RemoteName != "sw2" || ns[0].RemotePort != "Gi1/0/1" || ns[0].Protocol != "lldp" {
		t.Fatalf("neighbors %+v %v", ns, err)
	}
	if c, err := drv.Config(ctx); err != nil || !strings.Contains(c, "host-name vsrx1") {
		t.Errorf("config %q %v", c, err)
	}
	// show
	out, err := drv.Show(ctx, "show route | match 10.0")
	if err != nil || !strings.Contains(out, "ran: show route | match 10.0") {
		t.Errorf("show %v %q", err, out)
	}
	for _, bad := range []string{"show configuration", "show conf", "show config | display set", "show system configuration archival", "show security ike pre-shared-key", "request system reboot",
		"show version; request system reboot", "show route | save /var/tmp/x", "show"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// api
	api := drv.(APIer)
	v, text, err := api.APIGet(ctx, "/rpc/get-route-information")
	if err != nil || text || strings.Contains(toJSON(v), "SECRETCOMM") || !strings.Contains(toJSON(v), "inet.0") {
		t.Fatalf("apiget %v %v", err, v)
	}
	for _, bad := range []string{"/rpc/get-configuration", "/rpc/get-config", "/rpc/get-system-password", "/rpc/request-reboot", "/rpc", "/rpc/get-x?Bad=1", "/rpc/get-route-information/../x",
		"/rpc/get-license-key-information", "/rpc/get-ldap-users"} {
		if _, _, err := api.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if c, err := api.APICatalog(ctx); err != nil || !strings.Contains(toJSON(c), "get-route-information") {
		t.Errorf("catalog %v", err)
	}
	for _, p := range []string{"/rpc/get-configuration", "/rpc/get-system-password", "/rpc/get-interface-information"} {
		err := CheckAPIPathMCP(p)
		if (p == "/rpc/get-interface-information") != (err == nil) {
			t.Errorf("CheckAPIPathMCP(%s) = %v", p, err)
		}
	}
	// wrong password
	bad := open(t, junStub(t, &junState{}), Credential{Username: "admin", Password: "no"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := Open(junStub(t, &junState{}), Credential{Token: "x"}); err == nil {
		t.Error("a token alone was accepted")
	}
}

func TestJunosChange(t *testing.T) {
	st := &junState{}
	drv := junOpen(t, st)
	rc := drv.(RawChanger)
	ctx := context.Background()
	// a dry run loads, compares, checks, and puts the candidate back
	res, err := rc.RawChange(ctx, Raw{Lines: []string{"set interfaces ge-0/0/1 description \"to <sw3> & more\""}}, true)
	if err != nil || !res.DryRun || res.Applied || !strings.Contains(res.Before, "ge-0/0/1 description") || !st.has("<check/>") || st.has("<confirmed/>") {
		t.Fatalf("dry %+v %v", res, err)
	}
	if len(st.candidate) != 1 || len(st.committed) != 1 {
		t.Errorf("a dry run left the candidate changed: %v / %v", st.candidate, st.committed)
	}
	if !strings.Contains(strings.Join(st.rpcs, "\n"), "&lt;sw3&gt; &amp; more") {
		t.Error("the line was not XML-escaped")
	}
	// a change: committed confirmed, tested, confirmed
	res, err = rc.RawChange(ctx, Raw{Lines: []string{"set interfaces ge-0/0/1 description uplink2", "# comment", "deactivate protocols lldp interface ge-0/0/1"}}, false)
	if err != nil || !res.Applied || !res.Saved || st.confirmed != 1 || st.pending || len(st.committed) != 3 || !strings.Contains(res.Before, "uplink2") {
		t.Fatalf("change %+v %v state %+v", res, err, st)
	}
	if !st.has("<confirm-timeout>3</confirm-timeout>") {
		t.Error("the commit was not a confirmed commit")
	}
	// a line the device refuses: nothing committed, the candidate put back
	st.loadErr = true
	n := len(st.committed)
	if _, err := rc.RawChange(ctx, Raw{Lines: []string{"set interfaces ge-9/9/9 nonsense"}}, false); err == nil || !strings.Contains(err.Error(), "statement not found") || len(st.committed) != n {
		t.Fatalf("refused lines: %v", err)
	}
	st.loadErr = false
	// the commit check refuses
	st.checkErr = true
	if _, err := rc.RawChange(ctx, Raw{Lines: []string{"set system host-name x"}}, false); err == nil || !strings.Contains(err.Error(), "commit check") || len(st.candidate) != len(st.committed) || st.confirmed != 1 {
		t.Fatalf("check: %v candidate %v", err, st.candidate)
	}
	st.checkErr = false
	// somebody else's uncommitted change is not committed with ours
	st.candidate = append(st.candidate, "set system ntp server 10.1.1.1")
	if _, err := rc.RawChange(ctx, Raw{Lines: []string{"set system host-name y"}}, false); err == nil || !strings.Contains(err.Error(), "uncommitted") || !strings.Contains(err.Error(), "ntp server") {
		t.Fatalf("dirty candidate: %v", err)
	}
	st.candidate = append([]string(nil), st.committed...)
	// the device stops answering after the commit: not confirmed, Junos rolls it back by itself
	st.dead = true
	res, err = rc.RawChange(ctx, Raw{Lines: []string{"set system host-name z"}}, false)
	if err == nil || !res.Applied || res.Saved || st.confirmed != 1 || !strings.Contains(res.Note, "undoes the change by itself") {
		t.Fatalf("dead device: %+v %v", res, err)
	}
	st.dead, st.pending = false, false
	// a change that changes nothing
	if res, err = rc.RawChange(ctx, Raw{Lines: []string{st.committed[0]}}, false); err != nil || res.Applied || !strings.Contains(res.Note, "change nothing") {
		t.Errorf("no-op %+v %v", res, err)
	}
	for _, bad := range []Raw{
		{Lines: []string{"set system login user bob class super-user"}},
		{Lines: []string{"set system root-authentication plain-text-password"}},
		{Lines: []string{"set system services rest http"}},
		{Lines: []string{"delete system services netconf ssh"}},
		{Lines: []string{"set interfaces fxp0 unit 0 family inet address 1.1.1.1/24"}},
		{Lines: []string{"delete system"}},
		{Lines: []string{"delete"}},
		{Lines: []string{"request system reboot", "set system host-name x"}},
		{Lines: []string{"commit"}},
		{Lines: []string{"rollback 1"}},
		{Lines: []string{"load override /var/tmp/x"}},
		{Lines: []string{"set"}},
		{Lines: []string{"set a\nrequest system halt"}},
		{Lines: []string{"set a b"}, Body: "<x/>"},
		{Lines: []string{}},
		{Method: "GET", Path: "/rpc", Body: "<x/>"},
		{Method: "POST", Path: "/other", Body: "<clear-bgp-neighbor/>"},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestJunosRPCAndReboot(t *testing.T) {
	st := &junState{}
	drv := junOpen(t, st)
	rc := drv.(RawChanger)
	ctx := context.Background()
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/rpc", Body: `<clear-bgp-neighbor><neighbor>10.0.0.2</neighbor></clear-bgp-neighbor>`}, false)
	if err != nil || !res.Applied || !st.has("<clear-bgp-neighbor>") {
		t.Fatalf("rpc %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/rpc", Body: `<clear-bgp-neighbor/>`}, true); err != nil || res.Applied || !strings.Contains(res.Note, "would send") {
		t.Errorf("dry rpc %+v %v", res, err)
	}
	for _, body := range []string{`<load-configuration action="set"/>`, `<commit-configuration/>`, `<lock-configuration/>`, `<request-system-zeroize/>`, `<request-power-off/>`, `<request-halt/>`,
		`<get-route-information/>`, `<get-configuration/>`, `<request-set-password/>`, `<a/><b/>`, `not xml`, ``, `<a>`, `<?xml version="1.0"?><x/>`, `<!DOCTYPE x [<!ENTITY e "y">]><x/>`, `text<x/>`,
		`<request-package-add/>`, `<file-copy/>`, `<Upper/>`} {
		if _, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/rpc", Body: body}, false); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
	// a reboot is one line; the connection closing under it is the device restarting
	for _, l := range []string{"request system reboot", "Request  System Reboot now"} {
		st.rebooted = false
		res, err = rc.RawChange(ctx, Raw{Lines: []string{l}}, false)
		if err != nil || !res.Applied || !strings.Contains(res.Note, "restart") || !st.rebooted {
			t.Fatalf("reboot %q: %+v %v", l, res, err)
		}
	}
	st.rebooted = false
	if res, err = rc.RawChange(ctx, Raw{Lines: []string{"request system reboot"}}, true); err != nil || res.Applied || st.rebooted {
		t.Errorf("dry reboot %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/rpc", Body: `<request-reboot/>`}, false); err != nil || !res.Applied || !st.rebooted {
		t.Errorf("reboot as rpc %+v %v", res, err)
	}
}
