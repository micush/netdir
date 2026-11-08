package device

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func tlsDevice(t *testing.T, name, platform string, h http.Handler) Device {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	pn, _ := strconv.Atoi(port)
	return Device{Name: name, Platform: platform, Address: host, Port: pn, Insecure: true}
}

func jout(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- Catalyst SD-WAN Manager ----

type sdState struct {
	mu      sync.Mutex
	logins  int
	logouts int
	expire  bool
	posts   []string
	calls   []string
}

func sdStub(t *testing.T, st *sdState) Device {
	return tlsDevice(t, "vm", "sdwan", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		switch r.URL.Path {
		case "/j_security_check":
			_ = r.ParseForm()
			if r.Form.Get("j_username") != "admin" || r.Form.Get("j_password") != "S3CRET" {
				_, _ = w.Write([]byte("<html><body>login</body></html>"))
				return
			}
			st.logins++
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "sess" + strconv.Itoa(st.logins), Path: "/"})
			return
		case "/logout":
			st.logouts++
			return
		}
		c, err := r.Cookie("JSESSIONID")
		if err != nil || st.expire {
			st.expire = false
			_, _ = w.Write([]byte("<html>login</html>")) // an expired session gets the login page
			return
		}
		_ = c
		if r.URL.Path == "/dataservice/client/token" {
			_, _ = w.Write([]byte("XSRF123"))
			return
		}
		if r.Method != "GET" {
			if r.Header.Get("X-XSRF-TOKEN") != "XSRF123" {
				jout(w, 403, J{"error": "no token"})
				return
			}
			b, _ := io.ReadAll(r.Body)
			st.posts = append(st.posts, r.Method+" "+r.URL.Path+" "+string(b))
			jout(w, 200, J{"id": "t1"})
			return
		}
		st.calls = append(st.calls, r.URL.RequestURI())
		switch r.URL.Path {
		case "/dataservice/client/server":
			jout(w, 200, J{"data": J{"platformVersion": "20.12.1"}})
		case "/dataservice/device":
			jout(w, 200, J{"data": []J{{"host-name": "e1", "device-type": "vedge", "password": "x"}, {"host-name": "e2", "device-type": "vedge"}, {"host-name": "c1", "device-type": "vsmart"}}})
		case "/dataservice/alarms":
			jout(w, 200, J{"data": []J{{"message": "x"}}})
		default:
			jout(w, 404, J{"error": "not found"})
		}
	}))
}

func TestSDWAN(t *testing.T) {
	st := &sdState{}
	d := sdStub(t, st)
	if _, err := Open(d, Credential{Username: "admin"}); err == nil {
		t.Errorf("no password was accepted")
	}
	bad, _ := Open(d, Credential{Username: "admin", Password: "wrong"})
	if _, err := bad.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("wrong password: %v", err)
	}
	drv, err := Open(d, Credential{Username: "admin", Password: "S3CRET"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.OSVersion != "20.12.1" || f.Vendor != "Cisco" || !strings.Contains(f.Model, "3 device(s)") || !strings.Contains(f.Model, "2 vedge") {
		t.Errorf("facts: %v %+v", err, f)
	}
	txt, err := drv.Show(ctx, "show device")
	if err != nil || !strings.Contains(txt, "e1") || strings.Contains(txt, `"x"`) && strings.Contains(txt, "password\": \"x") {
		t.Errorf("show: %v %s", err, txt)
	}
	// the session expires: the driver logs in again
	st.mu.Lock()
	st.expire = true
	st.mu.Unlock()
	if _, _, err := drv.(APIer).APIGet(ctx, "/dataservice/alarms"); err != nil {
		t.Errorf("after expiry: %v", err)
	}
	if st.logins != 2 {
		t.Errorf("logins: %d, want the first and the one after the session expired", st.logins)
	}
	for _, p := range []string{"/dataservice/admin/user", "/dataservice/certificate/vedge/list", "/dataservice/settings/configuration/smtp", "/dataservice/client/token", "/x/../y", "/dataservice"} {
		if _, _, err := drv.(APIer).APIGet(ctx, p); err == nil {
			t.Errorf("%s was read", p)
		}
	}
	if _, err := drv.Show(ctx, "show admin/user"); err == nil {
		t.Errorf("show admin/user")
	}
	// changes
	rc := drv.(RawChanger)
	if _, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/dataservice/admin/user", Body: `{}`}, false); err == nil {
		t.Errorf("a change of the users was sent")
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/dataservice/device/action/reboot", Body: `{}`}, false); err == nil {
		t.Errorf("a restart was sent")
	}
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/dataservice/template/feature", Body: `{"templateName":"t"}`}, false)
	if err != nil || !res.Applied || len(st.posts) != 1 || !strings.Contains(st.posts[0], "templateName") {
		t.Errorf("change: %v %+v %v", err, res, st.posts)
	}
	drv.Close(ctx)
	if st.logouts != 1 {
		t.Errorf("logouts: %d", st.logouts)
	}
}

// ---- VMware NSX ----

func nsxStub(t *testing.T, calls *[]string, posts *[]string) Device {
	var mu sync.Mutex
	return tlsDevice(t, "nsx", "nsxt", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "S3CRET" {
			jout(w, 401, J{"error_message": "bad login"})
			return
		}
		if r.Method != "GET" {
			b, _ := io.ReadAll(r.Body)
			*posts = append(*posts, r.Method+" "+r.URL.Path+" "+string(b))
			jout(w, 200, J{})
			return
		}
		*calls = append(*calls, r.URL.RequestURI())
		switch r.URL.Path {
		case "/api/v1/node/version":
			jout(w, 200, J{"node_version": "4.1.2.0.0.22667789", "product_version": "4.1.2.0.0.22667785"})
		case "/api/v1/node/status":
			jout(w, 200, J{"system_status": J{"uptime": 86400000}})
		case "/api/v1/node":
			jout(w, 200, J{"hostname": "nsxmgr-01"})
		case "/api/v1/transport-nodes":
			jout(w, 200, J{"result_count": 1, "results": []J{{"display_name": "esx1", "node_deployment_info": J{"password": "pw"}}}})
		case "/policy/api/v1/infra/tier-0s":
			jout(w, 200, J{"results": []J{{"id": "t0"}}})
		default:
			jout(w, 404, J{"error_message": "no"})
		}
	}))
}

func TestNSXT(t *testing.T) {
	var calls, posts []string
	d := nsxStub(t, &calls, &posts)
	drv, err := Open(d, Credential{Username: "admin", Password: "S3CRET"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "nsxmgr-01" || f.OSVersion != "4.1.2.0.0.22667785" || f.UptimeS != 86400 || f.Vendor != "VMware" {
		t.Errorf("facts: %v %+v", err, f)
	}
	txt, err := drv.Show(ctx, "show transport-nodes")
	if err != nil || !strings.Contains(txt, "esx1") || strings.Contains(txt, `"pw"`) {
		t.Errorf("show: %v %s", err, txt)
	}
	if txt, err = drv.Show(ctx, "show infra/tier-0s"); err != nil || !strings.Contains(txt, "t0") { // the Policy API by its root
		t.Errorf("policy: %v %s", err, txt)
	}
	for _, p := range []string{"/api/v1/node/users", "/api/v1/trust-management/certificates", "/api/v1/aaa/providers", "/api/v1/cluster/api-certificate", "/api/v1/../x", "/other/v1/x", "/api/v1/vidm"} {
		if _, _, err := drv.(APIer).APIGet(ctx, p); err == nil {
			t.Errorf("%s was read", p)
		}
	}
	rc := drv.(RawChanger)
	for _, p := range []string{"/api/v1/node/users/1", "/api/v1/trust-management/certificates", "/api/v1/cluster?action=x", "/api/v1/node/services/http?action=restart", "/other"} {
		if _, err := rc.RawChange(ctx, Raw{Method: "POST", Path: p, Body: `{}`}, false); err == nil {
			t.Errorf("change %s was sent", p)
		}
	}
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/api/v1/logical-switches", Body: `{"display_name":"ls"}`}, false)
	if err != nil || !res.Applied || len(posts) != 1 {
		t.Errorf("change: %v %+v", err, res)
	}
	bad, _ := Open(d, Credential{Username: "admin", Password: "nope"})
	if _, err := bad.Facts(ctx); err == nil {
		t.Errorf("wrong password")
	}
}

// ---- Cisco ACI (APIC) ----

func aciStub(t *testing.T, st *sdState) Device {
	im := func(class string, attrs ...J) J {
		l := []J{}
		for _, a := range attrs {
			l = append(l, J{class: J{"attributes": a}})
		}
		return J{"totalCount": strconv.Itoa(len(l)), "imdata": l}
	}
	return tlsDevice(t, "apic", "aci", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		switch r.URL.Path {
		case "/api/aaaLogin.json":
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"pwd":"S3CRET"`) || !strings.Contains(string(b), `"name":"admin"`) {
				jout(w, 401, J{"imdata": []J{{"error": J{"attributes": J{"code": "401", "text": "bad"}}}}})
				return
			}
			st.logins++
			http.SetCookie(w, &http.Cookie{Name: "APIC-cookie", Value: "c" + strconv.Itoa(st.logins), Path: "/"})
			jout(w, 200, im("aaaLogin", J{"token": "t"}))
			return
		case "/api/aaaLogout.json":
			st.logouts++
			jout(w, 200, J{"imdata": []J{}})
			return
		}
		if _, err := r.Cookie("APIC-cookie"); err != nil || st.expire {
			st.expire = false
			jout(w, 403, J{"imdata": []J{}})
			return
		}
		if r.Method != "GET" {
			b, _ := io.ReadAll(r.Body)
			st.posts = append(st.posts, r.Method+" "+r.URL.Path+" "+string(b))
			jout(w, 200, J{"imdata": []J{}})
			return
		}
		st.calls = append(st.calls, r.URL.RequestURI())
		switch r.URL.Path {
		case "/api/node/class/topSystem.json":
			jout(w, 200, im("topSystem", J{"name": "apic1", "role": "controller", "version": "6.0(4c)", "serial": "FCH1234", "systemUpTime": "01:02:03:04.000", "oobMgmtAddr": "10.0.0.1", "fabricDomain": "fab1"},
				J{"name": "apic2", "role": "controller", "version": "6.0(4c)", "oobMgmtAddr": "10.0.0.2"}))
		case "/api/node/class/l1PhysIf.json":
			jout(w, 200, im("l1PhysIf", J{"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]", "id": "eth1/1", "adminSt": "up", "descr": "to spine", "speed": "inherit"},
				J{"dn": "topology/pod-1/node-101/sys/phys-[eth1/2]", "id": "eth1/2", "adminSt": "down", "speed": "10G"}))
		case "/api/node/class/ethpmPhysIf.json":
			jout(w, 200, im("ethpmPhysIf", J{"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]/phys", "operSt": "up", "operSpeed": "100G"},
				J{"dn": "topology/pod-1/node-101/sys/phys-[eth1/2]/phys", "operSt": "down", "operSpeed": "10G"}))
		case "/api/node/class/lldpAdjEp.json":
			jout(w, 200, im("lldpAdjEp", J{"dn": "topology/pod-1/node-101/sys/lldp/inst/if-[eth1/1]/adj-1", "sysName": "spine1", "portIdV": "Eth1/5", "mgmtIp": "10.0.1.1", "sysDesc": "Cisco NX-OS"}))
		case "/api/node/class/cdpAdjEp.json":
			jout(w, 200, im("cdpAdjEp", J{"dn": "topology/pod-1/node-101/sys/cdp/inst/if-[eth1/3]/adj-1", "devId": "legacy-sw", "portId": "Gi0/1", "platId": "WS-C3750"}))
		case "/api/node/class/fvTenant.json":
			if r.URL.Query().Get("rsp-prop-include") == "config-only" {
				jout(w, 200, im("fvTenant", J{"name": "common", "userdomain": "all"}))
				return
			}
			jout(w, 200, im("fvTenant", J{"name": "common", "dn": "uni/tn-common"}, J{"name": "prod", "dn": "uni/tn-prod"}))
		case "/api/node/class/faultInst.json":
			if r.URL.Query().Get("query-target-filter") != `eq(faultInst.severity,"critical")` {
				t.Errorf("filter: %q", r.URL.Query().Get("query-target-filter"))
			}
			jout(w, 200, im("faultInst", J{"code": "F0001", "severity": "critical", "dn": "topology/pod-1/node-101/fault-F0001"}))
		case "/api/node/mo/uni/tn-common.json":
			jout(w, 200, im("fvTenant", J{"name": "common"}))
		default:
			jout(w, 404, J{"imdata": []J{}})
		}
	}))
}

func TestACI(t *testing.T) {
	st := &sdState{}
	d := aciStub(t, st)
	if _, err := Open(d, Credential{Username: "admin"}); err == nil {
		t.Errorf("no password was accepted")
	}
	bad, _ := Open(d, Credential{Username: "admin", Password: "wrong"})
	if _, err := bad.Facts(context.Background()); err == nil {
		t.Errorf("wrong password")
	}
	drv, err := Open(d, Credential{Username: "admin", Password: "S3CRET"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "apic1" || f.OSVersion != "6.0(4c)" || f.Serial != "FCH1234" || f.UptimeS != ((24+2)*60+3)*60+4 || !strings.Contains(f.Model, "cluster of 2") {
		t.Errorf("facts: %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "node-101/eth1/1" || ifs[0].SpeedMbps != 100000 || ifs[0].OperUp == nil || !*ifs[0].OperUp || ifs[1].AdminUp == nil || *ifs[1].AdminUp || ifs[0].Description != "to spine" {
		t.Errorf("interfaces: %v %+v", err, ifs)
	}
	ns, err := drv.Neighbors(ctx)
	if err != nil || len(ns) != 2 || ns[0].LocalPort != "node-101/eth1/1" || ns[0].RemoteName != "spine1" || ns[0].RemotePort != "Eth1/5" || ns[0].RemoteAddr != "10.0.1.1" || ns[1].Protocol != "cdp" || ns[1].LocalPort != "node-101/eth1/3" {
		t.Errorf("neighbors: %v %+v", err, ns)
	}
	cfg, err := drv.Config(ctx)
	if err != nil || !strings.Contains(cfg, "common") {
		t.Errorf("config: %v %s", err, cfg)
	}
	txt, err := drv.Show(ctx, "show fvTenant")
	if err != nil || !strings.Contains(txt, "prod") {
		t.Errorf("show: %v %s", err, txt)
	}
	if txt, err = drv.Show(ctx, "show faultInst severity=critical"); err != nil || !strings.Contains(txt, "F0001") {
		t.Errorf("show filter: %v %s", err, txt)
	}
	if txt, err = drv.Show(ctx, "show mo uni/tn-common"); err != nil || !strings.Contains(txt, "common") {
		t.Errorf("show mo: %v %s", err, txt)
	}
	// the session is refused once: the driver logs in again
	st.mu.Lock()
	st.expire = true
	st.mu.Unlock()
	if _, _, err := drv.(APIer).APIGet(ctx, "/api/node/class/fvTenant.json"); err != nil {
		t.Errorf("after expiry: %v", err)
	}
	for _, p := range []string{"/api/node/class/aaaUser.json", "/api/node/mo/uni/userext.json", "/api/node/class/pkiFabricNodeSSLCertificate.json", "/api/node/class/snmpCommunityP.json",
		"/api/node/class/topSystem", "/api/aaaLogin.json", "/x", "/api/node/class/../x.json"} {
		if _, _, err := drv.(APIer).APIGet(ctx, p); err == nil {
			t.Errorf("%s was read", p)
		}
	}
	for _, c := range []string{"show aaaUser", "show fvTenant name=x\"y", "show mo uni;rm", "show"} {
		if _, err := drv.Show(ctx, c); err == nil {
			t.Errorf("%q was accepted", c)
		}
	}
	// relation classes (fvRsBd) are read: only the names of secrets are refused
	if _, _, err := drv.(APIer).APIGet(ctx, "/api/node/class/fvRsBd.json"); err != nil && strings.Contains(err.Error(), "not read here") {
		t.Errorf("a relation class was refused: %v", err)
	}
	rc := drv.(RawChanger)
	for _, c := range []Raw{{Method: "POST", Path: "/api/node/mo/uni/userext.json", Body: `{}`}, {Method: "POST", Path: "/api/node/mo/uni/fabric/fwgrp-x.json", Body: `{}`},
		{Method: "PUT", Path: "/api/node/mo/uni/tn-x.json", Body: `{}`}, {Method: "POST", Path: "/api/node/class/fvTenant.json", Body: `{}`}} {
		if _, err := rc.RawChange(ctx, c, false); err == nil {
			t.Errorf("%s %s was sent", c.Method, c.Path)
		}
	}
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/api/node/mo/uni/tn-new.json", Body: `{"fvTenant":{"attributes":{"name":"new","status":"created"}}}`}, false)
	if err != nil || !res.Applied || len(st.posts) != 1 {
		t.Errorf("change: %v %+v %v", err, res, st.posts)
	}
	drv.Close(ctx)
	if st.logouts != 1 {
		t.Errorf("logouts: %d", st.logouts)
	}
}
