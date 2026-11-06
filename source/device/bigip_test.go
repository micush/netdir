package device

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type bigipState struct {
	mu   sync.Mutex
	reqs []string
}

// bigipStub is an iControl REST server on loopback: GET answers keyed by path (the query is not part of the key), basic
// authentication as admin/s3cret or the token TOK in X-F5-Auth-Token.  The stub fails the test on any method but GET.
func bigipStub(t *testing.T, answers map[string]any) (Device, *bigipState) {
	t.Helper()
	st := &bigipState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !(ok && u == "admin" && p == "s3cret") && r.Header.Get("X-F5-Auth-Token") != "TOK" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request (reads send GET only): %s", r.Method, r.URL)
		}
		st.mu.Lock()
		st.reqs = append(st.reqs, r.URL.RequestURI())
		st.mu.Unlock()
		a, ok := answers[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "ltm1", Platform: "bigip", Address: host, Port: pn, Insecure: true}, st
}

func bigipAnswers() map[string]any {
	stat := func(name string, bitsIn, pkts int) J {
		return J{"nestedStats": J{"entries": J{
			"tmName":          J{"description": name},
			"status":          J{"description": "up"},
			"counters.bitsIn": J{"value": bitsIn}, "counters.bitsOut": J{"value": bitsIn * 2},
			"counters.pktsIn": J{"value": pkts}, "counters.pktsOut": J{"value": pkts + 1},
			"counters.errorsIn": J{"value": 3}, "counters.dropsOut": J{"value": 4},
		}}}
	}
	return map[string]any{
		"/mgmt/tm/cm/device": J{"items": []any{
			J{"name": "other.example.net", "hostname": "other.example.net", "selfDevice": "false"},
			J{"name": "ltm1.example.net", "hostname": "ltm1.example.net", "selfDevice": "true", "marketingName": "BIG-IP i5800", "chassisId": "f5-abcd-1234", "version": "16.1.4", "build": "0.0.5"}}},
		"/mgmt/tm/net/interface": J{"items": []any{
			J{"name": "1.1", "macAddress": "00:01:d7:00:00:01", "enabled": true, "mediaActive": "10000T-FD", "mtu": 1500, "description": "to core"},
			J{"name": "1.2", "macAddress": "00:01:d7:00:00:02", "disabled": true, "mediaActive": "none", "mtu": 1500}}},
		"/mgmt/tm/net/interface/stats": J{"entries": J{
			"https://localhost/mgmt/tm/net/interface/1.1/stats": stat("1.1", 8000, 10),
			"https://localhost/mgmt/tm/net/interface/1.2/stats": stat("1.2", 0, 0)}},
		"/mgmt/tm/net/self":                 J{"items": []any{J{"name": "self_int", "address": "10.1.1.5%1/24", "vlan": "/Common/internal"}}},
		"/mgmt/tm/net/route":                J{"items": []any{J{"name": "dflt", "network": "default", "gw": "10.1.1.1"}, J{"name": "r2", "network": "10.9.0.0/16", "gw": "10.1.1.2"}}},
		"/mgmt/tm/net/vlan":                 J{"items": []any{J{"name": "internal", "tag": 4093, "interfacesReference": J{"items": []any{J{"name": "1.1"}}}}}},
		"/mgmt/tm/net/routing/bgp":          J{"items": []any{J{"name": "bgp1", "localAs": 65001, "password": "bgp-secret"}}},
		"/mgmt/tm/security/firewall/policy": J{"items": []any{J{"name": "pol1"}}},
		"/mgmt/tm/ltm/virtual":              J{"items": []any{J{"name": "web", "destination": "/Common/10.1.1.100:443"}}},
		"/mgmt/tm/sys/cpu":                  J{"entries": J{}},
		"/mgmt/tm/sys/memory":               J{"entries": J{}},
	}
}

func TestBigIP(t *testing.T) {
	d, st := bigipStub(t, bigipAnswers())
	ctx := context.Background()
	for _, c := range []Credential{{Username: "admin", Password: "s3cret"}, {Token: "TOK"}} {
		drv := open(t, d, c)
		f, err := drv.Facts(ctx)
		if err != nil || f != (Facts{Hostname: "ltm1.example.net", Vendor: "F5", Model: "BIG-IP i5800", OSVersion: "16.1.4 build 0.0.5", Serial: "f5-abcd-1234"}) {
			t.Fatalf("facts: %v %+v", err, f)
		}
	}
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"})
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 3 || ifs[0].Name != "1.1" || ifs[0].AdminUp == nil || !*ifs[0].AdminUp || *ifs[1].AdminUp || ifs[2].Addresses[0] != "10.1.1.5/24" {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 2 || ps[0].Counters.InOctets != 1000 || ps[0].Counters.OutOctets != 2000 || ps[0].Counters.InErrors != 3 || ps[0].Counters.OutDiscards != 4 || ps[0].OperUp == nil || !*ps[0].OperUp {
		t.Fatalf("ports: %v %+v", err, ps)
	}
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 2 || rs[0].Prefix != "0.0.0.0/0" || rs[0].NextHop != "10.1.1.1" {
		t.Errorf("routes: %v %+v", err, rs)
	}
	rt, err := drv.(Router).Routing(ctx)
	if err != nil || rt.Protocols["bgp"] == nil || rt.Unavailable["ospf"] == "" {
		t.Fatalf("routing: %v %+v", err, rt)
	}
	if b, _ := json.Marshal(rt.Protocols["bgp"]); strings.Contains(string(b), "bgp-secret") {
		t.Errorf("a password is shown: %s", b)
	}
	vl, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vl) != 1 || vl[0].ID != 4093 || vl[0].Ports[0] != "1.1" {
		t.Errorf("vlans: %v %+v", err, vl)
	}
	if fw, err := drv.(Firewaller).Firewall(ctx); err != nil || fw.Protocols["policies"] == nil || fw.Unavailable["nat_policies"] == "" {
		t.Errorf("firewall: %v %+v", err, fw)
	}
	if r, err := drv.(Resourcer).Resources(ctx); err != nil || r.Details.Protocols["cpu"] == nil {
		t.Errorf("resources: %v %+v", err, r)
	}
	if _, err := drv.Neighbors(ctx); err != ErrUnsupported {
		t.Errorf("neighbors: %v", err)
	}
	if _, err := drv.Config(ctx); err != ErrUnsupported {
		t.Errorf("config: %v", err)
	}
	if _, err := drv.Show(ctx, "show version"); err != ErrUnsupported {
		t.Errorf("show: %v", err)
	}
	a := drv.(APIer)
	if v, text, err := a.APIGet(ctx, "/mgmt/tm/ltm/virtual?expandSubcollections=true"); err != nil || text || v == nil {
		t.Errorf("api: %v %v %v", v, text, err)
	}
	before := len(st.reqs)
	for _, bad := range []string{"/mgmt/tm/util/bash", "/mgmt/tm/util/ping", "/mgmt/shared/authn/login", "/mgmt/shared/file-transfer/uploads/x", "/mgmt/tm/sys/ucs",
		"/mgmt/tasks/x", "/rest/x", "/ltm/virtual", "", "/mgmt/tm/ltm/virtual?%zz"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%q was sent", bad)
		}
	}
	if len(st.reqs) != before {
		t.Errorf("a refused path reached the device: %v", st.reqs[before:])
	}
	if c, err := a.APICatalog(ctx); err != nil || c.(map[string]any)["how"] == nil {
		t.Errorf("catalog: %v", err)
	}
	// a wrong password is the device's 401, with no echo of it
	_, err = open(t, d, Credential{Username: "admin", Password: "nope"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "nope") {
		t.Errorf("wrong password: %v", err)
	}
	for _, c := range []Credential{{Username: "admin"}, {}} {
		if _, err := Open(d, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}
