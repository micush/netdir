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

type cxState struct {
	mu      sync.Mutex
	logins  int
	logouts int
	reqs    []string // "METHOD /path?query" of every request after the login
	version string
}

func (s *cxState) saw(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reqs {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// cxStub is an ArubaOS-CX REST API on loopback: a form login that sets a session cookie, a logout, and GETs answered from
// answers (keyed by the path below /rest/<version> and the query as it was sent; a key that is not there is a 404).  The stub
// fails the test on a password in a URL, a request without the session, and any method but GET after the login.
func cxStub(t *testing.T, answers map[string]any) (Device, *cxState) {
	t.Helper()
	st := &cxState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "s3cret") || strings.Contains(r.URL.RawPath+r.URL.Path, "s3cret") {
			t.Errorf("the password is in the URL: %s", r.URL)
		}
		rest := strings.TrimPrefix(r.URL.EscapedPath(), "/rest/")
		ver, below, _ := strings.Cut(rest, "/")
		below = "/" + below
		st.mu.Lock()
		st.version = ver
		st.mu.Unlock()
		switch {
		case below == "/login" && r.Method == http.MethodPost:
			if err := r.ParseForm(); err != nil || r.PostForm.Get("username") != "admin" || r.PostForm.Get("password") != "s3cret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
				return
			}
			st.mu.Lock()
			st.logins++
			st.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "id", Value: "sess1", Secure: true, Path: "/"})
			return
		case below == "/logout" && r.Method == http.MethodPost:
			st.mu.Lock()
			st.logouts++
			st.mu.Unlock()
			return
		}
		if c, err := r.Cookie("id"); err != nil || c.Value != "sess1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		key := below
		if r.URL.RawQuery != "" {
			key += "?" + r.URL.RawQuery
		}
		st.mu.Lock()
		st.reqs = append(st.reqs, r.Method+" "+key)
		st.mu.Unlock()
		if r.Method != http.MethodGet {
			t.Errorf("a %s request after the login (only GET): %s", r.Method, key)
		}
		a, ok := answers[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "sw1", Platform: "aoscx", Address: host, Port: pn, Insecure: true}, st
}

type J = map[string]any

// Field names: interface admin_state, link_state, link_speed (bit/s), mac_in_use, description, ip4_address, statistics
// (rx_bytes ... tx_dropped), lldp_neighbors' neighbor_info, vrf routes (prefix, from, distance, metric, nexthops), the vlan
// attributes and the subsystem product_info are the ones the Aruba API reference and pyaoscx use.  resource_utilization's
// cpu and memory, the temperature in millidegrees, the fan speed, the power supply's characteristics and the child resource
// names of the routing and ACL parts have only been seen in this stub.
func cxAnswers() map[string]any {
	const sub = "/system/subsystems/chassis%2C1"
	return map[string]any{
		"/system?selector=status":        J{"hostname": "sw1", "platform_name": "8325", "software_version": "FL.10.09.1000", "boot_time": 2000000 - 90061},
		"/system?selector=configuration": J{"hostname": "sw1", "other_config": J{}},
		sub + "?selector=status":         J{"product_info": J{"serial_number": "SG12345678", "product_name": "Aruba 8325-48Y8C"}, "resource_utilization": J{"cpu": 7, "memory": 41}},
		"/system/interfaces?depth=2&selector=status": J{
			"1%2F1%2F1": J{"name": "1/1/1", "admin_state": "up", "link_state": "up", "link_speed": 10000000000, "mac_in_use": "aa:bb:cc:00:00:01", "mtu": 1500, "duplex": "full", "type": "system"},
			"1%2F1%2F2": J{"name": "1/1/2", "admin_state": "down", "link_state": "down"},
			"vlan10":    J{"admin_state": "up", "link_state": "up", "mac_in_use": "aa:bb:cc:00:00:10"},
			"lag1":      J{"name": "lag1", "admin_state": "up", "link_state": "down"},
		},
		"/system/interfaces?depth=2&selector=configuration": J{
			"1%2F1%2F1": J{"name": "1/1/1", "description": "uplink", "vlan_tag": J{"10": "/rest/v10.09/system/vlans/10"}, "vlan_trunks": J{"20": "/rest/v10.09/system/vlans/20"}},
			"vlan10": J{"name": "vlan10", "ip4_address": "10.0.10.1/24", "ip4_address_secondary": []any{"10.0.11.1/24"},
				"ip6_address": J{"2001%3Adb8%3A%3A1%2F64": J{}}},
		},
		"/system/interfaces?depth=2&selector=statistics": J{
			"1%2F1%2F1": J{"name": "1/1/1", "statistics": J{"rx_bytes": 1000, "tx_bytes": 2000, "rx_packets": 10, "tx_packets": 20, "rx_errors": 1, "tx_errors": 2, "rx_dropped": 3, "tx_dropped": 4}},
		},
		"/system/interfaces/1%2F1%2F1/lldp_neighbors?depth=2": J{"aa:bb,1/1/1": J{"chassis_id": "aa:bb:cc:00:00:99", "port_id": "Gi0/1",
			"neighbor_info": J{"chassis_name": "core", "chassis_description": "Aruba", "mgmt_ip_list": "10.0.0.9,fe80::1", "port_description": "to sw1"}}},
		"/system/vrfs?depth=1": J{"default": "/rest/v10.09/system/vrfs/default", "mgmt": "/rest/v10.09/system/vrfs/mgmt"},
		"/system/vrfs/default/routes?depth=3": J{
			"10.9.0.0%2F24": J{"prefix": "10.9.0.0/24", "from": "ospf", "distance": 110, "metric": 20, "address_family": "ipv4", "nexthops": J{
				"a": J{"ip_address": "10.0.0.2", "port": J{"1%2F1%2F1": "/rest/v10.09/system/interfaces/1%2F1%2F1"}},
				"b": J{"ip_address": "10.0.0.3", "port": "/rest/v10.09/system/interfaces/1%2F1%2F2"}}},
			"0.0.0.0%2F0": J{"prefix": "0.0.0.0/0", "from": "static", "distance": 1, "nexthops": J{"n": J{"ip_address": "10.0.0.1", "port": "/rest/v10.09/system/interfaces/1%2F1%2F1"}}},
		},
		"/system/vrfs/default/bgp_routers?depth=4":      J{"1": J{"asn": 65001, "router_id": "1.1.1.1", "bgp_neighbors": J{"10.0.0.9": J{"password": "hunter2", "remote_as": 65002}}}},
		"/system/acls?depth=3":                          J{"web,ipv4": J{"name": "web", "list_type": "ipv4", "cfg_aces": J{"10": J{"action": "permit"}}}},
		"/system/acls?depth=3&selector=statistics":      J{"web,ipv4": J{"cfg_aces": J{"10": J{"hit_count": 5}}}},
		"/system/subsystems?depth=1":                    J{"chassis,1": "/rest/v10.09/system/subsystems/chassis%2C1"},
		sub + "/fans?depth=2&selector=status":           J{"1%2F1": J{"name": "1/1", "speed": 5000, "status": "ok"}},
		sub + "/temp_sensors?depth=2&selector=status":   J{"1%2F1": J{"name": "1/1", "temperature": 36500, "status": "normal"}},
		sub + "/power_supplies?depth=2&selector=status": J{"1%2F1": J{"name": "1/1", "status": "ok", "characteristics": J{"instantaneous_power": 120}}},
		"/system/vlans?depth=2": J{"1": J{"id": 1, "name": "DEFAULT_VLAN_1", "oper_state": "up", "admin": "up"}, "10": J{"id": 10, "name": "users", "oper_state": "up"},
			"20": J{"id": 20, "name": "voice", "oper_state": "down"}},
		"/fullconfigs/running-config":    J{"System": J{"hostname": "sw1"}, "Radius_Server": J{"shared_secret_ciphertext": "xyz"}},
		"/system/vrfs/default/some_part": J{"password": "pw", "name": "x"},
	}
}

var cxCred = Credential{Username: "admin", Password: "s3cret"}

func TestAOSCX(t *testing.T) {
	old := nowUnix
	nowUnix = func() int64 { return 2000000 }
	defer func() { nowUnix = old }()
	d, st := cxStub(t, cxAnswers())
	ctx := context.Background()
	drv, err := Open(d, cxCred)
	if err != nil {
		t.Fatal(err)
	}
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "sw1", Vendor: "Aruba", Model: "Aruba 8325-48Y8C", OSVersion: "FL.10.09.1000", Serial: "SG12345678", UptimeS: 90061}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 4 {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	by := map[string]Interface{}
	for _, i := range ifs {
		by[i.Name] = i
	}
	e1, e2, v10, lag := by["1/1/1"], by["1/1/2"], by["vlan10"], by["lag1"]
	if !*e1.AdminUp || !*e1.OperUp || e1.SpeedMbps != 10000 || e1.MAC != "aa:bb:cc:00:00:01" || e1.Description != "uplink" {
		t.Errorf("1/1/1: %+v", e1)
	}
	if *e2.AdminUp || *e2.OperUp || e2.SpeedMbps != 0 || !*lag.AdminUp || *lag.OperUp {
		t.Errorf("down ports: %+v %+v", e2, lag)
	}
	if strings.Join(v10.Addresses, " ") != "10.0.10.1/24 10.0.11.1/24 2001:db8::1/64" || v10.MAC != "aa:bb:cc:00:00:10" {
		t.Errorf("vlan10 (a member without a name attribute is named by its key): %+v", v10)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 1 || nb[0].LocalPort != "1/1/1" || nb[0].RemoteName != "core" || nb[0].RemotePort != "Gi0/1" || nb[0].RemoteAddr != "10.0.0.9" ||
		nb[0].RemoteDesc != "Aruba" || nb[0].Protocol != "lldp" {
		t.Errorf("neighbors: %v %+v", err, nb)
	}
	if st.saw("1%2F1%2F2/lldp") || st.saw("vlan10/lldp") || st.saw("lag1/lldp") {
		t.Error("LLDP was asked of a port that is down or is not a front-panel port")
	}
	c, err := drv.Config(ctx)
	if err != nil || !strings.Contains(c, "\"hostname\": \"sw1\"") {
		t.Errorf("config: %v %q", err, c)
	}
	if _, err := drv.Show(ctx, "show version"); err != ErrUnsupported {
		t.Errorf("show: %v", err)
	}
	// ports
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 4 {
		t.Fatalf("ports: %v %+v", err, ps)
	}
	var p Port
	for _, x := range ps {
		if x.Name == "1/1/1" {
			p = x
		}
	}
	cn := p.Counters
	if p.Type != "system" || p.MTU != 1500 || p.Duplex != "full" || cn.InOctets != 1000 || cn.OutOctets != 2000 || cn.InPackets != 10 || cn.OutPackets != 20 ||
		cn.InErrors != 1 || cn.OutErrors != 2 || cn.InDiscards != 3 || cn.OutDiscards != 4 || p.Properties["status"] == nil || p.Properties["configuration"] == nil {
		t.Errorf("port: %+v", p)
	}
	// routes
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 3 {
		t.Fatalf("routes (a VRF with no routes resource is skipped): %v %+v", err, rs)
	}
	var ospf, static []Route
	for _, r := range rs {
		if r.Protocol == "ospf" {
			ospf = append(ospf, r)
		} else {
			static = append(static, r)
		}
	}
	if len(ospf) != 2 || ospf[0].Prefix != "10.9.0.0/24" || ospf[0].Distance != 110 || ospf[0].Metric != 20 || ospf[0].VRF != "default" ||
		ospf[0].NextHop+ospf[1].NextHop != "10.0.0.210.0.0.3" || ospf[0].Interface+ospf[1].Interface != "1/1/11/1/2" {
		t.Errorf("ospf: %+v", ospf)
	}
	if len(static) != 1 || static[0].Prefix != "0.0.0.0/0" || static[0].NextHop != "10.0.0.1" || static[0].Interface != "1/1/1" || static[0].Distance != 1 {
		t.Errorf("static: %+v", static)
	}
	rt, err := drv.(Router).Routing(ctx)
	if err != nil || rt.Protocols["bgp_routers_default"] == nil || rt.Unavailable["ospf_routers_default"] == "" || rt.Unavailable["bgp_routers_mgmt"] == "" {
		t.Fatalf("routing: %v %+v", err, rt)
	}
	nbr := rt.Protocols["bgp_routers_default"].(map[string]any)["1"].(map[string]any)["bgp_neighbors"].(map[string]any)["10.0.0.9"].(map[string]any)
	if nbr["password"] != "(hidden)" || nbr["remote_as"] != float64(65002) {
		t.Errorf("bgp neighbor: %+v", nbr)
	}
	fw, err := drv.(Firewaller).Firewall(ctx)
	if err != nil || fw.Protocols["acls"] == nil || fw.Protocols["acl_statistics"] == nil || fw.Unavailable["policies"] == "" {
		t.Errorf("firewall: %v %+v", err, fw)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 7 || len(r.Memory) != 1 || r.Memory[0].UsedPercent != 41 || len(r.Sensors) != 3 {
		t.Fatalf("resources: %v %+v %+v %+v", err, r.CPU, r.Memory, r.Sensors)
	}
	sens := map[string]Sensor{}
	for _, s := range r.Sensors {
		sens[s.Kind] = s
	}
	if *sens["fan"].Reading != 5000 || sens["fan"].State != "ok" || *sens["temperature"].Reading != 36.5 || sens["temperature"].Units != "C" || *sens["psu"].Reading != 120 {
		t.Errorf("sensors: %+v", sens)
	}
	vl, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vl) != 3 || vl[1].ID != 10 || vl[1].Name != "users" || vl[1].Status != "up" || strings.Join(vl[1].Ports, ",") != "1/1/1" ||
		vl[2].ID != 20 || strings.Join(vl[2].Ports, ",") != "1/1/1" || vl[0].Ports != nil {
		t.Errorf("vlans: %v %+v", err, vl)
	}
	// the API
	a := drv.(APIer)
	v, text, err := a.APIGet(ctx, "/rest/v10.09/system/vrfs/default/some_part")
	if m, _ := v.(map[string]any); err != nil || text || m["password"] != "(hidden)" || m["name"] != "x" {
		t.Errorf("api get: %v %v %v", err, text, v)
	}
	before := len(st.reqs)
	for _, bad := range []string{"/system/vrfs", "/rest/v10.09/login", "/rest/v10.09/logout", "/rest/v10.09/LOGIN?x=1", "/other/rest/x"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if len(st.reqs) != before {
		t.Errorf("a refused path reached the switch: %v", st.reqs[before:])
	}
	if cat, err := a.APICatalog(ctx); err != nil || cat.(map[string]any)["how"] == nil {
		t.Errorf("catalog: %v", err)
	}
	// one login for the whole request, a logout in Close
	drv.Close(ctx)
	if st.logins != 1 || st.logouts != 1 {
		t.Errorf("logins %d logouts %d", st.logins, st.logouts)
	}
	if st.version != "v10.09" {
		t.Errorf("version %s", st.version)
	}
}

func TestAOSCXLoginAndOptions(t *testing.T) {
	d, st := cxStub(t, cxAnswers())
	ctx := context.Background()
	bad := open(t, d, Credential{Username: "admin", Password: "nope"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "nope") {
		t.Errorf("wrong password: %v", err)
	}
	if st.logouts != 0 {
		t.Error("a logout without a login")
	}
	for _, c := range []Credential{{Username: "admin"}, {Token: "x"}} {
		if _, err := Open(d, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	for _, v := range []string{"10.09", "v10.09/../x", "v1;2", "vv10", "v10.09.1.2"} {
		d.Options = map[string]string{"api_version": v}
		if _, err := Open(d, cxCred); err == nil {
			t.Errorf("api_version %q accepted", v)
		}
	}
	d.Options = map[string]string{"api_version": "v10.04"}
	drv := open(t, d, cxCred)
	_, _ = drv.Facts(ctx)
	if st.version != "v10.04" {
		t.Errorf("api_version not used: %s", st.version)
	}
}

func TestAOSCXReaders(t *testing.T) {
	got := cxItems(J{"a%2Fb": J{"x": 1}, "c": J{"name": "named"}})
	if len(got) != 2 || got[0]["name"] != "a/b" || got[1]["name"] != "named" {
		t.Errorf("%+v", got)
	}
	if one := cxItems(J{"hostname": "x", "n": 1}); len(one) != 1 || one[0]["hostname"] != "x" { // one object, not a collection
		t.Errorf("%+v", one)
	}
	if k := cxKeys(J{"1%2F1%2F1": "/rest/x", "default": "/rest/y"}); strings.Join(k, ",") != "1/1/1,default" {
		t.Errorf("%v", k)
	}
	if k := cxKeys([]any{"/rest/v10.09/system/vrfs/mgmt?depth=1"}); strings.Join(k, ",") != "mgmt" {
		t.Errorf("%v", k)
	}
	if r := cxRefs([]any{"/rest/v10.09/system/vlans/10", J{"20": "/x"}, ""}); strings.Join(r, ",") != "10,20" {
		t.Errorf("%v", r)
	}
	if cxRefs(nil) != nil || cxRefs("") != nil {
		t.Error("nothing is no reference")
	}
}
