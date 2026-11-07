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

type niosState struct {
	mu   sync.Mutex
	reqs []string
	ver  string
}

// niosStub is an Infoblox WAPI on loopback: HTTP basic authentication, and GET answers keyed by the object type below
// /wapi/<version>/ (the query is not part of the key).  The stub fails the test on any method but GET, a function call, or a
// password in a URL.
func niosStub(t *testing.T, answers map[string]any) (Device, *niosState) {
	t.Helper()
	st := &niosState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "s3cret") {
			t.Errorf("the password is in the URL: %s", r.URL)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"Error":"AdmConProtoError: Authorization Required","code":"Client.Ibap.Proto","text":"Authorization Required"}`))
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request (only GET is sent)", r.Method)
		}
		if strings.Contains(r.URL.RawQuery, "_function") {
			t.Errorf("a function call was sent: %s", r.URL)
		}
		rest := strings.TrimPrefix(r.URL.Path, "/wapi/")
		ver, typ, _ := strings.Cut(rest, "/")
		st.mu.Lock()
		st.ver = ver
		st.reqs = append(st.reqs, r.Method+" "+r.URL.RequestURI())
		st.mu.Unlock()
		a, ok := answers[typ]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"Error":"AdmConProtoError: Unknown object type","code":"Client.Ibap.Proto","text":"Unknown object type"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "ns1", Platform: "nios", Address: host, Port: pn, Insecure: true}, st
}

var niosCred = Credential{Username: "admin", Password: "s3cret"}

// Field names: member host_name, platform, vip_setting (address, subnet_mask, gateway), ipv6_setting (enabled, virtual_ip,
// cidr_prefix), node_info (hwmodel, hwid, hwplatform, service_status{service,status}), capacityreport (name, percent_used,
// total_objects, max_capacity) and upgradestatus (type=PNODE: current_version, member, ipv4_address) are the ones Infoblox's
// WAPI documentation lists; the node_info port settings (lan2_network_setting, mgmt_network_setting, lan_ha_port_setting)
// were only seen in this stub.
func niosAnswers(vip1 string) map[string]any {
	return map[string]any{
		"member": []any{
			J{"_ref": "member/b25l:ns1.example.com", "host_name": "ns1.example.com", "platform": "INFOBLOX",
				"vip_setting":  J{"address": vip1, "subnet_mask": "255.255.255.0", "gateway": "10.0.0.1"},
				"ipv6_setting": J{"enabled": true, "virtual_ip": "2001:db8::7", "cidr_prefix": 64},
				"snmp_setting": J{"queries_community_string": "public"},
				"node_info": []any{J{"hwmodel": "IB-1415", "hwid": "1234567890", "hwplatform": "INFOBLOX",
					"lan2_network_setting": J{"address": "192.168.5.7", "subnet_mask": "255.255.255.0"},
					"mgmt_network_setting": J{"address": "172.16.0.7", "subnet_mask": "255.255.0.0"},
					"lan_ha_port_setting":  J{"ha_ip_address": "10.0.0.8"},
					"service_status":       []any{J{"service": "DNS", "status": "WORKING"}, J{"service": "DHCP", "status": "INACTIVE"}}}}},
			J{"_ref": "member/b25m:ns2.example.com", "host_name": "ns2.example.com", "platform": "VNIOS",
				"vip_setting": J{"address": "10.0.0.9", "subnet_mask": "255.255.255.0", "gateway": "10.0.0.1"},
				"node_info":   []any{J{"hwmodel": "", "hwid": "VM-1", "hwplatform": "VNIOS", "service_status": []any{J{"service": "DNS", "status": "FAILED"}}}}},
		},
		"upgradestatus": []any{J{"member": "ns1.example.com", "current_version": "9.0.4-12345", "ipv4_address": vip1}, J{"member": "ns2.example.com", "current_version": "9.0.3", "ipv4_address": "10.0.0.9"}},
		"grid":          []any{J{"name": "Infoblox-Grid", "_ref": "grid/b25n:Infoblox-Grid"}},
		"capacityreport": []any{J{"name": "ns1.example.com", "percent_used": 12, "total_objects": 1000, "max_capacity": 8000, "hardware_type": "IB-1415", "role": "Master"},
			J{"name": "ns2.example.com", "percent_used": 3, "total_objects": 300, "max_capacity": 10000}},
		"": J{"supported_objects": []any{"network", "member"}, "supported_versions": []any{"v2.12"}, "requested_version": "v2.12"},
		"network": []any{J{"_ref": "network/b25:10.0.0.0/24/default", "network": "10.0.0.0/24", "extattrs": J{"Site": J{"value": "dc1"}},
			"tsig_key": "abc", "key": "k"}},
	}
}

func TestNIOS(t *testing.T) {
	d, st := niosStub(t, niosAnswers("127.0.0.1"))
	drv := open(t, d, niosCred)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "ns1.example.com", Vendor: "Infoblox", Model: "IB-1415", OSVersion: "9.0.4-12345", Serial: "1234567890"}) {
		t.Fatalf("facts (the member whose VIP is the address): %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	want := map[string]string{"lan1": "127.0.0.1/24 2001:db8::7/64", "lan2": "192.168.5.7/24", "mgmt": "172.16.0.7/16", "ha": "10.0.0.8"}
	if err != nil || len(ifs) != len(want) {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	for _, i := range ifs {
		if strings.Join(i.Addresses, " ") != want[i.Name] {
			t.Errorf("%s: %v (want %s)", i.Name, i.Addresses, want[i.Name])
		}
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
	if _, ok := drv.(Router); ok {
		t.Error("NIOS has no routing table")
	}
	if _, ok := drv.(VLANer); ok {
		t.Error("NIOS has no VLANs")
	}
	if _, ok := drv.(Porter); ok {
		t.Error("NIOS has no port counters")
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU != nil || len(r.Storage) != 2 || r.Storage[0].Name != "object capacity ns1.example.com" || r.Storage[0].UsedPercent != 12 || len(r.Sensors) != 3 {
		t.Fatalf("resources: %v %+v %+v", err, r.Storage, r.Sensors)
	}
	if s := r.Sensors[0]; s.Name != "ns1.example.com DNS" || s.State != "working" || r.Sensors[2].State != "failed" || r.Sensors[1].State != "inactive" {
		t.Errorf("sensors: %+v", r.Sensors)
	}
	if m := r.Details.Protocols["members"].([]any)[0].(map[string]any); m["snmp_setting"].(map[string]any)["queries_community_string"] != "(hidden)" {
		t.Errorf("a community string is shown: %v", m["snmp_setting"])
	}
	// the API
	a := drv.(APIer)
	v, text, err := a.APIGet(ctx, "/wapi/v2.12/network?_max_results=5")
	l, _ := v.([]any)
	if err != nil || text || len(l) != 1 {
		t.Fatalf("api get: %v %v %v", err, text, v)
	}
	if n := l[0].(map[string]any); n["tsig_key"] != "(hidden)" || n["key"] != "(hidden)" || n["network"] != "10.0.0.0/24" {
		t.Errorf("secrets in an object: %+v", n)
	}
	before := len(st.reqs)
	for _, bad := range []string{"/wapi/v2.12/fileop", "/wapi/v2.12/network?_function=restartservices", "/wapi/v2.12/network?_Function=x", "/wapi/v2.12/request",
		"/wapi/v2.12/restartservicestatus/x", "/api/v1/x", "/wapi/network", "/wapi/abc/network", "/wapi", "/", "/wapi/v2.12/network?a=%zz"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if len(st.reqs) != before {
		t.Errorf("a refused path reached the appliance: %v", st.reqs[before:])
	}
	cat, err := a.APICatalog(ctx)
	if m, _ := cat.(map[string]any); err != nil || m["how"] == nil || len(m["supported_objects"].([]any)) != 2 {
		t.Errorf("catalog: %v %+v", err, cat)
	}
	if st.ver != "v2.12" {
		t.Errorf("version %s", st.ver)
	}
}

func TestNIOSNotAMember(t *testing.T) {
	// an address that is no member's VIP: the grid answers, and every member's addresses are listed under its name
	d, _ := niosStub(t, niosAnswers("10.0.0.7"))
	drv := open(t, d, niosCred)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "Infoblox-Grid", Vendor: "Infoblox"}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 5 || ifs[0].Name != "ns1.example.com/ha" {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	// a host name that is a member's name picks that member
	d.Address = "localhost"
	a := niosAnswers("10.0.0.7")
	a["member"].([]any)[0].(J)["host_name"] = "localhost"
	d2, _ := niosStub(t, a)
	d2.Address = "localhost"
	f, err = open(t, d2, niosCred).Facts(ctx)
	if err != nil || f.Hostname != "localhost" || f.OSVersion != "" && f.OSVersion != "9.0.4-12345" {
		t.Errorf("host name match: %v %+v", err, f)
	}
}

func TestNIOSLoginAndOptions(t *testing.T) {
	d, st := niosStub(t, niosAnswers("127.0.0.1"))
	ctx := context.Background()
	if _, err := open(t, d, Credential{Username: "admin", Password: "nope"}).Facts(ctx); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "nope") {
		t.Errorf("wrong password: %v", err)
	}
	for _, c := range []Credential{{Username: "admin"}, {Token: "x"}} {
		if _, err := Open(d, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	for _, v := range []string{"2.12", "v2", "v2.12/../x", "v2.12.1.1", "v2;12"} {
		d.Options = map[string]string{"wapi_version": v}
		if _, err := Open(d, niosCred); err == nil {
			t.Errorf("wapi_version %q accepted", v)
		}
	}
	d.Options = map[string]string{"wapi_version": "v2.13.1"}
	_, _ = open(t, d, niosCred).Facts(ctx)
	if st.ver != "v2.13.1" {
		t.Errorf("wapi_version not used: %s", st.ver)
	}
}

func TestCheckAPIPathMCPArubaInfoblox(t *testing.T) {
	for _, ok := range []string{
		"/rest/v10.09/system?selector=status", "/rest/v10.09/system/interfaces?depth=2&selector=status", "/rest/v10.09/system/interfaces/1%2F1%2F1/lldp_neighbors?depth=2",
		"/rest/v10.09/system/vrfs/default/routes?depth=3", "/rest/v10.09/system/vlans?depth=2", "/rest/v10.09/system/acls?depth=3",
		"/wapi/v2.12/network?_max_results=5", "/wapi/v2.12/member?_return_fields=host_name", "/wapi/v2.12/zone_auth?_return_fields=fqdn", "/wapi/v2.12/record:a?name~=x",
		"/wapi/v2.12/lease?_max_results=5", "/wapi/v2.12/range", "/wapi/v2.12/capacityreport",
	} {
		if err := CheckAPIPathMCP(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"/rest/v10.09/fullconfigs/running-config", "/rest/v10.09/fullconfigs", "/rest/v10.09/configs/startup-config", "/rest/v10.09/accounts", "/rest/v10.09/accounts/admin",
		"/rest/v10.09/system/users", "/rest/v10.09/system/radius_servers", "/rest/v10.09/system/tacacs_servers", "/rest/v10.09/system/snmp_communities", "/rest/v10.09/system/aaa_server_groups",
		"/rest/v10.09/system/certificates", "/rest/v10.09/system/ssh_hostkeys",
		"/wapi/v2.12/adminuser", "/wapi/v2.12/admingroup", "/wapi/v2.12/authpolicy", "/wapi/v2.12/ldap_auth_service", "/wapi/v2.12/radius:authservice", "/wapi/v2.12/tacacsplus:authservice",
		"/wapi/v2.12/certificate:authservice", "/wapi/v2.12/dnsseckey", "/wapi/v2.12/tsigkey", "/wapi/v2.12/fileop", "/wapi/v2.12/snmpuser", "/wapi/v2.12/kerberoskey",
	} {
		if err := CheckAPIPathMCP(bad); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
}

// AAAA is the DNS record type, not AAA (authentication): its WAPI objects are readable over MCP, AAA still is not.
func TestCheckAPIPathMCPAAAARecords(t *testing.T) {
	for _, ok := range []string{"/wapi/v2.12/record:aaaa", "/wapi/v2.12/sharedrecord:aaaa?name=x", "/wapi/v2.12/record:host_ipv6addr"} {
		if err := CheckAPIPathMCP(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"/restconf/data/aaa", "/wapi/v2.12/aaa", "/wapi/v2.12/admingroup"} {
		if err := CheckAPIPathMCP(bad); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
}
