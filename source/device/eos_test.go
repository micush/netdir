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

type eosState struct {
	mu   sync.Mutex
	cmds []string
}

// eosStub is an Arista eAPI on loopback: HTTP basic authentication, and JSON-RPC runCmds answered from json (keyed by the
// command) or text (format "text").  A command that is not in the table is a JSON-RPC error, as eAPI answers.  The stub fails
// the test on any method but POST to /command-api, any JSON-RPC method but runCmds, a format other than json or text, a request with
// more than one command, and any command that is not a show command.
func eosStub(t *testing.T, js map[string]any, text map[string]string) (Device, *eosState) {
	t.Helper()
	st := &eosState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/command-api" {
			t.Errorf("%s %s (only POST /command-api)", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		var req struct {
			Method string `json:"method"`
			ID     string `json:"id"`
			Params struct {
				Version int      `json:"version"`
				Cmds    []string `json:"cmds"`
				Format  string   `json:"format"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("request: %v", err)
			return
		}
		if req.Method != "runCmds" || len(req.Params.Cmds) != 1 || req.Params.Format != "json" && req.Params.Format != "text" {
			t.Errorf("unexpected request: %+v", req)
		}
		cmd := req.Params.Cmds[0]
		if !strings.HasPrefix(cmd, "show ") {
			t.Errorf("a command that is not a show command was sent: %q", cmd)
		}
		st.mu.Lock()
		st.cmds = append(st.cmds, cmd)
		st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if req.Params.Format == "text" {
			if s, ok := text[cmd]; ok {
				out["result"] = []any{J{"output": s}}
			} else {
				out["error"] = J{"code": 1002, "message": "CLI command 1 of 1 '" + cmd + "' failed: invalid command"}
			}
		} else if v, ok := js[cmd]; ok {
			out["result"] = []any{v}
		} else {
			out["error"] = J{"code": 1002, "message": "CLI command 1 of 1 '" + cmd + "' failed: invalid command"}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "sw1", Platform: "eos", Address: host, Port: pn, Insecure: true}, st
}

func (s *eosState) saw(cmd string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if c == cmd {
			return true
		}
	}
	return false
}

// Field names: show version (modelName, version, serialNumber, bootupTimestamp, memTotal, memFree), show hostname, show interfaces
// (interfaceStatus, lineProtocolStatus, bandwidth, physicalAddress, interfaceAddress.primaryIp, interfaceCounters), show lldp
// neighbors detail, show vlan, and the environment counters named in Arista's documentation and the Harvest eAPI templates
// (currentTemperature, actualSpeed, outputPower, state).  The route table JSON, the IPv6 interface addresses, the cpuInfo of
// "show processes top once", the nesting of the environment answers and the part commands of the routing and firewall requests
// have only been seen in this stub.
func eosAnswers() (map[string]any, map[string]string) {
	js := map[string]any{
		"show version":  J{"modelName": "DCS-7050TX-64", "version": "4.28.3M", "serialNumber": "JPE12345678", "bootupTimestamp": 2000000.0 - 3700, "memTotal": 8000000, "memFree": 2000000},
		"show hostname": J{"hostname": "leaf1", "fqdn": "leaf1.example.net"},
		"show interfaces": J{"interfaces": J{
			"Ethernet1": J{"name": "Ethernet1", "interfaceStatus": "connected", "lineProtocolStatus": "up", "description": "to spine", "physicalAddress": "00:1c:73:00:00:01", "bandwidth": 10000000000,
				"mtu": 9214, "duplex": "duplexFull", "interfaceType": "EbraTestPhysicalPort",
				"interfaceCounters": J{"inOctets": 1000, "outOctets": 2000, "inUcastPkts": 8, "inMulticastPkts": 1, "inBroadcastPkts": 1, "outUcastPkts": 18, "outMulticastPkts": 1, "outBroadcastPkts": 1,
					"inDiscards": 3, "outDiscards": 4, "totalInErrors": 5, "totalOutErrors": 6, "inBitsRate": 8000.0, "outBitsRate": 16000.0, "inPktsRate": 7.0, "outPktsRate": 9.0, "linkStatusChanges": 2}},
			"Ethernet2": J{"name": "Ethernet2", "interfaceStatus": "disabled", "lineProtocolStatus": "down", "bandwidth": 0},
			"Vlan10": J{"interfaceStatus": "connected", "lineProtocolStatus": "up", "physicalAddress": "00:1c:73:00:00:10", "bandwidth": 0,
				"interfaceAddress":    []any{J{"primaryIp": J{"address": "10.0.10.1", "maskLen": 24}, "secondaryIpsOrderedList": []any{J{"address": "10.0.11.1", "maskLen": 24}}}},
				"interfaceAddressIp6": J{"globalUnicastIp6s": []any{J{"address": "2001:db8::1", "subnet": "2001:db8::/64"}}}},
			"Management1": J{"name": "Management1", "interfaceStatus": "connected", "lineProtocolStatus": "up", "bandwidth": 1000000000,
				"interfaceAddress": []any{J{"primaryIp": J{"address": "0.0.0.0", "maskLen": 0}}}},
		}},
		"show lldp neighbors detail": J{"lldpNeighbors": J{
			"Ethernet1": J{"lldpNeighborInfo": []any{J{"chassisId": "aa:bb:cc:00:00:99", "systemName": "spine1", "systemDescription": "Arista EOS\n", "neighborInterfaceInfo": J{"interfaceId_v2": "Ethernet49/1", "interfaceId": "\"Ethernet49/1\""},
				"managementAddresses": []any{J{"address": "10.0.0.9", "addressType": "ipv4"}}}}},
			"Ethernet2": J{"lldpNeighborInfo": []any{}},
		}},
		"show ip route vrf all": J{"vrfs": J{
			"default": J{"routes": J{
				"0.0.0.0/0":    J{"routeType": "static", "preference": 1, "metric": 0, "vias": []any{J{"nexthopAddr": "10.0.0.1", "interface": "Vlan10"}}},
				"10.9.0.0/24":  J{"routeType": "ospf", "preference": 110, "metric": 20, "vias": []any{J{"nexthopAddr": "10.0.0.2", "interface": "Ethernet1"}, J{"nexthopAddr": "10.0.0.3", "interface": "Ethernet2"}}},
				"10.0.10.0/24": J{"routeType": "connected", "preference": 0, "metric": 0, "vias": []any{J{"interface": "Vlan10"}}},
			}},
			"mgmt": J{"routes": J{}},
		}},
		"show ip bgp summary vrf all": J{"vrfs": J{"default": J{"peers": J{"10.0.0.9": J{"asn": "65002", "peerState": "Established", "password": "x"}}}}},
		"show ip access-lists":        J{"aclList": []any{J{"name": "web", "sequence": []any{J{"text": "permit ip any any", "sequenceNumber": 10, "counterData": J{"matches": 5}}}}}},
		"show vlan":                   J{"vlans": J{"1": J{"name": "default", "status": "active", "interfaces": J{}}, "10": J{"name": "users", "status": "active", "dynamic": false, "interfaces": J{"Ethernet5": J{}, "Ethernet1": J{}}}}},
		"show processes top once":     J{"cpuInfo": J{"%Cpu(s)": J{"idle": 96.5, "user": 2.0, "system": 1.5}}},
		"show environment cooling":    J{"fanTraySlots": []any{J{"label": "1", "status": "ok", "fans": []any{J{"label": "1/1", "status": "ok", "actualSpeed": 45}}}}, "powerSupplySlots": []any{J{"label": "1", "status": "ok", "fans": []any{J{"label": "PSU1/1", "status": "ok", "actualSpeed": 30}}}}},
		"show environment temperature": J{"tempSensors": []any{J{"name": "TempSensor1", "description": "Cpu temp sensor", "currentTemperature": 41.5, "hwStatus": "ok"}},
			"powerSupplySlots": []any{J{"tempSensors": []any{J{"name": "PowerSupply1Sensor1", "currentTemperature": 33.0, "hwStatus": "ok"}}}}},
		"show environment power": J{"powerSupplies": J{"1": J{"state": "ok", "outputPower": 85.5, "inputPower": 95.0, "capacity": 460}}},
		"show some secret thing": J{"password": "pw", "name": "x"},
	}
	text := map[string]string{
		"show running-config": "hostname leaf1\nusername admin secret sha512 $6$abc\n",
		"show version":        "Arista DCS-7050TX-64\n",
	}
	return js, text
}

var eosCred = Credential{Username: "admin", Password: "s3cret"}

func TestEOS(t *testing.T) {
	old := nowUnix
	nowUnix = func() int64 { return 2000000 }
	defer func() { nowUnix = old }()
	js, text := eosAnswers()
	d, st := eosStub(t, js, text)
	drv := open(t, d, eosCred)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "leaf1", Vendor: "Arista", Model: "DCS-7050TX-64", OSVersion: "4.28.3M", Serial: "JPE12345678", UptimeS: 3700}) {
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
	e1, e2, v10, mg := by["Ethernet1"], by["Ethernet2"], by["Vlan10"], by["Management1"]
	if !*e1.AdminUp || !*e1.OperUp || e1.SpeedMbps != 10000 || e1.MAC != "00:1c:73:00:00:01" || e1.Description != "to spine" {
		t.Errorf("Ethernet1: %+v", e1)
	}
	if *e2.AdminUp || *e2.OperUp || e2.SpeedMbps != 0 { // disabled is shut down
		t.Errorf("Ethernet2: %+v", e2)
	}
	if strings.Join(v10.Addresses, " ") != "10.0.10.1/24 10.0.11.1/24 2001:db8::1/64" { // named by its key
		t.Errorf("Vlan10: %+v", v10)
	}
	if mg.Addresses != nil || mg.SpeedMbps != 1000 {
		t.Errorf("Management1 (0.0.0.0 is no address): %+v", mg)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 1 || nb[0].LocalPort != "Ethernet1" || nb[0].RemoteName != "spine1" || nb[0].RemotePort != "Ethernet49/1" || nb[0].RemoteAddr != "10.0.0.9" ||
		nb[0].RemoteDesc != "Arista EOS" || nb[0].Protocol != "lldp" || nb[0].Detail["chassisId"] != "aa:bb:cc:00:00:99" {
		t.Errorf("neighbors: %v %+v", err, nb)
	}
	c, err := drv.Config(ctx)
	if err != nil || !strings.HasPrefix(c, "hostname leaf1") {
		t.Errorf("config: %v %q", err, c)
	}
	if s, err := drv.Show(ctx, "show version"); err != nil || !strings.HasPrefix(s, "Arista DCS") {
		t.Errorf("show: %v %q", err, s)
	}
	if _, err := drv.Show(ctx, "show nothing here"); err == nil || !strings.Contains(err.Error(), "invalid command") {
		t.Errorf("a command eAPI refuses is its refusal: %v", err)
	}
	for _, bad := range []string{"configure terminal", "enable", "write memory", "show version; reload", "show running-config | redirect flash:x", "reload"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was run", bad)
		}
		if st.saw(bad) {
			t.Errorf("%q reached the switch", bad)
		}
	}
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 4 {
		t.Fatalf("ports: %v %+v", err, ps)
	}
	var p Port
	for _, x := range ps {
		if x.Name == "Ethernet1" {
			p = x
		}
	}
	cn := p.Counters
	if p.Type != "EbraTestPhysicalPort" || p.MTU != 9214 || p.Duplex != "full" || cn.InOctets != 1000 || cn.OutOctets != 2000 || cn.InPackets != 10 || cn.OutPackets != 20 || cn.InUnicast != 8 ||
		cn.InDiscards != 3 || cn.OutDiscards != 4 || cn.InErrors != 5 || cn.OutErrors != 6 || cn.RxKbps != 8 || cn.TxKbps != 16 || cn.RxPPS != 7 || cn.Flaps != 2 || cn.All["inOctets"] != float64(1000) ||
		p.Properties["description"] != "to spine" || p.Properties["interfaceCounters"] != nil {
		t.Errorf("port: %+v", p)
	}
	rs, err := drv.(Router).Routes(ctx) // ipv6 is not answered (a command the switch lacks): the IPv4 table stands
	if err != nil || len(rs) != 4 {
		t.Fatalf("routes: %v %+v", err, rs)
	}
	if r := rs[0]; r.Prefix != "0.0.0.0/0" || r.Protocol != "static" || r.NextHop != "10.0.0.1" || r.Interface != "Vlan10" || r.Distance != 1 || r.VRF != "default" {
		t.Errorf("default route: %+v", r)
	}
	if rs[2].Protocol != "ospf" || rs[2].Prefix != "10.9.0.0/24" || rs[2].NextHop != "10.0.0.2" || rs[3].NextHop != "10.0.0.3" || rs[2].Metric != 20 || rs[2].Distance != 110 || rs[1].NextHop != "" || rs[1].Protocol != "connected" {
		t.Errorf("routes: %+v", rs)
	}
	rt, err := drv.(Router).Routing(ctx)
	if err != nil || rt.Protocols["bgp_summary"] == nil || rt.Unavailable["ospf_neighbors"] == "" {
		t.Fatalf("routing: %v %+v", err, rt)
	}
	peer := rt.Protocols["bgp_summary"].(map[string]any)["vrfs"].(map[string]any)["default"].(map[string]any)["peers"].(map[string]any)["10.0.0.9"].(map[string]any)
	if peer["password"] != "(hidden)" || peer["peerState"] != "Established" {
		t.Errorf("bgp peer: %+v", peer)
	}
	fw, err := drv.(Firewaller).Firewall(ctx)
	if err != nil || fw.Protocols["ip_access_lists"] == nil || fw.Unavailable["ipv6_access_lists"] == "" {
		t.Errorf("firewall: %v %+v", err, fw)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 3.5 || len(r.Memory) != 1 || r.Memory[0].Total != 8000000*1024 || r.Memory[0].Used != 6000000*1024 || r.Memory[0].UsedPercent != 75 {
		t.Fatalf("resources: %v %+v %+v", err, r.CPU, r.Memory)
	}
	if len(r.Sensors) != 5 {
		t.Fatalf("sensors: %+v", r.Sensors)
	}
	kinds := map[string]int{}
	for _, s := range r.Sensors {
		kinds[s.Kind]++
	}
	if kinds["fan"] != 2 || kinds["temperature"] != 2 || kinds["psu"] != 1 {
		t.Errorf("sensor kinds (nested sensors are found): %v", kinds)
	}
	last := r.Sensors[len(r.Sensors)-1]
	if last.Name != "PSU 1" || last.State != "ok" || *last.Reading != 85.5 || *r.Sensors[3].Reading != 41.5 {
		t.Errorf("sensors: %+v", r.Sensors)
	}
	vl, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vl) != 2 || vl[1].ID != 10 || vl[1].Name != "users" || vl[1].Status != "active" || strings.Join(vl[1].Ports, ",") != "Ethernet1,Ethernet5" || vl[0].Ports != nil {
		t.Errorf("vlans: %v %+v", err, vl)
	}
	// the API: a path names a show command
	a := drv.(APIer)
	v, isText, err := a.APIGet(ctx, "/eapi/show/some/secret/thing")
	if m, _ := v.(map[string]any); err != nil || isText || m["password"] != "(hidden)" || m["name"] != "x" {
		t.Errorf("secrets in an answer: %v %v %v", err, isText, v)
	}
	if v, _, err := a.APIGet(ctx, "/eapi/show/interfaces/Ethernet1%2F1"); err == nil { // a command the switch does not know is its refusal
		t.Errorf("a command not in the table: %v", v)
	} else if !st.saw("show interfaces Ethernet1/1") {
		t.Errorf("%%2F is a / inside a word: %v", st.cmds)
	}
	if v, isText, err := a.APIGet(ctx, "/eapi/show/version"); err != nil || isText || v.(map[string]any)["modelName"] != "DCS-7050TX-64" {
		t.Errorf("api get: %v %v %v", err, isText, v)
	}
	if v, isText, err := a.APIGet(ctx, "/eapi/show/running-config?format=text"); err != nil || !isText || !strings.HasPrefix(v.(string), "hostname") {
		t.Errorf("text: %v %v %v", err, isText, v)
	}
	before := len(st.cmds)
	for _, bad := range []string{"/eapi/", "/eapi/configure/terminal", "/eapi/enable", "/eapi/reload", "/eapi/show/version?format=xml", "/eapi/show/version?x=1", "/eapi/show/version/%zz",
		"/command-api", "/eapi/show/version%3Breload", "/eapi/show//version", "/other/show/version", "/eapi/show/running-config%20%7C%20redirect%20flash:x"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was run", bad)
		}
	}
	if len(st.cmds) != before {
		t.Errorf("a refused path reached the switch: %v", st.cmds[before:])
	}
	if cat, err := a.APICatalog(ctx); err != nil || cat.(map[string]any)["how"] == nil {
		t.Errorf("catalog: %v", err)
	}
}

func TestEOSLogin(t *testing.T) {
	js, text := eosAnswers()
	d, _ := eosStub(t, js, text)
	ctx := context.Background()
	if _, err := open(t, d, Credential{Username: "admin", Password: "nope"}).Facts(ctx); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "nope") {
		t.Errorf("wrong password: %v", err)
	}
	for _, c := range []Credential{{Username: "admin"}, {Token: "x"}} {
		if _, err := Open(d, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestEOSFindKey(t *testing.T) {
	got := findKey(J{"a": J{"tempSensors": []any{J{"name": "x"}}}, "b": []any{J{"tempSensors": J{"name": "y"}}}, "tempSensors": []any{J{"name": "z"}}}, "tempSensors")
	var names []string
	for _, g := range got {
		names = append(names, str(g["name"]))
	}
	if strings.Join(names, ",") != "x,y,z" && strings.Join(names, ",") != "z,x,y" {
		t.Errorf("%v", names)
	}
	if len(findKey(nil, "x")) != 0 {
		t.Error("nothing found in nothing")
	}
}

func TestCheckAPIPathMCPEOSAndTechnitium(t *testing.T) {
	for _, ok := range []string{
		"/eapi/show/version", "/eapi/show/interfaces", "/eapi/show/interfaces/Ethernet1%2F1", "/eapi/show/ip/route/vrf/all", "/eapi/show/ip/bgp/summary/vrf/all", "/eapi/show/lldp/neighbors/detail",
		"/eapi/show/vlan", "/eapi/show/environment/cooling", "/eapi/show/processes/top/once", "/eapi/show/ip/access-lists", "/eapi/show/mlag", "/eapi/show/vrrp", "/eapi/show/bfd/peers",
		"/api/settings/get", "/api/zones/list", "/api/zones/records/get?domain=a&zone=a", "/api/dashboard/stats/get?type=LastHour", "/api/cache/list", "/api/blocked/list", "/api/dhcp/scopes/list",
	} {
		if err := CheckAPIPathMCP(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"/eapi/show/running-config", "/eapi/show/run", "/eapi/show/running", "/eapi/show/ru", "/eapi/show/startup-config", "/eapi/show/start", "/eapi/show/session-config", "/eapi/show/tech-support", "/eapi/show/tech",
		"/eapi/show/snmp", "/eapi/show/sn", "/eapi/show/users", "/eapi/show/us", "/eapi/show/aaa", "/eapi/show/radius", "/eapi/show/tacacs", "/eapi/show/crypto", "/eapi/show/kerberos", "/eapi/show/privilege",
		"/eapi/show/RUN", "/eapi/show/%72un",
		"/api/admin/users/list", "/api/admin/sessions/list", "/api/user/session/get", "/api/user/profile/get",
	} {
		if err := CheckAPIPathMCP(bad); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
}
