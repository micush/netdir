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
	"sync/atomic"
	"testing"
)

// nxStub is a Nexus switch's NX-API on loopback.  cli maps "<type> <command>" to the body of the answer (JSON, or "ERR <code> <msg>"
// for a command error); rest maps a REST path (with query) to its answer.  The stub fails the test if a request is not a
// read-only type or not a show command: the driver must never send anything else.
type nxStubState struct {
	insCalls, logins, logouts atomic.Int32
	seen                      []string
}

func nxStub(t *testing.T, cli, rest map[string]string) (Device, *nxStubState) {
	t.Helper()
	st := &nxStubState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		switch {
		case r.URL.Path == "/ins" && r.Method == http.MethodPost:
			if !ok || u != "admin" || p != "s3cret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			st.insCalls.Add(1)
			b, _ := io.ReadAll(r.Body)
			var req struct {
				Ins map[string]any `json:"ins_api"`
			}
			if err := json.Unmarshal(b, &req); err != nil {
				t.Errorf("a request that is not JSON: %s", b)
				return
			}
			typ, _ := req.Ins["type"].(string)
			in, _ := req.Ins["input"].(string)
			st.seen = append(st.seen, typ+" "+in)
			if typ != "cli_show" && typ != "cli_show_ascii" || !strings.HasPrefix(in, "show ") || strings.ContainsAny(in, ";\n") {
				t.Errorf("a request that is not a read-only show command was sent: %s %q", typ, in)
			}
			body, ok := cli[typ+" "+in]
			out := map[string]any{"input": in, "msg": "Success", "code": "200"}
			switch {
			case !ok:
				out["msg"], out["code"] = "Input CLI command error", "400"
			case strings.HasPrefix(body, "ERR "):
				f := strings.SplitN(body, " ", 3)
				out["code"], out["msg"] = f[1], f[2]
			case typ == "cli_show_ascii":
				out["body"] = body
			default:
				var v any
				if err := json.Unmarshal([]byte(body), &v); err != nil {
					t.Errorf("stub body for %q is not JSON: %v", in, err)
				}
				out["body"] = v
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ins_api": map[string]any{"type": typ, "version": "1.0", "sid": "eoc", "outputs": map[string]any{"output": out}}})
		case r.URL.Path == "/api/aaaLogin.json" && r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"name":"admin"`) || !strings.Contains(string(b), `"pwd":"s3cret"`) {
				http.Error(w, `{"imdata":[{"error":{"attributes":{"code":"401","text":"Unauthorized"}}}]}`, http.StatusUnauthorized)
				return
			}
			st.logins.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "APIC-cookie", Value: "tok123", Path: "/", Secure: true})
			_, _ = w.Write([]byte(`{"imdata":[{"aaaLogin":{"attributes":{"token":"tok123"}}}]}`))
		case r.URL.Path == "/api/aaaLogout.json" && r.Method == http.MethodPost:
			st.logouts.Add(1)
			_, _ = w.Write([]byte(`{"imdata":[]}`))
		case strings.HasPrefix(r.URL.Path, "/api/") && r.Method == http.MethodGet:
			if c, err := r.Cookie("APIC-cookie"); err != nil || c.Value != "tok123" {
				http.Error(w, "no session", http.StatusForbidden)
				return
			}
			a, ok := rest[r.URL.RequestURI()]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(a))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "n9k1", Platform: "nxos", Address: host, Port: pn, Insecure: true}, st
}

var nxCred = Credential{Username: "admin", Password: "s3cret"}

// Field names: the NX-API keys of show version, show lldp neighbors detail, show vlan brief, show interface (interface, state,
// admin_state, desc, eth_hw_addr, eth_mtu, eth_bw, svi_*), show inventory and show system resources are the ones Cisco's NX-API CLI
// reference and NAPALM read; the eth_* counter names, the route table and the CDP, fan, temperature and power keys are from memory
// of real output and have only been seen here, in this stub.
const nxShowInterface = `{"TABLE_interface":{"ROW_interface":[
	{"interface":"Ethernet1/1","state":"up","admin_state":"up","desc":"to spine1","eth_hw_desc":"100/1000/10000 Ethernet","eth_hw_addr":"aabb.cc00.0100","eth_mtu":"9216","eth_bw":10000000,"eth_speed":"10 Gb/s","eth_duplex":"full",
	 "eth_inbytes":"5000000000","eth_inpkts":"50","eth_inucast":"40","eth_inmcast":"6","eth_inbcast":"4","eth_inerr":"3","eth_indiscard":"2","eth_outbytes":"7000","eth_outpkts":"70","eth_outucast":"70","eth_outerr":"1","eth_inrate1_bits":"8000","eth_inrate1_pkts":"9","eth_outrate1_bits":"16000","eth_outrate1_pkts":"12"},
	{"interface":"Ethernet1/2","state":"down","admin_state":"down","eth_hw_addr":"aabb.cc00.0101","eth_speed":"auto-speed","eth_bw":1000000,"eth_mtu":"1500"},
	{"interface":"Vlan10","state":"up","svi_admin_state":"up","svi_mac":"aabb.cc00.0110","svi_ip_addr":"10.0.0.2","svi_ip_mask":"24","svi_bw":1000000,"svi_mtu":"9216","svi_desc":"servers"},
	{"interface":"mgmt0","state":"up","admin_state":"up","eth_hw_addr":"aabb.cc00.0001","eth_ip_addr":"192.168.1.5","eth_ip_mask":"24","eth_bw":1000000,"eth_speed":"1000 Mb/s"},
	{"interface":"loopback0","state":"up","admin_state":"up","eth_ip_addr":"10.255.0.1","eth_ip_mask":"32","eth_bw":8000000}]}}`

func nxCLI() map[string]string {
	return map[string]string{
		"cli_show show version": `{"header_str":"Cisco Nexus Operating System (NX-OS) Software","kickstart_ver_str":"9.3(8)","sys_ver_str":"9.3(8)","chassis_id":"Nexus9000 C93180YC-EX Chassis",
			"host_name":"n9k1","proc_board_id":"FDO21470ABC","kern_uptm_days":2,"kern_uptm_hrs":3,"kern_uptm_mins":4,"kern_uptm_secs":5}`,
		"cli_show show inventory": `{"TABLE_inv":{"ROW_inv":[{"name":"\"Chassis\"","desc":"\"Nexus9000 C93180YC-EX Chassis\"","productid":"N9K-C93180YC-EX","serialnum":"FDO21470ABC"},
			{"name":"\"Slot 1\"","productid":"N9K-C93180YC-EX","serialnum":"FDO2147XYZ"}]}}`,
		"cli_show show interface": nxShowInterface,
		"cli_show show lldp neighbors detail": `{"neigh_count":"1","TABLE_nbor_detail":{"ROW_nbor_detail":{"l_port_id":"Eth1/1","chassis_id":"aabb.cc00.0200","port_id":"Ethernet1/49","port_desc":"to n9k1",
			"sys_name":"spine1","sys_desc":"Cisco Nexus9000","mgmt_addr":"10.0.0.11","mgmt_addr_type":"IPV4","ttl":"120","vlan_id":"not advertised"}}}`,
		"cli_show show cdp neighbors detail": `{"TABLE_cdp_neighbor_detail_info":{"ROW_cdp_neighbor_detail_info":[
			{"device_id":"fw1.example.net(FOC1234ABCD)","intf_id":"Ethernet1/2","port_id":"GigabitEthernet0/0","platform_id":"cisco ASA","v4mgmtaddr":"10.0.0.21"},
			{"device_id":"dup","intf_id":"Ethernet1/1","port_id":"x"}]}}`,
		"cli_show_ascii show running-config": "!Command: show running-configuration\nhostname n9k1\nfeature nxapi\nusername admin password 5 $5$abc role network-admin\n",
		"cli_show show ip route vrf all": `{"TABLE_vrf":{"ROW_vrf":[{"vrf-name-out":"default","TABLE_addrf":{"ROW_addrf":{"addrf":"ipv4","TABLE_prefix":{"ROW_prefix":[
			{"ipprefix":"0.0.0.0/0","ucast-nhops":"1","TABLE_path":{"ROW_path":{"ipnexthop":"10.0.0.1","ifname":"Vlan10","pref":"1","metric":"0","clientname":"static","type":"none"}}},
			{"ipprefix":"10.1.0.0/24","ucast-nhops":"2","TABLE_path":{"ROW_path":[{"ipnexthop":"10.0.0.3","ifname":"Vlan10","pref":"110","metric":"20","clientname":"ospf-1","type":"intra"},
				{"ipnexthop":"10.0.0.4","ifname":"Vlan10","pref":"110","metric":"20","clientname":"ospf-1","type":"intra"}]}},
			{"ipprefix":"10.0.0.0/24","TABLE_path":{"ROW_path":{"ipnexthop":"10.0.0.2/32","ifname":"Vlan10","pref":"0","metric":"0","clientname":"direct"}}}]}}}}]}}`,
		"cli_show show ip ospf neighbors vrf all":        `{"TABLE_ctx":{"ROW_ctx":{"ptag":"1","TABLE_nbr":{"ROW_nbr":{"rid":"10.255.0.11","state":"FULL","addr":"10.0.0.11","md5-password":"x"}}}}}`,
		"cli_show show bgp ipv4 unicast summary vrf all": "ERR 400 Invalid command",
		"cli_show show ip access-lists":                  `{"TABLE_ip_ahead":{"ROW_ip_ahead":{"acl_name":"EDGE-IN","TABLE_seqno":{"ROW_seqno":[{"seqno":"10","permitdeny":"permit","stats":"[match=77]"}]}}}}`,
		"cli_show show system resources":                 `{"load_avg_1min":"0.38","cpu_state_user":"2.56","cpu_state_kernel":"3.84","cpu_state_idle":"93.58","memory_usage_total":"16400304","memory_usage_used":"7062996","memory_usage_free":"9337308"}`,
		"cli_show show environment fan":                  `{"fandetails":{"TABLE_faninfo":{"ROW_faninfo":[{"fanname":"Fan1(sys_fan1)","fanmodel":"NXA-FAN-30CFM-B","fanstatus":"Ok"},{"fanname":"Fan2(sys_fan2)","fanstatus":"Failure"}]}}}`,
		"cli_show show environment temperature":          `{"TABLE_tempinfo":{"ROW_tempinfo":{"tempmod":"1","sensor":"Outlet","majthres":"75","minthres":"70","curtemp":"30","alarmstatus":"Ok"}}}`,
		"cli_show show environment power":                `{"powersup":{"TABLE_psinfo":{"ROW_psinfo":[{"psnum":"1","psmodel":"NXA-PAC-650W-PE","actual_out":"98 W","ps_status":"Ok"}]}}}`,
		"cli_show show vlan brief": `{"TABLE_vlanbriefxbrief":{"ROW_vlanbriefxbrief":[{"vlanshowbr-vlanid":"10","vlanshowbr-vlanid-utf":"10","vlanshowbr-vlanname":"servers","vlanshowbr-vlanstate":"active","vlanshowplist-ifidx":"Eth1/1,Po1"},
			{"vlanshowbr-vlanid":"1","vlanshowbr-vlanname":"default","vlanshowbr-vlanstate":"active","vlanshowplist-ifidx":"Ethernet1/3, Ethernet1/4"}]}}`,
		"cli_show_ascii show version | include NXOS": "  NXOS: version 9.3(8)\n",
	}
}

func TestNXOS(t *testing.T) {
	d, st := nxStub(t, nxCLI(), nil)
	drv := open(t, d, nxCred)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f != (Facts{Hostname: "n9k1", Vendor: "Cisco", Model: "N9K-C93180YC-EX", OSVersion: "9.3(8)", Serial: "FDO21470ABC", UptimeS: 183845}) {
		t.Fatalf("facts: %+v", f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 5 {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	by := map[string]Interface{}
	for _, i := range ifs {
		by[i.Name] = i
	}
	e1, e2, v10, mg, lo := by["Ethernet1/1"], by["Ethernet1/2"], by["Vlan10"], by["mgmt0"], by["loopback0"]
	if !*e1.AdminUp || !*e1.OperUp || e1.SpeedMbps != 10000 || e1.MAC != "aabb.cc00.0100" || e1.Description != "to spine1" || e1.Addresses != nil {
		t.Errorf("Ethernet1/1: %+v", e1)
	}
	if *e2.AdminUp || *e2.OperUp || e2.SpeedMbps != 1000 { // auto-speed: the nominal bandwidth stands
		t.Errorf("Ethernet1/2: %+v", e2)
	}
	if !*v10.AdminUp || !*v10.OperUp || v10.Addresses[0] != "10.0.0.2/24" || v10.MAC != "aabb.cc00.0110" || v10.Description != "servers" || v10.SpeedMbps != 0 {
		t.Errorf("Vlan10: %+v", v10)
	}
	if mg.Addresses[0] != "192.168.1.5/24" || mg.SpeedMbps != 1000 || lo.Addresses[0] != "10.255.0.1/32" || lo.SpeedMbps != 0 {
		t.Errorf("mgmt0 %+v loopback0 %+v", mg, lo)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 2 {
		t.Fatalf("neighbors (LLDP, then CDP only where LLDP has none; Eth1/1 and Ethernet1/1 are one port): %v %+v", err, nb)
	}
	if nb[0].LocalPort != "Ethernet1/1" || nb[0].Protocol != "lldp" || nb[0].RemoteName != "spine1" || nb[0].RemotePort != "Ethernet1/49" || nb[0].RemoteAddr != "10.0.0.11" ||
		nb[0].RemoteDesc != "Cisco Nexus9000" || nb[0].Detail["chassis_id"] != "aabb.cc00.0200" {
		t.Errorf("lldp neighbor: %+v", nb[0])
	}
	if nb[1].LocalPort != "Ethernet1/2" || nb[1].Protocol != "cdp" || nb[1].RemoteName != "fw1.example.net" || nb[1].RemoteAddr != "10.0.0.21" || nb[1].RemoteDesc != "cisco ASA" {
		t.Errorf("cdp neighbor: %+v", nb[1])
	}
	c, err := drv.Config(ctx)
	if err != nil || !strings.HasPrefix(c, "!Command: show running-configuration") || !strings.Contains(c, "hostname n9k1") {
		t.Errorf("config: %v %q", err, c)
	}
	s, err := drv.Show(ctx, "show version | include NXOS")
	if err != nil || !strings.Contains(s, "version 9.3(8)") {
		t.Errorf("show: %v %q", err, s)
	}
	// nothing that is not a show command reaches the switch
	before := st.insCalls.Load()
	for _, bad := range []string{"configure terminal", "show run | tee bootflash:x", "show version; reload", "reload", ""} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was sent", bad)
		}
	}
	if st.insCalls.Load() != before {
		t.Error("a refused command reached the switch")
	}
	// a wrong password is the switch's 401, reported, and not taken for "no neighbors"
	bad := open(t, d, Credential{Username: "admin", Password: "wrong"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := bad.Neighbors(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong password, neighbors: %v", err)
	}
	if _, err := Open(d, Credential{Token: "t"}); err == nil {
		t.Error("NX-OS without a user name and password was accepted")
	}
}

func TestNXOSFeatureOff(t *testing.T) {
	// no feature lldp, no CDP, no inventory: the common request still answers
	cli := map[string]string{"cli_show show version": `{"host_name":"n9k1","sys_ver_str":"10.2(3) [build 10.2(3)]"}`,
		"cli_show show lldp neighbors detail": "ERR 400 LLDP feature not enabled", "cli_show show cdp neighbors detail": "ERR 400 CDP is not enabled"}
	d, _ := nxStub(t, cli, nil)
	drv := open(t, d, nxCred)
	nb, err := drv.Neighbors(context.Background())
	if err != nil || len(nb) != 0 {
		t.Fatalf("%v %+v", err, nb)
	}
	f, err := drv.Facts(context.Background())
	if err != nil || f.OSVersion != "10.2(3)" || f.Model != "" {
		t.Errorf("%v %+v", err, f)
	}
}

func TestNXOSDetail(t *testing.T) {
	d, _ := nxStub(t, nxCLI(), nil)
	drv := open(t, d, nxCred)
	ctx := context.Background()
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 5 {
		t.Fatalf("%v %+v", err, ps)
	}
	var p Port
	for _, x := range ps {
		if x.Name == "Ethernet1/1" {
			p = x
		}
	}
	c := p.Counters
	if p.MTU != 9216 || p.Duplex != "full" || p.Type != "100/1000/10000 Ethernet" || c.InOctets != 5000000000 || c.InPackets != 50 || c.InUnicast != 40 || c.InErrors != 3 || c.InDiscards != 2 ||
		c.OutOctets != 7000 || c.OutPackets != 70 || c.OutErrors != 1 || c.RxPPS != 9 || c.TxPPS != 12 || c.RxKbps != 8 || c.TxKbps != 16 || c.All["eth_inbytes"] != "5000000000" || p.Properties["desc"] != "to spine1" {
		t.Errorf("port: %+v", p)
	}
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 4 { // the IPv6 table is a 400 (not found): the IPv4 table stands
		t.Fatalf("routes: %v %+v", err, rs)
	}
	byPrefix := map[string][]Route{}
	for _, r := range rs {
		byPrefix[r.Prefix] = append(byPrefix[r.Prefix], r)
	}
	if r := byPrefix["0.0.0.0/0"][0]; r.Protocol != "static" || r.NextHop != "10.0.0.1" || r.Interface != "Vlan10" || r.Distance != 1 || r.VRF != "default" {
		t.Errorf("default route: %+v", r)
	}
	if o := byPrefix["10.1.0.0/24"]; len(o) != 2 || o[0].Protocol != "ospf" || o[1].NextHop != "10.0.0.4" || o[0].Distance != 110 || o[0].Metric != 20 {
		t.Errorf("ospf routes: %+v", o)
	}
	if r := byPrefix["10.0.0.0/24"][0]; r.Protocol != "connected" || r.Raw["clientname"] != "direct" {
		t.Errorf("connected route: %+v", r)
	}
	rt, err := drv.(Router).Routing(ctx)
	if err != nil || rt.Protocols["ospf"] == nil || rt.Unavailable["bgp"] == "" || rt.Unavailable["eigrp"] == "" {
		t.Fatalf("routing: %v %+v", err, rt)
	}
	if got := rt.Protocols["ospf"].(map[string]any)["TABLE_ctx"].(map[string]any)["ROW_ctx"].(map[string]any)["TABLE_nbr"].(map[string]any)["ROW_nbr"].(map[string]any)["md5-password"]; got != "(hidden)" {
		t.Errorf("secret shown: %v", got)
	}
	fw, err := drv.(Firewaller).Firewall(ctx)
	if err != nil || fw.Protocols["ip_access_lists"] == nil || fw.Unavailable["ipv6_access_lists"] == "" {
		t.Errorf("firewall: %v %+v", err, fw)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 6.42 || len(r.Memory) != 1 || r.Memory[0].Total != 16400304*1024 || int(r.Memory[0].UsedPercent) != 43 {
		t.Fatalf("resources: %v %+v %+v", err, r.CPU, r.Memory)
	}
	kinds := map[string]Sensor{}
	for _, s := range r.Sensors {
		kinds[s.Name] = s
	}
	if len(r.Sensors) != 4 || kinds["Fan2(sys_fan2)"].State != "Failure" || kinds["Fan2(sys_fan2)"].Kind != "fan" ||
		kinds["module 1 Outlet"].Kind != "temperature" || *kinds["module 1 Outlet"].Reading != 30 || kinds["module 1 Outlet"].State != "Ok" ||
		kinds["PS1 NXA-PAC-650W-PE"].Kind != "psu" || *kinds["PS1 NXA-PAC-650W-PE"].Reading != 98 || kinds["PS1 NXA-PAC-650W-PE"].Units != "W" {
		t.Errorf("sensors: %+v", r.Sensors)
	}
	if r.Details.Unavailable["modules"] == "" || r.Details.Protocols["system_resources"] == nil {
		t.Errorf("details: %+v", r.Details)
	}
	vl, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vl) != 2 || vl[0].ID != 1 || vl[1].ID != 10 || vl[1].Name != "servers" || vl[1].Status != "active" ||
		strings.Join(vl[1].Ports, ",") != "Ethernet1/1,port-channel1" || strings.Join(vl[0].Ports, ",") != "Ethernet1/3,Ethernet1/4" {
		t.Errorf("vlans: %v %+v", err, vl)
	}
}

func TestNXOSAPI(t *testing.T) {
	rest := map[string]string{
		"/api/class/topSystem.json": `{"totalCount":"1","imdata":[{"topSystem":{"attributes":{"name":"n9k1","pwd":"hunter2","dn":"sys"}}}]}`,
		"/api/mo/sys.json?query-target=children&rsp-prop-include=naming-only": `{"imdata":[{"ipv4Entity":{"attributes":{"dn":"sys/ipv4"}}},{"intfEntity":{"attributes":{"dn":"sys/intf"}}}]}`,
		"/api/mo/sys/xml.xml": `<imdata totalCount="0"/>`,
	}
	d, st := nxStub(t, nil, rest)
	drv := open(t, d, nxCred)
	ctx := context.Background()
	a := drv.(APIer)
	v, text, err := a.APIGet(ctx, "/api/class/topSystem.json")
	if err != nil || text {
		t.Fatalf("%v %v", err, text)
	}
	ts := v.(map[string]any)["imdata"].([]any)[0].(map[string]any)["topSystem"].(map[string]any)["attributes"].(map[string]any)
	if ts["name"] != "n9k1" || ts["pwd"] != "(hidden)" {
		t.Errorf("attributes (a pwd is a secret): %v", ts)
	}
	if _, text, err := a.APIGet(ctx, "/api/mo/sys/xml.xml"); err != nil || !text {
		t.Errorf("an XML answer is text: %v %v", err, text)
	}
	if st.logins.Load() != 1 {
		t.Errorf("one session for the whole request, got %d logins", st.logins.Load())
	}
	for _, bad := range []string{"/ins", "/api/aaaLogin.json", "/api/aaaLogout.json", "/restconf/data/x", "/api/mo", "/api/other/x.json"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	cat, err := a.APICatalog(ctx)
	m, _ := cat.(map[string]any)
	if err != nil || m["how"] == nil || strings.Join(m["children_of_sys"].([]string), ",") != "intfEntity,ipv4Entity" {
		t.Errorf("catalog: %v %+v", err, cat)
	}
	drv.Close(ctx)
	if st.logouts.Load() != 1 {
		t.Errorf("the session was not closed: %d logouts", st.logouts.Load())
	}
	// a switch with the REST part off: the login fails and says so
	d2, _ := nxStub(t, nil, nil)
	if _, _, err := open(t, d2, Credential{Username: "admin", Password: "wrong"}).(APIer).APIGet(ctx, "/api/class/topSystem.json"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a failed login: %v", err)
	}
}

func TestNXOSCheckAPIPathMCP(t *testing.T) {
	for _, ok := range []string{"/api/mo/sys/intf.json", "/api/class/ipv4Route.json?rsp-subtree=full", "/api/class/topSystem.json", "/api/mo/sys/ch.json?rsp-subtree=children"} {
		if err := CheckAPIPathMCP(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"/api/mo/sys.json", "/api/mo/sys.json?rsp-subtree=full", "/api/node/mo/sys.json", "/api/class/aaaUser.json", "/api/class/aaaRadiusProvider.json",
		"/api/mo/sys/userext.json", "/api/class/snmpCommSecP.json", "/api/mo/sys/snmp.json", "/api/class/pkiEp.json"} {
		if err := CheckAPIPathMCP(bad); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
}
