package device

import (
	"context"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	in := map[string]any{"name": "x", "password": "p", "md5": map[string]any{"key-string": "k", "id": 1.0}, "bgp": map[string]any{"community": "65000:1", "neighbor-password": ""},
		"l": []any{map[string]any{"auth-key": "z", "ok": "y"}}}
	out := Redact(in).(map[string]any)
	if out["password"] != "(hidden)" || out["md5"] != "(hidden)" || out["name"] != "x" {
		t.Errorf("%v", out)
	}
	if b := out["bgp"].(map[string]any); b["community"] != "65000:1" || b["neighbor-password"] != "" {
		t.Errorf("bgp community is data, an empty secret stays empty: %v", b)
	}
	if l := out["l"].([]any)[0].(map[string]any); l["auth-key"] != "(hidden)" || l["ok"] != "y" {
		t.Errorf("%v", l)
	}
	if in["password"] != "p" {
		t.Error("the input was changed")
	}
}

func TestIOSXEDetail(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{
		"/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface": `{"Cisco-IOS-XE-interfaces-oper:interface":[
			{"name":"Gi1/0/1","interface-type":"iana-iftype-ethernet-csmacd","mtu":1500,"admin-status":"if-state-up","oper-status":"if-oper-state-ready","speed":"1000000000",
			 "ether-state":{"negotiated-duplex-mode":"full-duplex"},
			 "statistics":{"in-octets":"5000000000","in-unicast-pkts":"10","in-multicast-pkts":"2","in-broadcast-pkts":"1","in-errors":"3","out-octets":"7","out-unicast-pkts":"4","rx-pps":"9","num-flaps":"2","in-crc-errors":"5"}}]}`,
		"/restconf/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data": `{"Cisco-IOS-XE-ospf-oper:ospf-oper-data":{"ospf-state":{"ospf-instance":[{"process-id":1,"password":"x"}]}}}`,
		"/restconf/data/Cisco-IOS-XE-acl-oper:access-lists":    `{"Cisco-IOS-XE-acl-oper:access-lists":{"access-list":[{"name":"IN","access-list-entries":{"access-list-entry":[{"rule-name":"10","match-counter":"77"}]}}]}}`,
		"/restconf/data/ietf-routing:routing-state": `{"ietf-routing:routing-state":{"routing-instance":[{"name":"default","ribs":{"rib":[{"name":"ipv4-unicast","routes":{"route":[
			{"destination-prefix":"10.0.0.0/24","source-protocol":"ietf-routing:ospf","route-preference":110,"metric":20,"next-hop":{"next-hop-address":"192.168.1.1","outgoing-interface":"Vlan1"}}]}}]}}]}}`,
		"/restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data": "HTTP 400 unknown model",
	})
	d.Platform = "iosxe"
	drv := open(t, d, Credential{Username: "u", Password: "p"})
	ctx := context.Background()
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %+v", err, ps)
	}
	p := ps[0]
	c := p.Counters
	if p.MTU != 1500 || p.Duplex != "full-duplex" || c.InOctets != 5000000000 || c.InPackets != 13 || c.InErrors != 3 || c.OutPackets != 4 || c.RxPPS != 9 || c.Flaps != 2 ||
		c.All["in-crc-errors"] != "5" || p.Properties["statistics"] != nil || p.SpeedMbps != 1000 {
		t.Errorf("port: %+v", p)
	}
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 1 || rs[0].Prefix != "10.0.0.0/24" || rs[0].Protocol != "ospf" || rs[0].NextHop != "192.168.1.1" || rs[0].Interface != "Vlan1" || rs[0].Distance != 110 || rs[0].Metric != 20 || rs[0].VRF != "default" {
		t.Errorf("routes: %v %+v", err, rs)
	}
	r, err := drv.(Router).Routing(ctx)
	if err != nil || r.Protocols["ospf"] == nil || r.Unavailable["bgp"] == "" || r.Unavailable["eigrp"] == "" {
		t.Fatalf("routing: %v %+v", err, r)
	}
	if got := r.Protocols["ospf"].(map[string]any)["ospf-state"].(map[string]any)["ospf-instance"].([]any)[0].(map[string]any)["password"]; got != "(hidden)" {
		t.Errorf("secret shown: %v", got)
	}
	fw, err := drv.(Firewaller).Firewall(ctx)
	if err != nil || fw.Protocols["acl_counters"] == nil {
		t.Errorf("firewall: %v %+v", err, fw)
	}
}

func TestFortiOSDetail(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{
		"/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true": `{"status":"success","results":{"wan1":{"name":"wan1","link":true,"speed":1000,"duplex":1,"rx_bytes":100,"tx_bytes":200,"rx_packets":3,"tx_packets":4,"rx_errors":1,"tx_errors":2}}}`,
		"/api/v2/cmdb/system/interface":                                             `{"status":"success","results":[{"name":"wan1","type":"physical","mtu":1500,"passwd":"s"}]}`,
		"/api/v2/cmdb/system/interface?format=name|description|status|alias":        `{"status":"success","results":[{"name":"wan1","status":"up"}]}`,
		"/api/v2/monitor/router/ipv4":                                               `{"status":"success","results":[{"ip_mask":"0.0.0.0/0","type":"static","gateway":"203.0.113.1","interface":"wan1","distance":10,"metric":0}]}`,
		"/api/v2/monitor/router/ospf/neighbors":                                     `{"status":"success","results":[{"neighbor_ip":"10.0.0.2"}]}`,
		"/api/v2/monitor/firewall/policy":                                           `{"status":"success","results":[{"policyid":1,"hit_count":42,"bytes":1000,"packets":9}]}`,
		"/api/v2/cmdb/firewall/policy":                                              `{"status":"success","results":[{"policyid":1,"name":"allow","action":"accept"}]}`,
	})
	d.Platform = "fortios"
	drv := open(t, d, Credential{Token: "t"})
	ctx := context.Background()
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %+v", err, ps)
	}
	p := ps[0]
	if p.Counters.InOctets != 100 || p.Counters.OutOctets != 200 || p.Counters.InPackets != 3 || p.Counters.OutErrors != 2 || p.Type != "physical" || p.MTU != 1500 || p.Properties["passwd"] != "(hidden)" {
		t.Errorf("port: %+v", p)
	}
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 1 || rs[0].Protocol != "static" || rs[0].NextHop != "203.0.113.1" || rs[0].Distance != 10 {
		t.Errorf("routes: %v %+v", err, rs)
	}
	r, err := drv.(Router).Routing(ctx)
	if err != nil || r.Protocols["ospf_neighbors"] == nil || r.Unavailable["bgp_neighbors"] == "" {
		t.Errorf("routing: %v %+v", err, r)
	}
	fw, err := drv.(Firewaller).Firewall(ctx)
	if err != nil || fw.Protocols["policy_stats"] == nil || fw.Protocols["policies"] == nil {
		t.Errorf("firewall: %v %+v", err, fw)
	}
}

func TestIOSXEResourcesVLANs(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{
		"/restconf/data/Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization":                  `{"Cisco-IOS-XE-process-cpu-oper:cpu-utilization":{"five-seconds":12,"one-minute":9,"five-minutes":7}}`,
		"/restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics/memory-statistic":              `{"Cisco-IOS-XE-memory-oper:memory-statistic":[{"name":"Processor","total-memory":"1000","used-memory":"250","free-memory":"750"}]}`,
		"/restconf/data/Cisco-IOS-XE-platform-software-oper:cisco-platform-software/q-filesystem": `{"Cisco-IOS-XE-platform-software-oper:q-filesystem":[{"name":"flash:","size":"1000","free":"900"}]}`,
		"/restconf/data/Cisco-IOS-XE-environment-oper:environment-sensors/environment-sensor": `{"Cisco-IOS-XE-environment-oper:environment-sensor":[
			{"name":"Switch 1 PS A","location":"PS A","state":"Normal","current-reading":120,"sensor-units":"Watts"},
			{"name":"Switch 1 FAN 1","state":"Normal","current-reading":4000,"sensor-units":"RPM"},
			{"name":"Temp Sensor 1","state":"Green","current-reading":38,"sensor-units":"Celsius"}]}`,
		"/restconf/data/Cisco-IOS-XE-vlan-oper:vlans/vlan": `{"Cisco-IOS-XE-vlan-oper:vlan":[{"id":20,"name":"voice","status":"active","vlan-interfaces":[{"interface":"Gi1/0/2"},{"interface":"Gi1/0/3"}]},{"id":1,"name":"default","status":"active"}]}`,
	})
	d.Platform = "iosxe"
	drv := open(t, d, Credential{Username: "u", Password: "p"})
	ctx := context.Background()
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 12 || r.CPU.FiveMin != 7 || len(r.Memory) != 1 || r.Memory[0].UsedPercent != 25 ||
		len(r.Storage) != 1 || r.Storage[0].UsedPercent != 10 || len(r.Sensors) != 3 || r.Details.Unavailable["hardware_inventory"] == "" {
		t.Fatalf("resources: %v %+v", err, r)
	}
	kinds := map[string]string{}
	for _, s := range r.Sensors {
		kinds[s.Name] = s.Kind
	}
	if kinds["Switch 1 PS A"] != "psu" || kinds["Switch 1 FAN 1"] != "fan" || kinds["Temp Sensor 1"] != "temperature" {
		t.Errorf("kinds: %v", kinds)
	}
	vs, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vs) != 2 || vs[0].ID != 1 || vs[1].ID != 20 || len(vs[1].Ports) != 2 || vs[1].Name != "voice" {
		t.Errorf("vlans: %v %+v", err, vs)
	}
}

func TestFortiOSResourcesVLANs(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{
		"/api/v2/monitor/system/resource/usage": `{"status":"success","results":{"cpu":[{"current":14}],"mem":[{"current":41}],"disk":[{"current":6}]}}`,
		"/api/v2/monitor/system/sensor-info":    `{"status":"success","results":[{"name":"PSU1","status":"ok","value":1}]}`,
		"/api/v2/cmdb/system/interface":         `{"status":"success","results":[{"name":"wan1","type":"physical"},{"name":"v30","type":"vlan","vlanid":30,"interface":"port1","status":"up"}]}`,
	})
	d.Platform = "fortios"
	drv := open(t, d, Credential{Token: "t"})
	ctx := context.Background()
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 14 || r.Memory[0].UsedPercent != 41 || r.Storage[0].UsedPercent != 6 || len(r.Sensors) != 1 || r.Sensors[0].Kind != "psu" {
		t.Fatalf("resources: %v %+v", err, r)
	}
	vs, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vs) != 1 || vs[0].ID != 30 || vs[0].Ports[0] != "port1" || vs[0].Name != "v30" {
		t.Errorf("vlans: %v %+v", err, vs)
	}
}

func TestCheckAPIPath(t *testing.T) {
	for _, bad := range []string{"", "restconf/data", "//evil/x", "/a/../b", "http://x/y", "/a b", "/a#b", "/a\nb", "/a\\b"} {
		if _, err := CheckAPIPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if p, err := CheckAPIPath(" /restconf/data/x:y?depth=2 "); err != nil || p != "/restconf/data/x:y?depth=2" {
		t.Errorf("%q %v", p, err)
	}
}

func TestAPIGet(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{
		"/restconf/data/Cisco-IOS-XE-x-oper:x":    `{"Cisco-IOS-XE-x-oper:x":{"count":5,"password":"pw"}}`,
		"/restconf/data?depth=1":                  `{"ietf-restconf:data":{"Cisco-IOS-XE-native:native":{},"Cisco-IOS-XE-x-oper:x":{}}}`,
		"/restconf/tailf/modules/m/2024-01-01":    "module m {}",
		"/api/v2/monitor/system/status?vdom=root": `{"status":"success","results":{"hostname":"fw","admin-password":"zz"}}`,
		"/api/v2/monitor/system/config/backup":    "x",
	})
	ctx := context.Background()
	d.Platform = "iosxe"
	x := open(t, d, Credential{Username: "u", Password: "p"}).(APIer)
	v, text, err := x.APIGet(ctx, "/restconf/data/Cisco-IOS-XE-x-oper:x")
	m, _ := v.(map[string]any)["Cisco-IOS-XE-x-oper:x"].(map[string]any)
	if err != nil || text || m["count"] != 5.0 || m["password"] != "(hidden)" {
		t.Errorf("%v %v %v", v, text, err)
	}
	if v, text, err := x.APIGet(ctx, "/restconf/tailf/modules/m/2024-01-01"); err != nil || !text || v != "module m {}" {
		t.Errorf("text: %v %v %v", v, text, err)
	}
	if _, _, err := x.APIGet(ctx, "/other"); err == nil {
		t.Error("a path outside RESTCONF data was read")
	}
	cat, err := x.APICatalog(ctx)
	nodes, _ := cat.(map[string]any)["top_level_nodes"].([]string)
	if err != nil || len(nodes) != 2 || nodes[1] != "Cisco-IOS-XE-x-oper:x" {
		t.Errorf("catalog: %v %v", cat, err)
	}
	d.Platform, d.Options = "fortios", map[string]string{"vdom": "root"}
	f := open(t, d, Credential{Token: "t"}).(APIer)
	v, _, err = f.APIGet(ctx, "/api/v2/monitor/system/status")
	if r, _ := v.(map[string]any)["results"].(map[string]any); err != nil || r["hostname"] != "fw" || r["admin-password"] != "(hidden)" {
		t.Errorf("fortios: %v %v", v, err)
	}
	for _, p := range []string{"/api/v2/monitor/system/config/backup", "/api/v2/monitor/license/download", "/other"} {
		if _, _, err := f.APIGet(ctx, p); err == nil {
			t.Errorf("%s was read", p)
		}
	}
	if c, err := f.APICatalog(ctx); err != nil || c == nil {
		t.Error("fortios catalog")
	}
}

func TestRedactText(t *testing.T) {
	in := "hostname sw1\nenable secret 9 $9$abc\nusername admin privilege 15 password 7 0822455D0A16\nsnmp-server community public RO\n" +
		" neighbor 10.0.0.1 send-community both\n ip ospf message-digest-key 1 md5 7 SECRET1\ncrypto key pubkey-chain x\nset psksecret ENC abcdef\n" +
		`{"auth-key":"zzz","name":"ok"}` + "\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\ninterface Gi1/0/1\n description uplink\n"
	out := RedactText(in)
	for _, leak := range []string{"$9$abc", "0822455D0A16", "public", "SECRET1", "abcdef", "zzz", "MIIE"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"hostname sw1", "send-community both", "interface Gi1/0/1", "description uplink", `"ok"`, "enable secret (hidden)"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q was hidden:\n%s", keep, out)
		}
	}
}

func TestCheckAPIPathMCP(t *testing.T) {
	for _, bad := range []string{"/restconf/data/Cisco-IOS-XE-native:native", "/restconf/data/Cisco-IOS-XE-native:native?depth=9", "/restconf/data/Cisco-IOS-XE-native:native/snmp-server",
		"/restconf/data/Cisco-IOS-XE-native:native/username=admin", "/restconf/data/Cisco-IOS-XE-native:native/aaa", "/restconf/tailf/modules/a/b",
		"/api/v2/cmdb/user/local", "/api/v2/cmdb/system/snmp/community", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "/api/v2/cmdb/system/admin", "/api/v2/cmdb"} {
		if CheckAPIPathMCP(bad) == nil {
			t.Errorf("%s allowed", bad)
		}
	}
	for _, good := range []string{"/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces", "/restconf/data/Cisco-IOS-XE-native:native/router", "/api/v2/monitor/system/status", "/api/v2/cmdb/firewall/policy"} {
		if err := CheckAPIPathMCP(good); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
}
