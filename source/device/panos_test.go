package device

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// panStubState records what the stub saw.
type panStubState struct {
	keygens atomic.Int32
	queries []url.Values // every GET of the XML API, as the device got it
	polls   int          // how often a log job was asked for its result
}

const panKey = "LUFRPT1key"

// panStub is a PAN-OS XML API on loopback.  answers maps the operational command ("<show>...") or "config:<xpath>" to the XML of
// the <response>; "ERR <code> <msg>" is an error answer (HTTP 200, as PAN-OS does).  The stub fails the test if a request that is
// not the key request is not a GET, if a password is in a URL, or if the key is not in the X-PAN-KEY header.
func panStub(t *testing.T, answers map[string]string) (Device, *panStubState) {
	t.Helper()
	st := &panStubState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.RawQuery, "password") || strings.Contains(r.URL.RawQuery, "s3cret") {
			t.Errorf("a password is in the URL: %s", r.URL.RawQuery)
		}
		if r.Method == http.MethodPost && r.URL.Query().Get("type") == "keygen" {
			if err := r.ParseForm(); err != nil || r.PostForm.Get("user") != "admin" || r.PostForm.Get("password") != "s3cret" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`))
				return
			}
			st.keygens.Add(1)
			_, _ = w.Write([]byte(`<response status="success"><result><key>` + panKey + `</key></result></response>`))
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request to the XML API (only GET is sent, and POST for the key)", r.Method)
		}
		if r.Header.Get("X-PAN-KEY") != panKey {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`))
			return
		}
		q := r.URL.Query()
		st.queries = append(st.queries, q)
		key := q.Get("cmd")
		if q.Get("type") == "config" {
			key = "config:" + q.Get("xpath")
		}
		// a log search: "log:<log-type>" answers the job, the first read of a job says it is still running, the next is
		// "logget:<job>", and a finish is always accepted
		if q.Get("type") == "log" {
			switch q.Get("action") {
			case "":
				key = "log:" + q.Get("log-type")
			case "get":
				key = "logget:" + q.Get("job-id")
				if st.polls++; st.polls == 1 {
					_, _ = w.Write([]byte(`<response status="success"><result><job><status>ACT</status><id>` + q.Get("job-id") + `</id></job><log><logs count="0" progress="40"/></log></result></response>`))
					return
				}
			case "finish":
				_, _ = w.Write([]byte(`<response status="success"></response>`))
				return
			}
		}
		a, ok := answers[key]
		switch {
		case !ok:
			a = `<response status="error" code="17"><msg><line>Invalid command</line></msg></response>`
		case strings.HasPrefix(a, "ERR "):
			f := strings.SplitN(a, " ", 3)
			a = `<response status="error" code="` + f[1] + `"><msg><line>` + f[2] + `</line></msg></response>`
		}
		_, _ = w.Write([]byte(a))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "fw1", Platform: "panos", Address: host, Port: pn, Insecure: true}, st
}

func ok(result string) string {
	return `<response status="success"><result>` + result + `</result></response>`
}

const (
	panSystemInfo = "<show><system><info></info></system></show>"
	panDev        = "config:" + panDevices
)

// Field names: system info (hostname, model, serial, sw-version, uptime, ip-address), show interface all (ifnet/hw, name, ip, addr,
// state, state_c, speed, mac), show lldp neighbors all (entry name, neighbors/entry, system-name, port-id), show routing route
// (destination, nexthop, flags, interface, metric, virtual-router), rule-hit-count (hit-count and the timestamps), show devices
// all and the command forms are the ones PAN-OS's documentation, pan-os-python and NAPALM use.  The counter, thermal, fan and
// power names, the lldp management address and the session info are from memory and have only been seen in this stub.
func panFirewall() map[string]string {
	vs := "config:" + panDevices + "/vsys/entry[@name='vsys1']"
	return map[string]string{
		panSystemInfo: ok(`<system><hostname>fw1</hostname><ip-address>10.0.0.5</ip-address><netmask>255.255.255.0</netmask><default-gateway>10.0.0.1</default-gateway>
			<mac-address>00:1b:17:00:00:01</mac-address><uptime>12 days, 3:04:05</uptime><family>400</family><model>PA-440</model><serial>007051000123456</serial>
			<sw-version>10.2.7-h3</sw-version><operational-mode>normal</operational-mode></system>`),
		"<show><interface>all</interface></show>": ok(`<ifnet>
			<entry><name>ethernet1/1</name><zone>untrust</zone><fwd>vr:default</fwd><vsys>1</vsys><dyn-addr/><addr6/><tag>0</tag><ip>203.0.113.2/24</ip><id>16</id><addr/></entry>
			<entry><name>ethernet1/2</name><zone>trust</zone><vsys>1</vsys><tag>0</tag><ip>N/A</ip><id>17</id><addr/></entry>
			<entry><name>ethernet1/2.100</name><zone>dmz</zone><vsys>1</vsys><tag>100</tag><ip>192.168.100.1/24</ip><id>256</id><addr><member>192.168.100.254/24</member></addr></entry></ifnet>
			<hw><entry><name>ethernet1/1</name><duplex>full</duplex><type>0</type><state>up</state><st>1000/full/up</st><mac>00:1b:17:00:00:10</mac><mode>(autoneg)</mode><speed>1000</speed><id>16</id></entry>
			<entry><name>ethernet1/2</name><duplex>full</duplex><state>down</state><st>ukn/ukn/down</st><mac>00:1b:17:00:00:11</mac><speed>ukn</speed><state_c>down</state_c></entry></hw>`),
		panDev + "/network/interface": ok(`<interface><ethernet><entry name="ethernet1/1"><link-state>auto</link-state><layer3><mtu>1500</mtu><ip><entry name="203.0.113.2/24"/></ip></layer3><comment>ISP</comment></entry>
			<entry name="ethernet1/2"><link-state>down</link-state><layer3><units><entry name="ethernet1/2.100"><tag>100</tag><comment>dmz vlan</comment></entry></units></layer3></entry></ethernet></interface>`),
		"<show><counter><interface>all</interface></counter></show>": ok(`<ifnet><entry><name>ethernet1/1</name><ibytes>5000</ibytes><obytes>7000</obytes><ipackets>50</ipackets><opackets>70</opackets><ierrors>3</ierrors><idrops>2</idrops></entry></ifnet>
			<hw><entry><name>ethernet1/1</name><port><rx-unicast>40</rx-unicast><rx-multicast>6</rx-multicast><rx-broadcast>4</rx-broadcast><tx-unicast>70</tx-unicast></port></entry></hw>`),
		"<show><lldp><neighbors>all</neighbors></lldp></show>": ok(`<entry name="ethernet1/2"><neighbors><entry><chassis-id>aa:bb:cc:00:00:01</chassis-id><port-id>Gi1/0/48</port-id><port-description>fw uplink</port-description>
			<system-name>cat9300</system-name><system-description>Cisco IOS</system-description><management-address><address>192.168.1.2</address></management-address></entry></neighbors></entry>
			<entry name="ethernet1/1"><neighbors/></entry>`),
		"<show><routing><route></route></routing></show>": ok(`<entry><virtual-router>default</virtual-router><destination>0.0.0.0/0</destination><nexthop>203.0.113.1</nexthop><metric>10</metric><flags>A S</flags><age/><interface>ethernet1/1</interface><route-table>unicast</route-table></entry>
			<entry><virtual-router>default</virtual-router><destination>10.9.0.0/24</destination><nexthop>10.0.0.2</nexthop><metric>20</metric><flags>A O1</flags><age>5000</age><interface>ethernet1/2</interface></entry>
			<entry><virtual-router>default</virtual-router><destination>203.0.113.0/24</destination><nexthop>203.0.113.2</nexthop><metric>0</metric><flags>A C</flags><interface>ethernet1/1</interface></entry>`),
		"<show><routing><protocol><bgp><summary></summary></bgp></protocol></routing></show>": ok(`<entry peer="isp"><remote-as>64500</remote-as><status>Established</status></entry>`),
		"<show><routing><summary></summary></routing></show>":                                 ok(`<entry><virtual-router>default</virtual-router><total-routes>3</total-routes></entry>`),
		panDevices + "/network/virtual-router":                                                "",
		"config:" + panDevices + "/network/virtual-router":                                    ok(`<virtual-router><entry name="default"><protocol><bgp><auth-profile><entry name="p"><secret>-AQ==abc</secret></entry></auth-profile></bgp></protocol></entry></virtual-router>`),
		"<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all></all></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>": ok(`<rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="security"><rules>
			<entry name="allow-web"><latest>yes</latest><hit-count>42</hit-count><last-hit-timestamp>1761998400</last-hit-timestamp><last-reset-timestamp>0</last-reset-timestamp><first-hit-timestamp>1761990000</first-hit-timestamp></entry></rules></entry></rule-base></entry></vsys></rule-hit-count>`),
		"<show><session><info></info></session></show>": ok(`<num-max>262144</num-max><num-active>1200</num-active><num-tcp>900</num-tcp><pps>10</pps>`),
		vs + "/rulebase/security":                       ok(`<security><rules><entry name="allow-web"><from><member>trust</member></from><to><member>untrust</member></to><action>allow</action><password>oops</password></entry></rules></security>`),
		vs + "/address":                                 ok(`<address><entry name="web1"><ip-netmask>192.168.100.10</ip-netmask></entry></address>`),
		"<show><system><resources></resources></system></show>": ok(`<![CDATA[top - 12:34:56 up 12 days,  3:04,  1 user,  load average: 0.10, 0.12, 0.09
Tasks: 187 total,   1 running, 186 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.0 us,  1.5 sy,  0.0 ni, 96.0 id,  0.3 wa,  0.0 hi,  0.2 si,  0.0 st
KiB Mem :  8000000 total,  1000000 free,  5000000 used,  2000000 buff/cache
KiB Swap:  2000000 total,  2000000 free,        0 used.  2500000 avail Mem
]]>`),
		"<show><system><disk-space></disk-space></system></show>": ok(`<![CDATA[Filesystem      Size  Used Avail Use% Mounted on
/dev/root       7.0G  4.4G  2.2G  67% /
/dev/sda5        15G  1.0G   13G   7% /opt/pancfg
tmpfs           2.0G     0  2.0G   0% /dev/shm
]]>`),
		"<show><system><environmentals><thermal></thermal></environmentals></system></show>": ok(`<Slot1><entry><slot>1</slot><description>Temperature @ U6</description><alarm>False</alarm><DegreesC>31.0</DegreesC></entry></Slot1>`),
		"<show><system><environmentals><fans></fans></environmentals></system></show>":       ok(`<Slot1><entry><slot>1</slot><description>Fan #1 RPM</description><alarm>False</alarm><RPMs>5000</RPMs></entry></Slot1>`),
		"<show><system><environmentals><power></power></environmentals></system></show>":     ok(`<Slot1><entry><description>PS #1 Voltage</description><alarm>True</alarm><Volts>11.9</Volts></entry></Slot1>`),
		"<show><high-availability><state></state></high-availability></show>":                ok(`<enabled>no</enabled>`),
		"config:/config": `<response status="success" code="19"><result total-count="1" count="1"><config version="10.2.0" urldb="paloaltonetworks"><devices><entry name="localhost.localdomain"/></devices></config></result></response>`,
	}
}

var panCred = Credential{Token: panKey}

func TestPANOSFirewall(t *testing.T) {
	d, st := panStub(t, panFirewall())
	drv := open(t, d, panCred)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f != (Facts{Hostname: "fw1", Vendor: "Palo Alto Networks", Model: "PA-440", OSVersion: "10.2.7-h3", Serial: "007051000123456", UptimeS: 1047845}) {
		t.Fatalf("facts: %+v", f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 4 {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	by := map[string]Interface{}
	for _, i := range ifs {
		by[i.Name] = i
	}
	e1, e2, sub, mg := by["ethernet1/1"], by["ethernet1/2"], by["ethernet1/2.100"], by["management"]
	if !*e1.AdminUp || !*e1.OperUp || e1.SpeedMbps != 1000 || e1.MAC != "00:1b:17:00:00:10" || e1.Description != "ISP" || e1.Addresses[0] != "203.0.113.2/24" {
		t.Errorf("ethernet1/1: %+v", e1)
	}
	if *e2.AdminUp || *e2.OperUp || e2.SpeedMbps != 0 || e2.Addresses != nil { // N/A is no address; speed "ukn"
		t.Errorf("ethernet1/2: %+v", e2)
	}
	if sub.OperUp != nil || sub.Description != "dmz vlan" || len(sub.Addresses) != 2 || sub.Addresses[1] != "192.168.100.254/24" {
		t.Errorf("ethernet1/2.100: %+v", sub)
	}
	if mg.MAC != "00:1b:17:00:00:01" || mg.Addresses[0] != "10.0.0.5/24" {
		t.Errorf("management: %+v", mg)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 1 || nb[0].LocalPort != "ethernet1/2" || nb[0].RemoteName != "cat9300" || nb[0].RemotePort != "Gi1/0/48" || nb[0].RemoteAddr != "192.168.1.2" ||
		nb[0].RemoteDesc != "Cisco IOS" || nb[0].Protocol != "lldp" || nb[0].Detail["chassis-id"] != "aa:bb:cc:00:00:01" {
		t.Errorf("neighbors (a port with no neighbor is left out): %v %+v", err, nb)
	}
	c, err := drv.Config(ctx)
	if err != nil || !strings.HasPrefix(c, `<config version="10.2.0"`) || !strings.HasSuffix(c, "</config>") {
		t.Errorf("config: %v %q", err, c)
	}
	s, err := drv.Show(ctx, "show system info")
	if err != nil || !strings.Contains(s, `"hostname": "fw1"`) {
		t.Errorf("show (structured answer as JSON): %v %q", err, s)
	}
	s, err = drv.Show(ctx, "show system resources")
	if err != nil || !strings.HasPrefix(s, "top - 12:34:56") {
		t.Errorf("show (text answer as it is): %v %q", err, s)
	}
	if _, err := drv.Show(ctx, "show nothing here"); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("a command PAN-OS does not know is its refusal: %v", err)
	}
	if st.keygens.Load() != 0 {
		t.Error("an API key was made although the login has a key")
	}
	for _, q := range st.queries {
		if q.Get("type") != "op" && q.Get("type") != "config" || q.Get("type") == "config" && q.Get("action") != "show" {
			t.Errorf("a request that is not a show command or a read of the running configuration: %v", q)
		}
	}
	// a wrong key is the device's 403 and never echoed
	bad := open(t, d, Credential{Token: "WRONGKEY99"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "WRONGKEY99") {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := Open(d, Credential{Username: "admin"}); err == nil {
		t.Error("PAN-OS without a key or a password was accepted")
	}
}

func TestPANOSKeygen(t *testing.T) {
	d, st := panStub(t, panFirewall())
	ctx := context.Background()
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"})
	for i := 0; i < 3; i++ { // one key for the whole request
		if _, err := drv.Facts(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if st.keygens.Load() != 1 {
		t.Errorf("keygens: %d", st.keygens.Load())
	}
	// a wrong password is the device's 403 from the key request
	if _, err := open(t, d, Credential{Username: "admin", Password: "nope"}).Facts(ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestPANOSDetail(t *testing.T) {
	d, _ := panStub(t, panFirewall())
	drv := open(t, d, panCred)
	ctx := context.Background()
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 4 {
		t.Fatalf("%v %+v", err, ps)
	}
	var p Port
	for _, x := range ps {
		if x.Name == "ethernet1/1" {
			p = x
		}
	}
	c := p.Counters
	if p.Type != "ethernet" || p.MTU != 1500 || p.Duplex != "full" || c.InOctets != 5000 || c.InPackets != 50 || c.InErrors != 3 || c.InDiscards != 2 || c.OutOctets != 7000 || c.OutPackets != 70 ||
		c.InUnicast != 40 || c.InMulticast != 6 || c.OutUnicast != 70 || c.All["ibytes"] != "5000" || p.Properties["config"] == nil || p.Properties["hardware"] == nil {
		t.Errorf("port: %+v", p)
	}
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 3 {
		t.Fatalf("routes: %v %+v", err, rs)
	}
	if r := rs[0]; r.Protocol != "static" || r.Prefix != "0.0.0.0/0" || r.NextHop != "203.0.113.1" || r.Interface != "ethernet1/1" || r.Metric != 10 || r.VRF != "default" {
		t.Errorf("default route: %+v", r)
	}
	if rs[1].Protocol != "ospf" || rs[2].Protocol != "connected" {
		t.Errorf("protocols from the flags: %+v", rs)
	}
	rt, err := drv.(Router).Routing(ctx)
	if err != nil || rt.Protocols["bgp_summary"] == nil || rt.Protocols["summary"] == nil || rt.Unavailable["ospf_neighbors"] == "" || rt.Protocols["config_virtual_routers"] == nil {
		t.Fatalf("routing: %v %+v", err, rt)
	}
	vr := rt.Protocols["config_virtual_routers"].(map[string]any)["virtual-router"].(map[string]any)["entry"].([]any)[0].(map[string]any)
	if vr["name"] != "default" {
		t.Errorf("an entry's name is a key of it: %v", vr)
	}
	sec := vr["protocol"].(map[string]any)["bgp"].(map[string]any)["auth-profile"].(map[string]any)["entry"].([]any)[0].(map[string]any)["secret"]
	if sec != "(hidden)" {
		t.Errorf("secret shown: %v", sec)
	}
	fw, err := drv.(Firewaller).Firewall(ctx)
	if err != nil || fw.Protocols["hit_counts_security"] == nil || fw.Protocols["session_info"] == nil || fw.Protocols["addresses"] == nil || fw.Unavailable["hit_counts_nat"] == "" {
		t.Fatalf("firewall: %v %+v", err, fw)
	}
	rule := fw.Protocols["security_rules"].(map[string]any)["security"].(map[string]any)["rules"].(map[string]any)["entry"].([]any)[0].(map[string]any)
	if rule["name"] != "allow-web" || rule["password"] != "(hidden)" || rule["action"] != "allow" || rule["from"].(map[string]any)["member"].([]any)[0] != "trust" {
		t.Errorf("rule: %+v", rule)
	}
	hits := fw.Protocols["hit_counts_security"].(map[string]any)["rule-hit-count"].(map[string]any)["vsys"].(map[string]any)["entry"].([]any)[0].(map[string]any)
	if hr := hits["rule-base"].(map[string]any)["entry"].([]any)[0].(map[string]any)["rules"].(map[string]any)["entry"].([]any)[0].(map[string]any); hr["hit-count"] != "42" {
		t.Errorf("hit counts: %+v", hr)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 4 || len(r.Memory) != 2 {
		t.Fatalf("resources: %v %+v %+v", err, r.CPU, r.Memory)
	}
	if m := r.Memory[0]; m.Name != "system" || m.Total != 8000000*1024 || m.Used != 5500000*1024 || m.UsedPercent != 68.75 { // avail Mem is the memory's, though top prints it on the swap line
		t.Errorf("memory: %+v", m)
	}
	if m := r.Memory[1]; m.Name != "swap" || m.Total != 2000000*1024 || m.Used != 0 {
		t.Errorf("swap: %+v", m)
	}
	if len(r.Storage) != 3 || r.Storage[0].Name != "/" || r.Storage[0].UsedPercent != 67 || r.Storage[0].Size != 7*(1<<30) || r.Storage[1].Name != "/opt/pancfg" {
		t.Errorf("storage: %+v", r.Storage)
	}
	if len(r.Sensors) != 3 || r.Sensors[0].Kind != "temperature" || *r.Sensors[0].Reading != 31 || r.Sensors[0].State != "ok" ||
		r.Sensors[1].Kind != "fan" || *r.Sensors[1].Reading != 5000 || r.Sensors[2].Kind != "psu" || r.Sensors[2].State != "alarm" || *r.Sensors[2].Reading != 11.9 {
		t.Errorf("sensors: %+v", r.Sensors)
	}
	if r.Details.Protocols["ha_state"] == nil || r.Details.Unavailable["dataplane_cpu_minute"] == "" {
		t.Errorf("details: %+v", r.Details)
	}
	vl, err := drv.(VLANer).VLANs(ctx)
	if err != nil || len(vl) != 1 || vl[0].ID != 100 || vl[0].Name != "ethernet1/2.100" || strings.Join(vl[0].Ports, ",") != "ethernet1/2" {
		t.Errorf("vlans: %v %+v", err, vl)
	}
}

func panPanoramaAnswers() map[string]string {
	return map[string]string{
		panSystemInfo: ok(`<system><hostname>pano1</hostname><ip-address>10.0.0.9</ip-address><netmask>255.255.255.0</netmask><mac-address>00:50:56:00:00:09</mac-address><uptime>0 days, 0:10:00</uptime>
			<model>Panorama</model><serial>000710000999</serial><sw-version>10.2.7</sw-version><system-mode>panorama</system-mode></system>`),
		"<show><devices><all></all></devices></show>":               ok(`<devices><entry name="007051000123456"><serial>007051000123456</serial><connected>yes</connected><hostname>fw1</hostname><ip-address>10.0.0.5</ip-address><model>PA-440</model><sw-version>10.2.7-h3</sw-version></entry></devices>`),
		"<show><devicegroups></devicegroups></show>":                ok(`<devicegroups><entry name="dg1"><devices><entry name="007051000123456"/></devices></entry></devicegroups>`),
		"config:/config/shared/pre-rulebase":                        ok(`<pre-rulebase><security><rules><entry name="block-bad"><action>deny</action></entry></rules></security></pre-rulebase>`),
		"config:" + panDevices + "/device-group/entry[@name='dg1']": ok(`<entry name="dg1"><address><entry name="h1"><ip-netmask>10.1.1.1</ip-netmask></entry></address></entry>`),
	}
}

func TestPanorama(t *testing.T) {
	d, st := panStub(t, panPanoramaAnswers())
	d.Options = map[string]string{"device_group": "dg1"}
	ctx := context.Background()
	// the same device as platform panos is recognised from the system info, and as panorama it is one without asking
	for _, platform := range []string{"panos", "panorama"} {
		d.Platform = platform
		drv := open(t, d, panCred)
		f, err := drv.Facts(ctx)
		if err != nil || f.Hostname != "pano1" || f.Model != "Panorama" || f.Serial != "000710000999" || f.UptimeS != 600 {
			t.Fatalf("%s facts: %v %+v", platform, err, f)
		}
		ifs, err := drv.Interfaces(ctx) // "show interface all" is an error on this box: the management port stands
		if err != nil || len(ifs) != 1 || ifs[0].Name != "management" || ifs[0].Addresses[0] != "10.0.0.9/24" {
			t.Errorf("%s interfaces: %v %+v", platform, err, ifs)
		}
		if nb, err := drv.Neighbors(ctx); err != nil || len(nb) != 0 {
			t.Errorf("%s neighbors: %v %+v", platform, err, nb)
		}
		if _, err := drv.(Router).Routes(ctx); err != ErrUnsupported {
			t.Errorf("%s routes: %v", platform, err)
		}
		if _, err := drv.(Router).Routing(ctx); err != ErrUnsupported {
			t.Errorf("%s routing: %v", platform, err)
		}
		if _, err := drv.(VLANer).VLANs(ctx); err != ErrUnsupported {
			t.Errorf("%s vlans: %v", platform, err)
		}
		fw, err := drv.(Firewaller).Firewall(ctx)
		if err != nil || fw.Protocols["managed_devices"] == nil || fw.Protocols["device_groups"] == nil || fw.Protocols["shared_pre_rules"] == nil || fw.Protocols["device_group_config"] == nil {
			t.Fatalf("%s firewall: %v %+v", platform, err, fw)
		}
		if fw.Unavailable["templates"] == "" {
			t.Errorf("%s: a part the Panorama does not answer is listed as unavailable: %+v", platform, fw.Unavailable)
		}
		md := fw.Protocols["managed_devices"].(map[string]any)["devices"].(map[string]any)["entry"].([]any)[0].(map[string]any)
		if md["serial"] != "007051000123456" || md["connected"] != "yes" {
			t.Errorf("managed device: %+v", md)
		}
	}
	// the device group option reached the XPath of the group's configuration, and no rule hit counter was asked of a Panorama
	seen := false
	for _, q := range st.queries {
		seen = seen || q.Get("xpath") == panDevices+"/device-group/entry[@name='dg1']"
		if strings.Contains(q.Get("cmd"), "rule-hit-count") {
			t.Errorf("a firewall's command was sent to a Panorama: %v", q)
		}
	}
	if !seen {
		t.Error("the device group was not used")
	}
	// platform panorama is a Panorama even when the system info does not say so
	fwd, _ := panStub(t, panFirewall())
	fwd.Platform = "panorama"
	if _, err := open(t, fwd, panCred).(Router).Routes(ctx); err != ErrUnsupported {
		t.Errorf("forced panorama: %v", err)
	}
	// and the other way: platform panos on a firewall is a firewall
	fwd.Platform = "panos"
	if rs, err := open(t, fwd, panCred).(Router).Routes(ctx); err != nil || len(rs) != 3 {
		t.Errorf("panos on a firewall: %v %+v", err, rs)
	}
}

func TestPANOSOptionsAreXPathSafe(t *testing.T) {
	d, _ := panStub(t, nil)
	for _, o := range []map[string]string{{"vsys": "vsys1']/../../x['"}, {"vsys": "a<b"}, {"device_group": "x'] | //password | ['"}, {"vsys": strings.Repeat("v", 40)}} {
		d.Options = o
		if _, err := Open(d, panCred); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
	d.Options = map[string]string{"vsys": "vsys 2", "device_group": "branch-offices_1"}
	if _, err := Open(d, panCred); err != nil {
		t.Errorf("a real name was refused: %v", err)
	}
}

func TestPanCLIToXML(t *testing.T) {
	for cmd, want := range map[string]string{
		"show system info":               "<show><system><info></info></system></show>",
		`show interface "ethernet1/1"`:   "<show><interface>ethernet1/1</interface></show>",
		"show interface ethernet1/1":     "<show><interface>ethernet1/1</interface></show>",
		`show interface "all"`:           "<show><interface>all</interface></show>",
		"show session id 4711":           "<show><session><id>4711</id></session></show>",
		`show arp "a&b <c>"`:             "<show><arp>a&amp;b &lt;c&gt;</arp></show>",
		"show devices all":               "<show><devices><all></all></devices></show>",
		`show counter interface   "all"`: "<show><counter><interface>all</interface></counter></show>",
	} {
		got, err := panCLIToXML(cmd)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v (want %q)", cmd, got, err, want)
		}
		if _, err := panShowNames(got); err != nil {
			t.Errorf("%q: the XML made is not a show command: %v", cmd, err)
		}
	}
	for _, bad := range []string{"show", "show interface \"a", `show interface "a" b`, "show a | include b", "show 4711 foo", "reload", "show a/b c"} {
		if x, err := panCLIToXML(bad); err == nil {
			t.Errorf("%q made %q", bad, x)
		}
	}
}

func TestPANOSAPIGet(t *testing.T) {
	answers := panFirewall()
	answers["<show><admins></admins></show>"] = ok(`<admins><entry name="x"><phash>$1$abc</phash><password>pw</password></entry></admins>`)
	d, st := panStub(t, answers)
	drv := open(t, d, panCred)
	ctx := context.Background()
	a := drv.(APIer)
	v, text, err := a.APIGet(ctx, "/api/?type=op&cmd=<show><admins></admins></show>")
	if err != nil || text {
		t.Fatalf("%v %v", err, text)
	}
	adm := v.(map[string]any)["admins"].(map[string]any)["entry"].([]any)[0].(map[string]any)
	if adm["name"] != "x" || adm["phash"] != "(hidden)" || adm["password"] != "(hidden)" {
		t.Errorf("secrets (a phash is one): %+v", adm)
	}
	if v, text, err := a.APIGet(ctx, "/api/?type=op&cmd=%3Cshow%3E%3Csystem%3E%3Cresources%3E%3C%2Fresources%3E%3C%2Fsystem%3E%3C%2Fshow%3E"); err != nil || !text || !strings.HasPrefix(v.(string), "top - ") {
		t.Errorf("a text answer is flagged as text: %v %v", err, text)
	}
	if v, _, err := a.APIGet(ctx, "/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"); err != nil || v == nil {
		t.Errorf("config get: %v %v", err, v)
	} else if q := st.queries[len(st.queries)-1]; q.Get("action") != "get" {
		t.Errorf("the action was not passed on: %v", q)
	}
	before := len(st.queries)
	for _, bad := range []string{
		"/api/?type=op&cmd=<request><restart><system></system></restart></request>", "/api/?type=op&cmd=<clear><session></session></clear>",
		"/api/?type=op&cmd=<show></show><show></show>", "/api/?type=op&cmd=<show><system>", "/api/?type=op&cmd=<show></show>junk", "/api/?type=op&cmd=<!DOCTYPE x><show></show>",
		"/api/?type=op", "/api/?type=commit&cmd=<commit></commit>", "/api/?type=keygen&user=a&password=b", "/api/?type=export&category=configuration",
		"/api/?type=config&action=set&xpath=/config/x&element=<a/>", "/api/?type=config&action=delete&xpath=/config/x", "/api/?type=config&action=show", "/api/?type=config&action=show&xpath=config",
		"/api/?type=op&cmd=<show><system><info></info></system></show>&key=abc", "/api/?type=op&cmd=<show></show>&target=0071", "/api/?type=op&type=config&cmd=<show></show>",
		"/other?type=op&cmd=<show></show>", "/restapi/v10.2/Policies/SecurityRules", "/api/x?type=op",
	} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if len(st.queries) != before {
		t.Errorf("a refused path reached the device: %v", st.queries[before:])
	}
	cat, err := a.APICatalog(ctx)
	if m, _ := cat.(map[string]any); err != nil || m["how"] == nil || m["kind"] != "firewall" {
		t.Errorf("catalog: %v %+v", err, cat)
	}
}

func TestPANOSCheckAPIPathMCP(t *testing.T) {
	const dev = "/config/devices/entry[@name='localhost.localdomain']"
	for _, ok := range []string{
		"/api/?type=op&cmd=<show><system><info></info></system></show>",
		"/api/?type=op&cmd=<show><interface>all</interface></show>",
		"/api/?type=op&cmd=<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all></all></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>",
		"/api/?type=config&action=show&xpath=" + dev + "/vsys/entry[@name='vsys1']/rulebase/security",
		"/api/?type=config&action=show&xpath=" + dev + "/network/interface/ethernet/entry[@name='ethernet1/1']",
		"/api/?type=config&action=get&xpath=" + dev + "/vsys/entry[@name='vsys1']/address",
		"/api/?type=config&action=show&xpath=/config/shared/pre-rulebase",
		"/api/?type=config&action=show&xpath=" + dev + "/device-group/entry[@name='dg1']/pre-rulebase",
	} {
		if err := CheckAPIPathMCP(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"/api/", "/api/?type=op", "/api/?type=commit&cmd=<commit></commit>", "/api/?type=keygen&user=a&password=b",
		"/api/?type=op&cmd=<show><config><running></running></config></show>", "/api/?type=op&cmd=<show><admins></admins></show>", "/api/?type=op&cmd=<show><system><info>",
		"/api/?type=op&cmd=<request><license><fetch></fetch></license></request>",
		"/api/?type=config&action=show&xpath=/config", "/api/?type=config&action=show&xpath=/config/", "/api/?type=config&action=show&xpath=" + dev,
		"/api/?type=config&action=show&xpath=/config/devices", "/api/?type=config&action=show&xpath=/config/shared", "/api/?type=config&action=show&xpath=" + dev + "/vsys",
		"/api/?type=config&action=show&xpath=" + dev + "/vsys/entry[@name='vsys1']", "/api/?type=config&action=show&xpath=" + dev + "/device-group",
		"/api/?type=config&action=show&xpath=" + dev + "/device-group/entry[@name='dg1']", "/api/?type=config&action=show&xpath=" + dev + "/template/entry[@name='t1']",
		"/api/?type=config&action=show&xpath=/config/mgt-config/users", "/api/?type=config&action=show&xpath=/config/mgt-config",
		"/api/?type=config&action=show&xpath=/config/shared/admin", "/api/?type=config&action=show&xpath=/config/shared/certificate",
		"/api/?type=config&action=show&xpath=" + dev + "/deviceconfig/system", "/api/?type=config&action=show&xpath=" + dev + "/network/ike/gateway",
		"/api/?type=config&action=show&xpath=" + dev + "/network/tunnel/ipsec", "/api/?type=config&action=show&xpath=" + dev + "/vsys/entry[@name='vsys1']/authentication-profile",
		"/api/?type=config&action=show&xpath=" + dev + "/vsys/entry[@name='vsys1']/server-profile/ldap", "/api/?type=config&action=show&xpath=" + dev + "/vsys/entry[@name='vsys1']/local-user-database/user",
		"/api/?type=config&action=show&xpath=" + dev + "/vsys/entry[@name='vsys1']/authentication-sequence",
	} {
		if err := CheckAPIPathMCP(bad); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
}

func TestXPathSteps(t *testing.T) {
	names, preds := xpathSteps("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='ethernet1/1']")
	if strings.Join(names, ",") != "config,devices,entry,network,interface,ethernet,entry" || !preds[2] || preds[3] || !preds[6] {
		t.Errorf("%v %v", names, preds)
	}
	names, _ = xpathSteps("/config/devices/entry[@name='a/b[c]']/vsys")
	if strings.Join(names, ",") != "config,devices,entry,vsys" {
		t.Errorf("a / or ] inside quotes does not split: %v", names)
	}
	if names, _ := xpathSteps("/"); len(names) != 0 {
		t.Errorf("%v", names)
	}
}

func TestPANXMLReading(t *testing.T) {
	v, err := panResult([]byte(`<response status="success" code="19"><result total-count="2" count="2"><a name="x"><name>child</name><member>m1</member></a><entry name="e"/><b/><list><entry name="one"><v>1</v></entry></list></result></response>`))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	a := m["a"].(map[string]any)
	if a["name"] != "child" || a["@name"] != "x" || len(a["member"].([]any)) != 1 { // a name both attribute and child: the attribute is @name; a member is always a list
		t.Errorf("a: %+v", a)
	}
	if es := m["entry"].([]any); len(es) != 1 || es[0].(map[string]any)["name"] != "e" || m["b"] != "" {
		t.Errorf("entry %+v b %v", m["entry"], m["b"])
	}
	if _, has := m["total-count"]; has {
		t.Error("the result's own attributes are not data")
	}
	if one := m["list"].(map[string]any)["entry"].([]any); len(one) != 1 { // one <entry> is still a list
		t.Errorf("%+v", one)
	}
	// nothing there: success with an empty result, in the two ways PAN-OS says it
	for _, empty := range []string{`<response status="success" code="7"><result/></response>`, `<response status="success"/>`, `<response status="success"><result total-count="0" count="0"></result></response>`} {
		if v, err := panResult([]byte(empty)); err != nil || v != nil {
			t.Errorf("%s: %v %v", empty, v, err)
		}
	}
	// refusals carry their code
	for body, code := range map[string]int{`<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`: 403,
		`<response status="error" code="16"><msg>Not authorized</msg></response>`:                                  403,
		`<response status="error" code="7"><msg><line>Object not present</line></msg></response>`:                  404,
		`<response status="error" code="17"><msg><line>Invalid command</line><line>second</line></msg></response>`: 400} {
		_, err := panResult([]byte(body))
		se, ok := err.(*statusError)
		if !ok || se.Code != code || se.Body == "" {
			t.Errorf("%s: %v", body, err)
		}
	}
	for _, bad := range []string{``, `not xml`, `<html><body>login</body></html>`, `<response><result>&xxe;</result></response>`, `<response status="success"><result></response>`,
		`<response status="success"/><response/>`, strings.Repeat("<a>", 300)} {
		if _, err := panResult([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPANCountersAndTop(t *testing.T) {
	// an older top prints "96.0%id", a newer one uses MiB
	cpu, mem := panTop("Cpu(s):  2.0%us,  1.5%sy,  0.0%ni, 96.0%id,  0.3%wa\nMiB Mem :  1000.0 total,    100.0 free,    400.0 used,    500.0 buff/cache\nMiB Swap:      0.0 total,      0.0 free,      0.0 used.    700.0 avail Mem")
	if cpu == nil || cpu.Now != 4 || len(mem) != 1 || mem[0].Total != 1000<<20 || mem[0].Used != 300<<20 {
		t.Errorf("%+v %+v", cpu, mem)
	}
	if cpu, mem := panTop("nothing recognisable"); cpu != nil || mem != nil {
		t.Errorf("%+v %+v", cpu, mem)
	}
	if got := panDisk("Filesystem Size Used Avail Use% Mounted on\nnone\n"); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestNewSecretNamesAreHidden(t *testing.T) {
	in := map[string]any{"pwd": "a", "phash": "$1$x", "private-key": "-----", "api-key": "k", "snmp-community-string": "public", "pre-shared-key": map[string]any{"key": "zzz"},
		"bgp": map[string]any{"community": "65000:1"}, "name": "ok"}
	out := Redact(in).(map[string]any)
	for _, k := range []string{"pwd", "phash", "private-key", "api-key", "snmp-community-string", "pre-shared-key"} {
		if out[k] != "(hidden)" {
			t.Errorf("%s: %v", k, out[k])
		}
	}
	if out["bgp"].(map[string]any)["community"] != "65000:1" || out["name"] != "ok" {
		t.Errorf("data was hidden: %v", out)
	}
	if got := RedactText("snmp-community-string public\nphash $1$abc\nnxos pwd hunter2\nhostname fw1"); strings.Contains(got, "public") || strings.Contains(got, "$1$abc") || strings.Contains(got, "hunter2") || !strings.Contains(got, "hostname fw1") {
		t.Errorf("%q", got)
	}
}

func TestPANOSLogSearch(t *testing.T) {
	oldP := panLogPoll
	panLogPoll = time.Millisecond
	t.Cleanup(func() { panLogPoll = oldP })
	answers := panFirewall()
	answers["log:globalprotect"] = ok(`<job>18</job><msg><line>query job enqueued with jobid 18</line></msg>`)
	answers["logget:18"] = ok(`<job><tenq>09:00:01</tenq><status>FIN</status><id>18</id></job><log><logs count="2" progress="100">` +
		`<entry logid="71"><receive_time>2026/11/10 09:00:00</receive_time><serial>007051000012345</serial><type>GLOBALPROTECT</type><eventid>gateway-connected</eventid>` +
		`<srcuser>acme\jo.doe</srcuser><machinename>A-GTHKFGPW4Q</machinename><public_ip>198.51.100.77</public_ip><private_ip>10.20.30.40</private_ip><status>success</status></entry>` +
		`<entry logid="70"><receive_time>2026/11/10 08:59:00</receive_time><eventid>portal-auth</eventid><srcuser>acme\jo.doe</srcuser><machinename>A-GTHKFGPW4Q</machinename><status>success</status></entry>` +
		`</logs></log>`)
	answers["log:traffic"] = ok(`<job>19</job>`)
	answers["logget:19"] = ok(`<job><status>FIN</status><id>19</id></job><log><logs count="0" progress="100"/></log>`)
	answers["log:system"] = "ERR 403 Unauthorized request"
	d, st := panStub(t, answers)
	a := open(t, d, panCred).(APIer)
	ctx := context.Background()

	v, text, err := a.APIGet(ctx, "/api/?type=log&log-type=globalprotect&nlogs=50&query=(machinename%20eq%20'A-GTHKFGPW4Q')")
	if err != nil || text {
		t.Fatalf("%v %v", err, text)
	}
	es, _ := v.(map[string]any)["entry"].([]any)
	if len(es) != 2 || es[0].(map[string]any)["machinename"] != "A-GTHKFGPW4Q" || es[0].(map[string]any)["eventid"] != "gateway-connected" {
		t.Fatalf("the entries: %+v", v)
	}
	// what the device got: the search with the query decoded, the reads of the job until it had finished, and its removal
	var got []string
	for _, q := range st.queries {
		if q.Get("type") == "log" {
			got = append(got, q.Get("action")+"/"+q.Get("job-id")+"/"+q.Get("log-type")+"/"+q.Get("nlogs")+"/"+q.Get("query"))
		}
	}
	want := []string{"//globalprotect/50/(machinename eq 'A-GTHKFGPW4Q')", "get/18///", "get/18///", "finish/18///"}
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Errorf("the requests of a log search:\n got %q\nwant %q", got, want)
	}
	// nothing matched is an empty list, not an error
	if v, _, err := a.APIGet(ctx, "/api/?type=log&log-type=traffic&dir=forward&skip=20"); err != nil || len(v.(map[string]any)["entry"].([]any)) != 0 {
		t.Errorf("an empty search: %v %+v", err, v)
	}
	// a role without the log permission: the device's refusal is the answer
	if _, _, err := a.APIGet(ctx, "/api/?type=log&log-type=system"); err == nil {
		t.Error("a refused search gave no error")
	}
	before := len(st.queries)
	for _, bad := range []string{
		"/api/?type=log", "/api/?type=log&log-type=nosuch", "/api/?type=log&log-type=traffic&nlogs=0", "/api/?type=log&log-type=traffic&nlogs=5001", "/api/?type=log&log-type=traffic&nlogs=x",
		"/api/?type=log&log-type=traffic&dir=sideways", "/api/?type=log&log-type=traffic&skip=-1", "/api/?type=log&action=get&job-id=18", "/api/?type=log&action=finish&job-id=18",
		"/api/?type=log&log-type=traffic&key=abc", "/api/?type=log&log-type=traffic&cmd=<show></show>", "/api/?type=log&log-type=traffic&log-type=threat",
		"/api/?type=log&log-type=traffic&query=a%0Ab", "/api/?type=report&reporttype=predefined", "/api/?type=export&category=traffic-log",
	} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if len(st.queries) != before {
		t.Errorf("a refused path reached the device: %v", st.queries[before:])
	}
	// over MCP: every log but the configuration log, and never the job requests
	for _, good := range []string{"/api/?type=log&log-type=globalprotect&query=(machinename%20eq%20'A-GTHKFGPW4Q')", "/api/?type=log&log-type=traffic&nlogs=100", "/api/?type=log&log-type=auth"} {
		if err := CheckAPIPathMCP(good); err != nil {
			t.Errorf("%s refused over MCP: %v", good, err)
		}
	}
	for _, bad := range []string{"/api/?type=log&log-type=config", "/api/?type=log", "/api/?type=log&log-type=nosuch", "/api/?type=log&log-type=traffic&action=get&job-id=1"} {
		if err := CheckAPIPathMCP(bad); err == nil {
			t.Errorf("%s allowed over MCP", bad)
		}
	}
}

func TestPANOSLogSearchGivesUp(t *testing.T) {
	oldP, oldW := panLogPoll, panLogWait
	panLogPoll, panLogWait = time.Millisecond, 30*time.Millisecond
	t.Cleanup(func() { panLogPoll, panLogWait = oldP, oldW })
	answers := panFirewall()
	answers["log:threat"] = ok(`<job>20</job>`)
	answers["logget:20"] = ok(`<job><status>ACT</status><id>20</id></job>`)
	d, st := panStub(t, answers)
	a := open(t, d, panCred).(APIer)
	if _, _, err := a.APIGet(context.Background(), "/api/?type=log&log-type=threat"); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("a search that never finishes: %v", err)
	}
	if q := st.queries[len(st.queries)-1]; q.Get("action") != "finish" || q.Get("job-id") != "20" {
		t.Errorf("the job was not removed: %v", q)
	}
}
