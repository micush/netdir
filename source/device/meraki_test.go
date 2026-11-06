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
	"time"
)

type merakiState struct {
	mu    sync.Mutex
	calls []string
	ports []J // the switch's port configuration
	limit int // answer 429 this many times first
	fail  bool
	orgs  []J
	puts  int
}

func (s *merakiState) saw(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// merakiStub is the dashboard API on loopback: Bearer key KEY, one organization 1234 (or two), a switch Q2AA-BBBB-CCCC with 4 ports
// (port 4 is its uplink), a network, a VLAN that takes PUT.
func merakiStub(t *testing.T, st *merakiState) Device {
	t.Helper()
	merakiWait = time.Millisecond
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer KEY" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"errors":["Invalid API key"]}`))
			return
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		st.calls = append(st.calls, r.Method+" "+r.URL.RequestURI())
		if st.limit > 0 {
			st.limit--
			w.WriteHeader(429)
			return
		}
		out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		p := strings.TrimPrefix(r.URL.Path, "/api/v1")
		switch {
		case r.Method == "GET" && p == "/organizations":
			if st.orgs != nil {
				out(st.orgs)
			} else {
				out([]J{{"id": "1234", "name": "Acme"}})
			}
		case r.Method == "GET" && p == "/organizations/1234":
			out(J{"id": "1234", "name": "Acme"})
		case r.Method == "GET" && p == "/organizations/1234/devices/statuses":
			out([]J{{"serial": "Q2AA-BBBB-CCCC", "status": "online"}, {"serial": "Q2DD-EEEE-FFFF", "status": "offline"}})
		case r.Method == "GET" && p == "/organizations/1234/appliance/uplink/statuses":
			out([]J{{"networkId": "N_1", "serial": "Q2MX-1111-2222", "uplinks": []J{{"interface": "wan1", "status": "active", "ip": "192.0.2.10"}, {"interface": "wan2", "status": "failed"}}}})
		case r.Method == "GET" && p == "/organizations/1234/networks":
			out([]J{{"id": "N_1", "name": "HQ"}})
		case r.Method == "GET" && p == "/devices/Q2AA-BBBB-CCCC":
			out(J{"name": "sw-core", "model": "MS225-24P", "serial": "Q2AA-BBBB-CCCC", "firmware": "switch-15-21", "lanIp": "10.0.0.9", "mac": "aa:bb:cc:00:00:01"})
		case r.Method == "GET" && p == "/devices/Q2AA-BBBB-CCCC/switch/ports":
			out(st.ports)
		case r.Method == "GET" && p == "/devices/Q2AA-BBBB-CCCC/switch/ports/statuses":
			out([]J{{"portId": "1", "status": "Connected", "speed": "1 Gbps", "duplex": "full"}, {"portId": "2", "status": "Disconnected"},
				{"portId": "3", "status": "Disabled"}, {"portId": "4", "status": "Connected", "speed": "10 Gbps", "isUplink": true}})
		case r.Method == "GET" && p == "/devices/Q2AA-BBBB-CCCC/lldpCdp":
			out(J{"sourceMac": "aa", "ports": J{"4": J{"lldp": J{"systemName": "core-sw", "portId": "Gi1/0/1", "managementAddress": "10.0.0.1"}}, "1": J{"cdp": J{"deviceId": "ap1", "portId": "eth0"}}}})
		case r.Method == "GET" && p == "/devices/Q2MX-1111-2222/switch/ports":
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"errors":["This endpoint only supports switches"]}`))
		case r.Method == "GET" && p == "/devices/Q2MX-1111-2222":
			out(J{"name": "mx1", "model": "MX68", "serial": "Q2MX-1111-2222", "lanIp": "10.0.0.2", "mac": "aa:bb:cc:00:00:02"})
		case r.Method == "PUT" && strings.HasPrefix(p, "/devices/Q2AA-BBBB-CCCC/switch/ports/"):
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			id := strings.TrimPrefix(p, "/devices/Q2AA-BBBB-CCCC/switch/ports/")
			for _, pt := range st.ports {
				if pt["portId"] == id {
					for k, v := range b {
						pt[k] = v
					}
				}
			}
			out(J{})
		case p == "/networks/N_1/appliance/vlans/10":
			if r.Method == "GET" {
				out(J{"id": 10, "name": "users", "subnet": "10.1.0.0/24"})
				return
			}
			st.puts++
			b, _ := io.ReadAll(r.Body)
			if st.fail {
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(b)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "mk", Platform: "meraki", Address: host, Port: pn, Insecure: true, Options: map[string]string{}}
}

func newMerakiState() *merakiState {
	return &merakiState{ports: []J{{"portId": "1", "name": "uplink pc", "enabled": true}, {"portId": "2", "name": "", "enabled": true},
		{"portId": "3", "name": "old", "enabled": false}, {"portId": "4", "name": "to core", "enabled": true}}}
}

func openMeraki(t *testing.T, d Device, key string) Driver {
	t.Helper()
	drv, err := Open(d, Credential{Name: "k", Token: key})
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestMerakiOrgReads(t *testing.T) {
	st := newMerakiState()
	d := merakiStub(t, st)
	drv := openMeraki(t, d, "KEY")
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "Acme" || f.Vendor != "Cisco Meraki" || !strings.Contains(f.Model, "2 devices (1 online)") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "Q2MX-1111-2222 wan1" || ifs[0].OperUp == nil || !*ifs[0].OperUp || *ifs[1].OperUp || ifs[0].Addresses[0] != "192.0.2.10" {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	if _, err := drv.Neighbors(ctx); err != ErrUnsupported {
		t.Errorf("neighbors at org level: %v", err)
	}
	out, err := drv.Show(ctx, "show networks")
	if err != nil || !strings.Contains(out, `"HQ"`) {
		t.Fatalf("show networks: %q %v", out, err)
	}
	for _, bad := range []string{"show", "show nothing", "show networks | include x", "show clients", "show clients network=../x", "show device", "show networks serial=bad"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	v, _, err := drv.(APIer).APIGet(ctx, "/api/v1/organizations/1234/networks")
	if err != nil || len(rows(v)) != 1 {
		t.Fatalf("api get: %v %v", v, err)
	}
	for _, bad := range []string{"/admin", "/organizations/../x", "/api/v1/x", "organizations", "/organizations/1 2"} {
		if _, _, err := drv.(APIer).APIGet(ctx, bad); err == nil {
			t.Errorf("%q read", bad)
		}
	}
	// two organizations: say which
	st.orgs = []J{{"id": "1", "name": "A"}, {"id": "2", "name": "B"}}
	if _, err := openMeraki(t, d, "KEY").Facts(ctx); err == nil || !strings.Contains(err.Error(), "option org") {
		t.Errorf("two orgs: %v", err)
	}
	// a wrong key
	if _, err := openMeraki(t, d, "BAD").Facts(ctx); err == nil || strings.Contains(err.Error(), "BAD") {
		t.Errorf("wrong key: %v", err)
	}
}

func TestMerakiRateLimit(t *testing.T) {
	st := newMerakiState()
	st.limit = 2
	d := merakiStub(t, st)
	if _, err := openMeraki(t, d, "KEY").Facts(context.Background()); err != nil {
		t.Fatalf("two 429s are waited out: %v", err)
	}
	st.limit = 5
	if _, err := openMeraki(t, d, "KEY").Facts(context.Background()); err == nil {
		t.Error("five 429s gave an answer")
	}
}

func TestMerakiRedirect(t *testing.T) {
	mk := func(u string) (*http.Request, []*http.Request) {
		a, _ := http.NewRequest("GET", "https://api.meraki.com/x", nil)
		a.Header.Set("Authorization", "Bearer KEY")
		b, _ := http.NewRequest("GET", u, nil)
		return b, []*http.Request{a}
	}
	if r, via := mk("https://n123.meraki.com/api/v1/x"); merakiRedirect(r, via) != nil || r.Header.Get("Authorization") != "Bearer KEY" {
		t.Error("a meraki shard is followed with the key")
	}
	for _, u := range []string{"https://evil.example.com/x", "http://n1.meraki.com/x", "https://meraki.com.evil.net/x", "https://xmeraki.com.cn.evil/"} {
		if r, via := mk(u); merakiRedirect(r, via) == nil || r.Header.Get("Authorization") != "" {
			t.Errorf("%s followed", u)
		}
	}
}

func TestMerakiSwitch(t *testing.T) {
	st := newMerakiState()
	d := merakiStub(t, st)
	d.Options["serial"] = "q2aa-bbbb-cccc"
	drv := openMeraki(t, d, "KEY")
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "sw-core" || f.Model != "MS225-24P" || f.OSVersion != "switch-15-21" || f.Serial != "Q2AA-BBBB-CCCC" {
		t.Fatalf("facts %+v %v", f, err)
	}
	ports, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ports) != 4 || ports[0].Name != "1" || ports[0].SpeedMbps != 1000 || ports[3].SpeedMbps != 10000 ||
		ports[2].AdminUp == nil || *ports[2].AdminUp || ports[3].Properties["isUplink"] != true || ports[0].Description != "uplink pc" {
		t.Fatalf("ports %+v %v", ports, err)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 2 || nb[0].LocalPort != "1" || nb[0].Protocol != "cdp" || nb[0].RemoteName != "ap1" || nb[1].RemoteName != "core-sw" || nb[1].RemoteAddr != "10.0.0.1" {
		t.Fatalf("neighbors %+v %v", nb, err)
	}
	// an MX has no switch ports: its management address is the one interface
	d.Options["serial"] = "Q2MX-1111-2222"
	ifs, err := openMeraki(t, d, "KEY").Interfaces(ctx)
	if err != nil || len(ifs) != 1 || ifs[0].Addresses[0] != "10.0.0.2" {
		t.Fatalf("mx interfaces %+v %v", ifs, err)
	}
	for _, bad := range []string{"nope", "Q2AA-BBBB", "../x"} {
		d.Options["serial"] = bad
		if _, err := Open(d, Credential{Name: "k", Token: "KEY"}); err == nil {
			t.Errorf("serial %q accepted", bad)
		}
	}
}

func TestMerakiChange(t *testing.T) {
	st := newMerakiState()
	d := merakiStub(t, st)
	d.Options["serial"] = "Q2AA-BBBB-CCCC"
	drv := openMeraki(t, d, "KEY")
	ctx := context.Background()
	ch, err := drv.(Changer), error(nil)
	c, err := ParseChange(`change the description for ports 1-2 to read "desks"`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Change(ctx, c, true); err != nil || st.saw("PUT") != 0 {
		t.Fatalf("dry run: %v, %d puts", err, st.saw("PUT"))
	}
	if _, err := ch.Change(ctx, c, false); err != nil || st.ports[0]["name"] != "desks" || st.ports[1]["name"] != "desks" {
		t.Fatalf("describe: %v %v", err, st.ports)
	}
	c, _ = ParseChange("shut port 2 down")
	if _, err := ch.Change(ctx, c, false); err != nil || st.ports[1]["enabled"] != false {
		t.Fatalf("shut: %v %v", err, st.ports[1])
	}
	c, _ = ParseChange("no shutdown 3")
	if _, err := ch.Change(ctx, c, false); err != nil || st.ports[2]["enabled"] != true {
		t.Fatalf("no shut: %v %v", err, st.ports[2])
	}
	// the uplink is never shut down, and nothing is written
	puts := st.saw("PUT")
	c, _ = ParseChange("shut down 3-4")
	if _, err := ch.Change(ctx, c, false); err == nil || !strings.Contains(err.Error(), "uplink") || st.saw("PUT") != puts {
		t.Fatalf("uplink: %v", err)
	}
	// a port the switch lacks
	c, _ = ParseChange("shut down 9")
	if _, err := ch.Change(ctx, c, false); err == nil || !strings.Contains(err.Error(), "no port 9") {
		t.Fatalf("missing port: %v", err)
	}
	// an organization-level device cannot do typed port changes
	d.Options["serial"] = ""
	c, _ = ParseChange("shut down 1")
	if _, err := openMeraki(t, d, "KEY").(Changer).Change(ctx, c, false); err == nil || !strings.Contains(err.Error(), "serial") {
		t.Fatalf("org-level change: %v", err)
	}
}

func TestMerakiRawChange(t *testing.T) {
	st := newMerakiState()
	d := merakiStub(t, st)
	drv := openMeraki(t, d, "KEY").(RawChanger)
	ctx := context.Background()
	body := `{"name":"staff"}`
	r, err := drv.RawChange(ctx, Raw{Method: "PUT", Path: "/networks/N_1/appliance/vlans/10", Body: body}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "users") || st.puts != 0 {
		t.Fatalf("dry: %+v %v", r, err)
	}
	r, err = drv.RawChange(ctx, Raw{Method: "PUT", Path: "/api/v1/networks/N_1/appliance/vlans/10", Body: body}, false)
	if err != nil || !r.Applied || st.puts != 1 || r.RolledBack {
		t.Fatalf("put: %+v %v", r, err)
	}
	// a 5xx puts the old copy back (a second PUT)
	st.fail, st.puts = true, 0
	r, err = drv.RawChange(ctx, Raw{Method: "PUT", Path: "/networks/N_1/appliance/vlans/10", Body: body}, false)
	if err == nil || st.puts != 2 || !r.RolledBack && !strings.Contains(r.Note, "back") {
		t.Fatalf("5xx: %+v %v puts %d", r, err, st.puts)
	}
	st.fail = false
	before := len(st.calls)
	for _, bad := range []Raw{
		{Method: "PATCH", Path: "/networks/N_1/appliance/vlans/10", Body: body},
		{Method: "PUT", Path: "/organizations/1234/admins/5", Body: body},
		{Method: "POST", Path: "/organizations/1234/saml/idps", Body: body},
		{Method: "PUT", Path: "/networks/N_1/snmp", Body: body},
		{Method: "PUT", Path: "/devices/Q2AA-BBBB-CCCC/managementInterface", Body: body},
		{Method: "POST", Path: "/devices/Q2AA-BBBB-CCCC/reboot"},
		{Method: "POST", Path: "/networks/N_1/devices/remove", Body: body},
		{Method: "POST", Path: "/networks/N_1/firmwareUpgrades", Body: body},
		{Method: "DELETE", Path: "/networks/N_1"},
		{Method: "DELETE", Path: "/organizations/1234"},
		{Method: "PUT", Path: "/x/y", Body: body},
		{Method: "PUT", Path: "/networks/N_1/appliance/vlans/10?x=1", Body: body},
		{Method: "PUT", Path: "/networks/N_1/../x", Body: body},
		{Method: "PUT", Path: "/networks/N_1/appliance/vlans/10", Body: "{bad"},
		{Lines: []string{"x"}},
	} {
		if _, err := drv.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if len(st.calls) != before {
		t.Errorf("a refused change reached the API: %v", st.calls[before:])
	}
}

func TestMerakiDefaultAddress(t *testing.T) {
	devs := []Device{{Name: "m1", Platform: "meraki", Credential: "k"}, {Name: "s1", Platform: "iosxe", Credential: "k"}}
	err := Validate(devs, []Credential{{Name: "k", Token: "KEY"}})
	if err == nil || !strings.Contains(err.Error(), "s1") {
		t.Fatalf("an IOS-XE device with no address must still be refused: %v", err)
	}
	devs = devs[:1]
	if err := Validate(devs, []Credential{{Name: "k", Token: "KEY"}}); err != nil || devs[0].Address != "api.meraki.com" {
		t.Fatalf("meraki without an address: %v %q", err, devs[0].Address)
	}
}
