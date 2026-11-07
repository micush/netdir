package device

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stub is a device's API on loopback: path (with query) -> answer.
func stub(t *testing.T, check func(r *http.Request) bool, answers map[string]string) (Device, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil && !check(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		a, ok := answers[r.Method+" "+r.URL.RequestURI()]
		if !ok {
			a, ok = answers[r.URL.RequestURI()]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(a, "HTTP ") {
			code, _ := strconv.Atoi(a[5:8])
			http.Error(w, a[9:], code)
			return
		}
		_, _ = w.Write([]byte(a))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return Device{Name: "d1", Address: host, Port: p, Insecure: true}, srv
}

func open(t *testing.T, d Device, c Credential) Driver {
	t.Helper()
	drv, err := Open(d, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { drv.Close(context.Background()) })
	return drv
}

func TestValidate(t *testing.T) {
	creds := []Credential{{Name: "lab", Username: "admin", Password: "pw"}, {Name: "fgt", Token: "tok"}}
	devs := []Device{{Name: "sw1", Platform: " IOSXE ", Address: "10.0.0.2", Credential: "lab", Tags: []string{"site=home", " core", "core", ""}},
		{Name: "fw1", Platform: "fortios", Address: "fw.example.net", Credential: "fgt"}}
	if err := Validate(devs, creds); err != nil {
		t.Fatal(err)
	}
	if devs[0].Platform != "iosxe" || strings.Join(devs[0].Tags, ",") != "core,site=home" {
		t.Fatalf("not normalised: %+v", devs[0])
	}
	bad := []struct {
		name string
		d    Device
		c    []Credential
	}{
		{"unknown platform", Device{Name: "a", Platform: "ciscoios9000", Address: "1.2.3.4", Credential: "lab"}, creds},
		{"unknown credential", Device{Name: "a", Platform: "iosxe", Address: "1.2.3.4", Credential: "nope"}, creds},
		{"address with scheme", Device{Name: "a", Platform: "iosxe", Address: "https://1.2.3.4", Credential: "lab"}, creds},
		{"address with port", Device{Name: "a", Platform: "iosxe", Address: "sw:443", Credential: "lab"}, creds},
		{"bad name", Device{Name: "a b", Platform: "iosxe", Address: "1.2.3.4", Credential: "lab"}, creds},
		{"tag with space", Device{Name: "a", Platform: "iosxe", Address: "1.2.3.4", Credential: "lab", Tags: []string{"a b"}}, creds},
		{"ca and insecure", Device{Name: "a", Platform: "iosxe", Address: "1.2.3.4", Credential: "lab", Insecure: true, CAPEM: "x"}, creds},
		{"credential without secret", Device{Name: "a", Platform: "iosxe", Address: "1.2.3.4", Credential: "e"}, []Credential{{Name: "e", Username: "u"}}},
	}
	for _, b := range bad {
		if err := Validate([]Device{b.d}, b.c); err == nil {
			t.Errorf("%s: accepted", b.name)
		}
	}
	if err := Validate([]Device{devs[0], devs[0]}, creds); err == nil {
		t.Error("a device listed twice was accepted")
	}
}

func TestSelect(t *testing.T) {
	devs := []Device{{Name: "sw1", Platform: "iosxe", Tags: []string{"site=home"}}, {Name: "fw1", Platform: "fortios", Tags: []string{"site=home"}},
		{Name: "old", Platform: "iosxe", Disabled: true}}
	names := func(target string) string {
		got, err := Select(devs, target)
		if err != nil {
			return "error: " + err.Error()
		}
		var n []string
		for _, d := range got {
			n = append(n, d.Name)
		}
		return strings.Join(n, ",")
	}
	for target, want := range map[string]string{
		"all": "fw1,sw1", "SW1": "sw1", "tag:site=home": "fw1,sw1", "platform:iosxe": "sw1", "old": "old", "sw1, fw1": "fw1,sw1",
	} {
		if got := names(target); got != want {
			t.Errorf("Select(%q) = %s, want %s", target, got, want)
		}
	}
	for _, target := range []string{"", "nosuch", "sw1,nosuch", "tag:site=work"} {
		if _, err := Select(devs, target); err == nil {
			t.Errorf("Select(%q) accepted", target)
		}
	}
}

func TestCheckShow(t *testing.T) {
	for _, ok := range []string{"show version", "show ip int brief", "show run | include hostname", "show interfaces status | exclude notconnect",
		"show running-config | section interface Gi1/0/1", "show version | json"} {
		if _, err := CheckShow(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "conf t", "reload", "show version; reload", "show run | tee flash:x", "show run | redirect bootflash:x",
		"show run > flash:x", "show run\nreload", "show", "copy run start", "show run | append x", "show run | include x | tee y", "show `id`", "show $(id)"} {
		if _, err := CheckShow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIOSXE(t *testing.T) {
	basic := func(r *http.Request) bool {
		u, p, ok := r.BasicAuth()
		return ok && u == "admin" && p == "s3cret" && r.Header.Get("Accept") == yangJSON
	}
	d, _ := stub(t, basic, map[string]string{
		"/restconf/data/Cisco-IOS-XE-native:native/hostname": `{"Cisco-IOS-XE-native:hostname":"cat9300"}`,
		"/restconf/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware": `{"Cisco-IOS-XE-device-hardware-oper:device-hardware":{
			"device-inventory":[{"hw-type":"hw-type-pim","part-number":"X"},{"hw-type":"hw-type-chassis","part-number":"C9300-24P","serial-number":"FOC1234X0AB"}],
			"device-system-data":{"current-time":"2026-11-01T12:00:00+00:00","boot-time":"2026-10-31T12:00:00+00:00",
			"software-version":"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)"}}}`,
		"/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface": `{"Cisco-IOS-XE-interfaces-oper:interface":[
			{"name":"Vlan1","admin-status":"if-state-up","oper-status":"if-oper-state-ready","ipv4":"192.168.1.2","ipv4-subnet-mask":"255.255.255.0","speed":"1000000000","phys-address":"aa:bb:cc:00:00:01"},
			{"name":"GigabitEthernet1/0/1","description":"uplink","admin-status":"if-state-down","oper-status":"if-oper-state-no-pass","ipv4":"0.0.0.0","speed":"1000000000"}]}`,
		"/restconf/data/Cisco-IOS-XE-lldp-oper:lldp-entries/lldp-entry": `{"Cisco-IOS-XE-lldp-oper:lldp-entry":{"device-id":"fw","local-interface":"Gi1/0/48","connecting-interface":"port1"}}`,
		"/restconf/data/Cisco-IOS-XE-cdp-oper:cdp-neighbor-details/cdp-neighbor-detail": `{"Cisco-IOS-XE-cdp-oper:cdp-neighbor-detail":[
			{"device-name":"ap1","local-intf-name":"Gi1/0/2","port-id":"Gi0","platform-name":"AIR-AP","mgmt-address":{"ip-address":"192.168.1.20"}},
			{"device-name":"dup","local-intf-name":"Gi1/0/48","port-id":"x"}]}`,
		"/restconf/data/Cisco-IOS-XE-native:native": `{"Cisco-IOS-XE-native:native":{"hostname":"cat9300"}}`,
	})
	d.Platform = "iosxe"
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f != (Facts{Hostname: "cat9300", Vendor: "Cisco", Model: "C9300-24P", OSVersion: "17.9.4a", Serial: "FOC1234X0AB", UptimeS: 86400}) {
		t.Fatalf("facts: %+v", f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	g, v := ifs[0], ifs[1]
	if g.Name != "GigabitEthernet1/0/1" || *g.AdminUp || *g.OperUp || g.Addresses != nil || g.Description != "uplink" {
		t.Errorf("Gi1/0/1: %+v", g)
	}
	if !*v.OperUp || v.SpeedMbps != 1000 || v.Addresses[0] != "192.168.1.2/24" || v.MAC != "aa:bb:cc:00:00:01" {
		t.Errorf("Vlan1: %+v", v)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 2 {
		t.Fatalf("neighbors (LLDP, plus CDP only where LLDP has none): %v %+v", err, nb)
	}
	nb0, nb1 := nb[0], nb[1]
	if nb0.Protocol != "cdp" || nb0.Detail["platform-name"] != "AIR-AP" || nb1.Protocol != "lldp" || nb1.Detail["device-id"] != "fw" {
		t.Errorf("neighbor detail: %+v", nb)
	}
	nb0.Protocol, nb0.Detail, nb1.Protocol, nb1.Detail = "", nil, "", nil
	if !reflect.DeepEqual(nb0, Neighbor{LocalPort: "Gi1/0/2", RemoteName: "ap1", RemotePort: "Gi0", RemoteAddr: "192.168.1.20", RemoteDesc: "AIR-AP"}) ||
		!reflect.DeepEqual(nb1, Neighbor{LocalPort: "Gi1/0/48", RemoteName: "fw", RemotePort: "port1"}) {
		t.Errorf("neighbors: %+v", nb)
	}
	if c, err := drv.Config(ctx); err != nil || !strings.Contains(c, `"hostname":"cat9300"`) {
		t.Errorf("config: %v %q", err, c)
	}
	if _, err := drv.Show(ctx, "show version"); err != ErrUnsupported {
		t.Errorf("show: %v", err)
	}
	// a wrong password is the device's 401, reported
	bad := open(t, d, Credential{Username: "admin", Password: "wrong"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestIOSXENoNeighbors(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{}) // every model 404: no LLDP entries, no CDP
	d.Platform = "iosxe"
	nb, err := open(t, d, Credential{Username: "u", Password: "p"}).Neighbors(context.Background())
	if err != nil || len(nb) != 0 {
		t.Fatalf("%v %+v", err, nb)
	}
}

func TestFortiOS(t *testing.T) {
	bearer := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer tok123" }
	d, _ := stub(t, bearer, map[string]string{
		"/api/v2/monitor/system/status?vdom=root": `{"status":"success","serial":"FG100ETK1800XXXX","version":"v7.2.10","build":1706,
			"results":{"hostname":"fw-home","model_name":"FortiGate","model_number":"100E","model":"FG100E"}}`,
		"/api/v2/monitor/web-ui/state?vdom=root": `{"status":"success","results":{"utc_last_reboot":1761998400000}}`,
		"/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true&vdom=root": `{"status":"success","results":{
			"wan1":{"name":"wan1","mac":"00:09:0f:00:00:01","ip":"203.0.113.5","mask":24,"link":true,"speed":1000},
			"port1":{"name":"port1","mac":"00:09:0f:00:00:02","ip":"0.0.0.0","mask":0,"link":false,"speed":0}}}`,
		"/api/v2/cmdb/system/interface?format=name|description|status|alias&vdom=root": `{"status":"success","results":[
			{"name":"wan1","description":"ISP","status":"up"},{"name":"port1","alias":"lab","status":"down"}]}`,
		"/api/v2/monitor/network/lldp/neighbors?vdom=root":              `{"status":"success","results":[{"port_name":"port1","system_name":"cat9300","port_id":"Gi1/0/48","addresses":[{"address":"192.168.1.2"}]}]}`,
		"GET /api/v2/monitor/system/config/backup?scope=vdom&vdom=root": "HTTP 405 method not allowed",
		"POST /api/v2/monitor/system/config/backup?vdom=root":           "#config-version=FG100E-7.2.10\nconfig system global\nend\n",
	})
	d.Platform, d.Options = "fortios", map[string]string{"vdom": "root"}
	nowUnix = func() int64 { return 1761998400 + 3600 }
	defer func() { nowUnix = func() int64 { return time.Now().Unix() } }()
	drv := open(t, d, Credential{Token: "tok123"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f != (Facts{Hostname: "fw-home", Vendor: "Fortinet", Model: "FG100E", OSVersion: "7.2.10 build 1706", Serial: "FG100ETK1800XXXX", UptimeS: 3600}) {
		t.Fatalf("facts: %+v", f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	p, w := ifs[0], ifs[1]
	if p.Name != "port1" || *p.AdminUp || *p.OperUp || p.Description != "lab" || p.Addresses != nil {
		t.Errorf("port1: %+v", p)
	}
	if !*w.AdminUp || !*w.OperUp || w.SpeedMbps != 1000 || w.Addresses[0] != "203.0.113.5/24" || w.Description != "ISP" {
		t.Errorf("wan1: %+v", w)
	}
	nb, err := drv.Neighbors(ctx)
	if err != nil || len(nb) != 1 || nb[0].LocalPort != "port1" || nb[0].RemoteName != "cat9300" || nb[0].RemotePort != "Gi1/0/48" || nb[0].RemoteAddr != "192.168.1.2" || nb[0].Protocol != "lldp" || nb[0].Detail["system_name"] != "cat9300" {
		t.Errorf("neighbors: %v %+v", err, nb)
	}
	if c, err := drv.Config(ctx); err != nil || !strings.HasPrefix(c, "#config-version=FG100E") {
		t.Errorf("config (GET refused, then POST): %v %q", err, c)
	}
	if _, err := open(t, d, Credential{Token: "wrong"}).Facts(ctx); err == nil {
		t.Error("a wrong token was not reported")
	}
	if _, err := Open(d, Credential{Username: "u", Password: "p"}); err == nil {
		t.Error("FortiOS without a token was accepted")
	}
}

func TestNoRedirectWithCredentials(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	d, _ := stub(t, nil, nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	d.Port, _ = strconv.Atoi(port)
	d.Platform = "iosxe"
	if _, err := open(t, d, Credential{Username: "u", Password: "p"}).Facts(context.Background()); err == nil {
		t.Error("a redirect was taken as an answer")
	}
	if hits.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

func TestCertificateChecked(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{"/restconf/data/Cisco-IOS-XE-native:native/hostname": `{"x:hostname":"h"}`})
	d.Platform, d.Insecure = "iosxe", false
	if _, err := open(t, d, Credential{Username: "u", Password: "p"}).Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("a self-signed certificate was accepted without insecure: %v", err)
	}
}

func TestFanout(t *testing.T) {
	d, _ := stub(t, nil, map[string]string{"/restconf/data/Cisco-IOS-XE-native:native/hostname": `{"x:hostname":"sw"}`})
	d.Platform, d.Credential = "iosxe", "lab"
	slow := d
	slow.Name = "slow"
	missing := d
	missing.Name, missing.Credential = "nocred", "gone"
	creds := []Credential{{Name: "lab", Username: "u", Password: "hunter22"}}
	res := Fanout(context.Background(), []Device{d, slow, missing}, creds, 2, 5*time.Second, func(ctx context.Context, drv Driver) (any, error) {
		f, err := drv.Facts(ctx)
		if err != nil {
			return nil, err
		}
		if f.Hostname == "" {
			return nil, nil
		}
		return f.Hostname, nil
	})
	if len(res) != 3 || res[0].Device != "d1" || res[2].Device != "nocred" {
		t.Fatalf("%+v", res)
	}
	if res[2].OK || !strings.Contains(res[2].Error, "credential") {
		t.Errorf("missing credential: %+v", res[2])
	}
	// the device-hardware model 404s: the facts are what the switch has (the host name), not an error
	for _, r := range res[:2] {
		if !r.OK || r.Data != "sw" {
			t.Errorf("%+v", r)
		}
	}
	// an error never carries the password, even when the device echoes it
	res = Fanout(context.Background(), []Device{d}, creds, 1, time.Second, func(context.Context, Driver) (any, error) {
		return nil, errors.New("login hunter22 refused")
	})
	if res[0].OK || strings.Contains(res[0].Error, "hunter22") {
		t.Errorf("%+v", res[0])
	}
	// a panicking driver costs that device only
	res = Fanout(context.Background(), []Device{d}, creds, 1, time.Second, func(context.Context, Driver) (any, error) { panic("boom") })
	if res[0].OK || !strings.Contains(res[0].Error, "boom") {
		t.Errorf("panic: %+v", res[0])
	}
	b, _ := json.Marshal(res[0])
	if !strings.Contains(string(b), `"ok":false`) {
		t.Errorf("json: %s", b)
	}
}

func TestScrub(t *testing.T) {
	if got := scrub("login failed for hunter22 and tokABCD", Credential{Password: "hunter22", Token: "tokABCD"}); strings.Contains(got, "hunter22") || strings.Contains(got, "tokABCD") {
		t.Error(got)
	}
}
