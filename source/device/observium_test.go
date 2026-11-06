package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type obsState struct {
	mu       sync.Mutex
	reqs     []string
	throttle atomic.Int32 // the next requests answered 429
}

func (s *obsState) joined() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.reqs, " ")
}

func obsDevices() J {
	return J{
		"12": J{"device_id": "12", "hostname": "ipam2.example.com", "sysName": "ipam2", "vendor": "VMware", "os": "linux", "hardware": "VMware Virtual Platform",
			"version": "Ubuntu 22.04", "serial": "SN-12", "uptime": "86400", "status": "1",
			"snmp_community": "public-secret", "snmp_authpass": "authsecret", "snmp_cryptopass": "cryptsecret", "snmp_authname": "snmpuser"},
		"13": J{"device_id": "13", "hostname": "ipam3.example.com", "sysName": "ipam3", "os": "linux", "status": "1"},
		"14": J{"device_id": "14", "hostname": "core-sw.example.com", "sysName": "core-sw", "os": "ios", "status": "0"},
	}
}

// obsStub is an Observium on loopback, below prefix.  The shapes follow the documentation of the API for devices (a collection
// keyed by device ID under "devices") and the fields Observium's database uses for the rest; nothing here has been checked
// against a running Observium.  It fails the test on a request that is not a GET, on a credential in a URL and on a request
// without the credential (a Bearer token "APITOKEN", or the user "admin" with the password "s3cret").
func obsStub(t *testing.T, prefix string) (Device, *obsState) {
	t.Helper()
	st := &obsState{}
	good := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:s3cret"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "api_token") || strings.Contains(r.URL.String(), "s3cret") || strings.Contains(r.URL.String(), "APITOKEN") {
			t.Errorf("a credential is in the URL: %s", r.URL)
		}
		if a := r.Header.Get("Authorization"); a != "Bearer APITOKEN" && a != good {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":"failed","message":"Unauthorized"}`))
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request (only GET is ever sent): %s", r.Method, r.URL)
		}
		st.mu.Lock()
		st.reqs = append(st.reqs, r.URL.RequestURI())
		st.mu.Unlock()
		send := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if st.throttle.Add(-1) >= 0 {
			send(http.StatusTooManyRequests, J{"status": "failed", "message": "Too many requests"})
			return
		}
		st.throttle.Store(0)
		p, ok := strings.CutPrefix(r.URL.Path, prefix+"/api/v0")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		devs := obsDevices()
		switch {
		case p == "/devices/" && q.Get("fields") != "":
			out := J{}
			for id, d := range devs {
				m := d.(J)
				out[id] = J{"device_id": id, "hostname": m["hostname"], "sysName": m["sysName"]}
			}
			send(200, J{"status": "ok", "count": len(out), "devices": out})
		case p == "/devices/":
			send(200, J{"status": "ok", "count": len(devs), "devices": devs})
		case p == "/devices/ipam2.example.com/" || p == "/devices/12/":
			send(200, J{"status": "ok", "count": 1, "devices": J{"12": devs["12"]}})
		case strings.HasPrefix(p, "/devices/") && strings.Count(p, "/") == 3:
			send(404, J{"status": "failed", "message": "Device not found"})
		case p == "/ports/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 3, "ports": J{
				"101": J{"port_id": "101", "device_id": "12", "ifName": "eth0", "ifDescr": "eth0", "ifAlias": "uplink", "ifAdminStatus": "up", "ifOperStatus": "up",
					"ifSpeed": "1000000000", "ifPhysAddress": "005056aabbcc", "ifMtu": "1500", "ifType": "ethernetCsmacd", "ifDuplex": "fullDuplex",
					"ifInOctets": "5000", "ifOutOctets": "7000", "ifInUcastPkts": "50", "ifOutUcastPkts": "70", "ifInErrors": "2", "ifInOctets_rate": "1250", "ifOutOctets_rate": "2500", "deleted": "0"},
				"102": J{"port_id": "102", "device_id": "12", "ifName": "old0", "ifAdminStatus": "down", "ifOperStatus": "down", "deleted": "1"},
				"103": J{"port_id": "103", "device_id": "12", "ifName": "eth1", "ifAdminStatus": "up", "ifOperStatus": "down", "deleted": "0"},
			}})
		case p == "/address/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "addresses": []any{J{"port_id": "101", "ipv4_address": "10.0.0.5", "ipv4_prefixlen": "24"}}})
		case p == "/neighbours/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 2, "neighbours": []any{
				J{"port_id": "101", "remote_hostname": "core-sw.example.com", "remote_port": "Gi1/0/5", "remote_address": "10.0.0.1", "remote_platform": "cisco WS-C3850", "protocol": "LLDP", "active": "1"},
				J{"port_id": "103", "remote_hostname": "gone", "remote_port": "x", "protocol": "CDP", "active": "0"},
			}})
		case p == "/sensors/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 2, "sensors": J{
				"1": J{"sensor_id": "1", "sensor_descr": "CPU Temperature", "sensor_class": "temperature", "sensor_value": "42.5", "sensor_event": "ok"},
				"2": J{"sensor_id": "2", "sensor_descr": "Fan 1", "sensor_class": "fanspeed", "sensor_value": "3200", "sensor_event": "warn"},
			}})
		case p == "/status/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "statuses": []any{J{"status_id": "9", "status_descr": "Power Supply 1", "status_event": "ok"}}})
		case p == "/storage/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "storage": J{"5": J{"storage_id": "5", "storage_descr": "/", "storage_size": "100000", "storage_used": "25000", "storage_free": "75000", "storage_perc": "25"}}})
		case p == "/mempools/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "mempools": J{"6": J{"mempool_descr": "Physical memory", "mempool_total": "8000", "mempool_used": "2000", "mempool_free": "6000", "mempool_perc": "25"}}})
		case p == "/processors/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 2, "processors": J{"7": J{"processor_descr": "cpu0", "processor_usage": "10"}, "8": J{"processor_descr": "cpu1", "processor_usage": "30"}}})
		case p == "/inventory/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "inventory": J{"3": J{"entPhysicalDescr": "chassis", "entPhysicalSerialNum": "ABC123"}}})
		case p == "/counters/":
			send(404, J{"status": "failed", "message": "counters are not enabled"})
		case p == "/probes/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 0, "probes": []any{}})
		case p == "/alerts/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "alerts": J{"77": J{"alert_table_id": "77", "alert_status": "0", "entity_type": "port", "entity_id": "101"}}})
		case p == "/alerts/":
			send(200, J{"status": "ok", "count": 1, "alerts": J{"78": J{"alert_table_id": "78", "device_id": "14", "alert_status": "0"}}})
		case p == "/alert_log/" && q.Get("device_id") == "12":
			send(200, J{"status": "ok", "count": 1, "pagesize": 50, "pageno": 1, "countpage": 1, "entries": []any{J{"event_id": "5", "log_type": "ALERT_NOTIFY", "message": "port eth0 down"}}})
		case p == "/groups/":
			send(200, J{"status": "ok", "count": 0, "groups": J{}})
		case p == "/openapi.json":
			send(200, J{"openapi": "3.0.0", "info": J{"title": "Observium API"}})
		case p == "/sensors/" && q.Get("bad") == "1":
			send(200, J{"status": "failed", "message": "the query is wrong"})
		default:
			send(404, J{"status": "failed", "message": "no such thing: " + p})
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "observium", Platform: "observium", Address: host, Port: pn, Insecure: true}, st
}

func obsOpen(t *testing.T, opts map[string]string) (Driver, *obsState) {
	t.Helper()
	d, st := obsStub(t, strings.TrimRight(opts["prefix"], "/"))
	d.Options = opts
	return open(t, d, Credential{Token: "APITOKEN"}), st
}

func TestObserviumServer(t *testing.T) {
	drv, st := obsOpen(t, nil)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Observium" || !strings.Contains(f.Model, "3 devices") {
		t.Fatalf("facts: %v %+v", err, f)
	}
	for name, err := range map[string]error{"interfaces": func() error { _, e := drv.Interfaces(ctx); return e }(), "neighbors": func() error { _, e := drv.Neighbors(ctx); return e }(),
		"ports": func() error { _, e := drv.(Porter).Ports(ctx); return e }()} {
		if err != ErrUnsupported {
			t.Errorf("%s of the server: %v", name, err)
		}
	}
	if _, err := drv.Config(ctx); err != ErrUnsupported {
		t.Errorf("config: %v", err)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.Details.Protocols["alerts_failed"] == nil || r.Details.Protocols["devices"] == nil {
		t.Fatalf("resources: %v %+v", err, r)
	}
	if !strings.Contains(st.joined(), "/api/v0/alerts/?status=failed") {
		t.Errorf("requests: %s", st.joined())
	}
	if _, ok := drv.(RawChanger); !ok {
		t.Error("Observium can be changed (device_change_raw)")
	}
}

func TestObserviumBasicAuth(t *testing.T) {
	d, _ := obsStub(t, "")
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"})
	if f, err := drv.Facts(context.Background()); err != nil || f.Vendor != "Observium" {
		t.Fatalf("basic auth: %v %+v", err, f)
	}
	bad := open(t, d, Credential{Username: "admin", Password: "wrong"})
	if _, err := bad.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestObserviumDevice(t *testing.T) {
	drv, st := obsOpen(t, map[string]string{"device": "ipam2"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "ipam2.example.com", Vendor: "VMware", Model: "VMware Virtual Platform", OSVersion: "Ubuntu 22.04", Serial: "SN-12", UptimeS: 86400}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 { // old0 is deleted
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	var e0 Interface
	for _, i := range ifs {
		if i.Name == "old0" {
			t.Error("a deleted port is listed")
		}
		if i.Name == "eth0" {
			e0 = i
		}
	}
	if e0.Description != "uplink" || e0.SpeedMbps != 1000 || e0.MAC != "00:50:56:aa:bb:cc" || e0.OperUp == nil || !*e0.OperUp || e0.AdminUp == nil || !*e0.AdminUp ||
		strings.Join(e0.Addresses, " ") != "10.0.0.5/24" {
		t.Errorf("eth0: %+v", e0)
	}
	ps, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ps) != 2 {
		t.Fatalf("ports: %v %+v", err, ps)
	}
	for _, p := range ps {
		if p.Name == "eth0" && (p.Counters.InOctets != 5000 || p.Counters.OutOctets != 7000 || p.Counters.InErrors != 2 || p.Counters.RxKbps != 10 || p.Counters.TxKbps != 20 ||
			p.Counters.All["ifInOctets"] != "5000" || p.MTU != 1500 || p.Duplex != "fullDuplex" || p.Type != "ethernetCsmacd" || p.Properties["ifAlias"] != "uplink") {
			t.Errorf("eth0 port: %+v", p)
		}
	}
	ns, err := drv.Neighbors(ctx)
	if err != nil || len(ns) != 1 || ns[0].LocalPort != "eth0" || ns[0].RemoteName != "core-sw.example.com" || ns[0].RemotePort != "Gi1/0/5" || ns[0].Protocol != "lldp" || ns[0].RemoteAddr != "10.0.0.1" {
		t.Errorf("neighbors (the inactive one is left out): %v %+v", err, ns)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 20 || len(r.Memory) != 1 || r.Memory[0].Total != 8000 || r.Memory[0].UsedPercent != 25 || len(r.Storage) != 1 || r.Storage[0].UsedPercent != 25 || len(r.Sensors) != 2 {
		t.Fatalf("resources: %v %+v", err, r)
	}
	kinds := map[string]string{}
	for _, s := range r.Sensors {
		kinds[s.Name] = s.Kind + "/" + s.Units + "/" + s.State
	}
	if kinds["CPU Temperature"] != "temperature/C/ok" || kinds["Fan 1"] != "fan/rpm/warn" {
		t.Errorf("sensors: %v", kinds)
	}
	if r.Details.Protocols["status"] == nil || r.Details.Unavailable != nil {
		t.Errorf("details: %+v", r.Details)
	}
	if n := strings.Count(st.joined(), "/api/v0/devices/ipam2/"); n != 1 {
		t.Errorf("the device was looked up %d times (once, then remembered): %s", n, st.joined())
	}
}

// "show the observium device ipam2": one command, everything about the device.
func TestObserviumShowDevice(t *testing.T) {
	drv, _ := obsOpen(t, nil)
	ctx := context.Background()
	for _, cmd := range []string{"show device ipam2", "show device ipam2.example.com", "show device 12", "show device device=ipam2"} {
		out, err := drv.Show(ctx, cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("%s: not JSON: %v\n%s", cmd, err, out)
		}
		dev, _ := v["device"].(map[string]any)
		if dev["hostname"] != "ipam2.example.com" || dev["serial"] != "SN-12" {
			t.Errorf("%s: device: %v", cmd, dev)
		}
		for _, k := range []string{"ports", "addresses", "neighbours", "sensors", "status", "storage", "mempools", "processors", "inventory", "alerts", "alert_log"} {
			if l, _ := v[k].([]any); len(l) == 0 {
				t.Errorf("%s: %s is empty: %v", cmd, k, v[k])
			}
		}
		if l, ok := v["probes"].([]any); !ok || len(l) != 0 {
			t.Errorf("%s: probes should be an empty list: %v", cmd, v["probes"])
		}
		if un, _ := v["unavailable"].(map[string]any); un["counters"] == nil {
			t.Errorf("%s: counters, which Observium refused, are not listed as unavailable: %v", cmd, v["unavailable"])
		}
		if c, _ := v["counts"].(map[string]any); c["ports"] != float64(3) || c["neighbours"] != float64(2) {
			t.Errorf("%s: counts: %v", cmd, v["counts"])
		}
		for _, secret := range []string{"public-secret", "authsecret", "cryptsecret", "snmpuser"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s: shows %q", cmd, secret)
			}
		}
		if !strings.Contains(out, "(hidden)") {
			t.Errorf("%s: no secret was hidden", cmd)
		}
	}
	// a name that fits two devices, and one that fits none
	if _, err := drv.Show(ctx, "show device ipam"); err == nil || !strings.Contains(err.Error(), "ipam2.example.com") || !strings.Contains(err.Error(), "ipam3.example.com") {
		t.Errorf("ambiguous name: %v", err)
	}
	if _, err := drv.Show(ctx, "show device nosuch"); err == nil || !strings.Contains(err.Error(), "has no device that matches") {
		t.Errorf("unknown name: %v", err)
	}
	if _, err := drv.Show(ctx, "show device"); err == nil {
		t.Error("show device without a name on the server")
	}
	// on a driver for one device, the name may be left out
	one, _ := obsOpen(t, map[string]string{"device": "ipam2"})
	if out, err := one.Show(ctx, "show device"); err != nil || !strings.Contains(out, "ipam2.example.com") {
		t.Errorf("show device on a device: %v", err)
	}
}

func TestObserviumShowLists(t *testing.T) {
	drv, st := obsOpen(t, nil)
	ctx := context.Background()
	out, err := drv.Show(ctx, "show ports device=ipam2")
	if err != nil || !strings.Contains(out, "eth0") || !strings.Contains(st.joined(), "/api/v0/ports/?device_id=12") {
		t.Fatalf("show ports device=ipam2: %v\n%s\n%s", err, out, st.joined())
	}
	if _, err := drv.Show(ctx, "show devices"); err != nil || !strings.Contains(st.joined(), "/api/v0/devices/?pagesize=500") {
		t.Errorf("an unscoped list is paged: %v %s", err, st.joined())
	}
	if out, err := drv.Show(ctx, "show devices device=ipam2"); err != nil || !strings.Contains(out, "ipam2.example.com") || strings.Contains(out, "ipam3") {
		t.Errorf("show devices device=ipam2: %v\n%s", err, out)
	}
	if _, err := drv.Show(ctx, "show alerts status=failed"); err != nil || !strings.Contains(st.joined(), "/api/v0/alerts/?pagesize=500&status=failed") {
		t.Errorf("a filter is passed on: %v %s", err, st.joined())
	}
	if _, err := drv.Show(ctx, "show alert_log device=ipam2"); err != nil || !strings.Contains(st.joined(), "/api/v0/alert_log/?device_id=12") {
		t.Errorf("alert log: %v", err)
	}
	for _, bad := range []string{"show ports api_token=x", "show ports token=x", "show groups device=ipam2", "show nonsense", "show ports status", "show ports a=b;c", "show device ipam2 | include x", "show"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestObserviumAPIGet(t *testing.T) {
	drv, st := obsOpen(t, nil)
	ctx := context.Background()
	a := drv.(APIer)
	v, text, err := a.APIGet(ctx, "/devices/ipam2.example.com/")
	if err != nil || text || !strings.Contains(toJSON(v), "ipam2.example.com") || strings.Contains(toJSON(v), "public-secret") {
		t.Fatalf("devices: %v %v %s", err, text, toJSON(v))
	}
	if _, _, err := a.APIGet(ctx, "/api/v0/devices/"); err != nil {
		t.Errorf("with /api/v0: %v", err)
	}
	if v, _, err := a.APIGet(ctx, "/openapi.json"); err != nil || !strings.Contains(toJSON(v), "Observium API") {
		t.Errorf("openapi.json: %v", err)
	}
	for _, bad := range []string{"/users/", "/devices/../users/", "/devices/?api_token=x", "devices/", "/tokens/", "/devices/ x", "/"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
	if _, _, err := a.APIGet(ctx, "/sensors/?bad=1"); err == nil || !strings.Contains(err.Error(), "the query is wrong") {
		t.Errorf("a failed answer sent with HTTP 200: %v", err)
	}
	if c, err := a.APICatalog(ctx); err != nil || !strings.Contains(toJSON(c), "openapi.json") {
		t.Errorf("catalog: %v", err)
	}
	if strings.Contains(st.joined(), "/users/") {
		t.Errorf("a refused path was sent: %s", st.joined())
	}
}

func TestObserviumPrefix(t *testing.T) {
	drv, st := obsOpen(t, map[string]string{"prefix": "/observium/"})
	if f, err := drv.Facts(context.Background()); err != nil || !strings.Contains(f.Model, "3 devices") {
		t.Fatalf("facts below a prefix: %v %+v", err, f)
	}
	if !strings.Contains(st.joined(), "/observium/api/v0/devices/") {
		t.Errorf("requests: %s", st.joined())
	}
	if _, _, err := drv.(APIer).APIGet(context.Background(), "/observium/api/v0/devices/"); err != nil {
		t.Errorf("api get with the prefix: %v", err)
	}
}

func TestObserviumThrottle(t *testing.T) {
	old := obsWait
	obsWait = time.Millisecond
	defer func() { obsWait = old }()
	drv, st := obsOpen(t, nil)
	st.throttle.Store(1)
	if _, err := drv.Facts(context.Background()); err != nil {
		t.Errorf("one 429 is waited out: %v", err)
	}
	st.throttle.Store(5)
	if _, err := drv.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("a second 429 is an error: %v", err)
	}
}

func TestObserviumNew(t *testing.T) {
	d, _ := obsStub(t, "")
	if _, err := Open(d, Credential{Username: "admin"}); err == nil {
		t.Error("a user name without a password")
	}
	for _, o := range []map[string]string{{"device": "a b"}, {"device": "../x"}, {"prefix": "observium"}, {"prefix": "/a/../b"}, {"prefix": "/a b"}} {
		d.Options = o
		if _, err := Open(d, Credential{Token: "APITOKEN"}); err == nil {
			t.Errorf("options %v were accepted", o)
		}
	}
	d.Options = map[string]string{"device": "12", "prefix": "/observium"}
	if drv, err := Open(d, Credential{Token: "APITOKEN"}); err != nil {
		t.Errorf("good options: %v", err)
	} else {
		drv.Close(context.Background())
	}
	if err := Validate([]Device{{Name: "obs", Platform: "Observium", Address: "obs.example.com", Credential: "c"}}, []Credential{{Name: "c", Token: "t"}}); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestObsRows(t *testing.T) {
	cases := map[string]struct {
		in   string
		name string
		want int
	}{
		"keyed by id":            {`{"status":"ok","count":2,"ports":{"2":{"a":1},"10":{"a":2}}}`, "ports", 2},
		"list":                   {`{"status":"ok","count":1,"neighbours":[{"a":1}]}`, "neighbours", 1},
		"other wrapper":          {`{"status":"ok","count":1,"entries":[{"a":1},{"a":2}]}`, "alert_log", 2},
		"one row":                {`{"status":"ok","device":{"device_id":"1","hostname":"x"}}`, "devices", 1},
		"empty":                  {`{"status":"ok","count":0,"ports":{}}`, "ports", 0},
		"bare list":              {`[{"a":1},{"a":2},{"a":3}]`, "x", 3},
		"nothing":                {`{"status":"ok"}`, "ports", 0},
		"scalars only":           {`{"status":"ok","count":1}`, "ports", 0},
		"name beats meta":        {`{"status":"ok","pagesize":50,"ports":[{"a":1}]}`, "ports", 1},
		"status is the envelope": {`{"status":"ok","count":1,"statuses":[{"a":1}]}`, "status", 1},
	}
	for n, c := range cases {
		var v any
		if err := json.Unmarshal([]byte(c.in), &v); err != nil {
			t.Fatal(err)
		}
		if got := obsRows(v, c.name); len(got) != c.want {
			t.Errorf("%s: %d rows, want %d: %v", n, len(got), c.want, got)
		}
	}
	var v any
	_ = json.Unmarshal([]byte(`{"ports":{"10":{"i":10},"2":{"i":2},"1":{"i":1}}}`), &v)
	if r := obsRows(v, "ports"); len(r) != 3 || r[0]["i"] != float64(1) || r[1]["i"] != float64(2) || r[2]["i"] != float64(10) {
		t.Errorf("rows by ID are in numeric order: %v", r)
	}
}

func TestObsPick(t *testing.T) {
	all := []map[string]any{
		{"device_id": "1", "hostname": "ipam2.example.com", "sysName": "ipam2"},
		{"device_id": "2", "hostname": "ipam20.example.com", "sysName": "ipam20"},
		{"device_id": "3", "hostname": "core.example.com", "sysName": "core"},
		{"device_id": "4", "hostname": "core.lab.example.com", "sysName": "core-lab"},
	}
	for ref, want := range map[string]string{"ipam2": "1", "IPAM2": "1", "ipam20": "2", "3": "3", "core": "3", "core-lab": "4", "lab": "4", "ipam2.example.com": "1"} {
		if id, err := obsPick(ref, all); err != nil || id != want {
			t.Errorf("%q: %q %v, want %q", ref, id, err, want)
		}
	}
	for _, ref := range []string{"ipam", "example", "nothing"} {
		if id, err := obsPick(ref, all); err == nil {
			t.Errorf("%q picked %q", ref, id)
		}
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
