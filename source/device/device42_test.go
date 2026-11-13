package device

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type d42State struct {
	mu    sync.Mutex
	calls []string
}

func d42Stub(t *testing.T, st *d42State, noAll bool) Device {
	return tlsDevice(t, "d42", "device42", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.calls = append(st.calls, r.Method+" "+r.URL.RequestURI())
		st.mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "ro" || p != "pw-d42" {
			jout(w, 401, map[string]any{"msg": "no"})
			return
		}
		dev := func(id int, name, os, mfr, hw string, ips ...string) map[string]any {
			var l []any
			for _, ip := range ips {
				l = append(l, map[string]any{"ip": ip, "label": ""})
			}
			return map[string]any{"device_id": id, "name": name, "os": os, "manufacturer": mfr, "hardware": hw, "type": "physical", "building": "PHX1", "in_service": true, "ip_addresses": l}
		}
		switch r.URL.Path {
		case "/api/1.0/devices/all/":
			if noAll {
				jout(w, 404, map[string]any{"msg": "nope"})
				return
			}
			fallthrough
		case "/api/1.0/devices/":
			jout(w, 200, map[string]any{"total_count": 3, "limit": 100, "offset": 0, "Devices": []any{
				dev(1, "core1", "IOS XE", "Cisco", "C9300", "10.0.0.5"),
				dev(2, "fw 1", "FortiOS", "Fortinet", "FG200E", "10.0.0.6"),
				dev(3, "mystery", "", "Acme", "X1")}})
		case "/api/1.0/devices/name/core1/":
			jout(w, 200, map[string]any{"device_id": 1, "name": "core1", "snmp_community": "secretcomm", "serial_no": "S1"})
		case "/api/1.0/ips/", "/api/1.0/macs/", "/api/1.0/switchports/":
			jout(w, 200, map[string]any{"ips": []any{map[string]any{"ip": "10.0.0.5", "device": "core1"}}, "total_count": 1})
		case "/api/1.0/subnets/":
			jout(w, 200, map[string]any{"subnets": []any{map[string]any{"network": "10.0.0.0", "mask_bits": 24}}})
		case "/api/1.0/passwords/":
			jout(w, 200, map[string]any{"passwords": []any{map[string]any{"password": "x"}}})
		default:
			jout(w, 404, map[string]any{"msg": "not found"})
		}
	}))
}

func d42Open(t *testing.T, noAll bool) (Driver, *d42State) {
	st := &d42State{}
	d := d42Stub(t, st, noAll)
	drv, err := Open(d, Credential{Username: "ro", Password: "pw-d42"})
	if err != nil {
		t.Fatal(err)
	}
	return drv, st
}

func TestDevice42FactsAndInterfaces(t *testing.T) {
	drv, _ := d42Open(t, false)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Device42" || !strings.Contains(f.Model, "3 devices") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 3 || ifs[0].Name != "core1" || len(ifs[0].Addresses) != 1 || ifs[0].Addresses[0] != "10.0.0.5" {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
}

func TestDevice42FallsBackWhenNoDevicesAll(t *testing.T) {
	drv, st := d42Open(t, true)
	ifs, err := drv.Interfaces(context.Background())
	if err != nil || len(ifs) != 3 {
		t.Fatalf("%v %v", ifs, err)
	}
	if !strings.Contains(strings.Join(st.calls, "\n"), "GET /api/1.0/devices/?") {
		t.Fatalf("no fallback: %v", st.calls)
	}
}

func TestDevice42ShowAndRedaction(t *testing.T) {
	drv, _ := d42Open(t, false)
	ctx := context.Background()
	out, err := drv.Show(ctx, "show device core1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "secretcomm") || !strings.Contains(out, "S1") || !strings.Contains(out, "10.0.0.5") {
		t.Fatalf("show device: %s", out)
	}
	out, err = drv.Show(ctx, "show devices search=fortinet")
	if err != nil || !strings.Contains(out, `"matching": 1`) || !strings.Contains(out, "fw 1") {
		t.Fatalf("show devices: %s %v", out, err)
	}
	if out, err = drv.Show(ctx, "show subnets"); err != nil || !strings.Contains(out, "10.0.0.0") {
		t.Fatalf("show subnets: %s %v", out, err)
	}
	for _, bad := range []string{"show", "show nothing", "show devices limit=0", "show devices x=y", "show device a;b"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestDevice42APIGetRules(t *testing.T) {
	drv, st := d42Open(t, false)
	g := drv.(APIer)
	ctx := context.Background()
	if v, _, err := g.APIGet(ctx, "/api/1.0/subnets/"); err != nil || v == nil {
		t.Fatalf("%v %v", v, err)
	}
	if _, _, err := g.APIGet(ctx, "subnets/"); err != nil {
		t.Fatalf("version left out: %v", err)
	}
	for _, bad := range []string{"/api/1.0/passwords/", "/api/1.0/users/", "/api/3.0/devices/", "/other/x", "/api/1.0/../x", "/api/1.0/devices/?password=1", "/api/1.0/devices/?x=a%0Ab"} {
		if _, _, err := g.APIGet(ctx, bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
	for _, c := range st.calls {
		if strings.Contains(c, "passwords") || !strings.HasPrefix(c, "GET ") {
			t.Fatalf("a call that must not be sent: %s", c)
		}
	}
}

func TestDevice42Writes(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	d := tlsDevice(t, "d42", "device42", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "rw" || p != "pw" {
			jout(w, 401, nil)
			return
		}
		if r.Method != http.MethodGet {
			b, _ := io.ReadAll(r.Body)
			sent = append(sent, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type")+" "+string(b))
			jout(w, 200, map[string]any{"msg": []any{"device added", 7}, "code": 0})
			return
		}
		jout(w, 200, map[string]any{"total_count": 0, "Devices": []any{}})
	}))
	drv, err := Open(d, Credential{Username: "rw", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	rc := drv.(RawChanger)
	ctx := context.Background()
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/api/1.0/device/", Body: "name=core1&serial_no=S1"}, false)
	if err != nil || !res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "post", Path: "ips/", Body: `{"ipaddress":"10.0.0.9"}`}, false); err != nil {
		t.Fatal(err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/api/1.0/device/", Body: "name=x"}, true); err != nil || res.Applied || !res.DryRun {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	for _, bad := range []Raw{{Method: "POST", Path: "/api/1.0/passwords/", Body: "a=b"}, {Method: "POST", Path: "/api/1.0/users/", Body: "a=b"},
		{Method: "POST", Path: "/api/3.0/x/", Body: "a=b"}, {Method: "POST", Path: "/api/1.0/device/", Body: "{bad"}, {Method: "GET", Path: "/api/1.0/device/"},
		{Method: "POST", Path: "/api/1.0/../x/", Body: "a=b"}} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v was sent", bad)
		}
	}
	if len(sent) != 2 || !strings.Contains(sent[0], "application/x-www-form-urlencoded name=core1&serial_no=S1") || !strings.Contains(sent[1], "application/json") {
		t.Fatalf("sent %v", sent)
	}
}

func TestDevice42BadLogin(t *testing.T) {
	st := &d42State{}
	d := d42Stub(t, st, false)
	drv, err := Open(d, Credential{Username: "ro", Password: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drv.Facts(context.Background()); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("expected an error without the password: %v", err)
	}
	if _, err := Open(Device{Name: "x", Platform: "device42", Address: "h"}, Credential{}); err == nil {
		t.Fatal("no credential accepted")
	}
}

func TestDevice42Import(t *testing.T) {
	st := &d42State{}
	d := d42Stub(t, st, false)
	got, skipped, err := ImportDevices(context.Background(), d, Credential{Username: "ro", Password: "pw-d42"}, []Device{{Name: "other", Address: "10.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "core1" || got[0].Platform != "iosxe" || got[0].Address != "10.0.0.5" || !got[0].Disabled || !hasTag(got[0], "source=device42") || !hasTag(got[0], "site=PHX1") {
		t.Fatalf("got %+v", got)
	}
	if got[1].Platform != "fortios" || got[1].Name != "fw-1" {
		t.Fatalf("second %+v", got[1])
	}
	if len(skipped) != 1 || skipped[0].Name != "mystery" {
		t.Fatalf("skipped %+v", skipped)
	}
}

func TestD42Platform(t *testing.T) {
	for in, want := range map[string]string{"Cisco NX-OS": "nxos", "Cisco IOS XE": "iosxe", "Cisco IOS": "ios", "Arista EOS": "eos", "Juniper": "junos", "Windows Server": ""} {
		if got := d42Platform(in, "", ""); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
