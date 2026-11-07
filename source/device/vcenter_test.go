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
	"sync/atomic"
	"testing"
)

type vcState struct {
	mu      sync.Mutex
	calls   []string
	bodies  map[string]string
	logins  atomic.Int32
	logouts atomic.Int32
	expire  atomic.Int32
	legacy  bool // an old vCenter: /rest and {"value": ...}
}

func (s *vcState) seen(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == call {
			return true
		}
	}
	return false
}

// vcStub is a vCenter: POST /api/session (or /rest/com/vmware/cis/session) with Basic admin@vsphere.local:pw gives the session S<n>.
func vcStub(t *testing.T, st *vcState) Device {
	t.Helper()
	st.bodies = map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		root := "/api"
		if st.legacy {
			root = "/rest"
		}
		sessPath := root + "/session"
		if st.legacy {
			sessPath = "/rest/com/vmware/cis/session"
		}
		call := r.Method + " " + r.URL.Path
		st.mu.Lock()
		st.calls = append(st.calls, call)
		st.bodies[call] = string(b)
		st.mu.Unlock()
		send := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if v != nil {
				_ = json.NewEncoder(w).Encode(v)
			}
		}
		wrap := func(v any) any {
			if st.legacy {
				return J{"value": v}
			}
			return v
		}
		if r.URL.Path == sessPath && r.Method == "POST" {
			u, p, ok := r.BasicAuth()
			if !ok || u != "admin@vsphere.local" || p != "pw" {
				send(401, J{"error_type": "UNAUTHENTICATED"})
				return
			}
			n := st.logins.Add(1)
			send(201, wrap("S"+strconv.Itoa(int(n))))
			return
		}
		if r.URL.Path == "/api/session" && st.legacy {
			send(404, J{"error_type": "NOT_FOUND"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, root+"/") {
			send(404, J{"error_type": "NOT_FOUND"})
			return
		}
		sid := r.Header.Get("vmware-api-session-id")
		if r.URL.Path == sessPath && r.Method == "DELETE" {
			if sid == "S"+strconv.Itoa(int(st.logins.Load())) {
				st.logouts.Add(1)
			}
			send(204, nil)
			return
		}
		if sid != "S"+strconv.Itoa(int(st.logins.Load())) || st.expire.Add(-1) >= 0 {
			send(401, J{"error_type": "UNAUTHENTICATED"})
			return
		}
		p := strings.TrimPrefix(r.URL.Path, root)
		vms := []J{{"vm": "vm-10", "name": "web01", "power_state": "POWERED_ON", "cpu_count": 2, "memory_size_MiB": 4096},
			{"vm": "vm-11", "name": "db01", "power_state": "POWERED_OFF", "cpu_count": 4, "memory_size_MiB": 8192},
			{"vm": "vm-12", "name": "dup", "power_state": "POWERED_ON"}, {"vm": "vm-13", "name": "dup", "power_state": "POWERED_ON"}}
		switch {
		case r.Method == "GET" && p == "/appliance/system/version":
			send(200, wrap(J{"version": "8.0.3.00400", "build": "24322831", "product": "VMware vCenter Server", "install_time": "2026-01-01"}))
		case r.Method == "GET" && p == "/vcenter/datacenter":
			send(200, wrap([]J{{"datacenter": "datacenter-2", "name": "DC1"}}))
		case r.Method == "GET" && p == "/vcenter/host":
			send(200, wrap([]J{{"host": "host-20", "name": "esx1.example.com", "connection_state": "CONNECTED", "power_state": "POWERED_ON"},
				{"host": "host-21", "name": "esx2.example.com", "connection_state": "DISCONNECTED", "power_state": "POWERED_OFF"}}))
		case r.Method == "GET" && p == "/vcenter/vm":
			q := r.URL.Query()
			var out []J
			for _, v := range vms {
				if n := q.Get("names"); n != "" && v["name"] != n {
					continue
				}
				if ps := q.Get("power_states"); ps != "" && v["power_state"] != ps {
					continue
				}
				out = append(out, v)
			}
			send(200, wrap(out))
		case r.Method == "GET" && p == "/vcenter/vm/vm-10":
			send(200, wrap(J{"name": "web01", "power_state": "POWERED_ON", "cpu": J{"count": 2}, "memory": J{"size_MiB": 4096}, "nics": J{"4000": J{"mac_address": "00:50:56:aa:bb:cc"}}, "guest_OS": "UBUNTU_64"}))
		case r.Method == "GET" && p == "/vcenter/vm/vm-10/power":
			send(200, wrap(J{"state": "POWERED_ON"}))
		case r.Method == "GET" && p == "/vcenter/vm/vm-10/guest/identity":
			send(200, wrap(J{"host_name": "web01.example.com", "ip_address": "10.1.1.10", "full_name": J{"default_message": "Ubuntu Linux (64-bit)"}}))
		case r.Method == "GET" && p == "/vcenter/vm/vm-10/guest/networking/interfaces":
			send(200, wrap([]J{{"mac_address": "00:50:56:aa:bb:cc", "ip": J{"ip_addresses": []J{{"ip_address": "10.1.1.10"}}}}}))
		case r.Method == "GET" && p == "/vcenter/vm/vm-10/tools":
			send(404, J{"error_type": "NOT_FOUND"})
		case r.Method == "GET" && (p == "/vcenter/vm/vm-11" || p == "/vcenter/vm/vm-11/power"):
			send(200, wrap(J{"name": "db01", "state": "POWERED_OFF", "vnc_password": "VNCSECRET"}))
		case r.Method == "GET" && (p == "/vcenter/cluster" || p == "/vcenter/datastore" || p == "/vcenter/network" || p == "/vcenter/folder" || p == "/vcenter/resource-pool"):
			send(200, wrap([]J{{"name": "x"}}))
		case r.Method == "GET" && strings.HasPrefix(p, "/appliance/health/"):
			if p == "/appliance/health/system" {
				send(200, wrap("green"))
			} else if p == "/appliance/health/load" {
				send(200, wrap("orange"))
			} else {
				send(403, J{"error_type": "UNAUTHORIZED"})
			}
		case r.Method == "POST" && p == "/vcenter/vm/vm-10/power", r.Method == "PATCH" && p == "/vcenter/vm/vm-10/hardware/cpu",
			r.Method == "GET" && p == "/vcenter/vm/vm-10/hardware/cpu", r.Method == "PUT" && p == "/cis/tagging/tag/t1":
			send(200, wrap(J{"count": 2}))
		case strings.Contains(p, "session") || strings.Contains(p, "users") || strings.Contains(p, "tickets") || strings.Contains(p, "processes") || strings.Contains(p, "certificate") ||
			r.Method == "DELETE":
			t.Errorf("a denied request reached vCenter: %s %s", r.Method, r.URL)
			send(200, J{})
		default:
			send(404, J{"error_type": "NOT_FOUND"})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "vc", Platform: "vcenter", Address: h, Port: pn, Insecure: true}
}

var vcCred = Credential{Username: "admin@vsphere.local", Password: "pw"}

func TestVCenter(t *testing.T) {
	st := &vcState{}
	d := vcStub(t, st)
	ctx := context.Background()
	drv := Driver(nil)
	{
		var err error
		drv, err = Open(d, vcCred)
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "VMware" || f.OSVersion != "8.0.3.00400 build 24322831" || f.Model != "VMware vCenter Server" {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "esx1.example.com" || ifs[0].OperUp == nil || !*ifs[0].OperUp || *ifs[1].OperUp || *ifs[1].AdminUp {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	// the session expires once: the driver signs in again and the call goes through
	st.expire.Store(1)
	out, err := drv.Show(ctx, "show vms state=powered_off")
	if err != nil || !strings.Contains(out, "db01") || strings.Contains(out, "web01") || st.logins.Load() != 2 || !json.Valid([]byte(out)) {
		t.Fatalf("expired session: %v logins %d\n%s", err, st.logins.Load(), out)
	}
	if out, err = drv.Show(ctx, "show vms search=WEB"); err != nil || !strings.Contains(out, "web01") || strings.Contains(out, "db01") {
		t.Errorf("vms search: %v\n%s", err, out)
	}
	for _, ref := range []string{"web01", "vm-10"} {
		out, err = drv.Show(ctx, "show vm "+ref)
		if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "UBUNTU_64") || !strings.Contains(out, "10.1.1.10") || !strings.Contains(out, `"state": "POWERED_ON"`) ||
			!strings.Contains(out, `"errors"`) || !strings.Contains(out, "tools") {
			t.Fatalf("show vm %s: %v\n%s", ref, err, out)
		}
	}
	if out, err = drv.Show(ctx, "show vm db01"); err != nil || strings.Contains(out, "VNCSECRET") {
		t.Errorf("a secret in a VM record: %v\n%s", err, out)
	}
	if _, err := drv.Show(ctx, "show vm nope"); err == nil || !strings.Contains(err.Error(), "no virtual machine") {
		t.Errorf("unknown VM: %v", err)
	}
	if _, err := drv.Show(ctx, "show vm dup"); err == nil || !strings.Contains(err.Error(), "vm-12, vm-13") {
		t.Errorf("two VMs of one name: %v", err)
	}
	for _, c := range []string{"hosts", "clusters", "datacenters", "datastores", "networks", "folders", "resourcepools", "version"} {
		if out, err := drv.Show(ctx, "show "+c); err != nil || !json.Valid([]byte(out)) {
			t.Errorf("show %s: %v %s", c, err, out)
		}
	}
	if out, err = drv.Show(ctx, "show health"); err != nil || !strings.Contains(out, "green") || !strings.Contains(out, "orange") || !strings.Contains(out, `"errors"`) {
		t.Errorf("health: %v\n%s", err, out)
	}
	for _, bad := range []string{"show", "show users", "show sessions", "show vm", "show vm a;b", "show vm a/b", "show vms state=sideways", "show vms limit=0", "show vms foo=1",
		"show vms | x", "show hosts extra", "show version extra", "show health extra"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	api := drv.(APIer)
	v, text, err := api.APIGet(ctx, "/vcenter/vm/vm-11")
	if err != nil || text || strings.Contains(toJSON(v), "VNCSECRET") || !strings.Contains(toJSON(v), "db01") {
		t.Fatalf("apiget %v %v", err, v)
	}
	if _, _, err := api.APIGet(ctx, "/api/vcenter/vm?names=web01&power_states=POWERED_ON"); err != nil {
		t.Errorf("full path: %v", err)
	}
	for _, bad := range []string{"/session", "/vcenter/session", "/vcenter/vm/vm-10/console/tickets", "/vcenter/vm/vm-10/guest/processes", "/vcenter/vm/vm-10/guest/filesystem",
		"/appliance/local-accounts", "/appliance/access/ssh/../users", "/vcenter/certificate-management/vcenter/tls", "/vcenter/vm/../session", "/", "/other", "/vcenter?bad key=1",
		"https://x/vcenter/vm", "vcenter/vm", "/vcenter/vm/users"} {
		if _, _, err := api.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if c, err := api.APICatalog(ctx); err != nil || !strings.Contains(toJSON(c), "/vcenter/vm") {
		t.Errorf("catalog %v %v", c, err)
	}
	// closing deletes the session
	drv.Close(ctx)
	if st.logouts.Load() != 1 {
		t.Errorf("the session was not deleted: %d", st.logouts.Load())
	}
}

func TestVCenterLogin(t *testing.T) {
	st := &vcState{}
	d := vcStub(t, st)
	ctx := context.Background()
	if _, err := Open(d, Credential{Token: "x"}); err == nil {
		t.Error("no user and password accepted")
	}
	bad := open(t, d, Credential{Username: "admin@vsphere.local", Password: "no"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "sign-in refused") || strings.Contains(err.Error(), "no\"") {
		t.Errorf("wrong password: %v", err)
	}
	for _, o := range []map[string]string{{"api_style": "v2"}, {"api_style": "../x"}} {
		dd := d
		dd.Options = o
		if _, err := Open(dd, vcCred); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
}

// an old vCenter answers /rest with {"value": ...}: found by the sign-in, or forced
func TestVCenterLegacy(t *testing.T) {
	ctx := context.Background()
	for _, style := range []string{"", "rest"} {
		st := &vcState{legacy: true}
		d := vcStub(t, st)
		if style != "" {
			d.Options = map[string]string{"api_style": style}
		}
		drv := open(t, d, vcCred)
		f, err := drv.Facts(ctx)
		if err != nil || f.OSVersion != "8.0.3.00400 build 24322831" {
			t.Fatalf("style %q facts %+v %v", style, f, err)
		}
		out, err := drv.Show(ctx, "show vm web01")
		if err != nil || !strings.Contains(out, "UBUNTU_64") || strings.Contains(out, `"value"`) {
			t.Errorf("style %q show vm: %v\n%s", style, err, out)
		}
		if style == "" && !st.seen("POST /api/session") {
			t.Error("the new endpoint was not tried first")
		}
		if !st.seen("POST /rest/com/vmware/cis/session") {
			t.Error("the old endpoint was not used")
		}
	}
}

func TestVCenterChange(t *testing.T) {
	st := &vcState{}
	d := vcStub(t, st)
	ctx := context.Background()
	drv := open(t, d, vcCred)
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("not a RawChanger")
	}
	res, err := rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/vcenter/vm/vm-10/hardware/cpu", Body: `{"count":4}`}, true)
	if err != nil || !res.DryRun || res.Applied || !strings.Contains(res.Before, `"count":2`) {
		t.Fatalf("dry run %+v %v", res, err)
	}
	if st.seen("PATCH /api/vcenter/vm/vm-10/hardware/cpu") {
		t.Error("a dry run changed vCenter")
	}
	res, err = rc.RawChange(ctx, Raw{Method: "patch", Path: "/api/vcenter/vm/vm-10/hardware/cpu", Body: `{"count":4}`}, false)
	if err != nil || !res.Applied || st.bodies["PATCH /api/vcenter/vm/vm-10/hardware/cpu"] != `{"count":4}` {
		t.Fatalf("patch %+v %v", res, err)
	}
	// a power action is a query on a POST
	res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/vcenter/vm/vm-10/power?action=reset"}, false)
	if err != nil || !res.Applied || !st.seen("POST /api/vcenter/vm/vm-10/power") {
		t.Fatalf("power %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/cis/tagging/tag/t1", Body: `{"update_spec":{"name":"x"}}`}, false); err != nil || !res.Applied {
		t.Fatalf("tag %+v %v", res, err)
	}
	for _, bad := range []Raw{
		{Method: "DELETE", Path: "/vcenter/vm/vm-10"},
		{Method: "DELETE", Path: "/vcenter/host/host-20"},
		{Method: "DELETE", Path: "/vcenter/datastore/ds-1"},
		{Method: "DELETE", Path: "/vcenter/vm/vm-10/hardware/disk/2000"},
		{Method: "POST", Path: "/vcenter/vm/vm-10/console/tickets", Body: `{}`},
		{Method: "POST", Path: "/vcenter/vm/vm-10/guest/processes?action=create", Body: `{}`},
		{Method: "POST", Path: "/vcenter/deployment/install", Body: `{}`},
		{Method: "POST", Path: "/vcenter/certificate-management/vcenter/tls", Body: `{}`},
		{Method: "POST", Path: "/appliance/shutdown?action=reboot", Body: `{}`},
		{Method: "PUT", Path: "/appliance/networking/dns/servers", Body: `{}`},
		{Method: "POST", Path: "/session", Body: `{}`},
		{Method: "POST", Path: "/vcenter/users", Body: `{}`},
		{Method: "GET", Path: "/vcenter/vm"},
		{Method: "PATCH", Path: "/vcenter/vm/vm-10/hardware/cpu", Body: `{not json`},
		{Method: "PATCH", Path: "/vcenter/vm/vm-10/hardware/cpu"},
		{Method: "POST", Path: "/vcenter/vm/../session", Body: `{}`},
		{Method: "POST", Lines: []string{"x"}},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
