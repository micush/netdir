package device

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestRebootPredicates(t *testing.T) {
	post := func(path, body string) Raw { return Raw{Method: "post", Path: path, Body: body} }
	yes := []bool{
		iosxeReboot(post("/restconf/operations/Cisco-IOS-XE-rpc:reload", "")),
		aoscxReboot("/rest/v10.09/")(post("/rest/v10.09/boot?image=primary", "")),
		aoscxReboot("/rest/v10.09/")(post("/rest/v10.09/boot", "")),
		fortiosReboot(post("/api/v2/monitor/system/os/reboot", "")),
		bigipReboot(post("/mgmt/tm/sys", `{"command":"reboot"}`)),
		merakiReboot(post("/devices/Q2XX-AAAA-BBBB/reboot", "")),
		pveReboot(post("/nodes/pve1/status", `{"command":"reboot"}`)),
	}
	for i, ok := range yes {
		if !ok {
			t.Errorf("reboot %d was not recognised", i)
		}
	}
	no := []bool{
		iosxeReboot(Raw{Method: "GET", Path: "/restconf/operations/Cisco-IOS-XE-rpc:reload"}),
		iosxeReboot(post("/restconf/operations/Cisco-IOS-XE-rpc:reload/x", "")),
		aoscxReboot("/rest/v10.09/")(post("/rest/v10.09/boot?image=x", "")),
		aoscxReboot("/rest/v10.09/")(post("/rest/v10.09/boot?image=primary&a=b", "")),
		fortiosReboot(post("/api/v2/monitor/system/os/shutdown", "")),
		bigipReboot(post("/mgmt/tm/sys", `{"command":"halt"}`)),
		bigipReboot(post("/mgmt/tm/sys/config", `{"command":"reboot"}`)),
		merakiReboot(post("/devices/Q2/reboot/x", "")),
		merakiReboot(post("/organizations/1/reboot", "")),
		pveReboot(post("/nodes/pve1/status", `{"command":"shutdown"}`)),
		pveReboot(post("/nodes/pve1/qemu/100/status", `{"command":"reboot"}`)),
	}
	for i, ok := range no {
		if ok {
			t.Errorf("non-reboot %d was accepted", i)
		}
	}
	if c, ok := rebootLine([]string{" reload  now "}); !ok || c != "reload now" {
		t.Errorf("reload line %q %v", c, ok)
	}
	for _, l := range [][]string{{"reload in 5"}, {"reload", "vlan 10"}, {"reloadx"}, nil} {
		if _, ok := rebootLine(l); ok {
			t.Errorf("%q taken for a reload", l)
		}
	}
	if !connEnded(errors.New("Post x: EOF")) || connEnded(&statusError{Code: 500}) || connEnded(errors.New("connection refused")) {
		t.Error("connEnded")
	}
}

// A reboot goes out without the guard, the check afterwards and the put-back, and a connection that ends counts as a restart.
func TestRestRawReboot(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	drop := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if drop {
			c, _, _ := w.(http.Hijacker).Hijack()
			_ = c.Close()
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var pn int
	for _, c := range port {
		pn = pn*10 + int(c-'0')
	}
	api, err := newAPIClient(Device{Address: h, Port: pn, Insecure: true}, 443)
	if err != nil {
		t.Fatal(err)
	}
	alive := 0
	spec := restSpec{api: api, hdr: jsonHdr(), json: true,
		guard:  func(_, _ string) error { return errors.New("guard") },
		alive:  func(context.Context) error { alive++; return errors.New("down") },
		reboot: func(r Raw) bool { return r.Path == "/reboot" }}
	ctx := context.Background()
	for _, dropIt := range []bool{false, true} {
		drop = dropIt
		r, err := restRaw(ctx, spec, Raw{Method: "POST", Path: "/reboot"}, false)
		if err != nil || !r.Applied || r.RolledBack || !strings.Contains(r.Note, "restart") || alive != 0 {
			t.Fatalf("drop %v: %+v %v alive %d", dropIt, r, err, alive)
		}
	}
	if _, err := restRaw(ctx, spec, Raw{Method: "POST", Path: "/other"}, false); err == nil {
		t.Error("the guard did not apply to a request that is not a reboot")
	}
	if r, err := restRaw(ctx, spec, Raw{Method: "POST", Path: "/reboot"}, true); err != nil || r.Applied {
		t.Errorf("dry run %+v %v", r, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Errorf("requests: %v", seen)
	}
}

func TestRawEOSReload(t *testing.T) {
	d, reqs := eosRawStub(t, "")
	drv := open(t, d, rawAny).(RawChanger)
	ctx := context.Background()
	r, err := drv.RawChange(ctx, Raw{Lines: []string{"reload"}}, true)
	if err != nil || r.Applied || len(*reqs) != 0 {
		t.Fatalf("dry: %+v %v %v", r, err, *reqs)
	}
	r, err = drv.RawChange(ctx, Raw{Lines: []string{"reload"}, Save: true}, false)
	if err != nil || !r.Applied || !r.Saved {
		t.Fatalf("reload: %+v %v", r, err)
	}
	var flat []string
	for _, q := range *reqs {
		flat = append(flat, strings.Join(q, "|"))
	}
	if j := strings.Join(flat, "\n"); j != "write memory\nreload now" {
		t.Errorf("sent:\n%s", j)
	}
	if _, err := drv.RawChange(ctx, Raw{Lines: []string{"vlan 10", "reload"}}, false); err == nil {
		t.Error("a reload among other lines was accepted")
	}
}

func TestRawPANOSReboot(t *testing.T) {
	var seen []string
	d, _ := rawStub(t, "panos", func(w http.ResponseWriter, r *http.Request, body string) {
		seen = append(seen, r.URL.Query().Get("type")+" "+r.URL.Query().Get("cmd"))
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<response status="success" code="20"><msg>command succeeded</msg></response>`))
	})
	drv := open(t, d, Credential{Token: "KEYKEYKEY"}).(RawChanger)
	ctx := context.Background()
	if r, err := drv.RawChange(ctx, Raw{Method: "reboot"}, true); err != nil || r.Applied || len(seen) != 0 {
		t.Fatalf("dry: %+v %v %v", r, err, seen)
	}
	r, err := drv.RawChange(ctx, Raw{Method: "reboot", Save: true}, false)
	if err != nil || !r.Applied || !r.Saved || len(seen) != 2 || !strings.HasPrefix(seen[0], "commit") || !strings.Contains(seen[1], "<restart><system>") {
		t.Fatalf("reboot: %+v %v %v", r, err, seen)
	}
	if _, err := drv.RawChange(ctx, Raw{Method: "reboot", Path: "/config/x"}, false); err == nil {
		t.Error("a reboot with a path was accepted")
	}
}
