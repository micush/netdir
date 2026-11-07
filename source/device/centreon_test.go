package device

import (
	"context"
	"encoding/json"
	"fmt"
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

type centState struct {
	mu     sync.Mutex
	calls  []string
	bodies map[string]string
	logins atomic.Int32
	expire atomic.Int32
	many   int // when > 0 the server holds that many hosts, all up
}

func (s *centState) seen(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == call {
			return true
		}
	}
	return false
}

// centStub is a Centreon: POST <prefix>/api/<ver>/login gives the session token T<n>, every other call needs it (or the API token
// APITOKEN) in X-AUTH-TOKEN.
func centStub(t *testing.T, st *centState, prefix, ver string) Device {
	t.Helper()
	st.bodies = map[string]string{}
	hosts := []J{
		{"id": 1, "name": "web1", "alias": "web1-alias", "address_ip": "10.0.0.11", "status": J{"code": 0, "name": "UP"}, "output": "PING OK", "monitoring_server_name": "Central", "active_checks": true, "passive_checks": false},
		{"id": 2, "name": "db1", "alias": "db1", "address_ip": "10.0.0.12", "status": J{"code": 1, "name": "DOWN"}, "output": "CRITICAL - host down", "monitoring_server_name": "Central", "active_checks": true},
		{"id": 3, "name": "sw1", "alias": "sw1", "address_ip": "10.0.0.13", "status": J{"code": 2, "name": "UNREACHABLE"}, "monitoring_server_name": "Poller2"},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p := strings.TrimPrefix(r.URL.Path, prefix+"/api/"+ver)
		if !strings.HasPrefix(r.URL.Path, prefix+"/api/"+ver+"/") {
			t.Errorf("request outside the API: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		call := r.Method + " " + p
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
		list := func(rs []J, total int) {
			q := r.URL.Query()
			lim, _ := strconv.Atoi(q.Get("limit"))
			pg, _ := strconv.Atoi(q.Get("page"))
			if lim <= 0 {
				lim = 10
			}
			if pg <= 0 {
				pg = 1
			}
			from, to := (pg-1)*lim, pg*lim
			if from > len(rs) {
				from = len(rs)
			}
			if to > len(rs) {
				to = len(rs)
			}
			send(200, J{"result": rs[from:to], "meta": J{"page": pg, "limit": lim, "total": total}})
		}
		if r.Method == "POST" && p == "/login" {
			var in struct {
				Security struct {
					Credentials struct{ Login, Password string }
				}
			}
			_ = json.Unmarshal(b, &in)
			if in.Security.Credentials.Login != "admin" || in.Security.Credentials.Password != "pw" {
				send(401, J{"code": 401, "message": "Invalid credentials"})
				return
			}
			n := st.logins.Add(1)
			send(200, J{"contact": J{"id": 1, "name": "admin"}, "security": J{"token": "T" + strconv.Itoa(int(n))}})
			return
		}
		tok := r.Header.Get("X-Auth-Token")
		if tok != "APITOKEN" && tok != "T"+strconv.Itoa(int(st.logins.Load())) || st.expire.Add(-1) >= 0 {
			send(401, J{"code": 401, "message": "Invalid token"})
			return
		}
		switch {
		case r.Method == "GET" && p == "/platform/versions":
			send(200, J{"web": J{"major": "24", "minor": "04", "fix": "1", "version": "24.04.1"}, "modules": J{}})
		case r.Method == "GET" && p == "/monitoring/hosts":
			if st.many > 0 {
				var rs []J
				for i := 1; i <= st.many; i++ {
					rs = append(rs, J{"id": i, "name": fmt.Sprintf("h%03d", i), "status": J{"code": 0}})
				}
				list(rs, st.many)
				return
			}
			if s := r.URL.Query().Get("search"); s != "" {
				var m map[string]any
				_ = json.Unmarshal([]byte(s), &m)
				var rs []J
				for _, h := range hosts {
					if h["name"] == m["name"] {
						rs = append(rs, h)
					}
				}
				list(rs, len(rs))
				return
			}
			list(hosts, len(hosts))
		case r.Method == "GET" && p == "/monitoring/hosts/1":
			send(200, J{"id": 1, "name": "web1", "address_ip": "10.0.0.11", "status": J{"code": 0, "name": "UP"}, "acknowledged": false, "in_downtime": false, "downtimes": []J{}})
		case r.Method == "GET" && p == "/configuration/hosts/1":
			send(200, J{"id": 1, "name": "web1", "snmp_community": "SECRETCOMM", "snmp_version": "2c", "templates": []J{{"id": 4, "name": "OS-Linux-SNMP"}}})
		case r.Method == "GET" && p == "/monitoring/hosts/2":
			send(200, hosts[1])
		case r.Method == "GET" && p == "/configuration/hosts/2":
			send(403, J{"code": 403, "message": "You are not allowed to see this configuration"})
		case r.Method == "GET" && (p == "/monitoring/hosts/1/services" || p == "/monitoring/hosts/2/services"):
			list([]J{{"id": 10, "description": "Ping", "status": J{"code": 0, "name": "OK"}, "output": "OK - 0.4ms"},
				{"id": 11, "description": "Disk-/var", "status": J{"code": 2, "name": "CRITICAL"}, "output": "CRITICAL - 96% used"}}, 2)
		case r.Method == "GET" && p == "/monitoring/hosts/1/timeline":
			send(200, J{"result": []J{{"id": 1, "type": "event", "content": "web1 went UP"}}, "meta": J{"total": 1}})
		case r.Method == "GET" && p == "/monitoring/services":
			list([]J{{"id": 10, "description": "Ping", "host": J{"id": 1, "name": "web1"}, "status": J{"code": 0, "name": "OK"}},
				{"id": 11, "description": "Disk-/var", "host": J{"id": 1, "name": "web1"}, "status": J{"code": 2, "name": "CRITICAL"}, "output": "CRITICAL - 96% used"},
				{"id": 12, "description": "Load", "host": J{"id": 2, "name": "db1"}, "status": J{"code": 3, "name": "UNKNOWN"}}}, 3)
		case r.Method == "GET" && p == "/configuration/monitoring-servers":
			list([]J{{"id": 1, "name": "Central", "is_localhost": true}, {"id": 2, "name": "Poller2"}}, 2)
		case r.Method == "GET" && p == "/monitoring/hostgroups":
			list([]J{{"id": 1, "name": "Linux"}}, 1)
		case r.Method == "GET" && p == "/monitoring/downtimes":
			list(nil, 0)
		case r.Method == "PATCH" && p == "/configuration/hosts/1", r.Method == "POST" && p == "/monitoring/resources/downtime",
			r.Method == "POST" && p == "/configuration/hosts", r.Method == "DELETE" && p == "/configuration/hosts/3":
			send(204, nil)
		case r.Method == "POST" && p == centSaveEP:
			send(202, nil)
		case strings.Contains(p, "users") || strings.Contains(p, "administration") || strings.Contains(p, "contacts"):
			t.Errorf("a denied path reached Centreon: %s %s", r.Method, p)
			send(200, J{})
		default:
			send(404, J{"code": 404, "message": "Page not found"})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "cent", Platform: "centreon", Address: h, Port: pn, Insecure: true}
}

func TestCentreon(t *testing.T) {
	st := &centState{}
	d := centStub(t, st, "/centreon", "latest")
	ctx := context.Background()
	drv := open(t, d, Credential{Username: "admin", Password: "pw"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Centreon" || f.OSVersion != "24.04.1" || !strings.Contains(f.Model, "3 hosts") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 3 || ifs[0].Name != "web1" || ifs[0].OperUp == nil || !*ifs[0].OperUp || *ifs[1].OperUp || *ifs[2].OperUp ||
		len(ifs[0].Addresses) != 1 || ifs[0].Addresses[0] != "10.0.0.11" || ifs[0].AdminUp == nil || !*ifs[0].AdminUp || !strings.Contains(ifs[0].Description, "Central") {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	// the session expires once: the driver signs in again and the call goes through
	st.expire.Store(1)
	out, err := drv.Show(ctx, "show hosts status=down")
	if err != nil || !strings.Contains(out, "db1") || strings.Contains(out, "web1") || st.logins.Load() != 2 || !json.Valid([]byte(out)) {
		t.Fatalf("expired session: %v logins %d\n%s", err, st.logins.Load(), out)
	}
	if out, err = drv.Show(ctx, "show hosts search=SW"); err != nil || !strings.Contains(out, "sw1") || strings.Contains(out, "db1") {
		t.Errorf("hosts search: %v\n%s", err, out)
	}
	for _, ref := range []string{"web1", "1", "web1-alias", "10.0.0.11"} {
		out, err = drv.Show(ctx, "show host "+ref)
		if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "PING OK") && !strings.Contains(out, "acknowledged") || !strings.Contains(out, "Disk-/var") ||
			!strings.Contains(out, "OS-Linux-SNMP") || !strings.Contains(out, "went UP") || strings.Contains(out, "SECRETCOMM") {
			t.Fatalf("show host %s: %v\n%s", ref, err, out)
		}
	}
	// a part the user may not read is named, the rest answered
	out, err = drv.Show(ctx, "show host db1")
	if err != nil || !strings.Contains(out, `"errors"`) || !strings.Contains(out, "not allowed") || !strings.Contains(out, "Disk-/var") {
		t.Fatalf("show host db1: %v\n%s", err, out)
	}
	if _, err := drv.Show(ctx, "show host nope"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Errorf("unknown host: %v", err)
	}
	out, err = drv.Show(ctx, "show services status=critical")
	if err != nil || !strings.Contains(out, "Disk-/var") || strings.Contains(out, `"Ping"`) || strings.Contains(out, "Load") {
		t.Errorf("critical services: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show services host=db1"); err != nil || !strings.Contains(out, "Ping") {
		t.Errorf("services of a host: %v\n%s", err, out)
	}
	out, err = drv.Show(ctx, "show problems")
	var pr struct {
		Hosts    []struct{ Name string }
		Services []struct{ Description string }
	}
	if err != nil || json.Unmarshal([]byte(out), &pr) != nil || len(pr.Hosts) != 2 || pr.Hosts[0].Name != "db1" || pr.Hosts[1].Name != "sw1" ||
		len(pr.Services) != 2 || pr.Services[0].Description != "Disk-/var" || pr.Services[1].Description != "Load" {
		t.Errorf("problems: %v\n%s", err, out)
	}
	for _, c := range []string{"platform", "pollers", "hostgroups", "downtimes"} {
		if out, err := drv.Show(ctx, "show "+c); err != nil || !json.Valid([]byte(out)) {
			t.Errorf("show %s: %v %s", c, err, out)
		}
	}
	for _, bad := range []string{"show", "show users", "show host", "show host a b", "show host a;b", "show hosts status=sideways", "show hosts limit=0", "show hosts foo=1",
		"show hosts | include x", "show services host", "show platform extra", "show pollers 1"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}

	api := drv.(APIer)
	v, text, err := api.APIGet(ctx, "/configuration/hosts/1")
	if err != nil || text || strings.Contains(toJSON(v), "SECRETCOMM") || !strings.Contains(toJSON(v), "OS-Linux-SNMP") {
		t.Fatalf("apiget %v %v", err, v)
	}
	// the prefix and /api/latest are accepted, a query is sent in fixed form
	if _, _, err := api.APIGet(ctx, "/centreon/api/latest/monitoring/hosts?search=%7B%22name%22%3A%22web1%22%7D&limit=5"); err != nil {
		t.Errorf("full path: %v", err)
	}
	for _, bad := range []string{"/configuration/users", "/configuration/contacts/3", "/administration/parameters", "/login", "/monitoring/../configuration/users", "/", "/a/b",
		"/platform/updates/../users", "/monitoring/hosts?bad key=1", "https://x/monitoring/hosts", "/configuration/hosts/users"} {
		if _, _, err := api.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if c, err := api.APICatalog(ctx); err != nil || !strings.Contains(toJSON(c), "/monitoring/hosts") {
		t.Errorf("catalog %v %v", c, err)
	}
	if st.seen("GET /configuration/users") || st.seen("GET /login") {
		t.Error("a denied read reached Centreon")
	}
}

func TestCentreonToken(t *testing.T) {
	st := &centState{}
	d := centStub(t, st, "/centreon", "latest")
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "APITOKEN"})
	if f, err := drv.Facts(ctx); err != nil || f.OSVersion != "24.04.1" {
		t.Fatalf("facts %+v %v", f, err)
	}
	if st.logins.Load() != 0 || st.seen("POST /login") {
		t.Error("an API token signed in")
	}
	// a refused token is said so, not renewed
	bad := open(t, d, Credential{Token: "WRONG"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "API token") {
		t.Errorf("wrong token: %v", err)
	}
	// the wrong password
	pw := open(t, d, Credential{Username: "admin", Password: "no"})
	if _, err := pw.Facts(ctx); err == nil || !strings.Contains(err.Error(), "sign-in failed") || strings.Contains(err.Error(), `"no"`) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := Open(d, Credential{}); err == nil {
		t.Error("no credential accepted")
	}
}

func TestCentreonOptions(t *testing.T) {
	ctx := context.Background()
	st := &centState{}
	d := centStub(t, st, "", "24.04")
	d.Options = map[string]string{"prefix": "none", "api_version": "24.04"}
	drv := open(t, d, Credential{Username: "admin", Password: "pw"})
	if f, err := drv.Facts(ctx); err != nil || f.OSVersion != "24.04.1" {
		t.Fatalf("no prefix, fixed release: %+v %v", f, err)
	}
	st2 := &centState{}
	d2 := centStub(t, st2, "/monitor/centreon", "latest")
	d2.Options = map[string]string{"prefix": "/monitor/centreon/"}
	if f, err := open(t, d2, Credential{Username: "admin", Password: "pw"}).Facts(ctx); err != nil || f.OSVersion != "24.04.1" {
		t.Fatalf("other prefix: %+v %v", f, err)
	}
	for _, o := range []map[string]string{{"prefix": "/a b"}, {"prefix": "/a/../b"}, {"api_version": "v2"}, {"api_version": "../x"}} {
		dd := d
		dd.Options = o
		if _, err := Open(dd, Credential{Username: "admin", Password: "pw"}); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
}

func TestCentreonPaging(t *testing.T) {
	st := &centState{many: 250}
	d := centStub(t, st, "/centreon", "latest")
	drv := open(t, d, Credential{Username: "admin", Password: "pw"})
	ifs, err := drv.Interfaces(context.Background())
	if err != nil || len(ifs) != 250 {
		t.Fatalf("interfaces %d %v", len(ifs), err)
	}
	out, err := drv.Show(context.Background(), "show hosts limit=5")
	if err != nil || !strings.Contains(out, `"matching": 250`) || !strings.Contains(out, `"shown": 5`) {
		t.Errorf("limit: %v\n%s", err, out)
	}
}

func TestCentreonChange(t *testing.T) {
	st := &centState{}
	d := centStub(t, st, "/centreon", "latest")
	ctx := context.Background()
	drv := open(t, d, Credential{Username: "admin", Password: "pw"})
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("not a RawChanger")
	}
	// a dry run reads what is there and sends nothing
	res, err := rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/configuration/hosts/1", Body: `{"alias":"web-one"}`}, true)
	if err != nil || !res.DryRun || res.Applied || !strings.Contains(res.Before, "OS-Linux-SNMP") {
		t.Fatalf("dry run %+v %v", res, err)
	}
	if st.seen("PATCH /configuration/hosts/1") {
		t.Error("a dry run changed Centreon")
	}
	res, err = rc.RawChange(ctx, Raw{Method: "patch", Path: "/centreon/api/latest/configuration/hosts/1", Body: `{"alias":"web-one"}`}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Note, "exported") || st.bodies["PATCH /configuration/hosts/1"] != `{"alias":"web-one"}` {
		t.Fatalf("patch %+v %v", res, err)
	}
	res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/monitoring/resources/downtime", Body: `{"resources":[{"type":"host","id":1}]}`}, false)
	if err != nil || !res.Applied || res.Note != "" {
		t.Fatalf("downtime %+v %v", res, err)
	}
	res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/configuration/hosts", Body: `{"name":"new1"}`, Save: true}, false)
	if err != nil || !res.Applied || !res.Saved || !st.seen("POST "+centSaveEP) {
		t.Fatalf("create with save %+v %v", res, err)
	}
	// a session that expired is renewed before the change
	st.expire.Store(1)
	if res, err = rc.RawChange(ctx, Raw{Method: "DELETE", Path: "/configuration/hosts/3"}, false); err != nil || !res.Applied || st.logins.Load() < 2 {
		t.Fatalf("delete after expiry %+v %v logins %d", res, err, st.logins.Load())
	}
	for _, bad := range []Raw{
		{Method: "POST", Path: "/configuration/users", Body: `{}`},
		{Method: "PATCH", Path: "/configuration/contacts/1", Body: `{}`},
		{Method: "POST", Path: "/administration/parameters/api", Body: `{}`},
		{Method: "POST", Path: "/login", Body: `{}`},
		{Method: "POST", Path: "/platform/updates", Body: `{}`},
		{Method: "POST", Path: "/monitoring/hosts/users", Body: `{}`},
		{Method: "GET", Path: "/monitoring/hosts"},
		{Method: "PATCH", Path: "/configuration/hosts/1", Body: `{not json`},
		{Method: "PATCH", Path: "/configuration/hosts/1"},
		{Method: "POST", Path: "/configuration/hosts/../users", Body: `{}`},
		{Method: "POST", Lines: []string{"x"}},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
