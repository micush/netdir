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
)

type ipfState struct {
	badVer string // what /api/version claims, when it is wrong
	mu     sync.Mutex
	reqs   []string
	bodies []string
}

func (s *ipfState) joined() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.reqs, "\n")
}

// ipfStub is IP Fabric 7.3 on a TLS server: /api/version, a token (X-API-Token: TOK) or a login (ipf/pw), and some tables.
func ipfStub(t *testing.T, st *ipfState) Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		st.mu.Lock()
		st.reqs = append(st.reqs, r.Method+" "+r.URL.Path)
		st.bodies = append(st.bodies, string(b))
		st.mu.Unlock()
		send := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if strings.Contains(r.URL.String(), "TOK") {
			t.Errorf("a credential is in the URL: %s", r.URL)
		}
		if r.URL.Path == "/api/version" {
			send(200, J{"apiVersion": firstOf(st.badVer, "v7.3"), "releaseVersion": "7.3.4+0"})
			return
		}
		if r.URL.Path == "/api/v7.3/auth/login" {
			var l map[string]string
			_ = json.Unmarshal(b, &l)
			if l["username"] != "ipf" || l["password"] != "pw" {
				send(401, J{"message": "bad login"})
				return
			}
			send(200, J{"accessToken": "ACCESS", "refreshToken": "R"})
			return
		}
		if r.Header.Get("X-API-Token") != "TOK" && r.Header.Get("Authorization") != "Bearer ACCESS" {
			send(401, J{"message": "unauthorized"})
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/api/v7.3")
		var q struct {
			Columns    []string       `json:"columns"`
			Filters    map[string]any `json:"filters"`
			Pagination struct{ Limit, Start int }
			Snapshot   string `json:"snapshot"`
		}
		_ = json.Unmarshal(b, &q)
		dev := func(h string) J {
			return J{"id": "1", "hostname": h, "siteName": "DC1", "vendor": "cisco", "version": "17.3", "sn": "SN-IPF-1", "snmp_community": "COMM"}
		}
		switch {
		case r.Method == "POST" && p == "/tables/inventory/devices":
			if q.Snapshot != "$last" {
				t.Errorf("snapshot %q", q.Snapshot)
			}
			if h, ok := q.Filters["hostname"].([]any); ok {
				name := h[1].(string)
				if name == "core" {
					send(200, J{"data": []J{dev("core1"), dev("core2")}, "_meta": J{"count": 2}})
					return
				}
				if name == "none" {
					send(200, J{"data": []J{}, "_meta": J{"count": 0}})
					return
				}
				send(200, J{"data": []J{dev(name)}, "_meta": J{"count": 1}})
				return
			}
			send(200, J{"data": []J{dev("core1")}, "_meta": J{"count": 42}})
		case r.Method == "POST" && p == "/tables/inventory/interfaces":
			for _, c := range q.Columns {
				if c == "l1" {
					send(422, J{"message": "unknown column l1"})
					return
				}
			}
			send(200, J{"data": []J{{"id": "i1", "hostname": "core1", "intName": "Gi1/0/1"}}, "_meta": J{"count": 1}})
		case r.Method == "POST" && p == "/tables/addressing/arp":
			send(200, J{"data": []J{{"id": "a1", "hostname": "core1", "ip": "10.0.0.9"}}, "_meta": J{"count": 1}})
		case r.Method == "POST" && p == "/tables/management/snapshots":
			if q.Snapshot != "" {
				t.Errorf("snapshots table got snapshot %q", q.Snapshot)
			}
			send(200, J{"data": []J{{"id": "s1", "status": "done"}}, "_meta": J{"count": 1}})
		case r.Method == "GET" && p == "/os/version":
			send(200, J{"version": "v7.3.4"})
		case r.Method == "POST" && p == "/tables/routing/protocols/bgp/neighbors":
			send(200, J{"data": []J{{"id": "b1", "hostname": "core1", "neiIp": "10.0.0.2"}}, "_meta": J{"count": 1}})
		case r.Method == "GET" && p == "/snapshots":
			send(200, []J{{"id": "s1"}})
		case r.Method == "PATCH" || r.Method == "POST" || r.Method == "DELETE":
			send(200, J{"ok": true})
		default:
			send(404, J{"message": "nope " + r.URL.Path})
		}
	}))
	t.Cleanup(srv.Close)
	d := Device{Name: "ipf", Platform: "ipfabric", Insecure: true}
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	d.Address, d.Port = h, 0
	d.Port, _ = strconv.Atoi(port)
	return d
}

func TestIPFabric(t *testing.T) {
	st := &ipfState{}
	d := ipfStub(t, st)
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOK"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "IP Fabric" || f.OSVersion != "7.3.4+0" || !strings.Contains(f.Model, "42 devices") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx) // the first request is refused for its columns; the minimal ones are used
	if err != nil || len(ifs) != 1 || ifs[0].Name != "core1:Gi1/0/1" {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	if _, err := drv.Neighbors(ctx); err != ErrUnsupported {
		t.Errorf("neighbors %v", err)
	}
	out, err := drv.Show(ctx, "show device core1")
	if err != nil || !strings.Contains(out, `"hostname": "core1"`) || !strings.Contains(out, "10.0.0.9") || !strings.Contains(out, "Gi1/0/1") || strings.Contains(out, "COMM") {
		t.Fatalf("show device: %v\n%s", err, out)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("not JSON:\n%s", out)
	}
	if _, err := drv.Show(ctx, "show device core"); err == nil || !strings.Contains(err.Error(), "2 devices match") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := drv.Show(ctx, "show device none"); err == nil {
		t.Error("no device")
	}
	out, err = drv.Show(ctx, "show snapshots")
	if err != nil || !strings.Contains(out, `"s1"`) {
		t.Fatalf("snapshots %v %s", err, out)
	}
	out, err = drv.Show(ctx, "show devices siteName=DC* columns=id,hostname limit=5")
	if err != nil || !strings.Contains(out, `"count": 42`) {
		t.Fatalf("devices %v %s", err, out)
	}
	for _, bad := range []string{"show", "show nothing", "show devices limit=5000", "show devices siteName", "show devices x=a b", "show devices snapshot=../x", "show devices | include x", "show tables/a/b/c/d/e/f/g"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	v, text, err := drv.(APIer).APIGet(ctx, "/tables/inventory/devices?columns=id,hostname&limit=10&siteName=DC1")
	if err != nil || text || !strings.Contains(toJSON(v), "core1") {
		t.Fatalf("apiget %v %v", err, v)
	}
	if _, _, err := drv.(APIer).APIGet(ctx, "/snapshots"); err != nil {
		t.Errorf("snapshots: %v", err)
	}
	for _, bad := range []string{"/users", "/auth/login", "/settings", "/tables/../users", "/api/v7.3/users/me"} {
		if _, _, err := drv.(APIer).APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
}

func TestIPFabricLoginAndChange(t *testing.T) {
	st := &ipfState{}
	d := ipfStub(t, st)
	ctx := context.Background()
	if _, err := Open(d, Credential{Username: "ipf", Password: "bad"}); err != nil {
		t.Fatal(err)
	}
	bad, _ := Open(d, Credential{Username: "ipf", Password: "bad"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "sign-in failed") {
		t.Errorf("bad login: %v", err)
	}
	drv := open(t, d, Credential{Username: "ipf", Password: "pw"})
	if f, err := drv.Facts(ctx); err != nil || f.Vendor != "IP Fabric" {
		t.Fatalf("facts after login %+v %v", f, err)
	}
	rc := drv.(RawChanger)
	r, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/snapshots/s1/lock", Body: `{}`}, true)
	if err != nil || r.Applied {
		t.Fatalf("dry %+v %v", r, err)
	}
	r, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/api/v7.3/snapshots/s1/lock", Body: `{}`}, false)
	if err != nil || !r.Applied || !strings.Contains(st.joined(), "POST /api/v7.3/snapshots/s1/lock") {
		t.Fatalf("change %+v %v\n%s", r, err, st.joined())
	}
	for _, b := range []Raw{{Method: "POST", Path: "/users", Body: `{}`}, {Method: "DELETE", Path: "/tokens/1"}, {Method: "PATCH", Path: "/settings/ldap", Body: `{}`}, {Method: "GET", Path: "/snapshots"}} {
		if _, err := rc.RawChange(ctx, b, false); err == nil {
			t.Errorf("%+v accepted", b)
		}
	}
	if _, err := Open(Device{Name: "x", Platform: "ipfabric", Address: "h", Options: map[string]string{"api_version": "7"}}, Credential{Token: "T"}); err == nil {
		t.Error("bad api_version accepted")
	}
	if _, err := Open(Device{Name: "x", Platform: "ipfabric", Address: "h", Options: map[string]string{"snapshot": "last"}}, Credential{Token: "T"}); err == nil {
		t.Error("bad snapshot accepted")
	}
	if _, err := Open(Device{Name: "x", Platform: "ipfabric", Address: "h"}, Credential{}); err == nil {
		t.Error("no credential accepted")
	}
}

// The version /api/version names gets a 404 (IP Fabric 8.1 was reported so): the release's own major.minor is tried, and a nested
// table (BGP neighbors) is read.
func TestIPFabricWrongVersion(t *testing.T) {
	st := &ipfState{badVer: "v9.9"}
	d := ipfStub(t, st)
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOK"})
	v, _, err := drv.(APIer).APIGet(ctx, "/tables/routing/protocols/bgp/neighbors?columns=hostname,neiIp&hostname=core1")
	if err != nil || !strings.Contains(toJSON(v), "10.0.0.2") {
		t.Fatalf("nested table: %v %v\n%s", err, v, st.joined())
	}
	if !strings.Contains(st.joined(), "GET /api/v9.9/os/version") || !strings.Contains(st.joined(), "POST /api/v7.3/tables/routing/protocols/bgp/neighbors") {
		t.Errorf("probing:\n%s", st.joined())
	}
	// nothing answers: the error says which paths were tried
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			_, _ = w.Write([]byte(`{"apiVersion":"v8.1","releaseVersion":"8.1.8+0"}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"Requested Resource Not Found"}`))
	}))
	t.Cleanup(dead.Close)
	h, port, _ := net.SplitHostPort(dead.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	drv2 := open(t, Device{Name: "d", Platform: "ipfabric", Address: h, Port: pn, Insecure: true}, Credential{Token: "TOK"})
	_, err = drv2.Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "/api/v8.1/os/version") || !strings.Contains(err.Error(), "/api/v8/snapshots") || !strings.Contains(err.Error(), "api_version") {
		t.Errorf("dead: %v", err)
	}
	if _, err := drv2.Show(ctx, "show devices"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("show on a dead API: %v", err)
	}
}

func TestIPFabricDiagnose(t *testing.T) {
	st := &ipfState{}
	d := ipfStub(t, st)
	drv := open(t, d, Credential{Token: "TOK"})
	out, err := drv.Show(context.Background(), "show diagnose")
	if err != nil || !json.Valid([]byte(out)) || strings.Contains(out, `"TOK"`) {
		t.Fatalf("diagnose %v\n%s", err, out)
	}
	for _, want := range []string{"GET /api/version", "GET /api/v7.3/os/version", "POST /api/v7.3/tables/inventory/sites", `"auth": "none"`, "401"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
