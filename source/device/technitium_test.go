package device

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type techState struct {
	mu      sync.Mutex
	reqs    []string
	logins  int
	logouts int
}

// techStub is a Technitium DNS Server API on loopback: a form login that answers a session token, a logout, an API token, and
// GET answers keyed by path (the query is not part of the key).  Everything answers HTTP 200 with the {"status": ...} envelope, as
// Technitium does.  The stub fails the test on a credential or token in a URL, a request without a valid Bearer token, and any
// request that is not the login or logout and does not name a get, list or query endpoint: Technitium deletes zones with a GET, so
// that is the one thing the driver must never send.
func techStub(t *testing.T, answers map[string]any) (Device, *techState) {
	t.Helper()
	st := &techState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RawQuery), "token") || strings.Contains(r.URL.String(), "s3cret") {
			t.Errorf("a credential is in the URL: %s", r.URL)
		}
		send := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		if r.URL.Path == "/api/user/login" && r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil || r.PostForm.Get("user") != "admin" || r.PostForm.Get("pass") != "s3cret" {
				send(J{"status": "error", "errorMessage": "Invalid username or password for user: admin"})
				return
			}
			st.mu.Lock()
			st.logins++
			st.mu.Unlock()
			send(J{"displayName": "Administrator", "username": "admin", "token": "SESSIONTOKEN", "status": "ok"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer SESSIONTOKEN" && r.Header.Get("Authorization") != "Bearer APITOKEN" {
			send(J{"status": "invalid-token", "errorMessage": "Invalid token or session expired."})
			return
		}
		if r.URL.Path == "/api/user/logout" && r.Method == http.MethodPost {
			st.mu.Lock()
			st.logouts++
			st.mu.Unlock()
			send(J{"status": "ok"})
			return
		}
		segs := strings.Split(r.URL.Path, "/")
		if last := segs[len(segs)-1]; !techReadRE.MatchString(last) {
			t.Errorf("a request that does not name a read endpoint: %s %s", r.Method, r.URL)
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request (only GET after the login): %s", r.Method, r.URL)
		}
		st.mu.Lock()
		st.reqs = append(st.reqs, r.URL.RequestURI())
		st.mu.Unlock()
		a, ok := answers[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		send(J{"status": "ok", "response": a})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "dns1", Platform: "technitium", Address: host, Port: pn, Insecure: true}, st
}

// Field names: settings (version, uptimestamp, dnsServerDomain, dnsServerLocalEndPoints, tsigKeys) and the dashboard's stats
// are the ones in Technitium's API documentation; this stub has only been checked against what that documentation shows and the
// forms the changelog lists.
func techAnswers() map[string]any {
	return map[string]any{
		"/api/settings/get": J{"version": "15.0", "uptimestamp": "2026-11-01T10:00:00.0000000Z", "dnsServerDomain": "dns1.example.net",
			"dnsServerLocalEndPoints": []any{"0.0.0.0:53", "[::]:53"},
			"tsigKeys":                []any{J{"keyName": "k1", "sharedSecret": "abc", "algorithmName": "hmac-sha256"}},
			"proxy":                   J{"type": "None", "password": "p"}},
		"/api/dashboard/stats/get": J{"stats": J{"totalQueries": 100, "totalNxDomain": 3, "totalBlocked": 7, "cachedEntries": 55, "zones": 4}},
		"/api/zones/list":          J{"zones": []any{J{"name": "example.com", "type": "Primary", "disabled": false}}},
	}
}

func TestTechnitiumToken(t *testing.T) {
	boot := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC).Unix()
	old := nowUnix
	nowUnix = func() int64 { return boot + 90000 }
	defer func() { nowUnix = old }()
	d, st := techStub(t, techAnswers())
	drv := open(t, d, Credential{Token: "APITOKEN"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "dns1.example.net", Vendor: "Technitium", Model: "DNS Server", OSVersion: "15.0", UptimeS: 90000}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 1 || ifs[0].Name != "dns" || strings.Join(ifs[0].Addresses, " ") != "0.0.0.0:53 [::]:53" {
		t.Errorf("interfaces: %v %+v", err, ifs)
	}
	if _, err := drv.Neighbors(ctx); err != ErrUnsupported {
		t.Errorf("neighbors: %v", err)
	}
	if _, err := drv.Config(ctx); err != ErrUnsupported {
		t.Errorf("config: %v", err)
	}
	if _, err := drv.Show(ctx, "show version"); err != ErrUnsupported {
		t.Errorf("show: %v", err)
	}
	if _, ok := drv.(Router); ok {
		t.Error("a DNS server has no routing table")
	}
	if _, ok := drv.(Firewaller); ok {
		t.Error("a DNS server has no firewall")
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU != nil || r.Details.Protocols["stats_last_hour"] == nil || r.Details.Protocols["stats_last_day"] == nil {
		t.Fatalf("resources: %v %+v", err, r)
	}
	if !strings.Contains(strings.Join(st.reqs, " "), "type=LastDay") {
		t.Errorf("requests: %v", st.reqs)
	}
	// the API: the settings come back with their secrets hidden
	a := drv.(APIer)
	v, text, err := a.APIGet(ctx, "/api/settings/get")
	m, _ := v.(map[string]any)
	if err != nil || text || m["version"] != "15.0" {
		t.Fatalf("api get: %v %v %v", err, text, v)
	}
	key := m["tsigKeys"].([]any)[0].(map[string]any)
	if key["sharedSecret"] != "(hidden)" || key["keyName"] != "k1" || m["proxy"].(map[string]any)["password"] != "(hidden)" {
		t.Errorf("secrets: %+v", m)
	}
	if v, _, err := a.APIGet(ctx, "/api/zones/list?pageNumber=1"); err != nil || v.(map[string]any)["zones"] == nil {
		t.Errorf("zones: %v %v", err, v)
	}
	// nothing but a read endpoint is sent, whatever the caller asks for
	before := len(st.reqs)
	for _, bad := range []string{
		"/api/zones/delete?zone=example.com", "/api/zones/create?zone=x", "/api/zones/records/delete?domain=a", "/api/zones/export?zone=example.com", "/api/settings/set", "/api/settings/backup",
		"/api/user/logout", "/api/user/login?user=a&pass=b", "/api/user/createToken", "/api/dnsClient/resolve?server=1.1.1.1&domain=a", "/api/cache/flush", "/api/blocked/delete?domain=a",
		"/api/admin/users/create", "/api/zones/getx", "/api/zones/getfoo", "/api/zones/listing", "/api/get", "/api/zones", "/zones/list", "/api/zones/list?token=x", "/api/zones/list?PASS=x",
		"/api/zones/list?totp=1", "/api/zones/list?%zz", "/other/api/zones/list",
	} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was sent", bad)
		}
	}
	if len(st.reqs) != before {
		t.Errorf("a refused path reached the server: %v", st.reqs[before:])
	}
	if cat, err := a.APICatalog(ctx); err != nil || cat.(map[string]any)["how"] == nil {
		t.Errorf("catalog: %v", err)
	}
	drv.Close(ctx)
	if st.logins != 0 || st.logouts != 0 {
		t.Errorf("an API token is not logged in or out: %d %d", st.logins, st.logouts)
	}
}

func TestTechnitiumLogin(t *testing.T) {
	d, st := techStub(t, techAnswers())
	ctx := context.Background()
	drv, err := Open(d, Credential{Username: "admin", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := drv.Facts(ctx); err != nil {
			t.Fatal(err)
		}
	}
	drv.Close(ctx)
	if st.logins != 1 || st.logouts != 1 {
		t.Errorf("one login and one logout for a request: %d %d", st.logins, st.logouts)
	}
	// wrong password: the server's refusal, no echo of it
	_, err = open(t, d, Credential{Username: "admin", Password: "nope"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "400") || strings.Contains(err.Error(), "nope") {
		t.Errorf("wrong password: %v", err)
	}
	if st.logouts != 1 {
		t.Error("a logout without a login")
	}
	// a token the server does not know is a 401
	_, err = open(t, d, Credential{Token: "WRONG"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "WRONG") {
		t.Errorf("wrong token: %v", err)
	}
	for _, c := range []Credential{{Username: "admin"}, {Password: "x"}, {}} {
		if _, err := Open(d, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestTechRead(t *testing.T) {
	for _, ok := range []string{"/api/zones/list", "/api/dashboard/stats/getTop?type=LastDay", "/api/apps/listStoreApps", "/api/logs/query", "/api/zones/records/get?domain=a&zone=a", "/api/settings/getTsigKeyNames"} {
		if _, err := techRead(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"/api/zones/delete", "/api/zones/getting", "/api/zones/Get", "/api/x", "/zones/list", "", "/api/zones/list?token=1"} {
		if p, err := techRead(bad); err == nil {
			t.Errorf("%q allowed as %q", bad, p)
		}
	}
}
