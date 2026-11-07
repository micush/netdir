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

type rcState struct {
	mu     sync.Mutex
	calls  []string
	bodies map[string]string
	paged  bool // /zones answers in two pages
}

func (s *rcState) seen(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == call {
			return true
		}
	}
	return false
}

// rcStub is RcodeZero: every call needs "Authorization: Bearer TOK1".
func rcStub(t *testing.T, st *rcState, root string) Device {
	t.Helper()
	st.bodies = map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(r.URL.Path, root+"/") {
			t.Errorf("request outside the API: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, root)
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
		if r.Header.Get("Authorization") != "Bearer TOK1" {
			send(401, J{"status": "failed", "message": "Unauthenticated"})
			return
		}
		switch {
		case r.Method == "GET" && p == "/zones":
			zs := []J{{"domain": "example.com", "type": "MASTER", "dnssec_status": "ACTIVE", "serial": 5, "masters": []string{}},
				{"domain": "example.net", "type": "SLAVE", "masters": []string{"192.0.2.1"}}}
			if st.paged {
				if r.URL.Query().Get("page") == "2" {
					send(200, J{"data": zs[1:], "current_page": 2, "last_page": 2})
				} else {
					send(200, J{"data": zs[:1], "current_page": 1, "last_page": 2})
				}
				return
			}
			send(200, J{"data": zs, "current_page": 1, "last_page": 1})
		case r.Method == "GET" && p == "/zones/example.com":
			send(200, J{"domain": "example.com", "type": "MASTER", "dnssec_status": "ACTIVE", "tsig_key": "TSIGSECRET"})
		case r.Method == "GET" && p == "/zones/nope.com":
			send(404, J{"status": "failed", "message": "zone not found"})
		case r.Method == "GET" && p == "/zones/example.com/rrsets":
			send(200, J{"data": []J{
				{"name": "example.com.", "type": "SOA", "ttl": 3600, "records": []J{{"content": "sns.dns.icann.org. noc.dns.icann.org. 5 7200 3600 1209600 3600", "disabled": false}}},
				{"name": "www.example.com.", "type": "A", "ttl": 60, "records": []J{{"content": "192.0.2.10", "disabled": false}}},
				{"name": "mail.example.com.", "type": "MX", "ttl": 300, "records": []J{{"content": "10 mx.example.com.", "disabled": false}}}}})
		case r.Method == "GET" && p == "/zones/example.com/stats/queries":
			send(200, J{"data": []J{{"date": "2026-11-01", "queries": 42}}})
		case r.Method == "GET" && p == "/zones/example.com/stats/magnitude":
			send(200, J{"magnitude": 3.1})
		case r.Method == "GET" && p == "/stats/queries":
			send(200, J{"data": []J{{"date": "2026-11-01", "queries": 99}}})
		case r.Method == "GET" && p == "/messages":
			send(200, J{"data": []J{{"id": 1, "subject": "welcome"}}})
		case r.Method == "GET" && p == "/settings/secondaries":
			send(200, J{"data": []J{{"ip": "192.0.2.2"}}})
		case r.Method == "GET" && p == "/settings":
			send(200, J{"data": J{"defaultsecondaries": []string{"192.0.2.2"}}})
		case r.Method == "PATCH" && p == "/zones/example.com/rrsets", r.Method == "POST" && p == "/zones",
			r.Method == "POST" && p == "/zones/example.com/retrieve", r.Method == "PUT" && p == "/settings/secondaries":
			send(200, J{"status": "ok"})
		case strings.Contains(p, "tsig") || strings.Contains(p, "token") || strings.Contains(p, "users"):
			t.Errorf("a denied path reached RcodeZero: %s %s", r.Method, p)
			send(200, J{})
		default:
			send(404, J{"status": "failed", "message": "not found"})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "rc0", Platform: "rcode0", Address: h, Port: pn, Insecure: true}
}

func TestRcode0(t *testing.T) {
	st := &rcState{}
	d := rcStub(t, st, "/api/v1")
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOK1"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "RcodeZero" || !strings.Contains(f.Model, "2 zones") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "example.com" || ifs[0].Description != "master, DNSSEC active" || ifs[1].Description != "slave" {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	if !st.seen("GET /zones") {
		t.Error("zones not asked")
	}
	// more pages than the first are read
	st.paged = true
	if ifs, err = drv.Interfaces(ctx); err != nil || len(ifs) != 2 || ifs[1].Name != "example.net" {
		t.Errorf("two pages: %+v %v", ifs, err)
	}
	st.paged = false
	out, err := drv.Show(ctx, "show zones search=net")
	if err != nil || !strings.Contains(out, "example.net") || strings.Contains(out, "example.com") || !json.Valid([]byte(out)) {
		t.Fatalf("zones: %v\n%s", err, out)
	}
	out, err = drv.Show(ctx, "show zone example.com")
	if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "192.0.2.10") || !strings.Contains(out, `"rrsets_total": 3`) || !strings.Contains(out, `"queries": 42`) || strings.Contains(out, "TSIGSECRET") {
		t.Fatalf("zone: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show rrsets zone=example.com type=mx"); err != nil || !strings.Contains(out, "mail.example.com") || strings.Contains(out, "www.example.com") {
		t.Errorf("rrsets: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show rrsets zone=example.com search=192.0.2"); err != nil || !strings.Contains(out, "www.example.com") || strings.Contains(out, "mail.") {
		t.Errorf("rrsets search: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show stats zone=example.com kind=magnitude"); err != nil || !strings.Contains(out, "3.1") {
		t.Errorf("zone stats: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show stats"); err != nil || !strings.Contains(out, "99") {
		t.Errorf("stats: %v\n%s", err, out)
	}
	for _, c := range []string{"messages", "secondaries", "settings"} {
		if out, err := drv.Show(ctx, "show "+c); err != nil || !json.Valid([]byte(out)) {
			t.Errorf("show %s: %v %s", c, err, out)
		}
	}
	if _, err := drv.Show(ctx, "show zone nope.com"); err == nil {
		t.Error("an unknown zone answered")
	}
	for _, bad := range []string{"show", "show tsig", "show users", "show zone", "show zone a/b", "show zone a b", "show zones foo=1", "show zones limit=0", "show zones | x", "show rrsets",
		"show rrsets zone=a/b", "show rrsets zone=a type=A/B", "show stats zone=a/b", "show stats kind=../x", "show stats kind=Q", "show messages x"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	api := drv.(APIer)
	v, text, err := api.APIGet(ctx, "/zones/example.com")
	if err != nil || text || strings.Contains(toJSON(v), "TSIGSECRET") || !strings.Contains(toJSON(v), "ACTIVE") {
		t.Fatalf("apiget %v %v", err, v)
	}
	if _, _, err := api.APIGet(ctx, "/api/v1/zones/example.com/rrsets?page_size=-1"); err != nil {
		t.Errorf("full path: %v", err)
	}
	for _, bad := range []string{"/settings/tsigout", "/zones/example.com/tsig", "/tokens", "/users", "/settings/users", "/zones/../users", "/", "/other", "/zones?bad key=1", "https://x/zones", "zones"} {
		if _, _, err := api.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if c, err := api.APICatalog(ctx); err != nil || !strings.Contains(toJSON(c), "/zones") {
		t.Errorf("catalog %v %v", c, err)
	}
	for _, c := range []string{"GET /settings/tsigout", "GET /tokens", "GET /users"} {
		if st.seen(c) {
			t.Errorf("a denied read reached RcodeZero: %s", c)
		}
	}
}

func TestRcode0Token(t *testing.T) {
	st := &rcState{}
	d := rcStub(t, st, "/api/v1")
	if _, err := Open(d, Credential{}); err == nil {
		t.Error("no token accepted")
	}
	if _, err := Open(d, Credential{Token: "a b"}); err == nil {
		t.Error("a token with a space accepted")
	}
	bad := open(t, d, Credential{Token: "WRONG"})
	if _, err := bad.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "API token") || strings.Contains(err.Error(), "WRONG") {
		t.Errorf("wrong token: %v", err)
	}
	st2 := &rcState{}
	d2 := rcStub(t, st2, "/api/v2")
	d2.Options = map[string]string{"api_version": "v2"}
	if f, err := open(t, d2, Credential{Token: "TOK1"}).Facts(context.Background()); err != nil || f.Vendor != "RcodeZero" {
		t.Errorf("v2: %+v %v", f, err)
	}
	st3 := &rcState{}
	d3 := rcStub(t, st3, "/rc")
	d3.Options = map[string]string{"prefix": "/rc/"}
	if f, err := open(t, d3, Credential{Token: "TOK1"}).Facts(context.Background()); err != nil || f.Vendor != "RcodeZero" {
		t.Errorf("prefix: %+v %v", f, err)
	}
	for _, o := range []map[string]string{{"api_version": "v3"}, {"api_version": "../x"}, {"prefix": "/a b"}, {"prefix": "/a/../b"}} {
		dd := d
		dd.Options = o
		if _, err := Open(dd, Credential{Token: "TOK1"}); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
}

func TestRcode0Change(t *testing.T) {
	st := &rcState{}
	d := rcStub(t, st, "/api/v1")
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOK1"})
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("not a RawChanger")
	}
	patch := `[{"name":"www.example.com.","type":"A","changetype":"update","ttl":120,"records":[{"content":"192.0.2.20"}]}]`
	res, err := rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/zones/example.com/rrsets", Body: patch}, true)
	if err != nil || !res.DryRun || res.Applied || !strings.Contains(res.Before, "192.0.2.10") {
		t.Fatalf("dry run %+v %v", res, err)
	}
	if st.seen("PATCH /zones/example.com/rrsets") {
		t.Error("a dry run changed RcodeZero")
	}
	res, err = rc.RawChange(ctx, Raw{Method: "patch", Path: "/api/v1/zones/example.com/rrsets", Body: patch}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Note, "not put back") || st.bodies["PATCH /zones/example.com/rrsets"] != patch {
		t.Fatalf("patch %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/zones", Body: `{"domain":"new.example","type":"master"}`}, false); err != nil || !res.Applied {
		t.Fatalf("add zone %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/zones/example.com/retrieve"}, false); err != nil || !res.Applied {
		t.Fatalf("retrieve %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/settings/secondaries", Body: `{"ip":"192.0.2.3"}`}, false); err != nil || !res.Applied {
		t.Fatalf("settings %+v %v", res, err)
	}
	for _, bad := range []Raw{
		{Method: "DELETE", Path: "/zones/example.com"},
		{Method: "DELETE", Path: "/zones"},
		{Method: "POST", Path: "/settings/tsigout", Body: `{}`},
		{Method: "POST", Path: "/zones/example.com/tsig", Body: `{}`},
		{Method: "POST", Path: "/tokens", Body: `{}`},
		{Method: "POST", Path: "/users", Body: `{}`},
		{Method: "POST", Path: "/stats/queries", Body: `{}`},
		{Method: "GET", Path: "/zones"},
		{Method: "PATCH", Path: "/zones/example.com/rrsets", Body: `{not json`},
		{Method: "PATCH", Path: "/zones/example.com/rrsets"},
		{Method: "PATCH", Path: "/zones/../users", Body: `{}`},
		{Method: "POST", Lines: []string{"x"}},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	for _, c := range []string{"DELETE /zones/example.com", "POST /settings/tsigout", "POST /tokens", "POST /users"} {
		if st.seen(c) {
			t.Errorf("a refused change reached RcodeZero: %s", c)
		}
	}
}

func TestDnsHide(t *testing.T) {
	v := dnsHide(map[string]any{"a": []map[string]any{{"authorization": "x", "ok": "y"}}, "tsig": map[string]any{"k": "v"}, "n": nil})
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), `"x"`) || strings.Contains(string(b), `"v"`) || !strings.Contains(string(b), `"y"`) {
		t.Errorf("hidden %s", b)
	}
}
