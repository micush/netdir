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

type nsState struct {
	mu     sync.Mutex
	calls  []string
	bodies map[string]string
	big    bool // the zone holds a full page of records
}

func (s *nsState) seen(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == call {
			return true
		}
	}
	return false
}

// nsStub is NS1: every call needs the key KEY1 in X-NSONE-Key.
func nsStub(t *testing.T, st *nsState, prefix string) Device {
	t.Helper()
	st.bodies = map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(r.URL.Path, prefix+"/") {
			t.Errorf("request outside the API: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, prefix)
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
		if r.Header.Get("X-NSONE-Key") != "KEY1" {
			send(401, J{"message": "Unauthorized"})
			return
		}
		if r.URL.RawQuery != "" && r.Method == "GET" && strings.Contains(r.URL.RawQuery, "key=") {
			t.Errorf("a key in a URL: %s", r.URL)
		}
		switch {
		case r.Method == "GET" && p == "/zones":
			send(200, []J{{"id": "z1", "zone": "example.com", "ttl": 3600, "dnssec": true, "records_count": 3, "secondary": J{"enabled": false}},
				{"id": "z2", "zone": "example.org", "ttl": 300, "secondary": J{"enabled": true}}})
		case r.Method == "GET" && p == "/zones/example.com":
			recs := []J{{"id": "r1", "domain": "example.com", "type": "SOA", "ttl": 3600, "short_answers": []string{"ns1.nsone.net hostmaster.nsone.net 1 43200 7200 1209600 3600"}},
				{"id": "r2", "domain": "www.example.com", "type": "A", "ttl": 60, "tier": 1, "short_answers": []string{"192.0.2.10", "192.0.2.11"}},
				{"id": "r3", "domain": "mail.example.com", "type": "MX", "ttl": 300, "short_answers": []string{"10 mx.example.com."}}}
			if st.big {
				recs = nil
				for i := 0; i < nsPage; i++ {
					recs = append(recs, J{"id": "r" + strconv.Itoa(i), "domain": "h" + strconv.Itoa(i) + ".example.com", "type": "A", "ttl": 60})
				}
			}
			send(200, J{"zone": "example.com", "ttl": 3600, "records": recs, "dns_servers": []string{"dns1.p01.nsone.net"}, "tsig": J{"key": "TSIGSECRET"}})
		case r.Method == "GET" && p == "/zones/nope.com":
			send(404, J{"message": "zone not found"})
		case r.Method == "GET" && p == "/zones/example.com/www.example.com/A":
			send(200, J{"zone": "example.com", "domain": "www.example.com", "type": "A", "ttl": 60, "answers": []J{{"answer": []string{"192.0.2.10"}}}, "filters": []J{{"filter": "up"}}})
		case r.Method == "GET" && p == "/monitoring/jobs":
			send(200, []J{{"id": "j1", "name": "web", "job_type": "http", "config": J{"url": "http://192.0.2.10/", "authorization": "Basic SECRETAUTH"}}})
		case r.Method == "GET" && p == "/data/sources":
			send(200, []J{{"id": "s1", "name": "api", "sourcetype": "nsone_v1"}})
		case r.Method == "GET" && p == "/data/feeds/s1":
			send(200, []J{{"id": "f1", "name": "feed"}})
		case r.Method == "GET" && p == "/networks":
			send(200, []J{{"id": 1, "label": "NS1 Global Network"}})
		case r.Method == "GET" && p == "/stats/qps":
			send(200, J{"qps": 12.5})
		case r.Method == "GET" && p == "/stats/usage":
			send(200, []J{{"queries": 1000}})
		case r.Method == "GET" && p == "/account/plan":
			send(200, J{"plan": "pro"})
		case r.Method == "PUT" && p == "/zones/example.com/new.example.com/A", r.Method == "POST" && p == "/zones/example.com/www.example.com/A",
			r.Method == "DELETE" && p == "/zones/example.com/old.example.com/A":
			send(200, J{"ok": true})
		case strings.Contains(p, "apikeys") || strings.Contains(p, "users") || strings.Contains(p, "teams") || strings.Contains(p, "settings") || strings.Contains(p, "lists") || strings.Contains(p, "tsig"):
			t.Errorf("a denied path reached NS1: %s %s", r.Method, p)
			send(200, J{})
		default:
			send(404, J{"message": "not found"})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "ns1", Platform: "nsone", Address: h, Port: pn, Insecure: true}
}

func TestNsone(t *testing.T) {
	st := &nsState{}
	d := nsStub(t, st, "/v1")
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "KEY1"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "NS1" || !strings.Contains(f.Model, "2 zones") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "example.com" || !strings.Contains(ifs[0].Description, "DNSSEC") || !strings.Contains(ifs[0].Description, "3 records") || !strings.Contains(ifs[1].Description, "secondary") {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	out, err := drv.Show(ctx, "show zones search=org")
	if err != nil || !strings.Contains(out, "example.org") || strings.Contains(out, "example.com") || !json.Valid([]byte(out)) {
		t.Fatalf("zones: %v\n%s", err, out)
	}
	out, err = drv.Show(ctx, "show zone example.com")
	if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "192.0.2.10") || !strings.Contains(out, `"records_total": 3`) || strings.Contains(out, "TSIGSECRET") || strings.Contains(out, `"note"`) {
		t.Fatalf("zone: %v\n%s", err, out)
	}
	st.big = true
	out, err = drv.Show(ctx, "show zone example.com limit=5")
	if err != nil || !strings.Contains(out, `"records_shown": 5`) || !strings.Contains(out, "first") || !strings.Contains(out, `"records_total": 2500`) {
		t.Fatalf("a full page: %v\n%s", err, out)
	}
	st.big = false
	out, err = drv.Show(ctx, "show records zone=example.com type=a")
	if err != nil || !strings.Contains(out, "www.example.com") || strings.Contains(out, "mail.example.com") {
		t.Errorf("records: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show records zone=example.com search=mx.example"); err != nil || !strings.Contains(out, "mail.example.com") || strings.Contains(out, "www") {
		t.Errorf("records search: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show record example.com www.example.com a"); err != nil || !strings.Contains(out, `"filter": "up"`) {
		t.Errorf("record: %v\n%s", err, out)
	}
	if out, err = drv.Show(ctx, "show monitors"); err != nil || !strings.Contains(out, "192.0.2.10") || strings.Contains(out, "SECRETAUTH") {
		t.Errorf("monitors: %v\n%s", err, out)
	}
	for _, c := range []string{"datasources", "networks", "qps", "usage", "feeds source=s1"} {
		if out, err := drv.Show(ctx, "show "+c); err != nil || !json.Valid([]byte(out)) {
			t.Errorf("show %s: %v %s", c, err, out)
		}
	}
	if _, err := drv.Show(ctx, "show zone nope.com"); err == nil {
		t.Error("an unknown zone answered")
	}
	for _, bad := range []string{"show", "show users", "show apikeys", "show zone", "show zone a/b", "show zone a;b", "show zones foo=1", "show zones limit=0", "show zones | x",
		"show records", "show records zone=a/b", "show records zone=a type=A/B", "show record a b", "show record a b/c A", "show monitors x", "show feeds", "show feeds source=a/b"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	api := drv.(APIer)
	v, text, err := api.APIGet(ctx, "/zones/example.com")
	if err != nil || text || strings.Contains(toJSON(v), "TSIGSECRET") || !strings.Contains(toJSON(v), "192.0.2.10") {
		t.Fatalf("apiget %v %v", err, v)
	}
	if _, _, err := api.APIGet(ctx, "/v1/account/plan"); err != nil {
		t.Errorf("full path: %v", err)
	}
	for _, bad := range []string{"/account/apikeys", "/account/users", "/account/teams/1", "/account/settings", "/lists", "/zones/example.com/tsig", "/zones/../account/apikeys",
		"/", "/billing", "/zones?bad key=1", "https://x/zones", "/zones/users", "zones"} {
		if _, _, err := api.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if c, err := api.APICatalog(ctx); err != nil || !strings.Contains(toJSON(c), "/zones") {
		t.Errorf("catalog %v %v", c, err)
	}
	for _, c := range []string{"GET /account/apikeys", "GET /account/users", "GET /lists"} {
		if st.seen(c) {
			t.Errorf("a denied read reached NS1: %s", c)
		}
	}
}

func TestNsoneKey(t *testing.T) {
	st := &nsState{}
	d := nsStub(t, st, "/v1")
	if _, err := Open(d, Credential{}); err == nil {
		t.Error("no key accepted")
	}
	if _, err := Open(d, Credential{Token: "a b"}); err == nil {
		t.Error("a key with a space accepted")
	}
	bad := open(t, d, Credential{Token: "WRONG"})
	if _, err := bad.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "API key") || strings.Contains(err.Error(), "WRONG") {
		t.Errorf("wrong key: %v", err)
	}
	for _, o := range []map[string]string{{"prefix": "/a b"}, {"prefix": "/a/../b"}} {
		dd := d
		dd.Options = o
		if _, err := Open(dd, Credential{Token: "KEY1"}); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
	st2 := &nsState{}
	d2 := nsStub(t, st2, "/api/v1")
	d2.Options = map[string]string{"prefix": "/api/v1/"}
	if f, err := open(t, d2, Credential{Token: "KEY1"}).Facts(context.Background()); err != nil || f.Vendor != "NS1" {
		t.Errorf("other prefix: %+v %v", f, err)
	}
	st3 := &nsState{}
	d3 := nsStub(t, st3, "")
	d3.Options = map[string]string{"prefix": "none"}
	if f, err := open(t, d3, Credential{Token: "KEY1"}).Facts(context.Background()); err != nil || f.Vendor != "NS1" {
		t.Errorf("no prefix: %+v %v", f, err)
	}
}

func TestNsoneChange(t *testing.T) {
	st := &nsState{}
	d := nsStub(t, st, "/v1")
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "KEY1"})
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("not a RawChanger")
	}
	// a dry run of an update reads the record and sends nothing
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/zones/example.com/www.example.com/A", Body: `{"ttl":120}`}, true)
	if err != nil || !res.DryRun || res.Applied || !strings.Contains(res.Before, "192.0.2.10") {
		t.Fatalf("dry run %+v %v", res, err)
	}
	if st.seen("POST /zones/example.com/www.example.com/A") {
		t.Error("a dry run changed NS1")
	}
	res, err = rc.RawChange(ctx, Raw{Method: "post", Path: "/v1/zones/example.com/www.example.com/A", Body: `{"ttl":120}`}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Before, "192.0.2.10") || !strings.Contains(res.Note, "not put back") || st.bodies["POST /zones/example.com/www.example.com/A"] != `{"ttl":120}` {
		t.Fatalf("update %+v %v", res, err)
	}
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/zones/example.com/new.example.com/A", Body: `{"zone":"example.com","domain":"new.example.com","type":"A","answers":[{"answer":["192.0.2.50"]}]}`}, false)
	if err != nil || !res.Applied {
		t.Fatalf("create %+v %v", res, err)
	}
	if res, err = rc.RawChange(ctx, Raw{Method: "DELETE", Path: "/zones/example.com/old.example.com/A"}, false); err != nil || !res.Applied {
		t.Fatalf("delete %+v %v", res, err)
	}
	for _, bad := range []Raw{
		{Method: "DELETE", Path: "/zones/example.com"},
		{Method: "DELETE", Path: "/zones"},
		{Method: "POST", Path: "/account/apikeys", Body: `{}`},
		{Method: "PUT", Path: "/account/users", Body: `{}`},
		{Method: "POST", Path: "/zones/example.com/tsig", Body: `{}`},
		{Method: "POST", Path: "/lists/1", Body: `{}`},
		{Method: "POST", Path: "/stats/qps", Body: `{}`},
		{Method: "PATCH", Path: "/zones/example.com/www.example.com/A", Body: `{}`},
		{Method: "GET", Path: "/zones"},
		{Method: "POST", Path: "/zones/example.com/www.example.com/A", Body: `{not json`},
		{Method: "PUT", Path: "/zones/example.com/new.example.com/A"},
		{Method: "POST", Path: "/zones/../account/apikeys", Body: `{}`},
		{Method: "POST", Lines: []string{"x"}},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	for _, c := range []string{"POST /account/apikeys", "PUT /account/users", "DELETE /zones/example.com", "GET /account/apikeys"} {
		if st.seen(c) {
			t.Errorf("a refused change reached NS1: %s", c)
		}
	}
}
