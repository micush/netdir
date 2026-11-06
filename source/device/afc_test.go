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
)

type afcState struct {
	mu       sync.Mutex
	logins   int
	deleted  int
	calls    []string
	expire   bool   // the next authenticated call answers 401 once
	under    string // "" (/api/v1/<res>) or "/api" (/api/v1/api/<res>)
	puts     []string
	failPut  bool
	posts    []string
	badLogin bool
}

func afcStub(t *testing.T, st *afcState) Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		out := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if r.URL.Path == "/api/v1/auth/token" {
			switch r.Method {
			case "POST":
				if st.badLogin || r.Header.Get("X-Auth-Username") != "admin" || r.Header.Get("X-Auth-Password") != "S3CRET" {
					out(401, J{"message": "bad login"})
					return
				}
				st.logins++
				out(200, J{"result": "TOKEN" + strconv.Itoa(st.logins)})
			case "DELETE":
				st.deleted++
				out(200, J{})
			}
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "TOKEN") {
			out(401, J{})
			return
		}
		if st.expire {
			st.expire = false
			out(401, J{})
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/api/v1")
		if st.under != "" {
			if !strings.HasPrefix(p, "/api/") {
				out(404, J{})
				return
			}
			p = strings.TrimPrefix(p, "/api")
		}
		if r.Method != "GET" {
			if p == "/fabrics/f1" && r.Method == "PUT" {
				b := make([]byte, 400)
				n, _ := r.Body.Read(b)
				st.puts = append(st.puts, string(b[:n]))
				if st.failPut && len(st.puts) == 1 {
					out(500, J{})
					return
				}
				out(200, J{"result": J{}})
				return
			}
			if p == "/vlans" && r.Method == "POST" {
				st.posts = append(st.posts, p)
				out(201, J{"result": J{"uuid": "v1"}})
				return
			}
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			out(404, J{})
			return
		}
		st.calls = append(st.calls, p+"?"+r.URL.RawQuery)
		switch p {
		case "/fabrics":
			out(200, J{"count": 2, "result": []J{{"uuid": "f1", "name": "dc1", "password": "x"}, {"uuid": "f2", "name": "dc2"}}})
		case "/fabrics/f1":
			out(200, J{"result": J{"uuid": "f1", "name": "dc1"}})
		case "/switches":
			if r.URL.Query().Get("name") == "leaf1" {
				out(200, J{"result": []J{{"uuid": "s1", "name": "leaf1"}}})
				return
			}
			out(200, J{"result": []J{{"uuid": "s1", "name": "leaf1"}, {"uuid": "s2", "name": "leaf2"}}})
		case "/vlans":
			out(200, J{"result": []J{}})
		default:
			out(404, J{})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "afc", Platform: "afc", Address: h, Port: pn, Insecure: true}
}

func openAFC(t *testing.T, d Device, pw string) Driver {
	t.Helper()
	drv, err := Open(d, Credential{Name: "c", Username: "admin", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestAFCRead(t *testing.T) {
	st := &afcState{}
	drv := openAFC(t, afcStub(t, st), "S3CRET")
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Aruba" || !strings.Contains(f.Model, "2 fabric(s): dc1, dc2") {
		t.Fatalf("facts %+v %v", f, err)
	}
	out, err := drv.Show(ctx, "show switches name=leaf1")
	if err != nil || !strings.Contains(out, "leaf1") || strings.Contains(out, "leaf2") {
		t.Fatalf("show: %q %v", out, err)
	}
	if out, _ = drv.Show(ctx, "show fabrics"); strings.Contains(out, `"x"`) {
		t.Errorf("a password was shown: %s", out)
	}
	if st.logins != 1 {
		t.Errorf("logged in %d times", st.logins)
	}
	st.expire = true // the token is refused once: renewed, the call repeated
	if _, err := drv.Show(ctx, "show vlans"); err != nil || st.logins != 2 {
		t.Errorf("renew: %v logins %d", err, st.logins)
	}
	before := len(st.calls)
	for _, bad := range []string{"show", "show users", "show tokens", "show fabrics name=a;b", "show fabrics |x", "show Fab/rics", "show fabrics name="} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(st.calls) != before {
		t.Errorf("a refused command reached the AFC: %v", st.calls[before:])
	}
	a := drv.(APIer)
	for _, ok := range []string{"/fabrics", "/api/v1/fabrics", "/api/v1/api/fabrics", "/fabrics/f1", "/switches?name=leaf1"} {
		if _, _, err := a.APIGet(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	before = len(st.calls)
	for _, bad := range []string{"/users", "/auth/token", "/fabrics/../users", "/fabrics/f1/users", "/a/b/c/d", "fabrics", "/fabrics/f 1", "/licenses", "/tokens/x", "/fabrics?%zz"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s read", bad)
		}
	}
	if len(st.calls) != before {
		t.Errorf("a refused path reached the AFC: %v", st.calls[before:])
	}
	drv.Close(ctx)
	if st.deleted != 1 {
		t.Errorf("token deleted %d times", st.deleted)
	}
	if _, err := Open(afcStub(t, st), Credential{Name: "c", Token: "x"}); err == nil {
		t.Error("a token alone was accepted")
	}
}

func TestAFCSecondPrefixAndBadLogin(t *testing.T) {
	st := &afcState{under: "/api"}
	drv := openAFC(t, afcStub(t, st), "S3CRET")
	if f, err := drv.Facts(context.Background()); err != nil || !strings.Contains(f.Model, "dc1") {
		t.Errorf("below /api/v1/api: %+v %v", f, err)
	}
	_, err := openAFC(t, afcStub(t, &afcState{}), "WRONG!").Facts(context.Background())
	if err == nil || strings.Contains(err.Error(), "WRONG!") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestAFCChange(t *testing.T) {
	st := &afcState{}
	drv := openAFC(t, afcStub(t, st), "S3CRET")
	rc := drv.(RawChanger)
	ctx := context.Background()
	for _, bad := range []Raw{
		{Method: "POST", Path: "/api/v1/users", Body: `{}`},
		{Method: "PUT", Path: "/api/v1/auth/token", Body: `{}`},
		{Method: "POST", Path: "/api/v1/fabrics/f1/upgrade", Body: `{}`},
		{Method: "POST", Path: "/api/v1/../users", Body: `{}`},
		{Method: "POST", Path: "/api/v1/vlans?x=1", Body: `{}`},
		{Method: "POST", Path: "/api/v1/vlans", Body: `{bad`},
		{Method: "GET", Path: "/api/v1/vlans"},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if len(st.posts)+len(st.puts) != 0 {
		t.Fatal("a refused change was sent")
	}
	if r, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/api/v1/vlans", Body: `{"vlan_id":10}`}, true); err != nil || r.Applied || len(st.posts) != 0 {
		t.Errorf("dry run: %+v %v", r, err)
	}
	if r, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/vlans", Body: `{"vlan_id":10}`}, false); err != nil || !r.Applied || len(st.posts) != 1 {
		t.Errorf("post: %+v %v", r, err)
	}
	// a PUT that fails with a 5xx is put back from the copy taken first
	st.failPut = true
	if _, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "/api/v1/fabrics/f1", Body: `{"name":"new"}`}, false); err == nil {
		t.Error("the failing PUT gave no error")
	}
	if len(st.puts) != 2 || !strings.Contains(st.puts[1], `"dc1"`) {
		t.Errorf("not put back: %v", st.puts)
	}
}
