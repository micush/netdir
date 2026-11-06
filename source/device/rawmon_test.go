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

// monStub is a TLS server that answers GETs with a fixed body and records every other request.
type monStub struct {
	mu     sync.Mutex
	writes []string
	bodies []string
}

func monServer(t *testing.T, token bool, get func(path string) (int, any)) (Device, *monStub) {
	t.Helper()
	st := &monStub{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		send := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			send(200, J{"access_token": "TOK", "expires_in": 3599})
			return
		}
		if token && r.Header.Get("Authorization") != "Bearer TOK" && r.Header.Get("Authorization") != "Bearer APITOKEN" {
			send(401, J{"status": "failed"})
			return
		}
		if r.Method != http.MethodGet {
			b, _ := io.ReadAll(r.Body)
			st.mu.Lock()
			st.writes = append(st.writes, r.Method+" "+r.URL.RequestURI())
			st.bodies = append(st.bodies, string(b))
			st.mu.Unlock()
			send(200, J{"status": "ok"})
			return
		}
		code, v := get(r.URL.Path)
		send(code, v)
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Address: h, Port: pn, Insecure: true, Options: map[string]string{"login_host": srv.Listener.Addr().String()}}, st
}

func TestObserviumRawChange(t *testing.T) {
	d, st := monServer(t, true, func(p string) (int, any) {
		if strings.Contains(p, "/devices/12/") || strings.HasSuffix(p, "/devices/12") {
			return 200, J{"status": "ok", "devices": J{"12": J{"device_id": "12", "hostname": "ipam2", "snmp_community": "SECRETCOMM"}}}
		}
		return 200, J{"status": "ok", "devices": J{"12": J{"device_id": "12"}}}
	})
	d.Name, d.Platform = "obs", "observium"
	rc := open(t, d, Credential{Token: "APITOKEN"}).(RawChanger)
	ctx := context.Background()

	r, err := rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/devices/12/", Body: `{"location":"rack 4"}`}, true)
	if err != nil || r.Applied || len(st.writes) != 0 || !strings.Contains(r.Before, "ipam2") || strings.Contains(r.Before, "SECRETCOMM") {
		t.Fatalf("dry run %+v %v writes %v", r, err, st.writes)
	}
	r, err = rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/devices/12/", Body: `{"location":"rack 4"}`}, false)
	if err != nil || !r.Applied || len(st.writes) != 1 || st.writes[0] != "PATCH /api/v0/devices/12/" || st.bodies[0] != `{"location":"rack 4"}` {
		t.Fatalf("change %+v %v writes %v", r, err, st.writes)
	}
	for _, bad := range []Raw{{Method: "POST", Path: "/users/", Body: `{}`}, {Method: "GET", Path: "/devices/"}, {Method: "POST", Path: "/devices/../x"}, {Lines: []string{"x"}}} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	if len(st.writes) != 1 {
		t.Fatalf("refused requests were sent: %v", st.writes)
	}
}

func TestEntraRawChange(t *testing.T) {
	d, st := monServer(t, true, func(p string) (int, any) {
		if strings.HasPrefix(p, "/v1.0/devices/d1") {
			return 200, J{"id": "d1", "displayName": "LAPTOP-1", "accountEnabled": true}
		}
		return 404, J{"error": J{"code": "Request_ResourceNotFound"}}
	})
	d.Name, d.Platform = "entra", "entra"
	d.Options["tenant"] = "t1"
	drv, err := Open(d, Credential{Name: "app", Username: "APPID", Password: "S3CRET"})
	if err != nil {
		t.Fatal(err)
	}
	rc := drv.(RawChanger)
	ctx := context.Background()

	r, err := rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/devices/d1", Body: `{"accountEnabled":false}`}, true)
	if err != nil || r.Applied || len(st.writes) != 0 || !strings.Contains(r.Before, "LAPTOP-1") {
		t.Fatalf("dry run %+v %v", r, err)
	}
	r, err = rc.RawChange(ctx, Raw{Method: "PATCH", Path: "/v1.0/devices/d1", Body: `{"accountEnabled":false}`}, false)
	if err != nil || !r.Applied || len(st.writes) != 1 || st.writes[0] != "PATCH /v1.0/devices/d1" {
		t.Fatalf("change %+v %v writes %v", r, err, st.writes)
	}
	for _, bad := range []Raw{
		{Method: "POST", Path: "/users/a@b.c/authentication/methods", Body: `{}`},
		{Method: "PATCH", Path: "/users/a@b.c", Body: `{"passwordProfile":{"password":"x"}}`},
		{Method: "GET", Path: "/devices/d1"},
		{Method: "POST", Path: "/applications", Body: `{}`},
		{Method: "POST", Path: "/users/a@b.c/sendMail", Body: `{}`},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	if len(st.writes) != 1 {
		t.Fatalf("refused requests were sent: %v", st.writes)
	}
}
