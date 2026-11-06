package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netdir/device"
)

func TestEntraSigninOps(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		f, _ := url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/devicecode"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "DC-SECRET", "user_code": "ABCD", "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900, "interval": 1})
		case f.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code":
			polls++
			if polls == 1 {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "A", "refresh_token": "RT1", "expires_in": 3600})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	e, _ := mcpEnv(t)
	dc, _, err := e.mg.LiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "browser", Token: "rt:"}, {Name: "secret", Username: "app", Password: "pw"}}
	dc.Settings.Devices = []device.Device{
		{Name: "entra", Platform: "entra", Address: host, Port: pn, Credential: "browser", Insecure: true, Options: map[string]string{"login_host": srv.Listener.Addr().String()}},
		{Name: "entra2", Platform: "entra", Address: host, Port: pn, Credential: "secret", Insecure: true},
		{Name: "sw1", Platform: "eos", Address: host, Credential: "secret", Insecure: true}}
	if err := e.mg.PutConfig(dc, "test", "devices"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"device":"nope"}`, `{"device":"sw1"}`, `{"device":"entra2"}`, `{`} {
		if _, err := e.mg.Op("device.signin_start", json.RawMessage(bad), "alice"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	v, err := e.mg.Op("device.signin_start", json.RawMessage(`{"device":"entra"}`), "alice")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if b, _ := json.Marshal(m); strings.Contains(string(b), "DC-SECRET") || m["user_code"] != "ABCD" {
		t.Fatalf("start answer %s", b)
	}
	args, _ := json.Marshal(map[string]any{"id": m["id"]})
	if v, err = e.mg.Op("device.signin_poll", args, "alice"); err != nil || v.(map[string]any)["state"] != "pending" { // too early: not even asked
		t.Fatalf("early poll: %v %v", v, err)
	}
	mu.Lock()
	if polls != 0 {
		t.Errorf("Microsoft was asked %d times before the interval", polls)
	}
	mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	if v, err = e.mg.Op("device.signin_poll", args, "alice"); err != nil || v.(map[string]any)["state"] != "pending" {
		t.Fatalf("pending: %v %v", v, err)
	}
	time.Sleep(1100 * time.Millisecond)
	if v, err = e.mg.Op("device.signin_poll", args, "alice"); err != nil || v.(map[string]any)["state"] != "done" {
		t.Fatalf("done: %v %v", v, err)
	}
	if _, err = e.mg.Op("device.signin_poll", args, "alice"); err == nil {
		t.Error("a finished sign-in was polled again")
	}
	token := func() string {
		dc, _, _ := e.mg.LiveConfig()
		for _, c := range dc.Settings.DeviceCredentials {
			if c.Name == "browser" {
				return c.Token + "|" + c.Username + "|" + c.Password
			}
		}
		return ""
	}
	if got := token(); got != "rt:RT1||" {
		t.Fatalf("stored %q", got)
	}
	// a renewal replaces the token it was made from, at most once a day, and never a newer sign-in
	e.mg.entraRefreshed("browser", "OLD", "RT9")
	if got := token(); got != "rt:RT1||" {
		t.Errorf("a renewal of another token was stored: %q", got)
	}
	e.mg.entraRefreshed("browser", "RT1", "RT2")
	if got := token(); got != "rt:RT2||" {
		t.Errorf("renewal not stored: %q", got)
	}
	e.mg.entraRefreshed("browser", "RT2", "RT3")
	if got := token(); got != "rt:RT2||" {
		t.Errorf("a second renewal within a day was stored: %q", got)
	}
}
