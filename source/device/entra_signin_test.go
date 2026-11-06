package device

import (
	"context"
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
)

type signinState struct {
	mu        sync.Mutex
	polls     int
	refreshes int
	scopes    []string
	bearers   []string
}

func signinStub(t *testing.T, st *signinState) Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		out := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		b, _ := io.ReadAll(r.Body)
		f, _ := url.ParseQuery(string(b))
		switch r.URL.Path {
		case "/organizations/oauth2/v2.0/devicecode":
			st.scopes = append(st.scopes, f.Get("scope"))
			if f.Get("client_id") != EntraPublicClient || f.Get("client_secret") != "" {
				out(400, J{"error": "invalid_client"})
				return
			}
			out(200, J{"device_code": "DC1", "user_code": "ABCD-EFGH", "verification_uri": "http://evil.example/x", "expires_in": 900, "interval": 1})
		case "/organizations/oauth2/v2.0/token":
			if f.Get("client_id") != EntraPublicClient || f.Get("client_secret") != "" {
				out(400, J{"error": "invalid_client"})
				return
			}
			switch f.Get("grant_type") {
			case "urn:ietf:params:oauth:grant-type:device_code":
				st.polls++
				if f.Get("device_code") != "DC1" {
					out(400, J{"error": "bad_verification_code"})
				} else if st.polls < 3 {
					out(400, J{"error": "authorization_pending"})
				} else {
					out(200, J{"access_token": "A0", "refresh_token": "RT1", "expires_in": 3600})
				}
			case "refresh_token":
				st.scopes = append(st.scopes, f.Get("scope"))
				switch f.Get("refresh_token") {
				case "RT1":
					st.refreshes++
					out(200, J{"access_token": "A1", "refresh_token": "RT2", "expires_in": 3600})
				case "RT2":
					st.refreshes++
					out(200, J{"access_token": "A2", "refresh_token": "RT3", "expires_in": 3600})
				default:
					out(400, J{"error": "invalid_grant", "error_description": "AADSTS70008: expired"})
				}
			}
		case "/v1.0/organization":
			st.bearers = append(st.bearers, r.Header.Get("Authorization"))
			out(200, J{"value": []J{{"id": "tenant-guid", "displayName": "Contoso Ltd"}}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			out(404, J{})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "entra", Platform: "entra", Address: h, Port: pn, Insecure: true, Options: map[string]string{"login_host": srv.Listener.Addr().String()}}
}

func TestEntraBrowserSignin(t *testing.T) {
	st := &signinState{}
	d := signinStub(t, st)
	ctx := context.Background()
	c, err := EntraStartSignin(ctx, d)
	if err != nil || c.UserCode != "ABCD-EFGH" || c.Interval != 1 {
		t.Fatalf("start: %+v %v", c, err)
	}
	if c.VerificationURI != "https://microsoft.com/devicelogin" {
		t.Errorf("a non-https link was passed on: %q", c.VerificationURI)
	}
	if b, _ := json.Marshal(c); strings.Contains(string(b), "DC1") {
		t.Errorf("the device code reaches the page: %s", b)
	}
	if !strings.Contains(st.scopes[0], "User.Read.All") || !strings.Contains(st.scopes[0], "Device.Read.All") || !strings.Contains(st.scopes[0], "offline_access") {
		t.Errorf("scope %q", st.scopes[0])
	}
	var rt string
	for i := 0; i < 2; i++ {
		if _, pending, err := EntraPollSignin(ctx, d, c.DeviceCode); err != nil || !pending {
			t.Fatalf("poll %d: pending %v %v", i, pending, err)
		}
	}
	if rt, _, err = EntraPollSignin(ctx, d, c.DeviceCode); err != nil || rt != "RT1" {
		t.Fatalf("done: %q %v", rt, err)
	}
	if _, _, err := EntraPollSignin(ctx, d, "OTHER"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("bad code: %v", err)
	}
	if _, err := EntraStartSignin(ctx, Device{Platform: "eos"}); err == nil {
		t.Error("another platform was signed in")
	}

	// the stored login is a refresh token: one refresh for any number of drivers opened with it, the new token handed on
	var mu sync.Mutex
	var got [][3]string
	EntraRefreshed = func(cred, old, new string) { mu.Lock(); got = append(got, [3]string{cred, old, new}); mu.Unlock() }
	t.Cleanup(func() { EntraRefreshed = nil; entraSessions.Delete("signin-login") })
	cred := Credential{Name: "signin-login", Token: EntraStoredToken(rt)}
	for i := 0; i < 3; i++ {
		drv, err := Open(d, cred)
		if err != nil {
			t.Fatal(err)
		}
		f, err := drv.Facts(ctx)
		if err != nil || f.Hostname != "Contoso Ltd" {
			t.Fatalf("facts %+v %v", f, err)
		}
	}
	if st.refreshes != 1 {
		t.Errorf("%d refreshes for three drivers", st.refreshes)
	}
	for _, b := range st.bearers {
		if b != "Bearer A1" {
			t.Errorf("bearer %q", b)
		}
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if len(got) != 1 || got[0] != [3]string{"signin-login", "RT1", "RT2"} {
		t.Errorf("new refresh token handed on: %v", got)
	}
	mu.Unlock()
	// the daemon saved RT2: the next driver carries it, and the held access token is still used
	if drv, err := Open(d, Credential{Name: "signin-login", Token: EntraStoredToken("RT2")}); err != nil {
		t.Fatal(err)
	} else if _, err := drv.Facts(ctx); err != nil || st.refreshes != 1 {
		t.Errorf("after the save: %v, %d refreshes", err, st.refreshes)
	}
	// signed in again as someone else: the old session is dropped
	if drv, err := Open(d, Credential{Name: "signin-login", Token: EntraStoredToken("BAD")}); err != nil {
		t.Fatal(err)
	} else if _, err := drv.Facts(ctx); err == nil || !strings.Contains(err.Error(), "sign in again") || strings.Contains(err.Error(), "BAD") {
		t.Errorf("revoked: %v", err)
	}
	if _, err := Open(d, Credential{Name: "x", Token: "rt:"}); err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Errorf("empty login: %v", err)
	}
}
