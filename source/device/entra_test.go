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

const (
	aliceID = "11111111-2222-3333-4444-555555555555"
	bobID   = "66666666-7777-8888-9999-000000000000"
)

type entraState struct {
	mu     sync.Mutex
	tokens int
	calls  []string
	limit  int
}

// entraStub is Entra's token endpoint and Graph on one TLS server: client credentials flow for tenant t1 (app APPID, secret S3CRET),
// Graph answers for two users (alice, and bob who shares the name "Bo"), alice's registered devices (one also owned, ownedDevices has
// two pages).  The stub fails the test on any Graph request that is not a GET, and on a Graph request without the token.
func entraStub(t *testing.T, st *entraState) Device {
	t.Helper()
	entraWait = time.Millisecond
	var host string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		out := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if r.URL.Path == "/t1/oauth2/v2.0/token" {
			b, _ := io.ReadAll(r.Body)
			f, _ := url.ParseQuery(string(b))
			if r.Method != "POST" || f.Get("client_id") != "APPID" || f.Get("client_secret") != "S3CRET" || f.Get("grant_type") != "client_credentials" || f.Get("scope") != "https://"+strings.Split(host, ":")[0]+"/.default" {
				out(401, J{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
				return
			}
			st.tokens++
			out(200, J{"access_token": "TOK", "expires_in": 3599, "token_type": "Bearer"})
			return
		}
		if r.Method != "GET" {
			t.Errorf("Graph got %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer TOK" {
			out(401, J{"error": J{"code": "InvalidAuthenticationToken"}})
			return
		}
		st.calls = append(st.calls, r.URL.RequestURI())
		if st.limit > 0 {
			st.limit--
			w.WriteHeader(429)
			return
		}
		alice := J{"id": aliceID, "displayName": "Alice Adams", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com"}
		bob := J{"id": bobID, "displayName": "Bo Brown", "userPrincipalName": "bo.brown@contoso.com"}
		dev := func(id, name, os string) J {
			return J{"@odata.type": "#microsoft.graph.device", "id": id, "deviceId": "dev-" + id, "displayName": name, "operatingSystem": os, "isCompliant": true, "isManaged": true, "managementType": "MDM", "trustType": "AzureAd"}
		}
		p := strings.TrimPrefix(r.URL.Path, "/v1.0")
		q := r.URL.Query()
		switch {
		case p == "/organization":
			out(200, J{"value": []J{{"id": "tenant-guid", "displayName": "Contoso Ltd"}}})
		case p == "/users/alice@contoso.com" || p == "/users/"+aliceID:
			out(200, alice)
		case p == "/users/nobody@contoso.com" || p == "/users/00000000-0000-0000-0000-000000000000":
			out(404, J{"error": J{"code": "Request_ResourceNotFound"}})
		case p == "/users" && strings.Contains(q.Get("$filter"), "'Alice'"):
			out(200, J{"value": []J{alice}})
		case p == "/users" && strings.Contains(q.Get("$filter"), "'Bo'"):
			out(200, J{"value": []J{alice, bob}})
		case p == "/users" && strings.Contains(q.Get("$filter"), "'Carol'"):
			if strings.Contains(q.Get("$filter"), "onPremisesSamAccountName") {
				out(400, J{"error": J{"code": "Request_UnsupportedQuery"}})
				return
			}
			out(200, J{"value": []J{{"id": "99999999-0000-0000-0000-000000000000", "displayName": "Carol Cook", "userPrincipalName": "carol@contoso.com"}}})
		case p == "/users" && strings.Contains(q.Get("$filter"), "nobody@contoso.com"):
			out(200, J{"value": []J{}})
		case p == "/users/"+aliceID+"/registeredDevices/microsoft.graph.device":
			out(200, J{"value": []J{dev("d1", "LAPTOP-ALICE", "Windows"), dev("d2", "iPhone-Alice", "iOS")}})
		case p == "/users/"+aliceID+"/ownedDevices/microsoft.graph.device" && q.Get("page") == "":
			out(200, J{"value": []J{dev("d1", "LAPTOP-ALICE", "Windows")}, "@odata.nextLink": "https://" + host + "/v1.0/users/" + aliceID + "/ownedDevices/microsoft.graph.device?page=2&$top=999"})
		case p == "/users/"+aliceID+"/ownedDevices/microsoft.graph.device" && q.Get("page") == "2":
			out(200, J{"value": []J{dev("d3", "Surface-Lab", "Windows")}})
		case p == "/users/"+bobID+"/registeredDevices/microsoft.graph.device" || p == "/users/"+bobID+"/ownedDevices/microsoft.graph.device":
			out(200, J{"value": []J{}})
		default:
			t.Errorf("unexpected Graph request %s", r.URL)
			out(404, J{})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	host = srv.Listener.Addr().String()
	pn, _ := strconv.Atoi(port)
	return Device{Name: "entra", Platform: "entra", Address: h, Port: pn, Insecure: true, Options: map[string]string{"tenant": "t1", "login_host": host}}
}

func openEntra(t *testing.T, d Device, secret string) Driver {
	t.Helper()
	drv, err := Open(d, Credential{Name: "app", Username: "APPID", Password: secret})
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestEntraUserDevices(t *testing.T) {
	st := &entraState{}
	d := entraStub(t, st)
	// the scope names the Graph host without its port
	drv := openEntra(t, d, "S3CRET")
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "Contoso Ltd" || f.Vendor != "Microsoft Entra ID" || !strings.Contains(f.Model, "tenant-guid") {
		t.Fatalf("facts %+v %v", f, err)
	}
	for _, who := range []string{"user=alice@contoso.com", "user=" + aliceID, "user=Alice", "Alice", "alice@contoso.com"} {
		out, err := drv.Show(ctx, "show devices "+who)
		if err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		var a struct {
			User struct {
				ID                string
				UserPrincipalName string
			}
			Count   int
			Devices []struct {
				ID       string
				Name     string `json:"displayName"`
				Relation []string
			}
		}
		if err := json.Unmarshal([]byte(out), &a); err != nil {
			t.Fatalf("%s: not JSON: %v\n%s", who, err, out)
		}
		if a.User.ID != aliceID || a.Count != 3 || len(a.Devices) != 3 {
			t.Fatalf("%s: %+v", who, a)
		}
		// sorted by name: iPhone-Alice, LAPTOP-ALICE, Surface-Lab; the laptop is both registered and owned (paged)
		if a.Devices[0].Name != "iPhone-Alice" || strings.Join(a.Devices[0].Relation, ",") != "registered" ||
			a.Devices[1].Name != "LAPTOP-ALICE" || strings.Join(a.Devices[1].Relation, ",") != "registered,owned" ||
			a.Devices[2].Name != "Surface-Lab" || strings.Join(a.Devices[2].Relation, ",") != "owned" {
			t.Fatalf("%s: devices %+v", who, a.Devices)
		}
		if !strings.Contains(out, `"managementType": "MDM"`) || !strings.Contains(out, `"isCompliant": true`) {
			t.Errorf("management type or compliance missing: %s", out)
		}
		if strings.Contains(out, "@odata") {
			t.Errorf("odata noise in %s", out)
		}
	}
	if st.tokens != 1 {
		t.Errorf("a token was asked for %d times for one driver", st.tokens)
	}
	out, err := drv.Show(ctx, "show user user=Alice")
	if err != nil || !strings.Contains(out, "alice@contoso.com") {
		t.Errorf("show user: %q %v", out, err)
	}
	// the account name filter is tried first and the plain one when the tenant refuses it
	if out, err := drv.Show(ctx, "show user user=Carol"); err != nil || !strings.Contains(out, "carol@contoso.com") {
		t.Errorf("fallback: %q %v", out, err)
	}
	if !strings.Contains(strings.Join(st.calls, " "), "mailNickname") {
		t.Errorf("the account name filter was not tried: %v", st.calls)
	}
	// ambiguity is listed, not guessed
	if _, err := drv.Show(ctx, "show devices user=Bo"); err == nil || !strings.Contains(err.Error(), "several users") || !strings.Contains(err.Error(), "bo.brown@contoso.com") {
		t.Errorf("ambiguous: %v", err)
	}
	// no such user
	for _, who := range []string{"nobody@contoso.com", "00000000-0000-0000-0000-000000000000"} {
		if _, err := drv.Show(ctx, "show devices user="+who); err == nil || !strings.Contains(err.Error(), "no user matches") {
			t.Errorf("%s: %v", who, err)
		}
	}
	before := len(st.calls)
	for _, bad := range []string{"show", "show devices", "show devices user=", "show devices user=a;b", "show devices user=a|b", "show devices user=x\"y", "show nothing user=a", "show devices user=" + strings.Repeat("a", 129)} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(st.calls) != before {
		t.Errorf("a refused command reached Graph: %v", st.calls[before:])
	}
	if _, err := drv.Interfaces(ctx); err != ErrUnsupported {
		t.Errorf("interfaces: %v", err)
	}
	if _, ok := drv.(RawChanger); ok {
		t.Error("the Entra driver can write")
	}
	if _, ok := drv.(Changer); ok {
		t.Error("the Entra driver can change ports")
	}
}

func TestEntraAuthAndLimits(t *testing.T) {
	st := &entraState{}
	d := entraStub(t, st)
	_, err := openEntra(t, d, "WRONG!").Facts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "WRONG!") {
		t.Errorf("wrong secret: %v", err)
	}
	st.limit = 2
	if _, err := openEntra(t, d, "S3CRET").Facts(context.Background()); err != nil {
		t.Errorf("two 429s are waited out: %v", err)
	}
	st.limit = 5
	if _, err := openEntra(t, d, "S3CRET").Facts(context.Background()); err == nil {
		t.Error("five 429s gave an answer")
	}
	for _, o := range []map[string]string{{}, {"tenant": "../x"}, {"tenant": "a b"}} {
		d2 := d
		d2.Options = o
		if _, err := Open(d2, Credential{Name: "app", Username: "APPID", Password: "S3CRET"}); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
	if _, err := Open(d, Credential{Name: "app", Username: "APPID"}); err == nil {
		t.Error("no secret accepted")
	}
	// a ready-made token needs no tenant and no sign-in
	d3 := d
	d3.Options = nil
	drv, err := Open(d3, Credential{Name: "app", Token: "TOK"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drv.Facts(context.Background()); err != nil {
		t.Errorf("token credential: %v", err)
	}
}

func TestEntraAPIGet(t *testing.T) {
	st := &entraState{}
	d := entraStub(t, st)
	drv := openEntra(t, d, "S3CRET").(APIer)
	ctx := context.Background()
	for _, ok := range []string{"/organization", "/v1.0/organization", "/users/alice@contoso.com", "/users/" + aliceID + "/registeredDevices/microsoft.graph.device?$top=5"} {
		if _, _, err := drv.APIGet(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	before := len(st.calls)
	for _, bad := range []string{"/me", "/users/" + aliceID + "/messages", "/users/" + aliceID + "/authentication/methods", "/users/" + aliceID + "/drive", "/applications", "/servicePrincipals",
		"/groups", "/users/x/y/z", "/devices/x/extensions", "/../x", "users", "/organization/../me", "/users?%zz"} {
		if _, _, err := drv.APIGet(ctx, bad); err == nil {
			t.Errorf("%s read", bad)
		}
	}
	if len(st.calls) != before {
		t.Errorf("a refused path reached Graph: %v", st.calls[before:])
	}
}
