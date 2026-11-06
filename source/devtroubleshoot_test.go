package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"netdir/device"
)

// troubleEnv is mcpEnv with one stub serving Entra (token and Graph) and a Meraki dashboard: Joe has two devices, the newer one
// (JSMITH-LAPTOP) was seen on the network, the older one (OLD-PC) was not.
func troubleEnv(t *testing.T, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any)) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if r.Method != "GET" && !strings.HasSuffix(r.URL.Path, "/token") {
			t.Errorf("%s %s", r.Method, r.URL)
		}
		type J = map[string]any
		dev := func(id, name, last string) J {
			return J{"id": id, "displayName": name, "operatingSystem": "Windows", "approximateLastSignInDateTime": last}
		}
		switch p := r.URL.Path; {
		case strings.HasSuffix(p, "/oauth2/v2.0/token"):
			_, _ = io.Copy(io.Discard, r.Body)
			out(200, J{"access_token": "TOK", "expires_in": 3599})
		case p == "/v1.0/users/joe@contoso.com":
			out(200, J{"id": "11111111-2222-3333-4444-555555555555", "displayName": "Joe Smith", "userPrincipalName": "joe@contoso.com"})
		case strings.HasSuffix(p, "/registeredDevices/microsoft.graph.device"):
			out(200, J{"value": []J{dev("d1", "OLD-PC", "2026-10-01T08:00:00Z"), dev("d2", "JSMITH-LAPTOP", "2026-11-05T09:30:00Z")}})
		case strings.HasSuffix(p, "/ownedDevices/microsoft.graph.device"):
			out(200, J{"value": []J{}})
		case p == "/api/v1/organizations/1/networks":
			out(200, []J{{"id": "L_1", "name": "HQ"}})
		case p == "/api/v1/networks/L_1/clients":
			out(200, []J{{"id": "k1", "mac": "aa:bb:cc:00:00:01", "description": "jsmith-laptop", "ip": "10.1.1.5", "recentDeviceSerial": "Q2AB-CDEF-GHIJ", "recentDeviceConnection": "Wired", "lastSeen": 1000}})
		case p == "/api/v1/networks/L_1/clients/k1/usageHistory":
			out(200, []J{{"ts": 1, "sent": 1, "received": 2}})
		case p == "/api/v1/organizations/1/devices/statuses":
			out(200, []J{{"serial": "Q2AB-CDEF-GHIJ", "status": "online"}})
		default:
			out(404, J{})
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	e, post := mcpEnv(t, acl...)
	dc, _, err := e.mg.LiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "app", Username: "APPID", Password: "S3CRET"}, {Name: "key", Token: "KEY"}}
	dc.Settings.Devices = []device.Device{
		{Name: "entra", Platform: "entra", Address: host, Port: pn, Credential: "app", Insecure: true, Options: map[string]string{"tenant": "t1", "login_host": srv.Listener.Addr().String()}},
		{Name: "mer", Platform: "meraki", Address: host, Port: pn, Credential: "key", Insecure: true, Options: map[string]string{"org": "1"}},
		{Name: "mer-sw", Platform: "meraki", Address: host, Port: pn, Credential: "key", Insecure: true, Options: map[string]string{"org": "1", "serial": "Q2AB-CDEF-GHIJ"}}}
	if err := e.mg.PutConfig(dc, "test", "devices"); err != nil {
		t.Fatal(err)
	}
	return e, post
}

func TestDeviceTroubleshoot(t *testing.T) {
	e, _ := troubleEnv(t)
	v, err := e.mg.Op("device.troubleshoot", json.RawMessage(`{"user":"joe@contoso.com"}`), "alice")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var r struct {
		EntraDevice  string `json:"entra_device"`
		MerakiDevice string `json:"meraki_device"`
		Count        int    `json:"device_count"`
		Hours        int    `json:"window_hours"`
		Notes        []string
		Devices      []struct {
			Entra   map[string]any
			Network struct {
				Matches []struct {
					Client map[string]any
					Usage  any
				}
			}
		}
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if r.EntraDevice != "entra" || r.MerakiDevice != "mer" || r.Count != 2 || r.Hours != 6 || len(r.Devices) != 1 {
		t.Fatalf("answer: %s", b)
	}
	d := r.Devices[0]
	if d.Entra["displayName"] != "JSMITH-LAPTOP" || len(d.Network.Matches) != 1 || d.Network.Matches[0].Client["ip"] != "10.1.1.5" || d.Network.Matches[0].Usage == nil {
		t.Fatalf("most recent device: %s", b)
	}
	// two devices: the older one was not seen on the network, and that is said
	v, err = e.mg.Op("device.troubleshoot", json.RawMessage(`{"user":"joe@contoso.com","devices":"2","hours":"12"}`), "alice")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(v)
	if !strings.Contains(string(b), "OLD-PC") || !strings.Contains(string(b), "no Meraki client by that name") || !strings.Contains(string(b), `"window_hours":12`) {
		t.Errorf("two devices: %s", b)
	}
	for _, bad := range []string{`{}`, `{"user":"joe@contoso.com","hours":"0"}`, `{"user":"joe@contoso.com","hours":"500"}`, `{"user":"joe@contoso.com","devices":"9"}`,
		`{"user":"joe@contoso.com","entra":"mer"}`, `{"user":"joe@contoso.com","meraki":"mer-sw"}`, `{"user":"nobody@contoso.com"}`} {
		if v, err := e.mg.Op("device.troubleshoot", json.RawMessage(bad), "alice"); err == nil {
			b, _ := json.Marshal(v)
			if !strings.Contains(string(b), "no network lookup") { // a named device that cannot be used is an error or a note
				t.Errorf("%s accepted: %s", bad, b)
			}
		}
	}
}

func TestMCPTroubleshootReadOnly(t *testing.T) {
	_, post := troubleEnv(t, "127.0.0.1") // a read-only key
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if !strings.Contains(strings.Join(toolNames(t, m), ","), "device_troubleshoot_user") {
		t.Fatal("a read-only caller is not offered device_troubleshoot_user")
	}
	_, m = post(mcpCall("device_troubleshoot_user", `{"user":"joe@contoso.com"}`))
	txt, isErr := toolResult(t, m)
	if isErr || !strings.Contains(txt, "JSMITH-LAPTOP") || !strings.Contains(txt, "10.1.1.5") {
		t.Fatalf("ro call: %v %s", isErr, txt)
	}
	if strings.Contains(txt, "S3CRET") || strings.Contains(txt, "KEY") {
		t.Error("a secret in the answer")
	}
}

func TestShortCommand(t *testing.T) {
	for in, want := range map[string]string{
		"tshoot msmith":    "--troubleshoot-user msmith",
		"tshoot msmith 12": "--troubleshoot-user msmith --troubleshoot-hours 12",
		"tshoot joe@contoso.com 3 --log-level debug": "--troubleshoot-user joe@contoso.com --troubleshoot-hours 3 --log-level debug",
		"--tshoot":             "--tshoot",
		"tshoot":               "tshoot",
		"tshoot --all-nodes":   "tshoot --all-nodes",
		"--tshoot --all-nodes": "--tshoot --all-nodes",
	} {
		if got := strings.Join(shortCommand(strings.Fields(in)), " "); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
