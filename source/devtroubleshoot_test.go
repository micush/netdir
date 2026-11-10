package main

import (
	"encoding/json"
	"fmt"
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
	return troubleEnvWith(t, false, acl...)
}

// troubleLogQueries are the log searches the stub Panorama of troubleEnvWith got, "log-type: query".
var troubleLogQueries []string

// troubleEnvWith is troubleEnv, with a Panorama in the inventory when pan is set.  The stub also answers as that Panorama: its
// GlobalProtect log says Joe connected with JSMITH-LAPTOP (and before that with JSMITH-HOME), its traffic log has one entry.
func troubleEnvWith(t *testing.T, pan bool, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any)) {
	t.Helper()
	troubleLogQueries = nil
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
		case p == "/api/": // the Panorama's XML API: a log search is a job that has finished when it is read
			q := r.URL.Query()
			xml := func(x string) {
				_, _ = w.Write([]byte(`<response status="success"><result>` + x + `</result></response>`))
			}
			if r.Header.Get("X-PAN-KEY") != "PANKEY" || q.Get("type") != "log" {
				w.WriteHeader(403)
				return
			}
			jobs := map[string]string{"globalprotect": "1", "traffic": "2", "threat": "3"}
			switch q.Get("action") {
			case "":
				troubleLogQueries = append(troubleLogQueries, q.Get("log-type")+": "+q.Get("query"))
				xml(`<job>` + jobs[q.Get("log-type")] + `</job>`)
			case "get":
				fin := `<job><status>FIN</status><id>` + q.Get("job-id") + `</id></job><log><logs count="1" progress="100">`
				switch q.Get("job-id") {
				case "1":
					xml(fin + `<entry logid="9"><receive_time>2026/11/10 09:00:00</receive_time><srcuser>contoso\joe</srcuser><machinename>JSMITH-LAPTOP</machinename><eventid>gateway-connected</eventid><status>success</status><public_ip>151.101.1.7</public_ip><private_ip>10.9.9.9</private_ip></entry>` +
						`<entry logid="8"><receive_time>2026/11/09 20:00:00</receive_time><srcuser>contoso\joe</srcuser><machinename>JSMITH-HOME</machinename><eventid>gateway-logout</eventid><private_ip>10.9.9.8</private_ip></entry></logs></log>`)
				case "2":
					xml(fin + `<entry logid="5"><receive_time>2026/11/10 09:01:00</receive_time><src>10.1.1.5</src><dst>192.0.2.53</dst><app>dns</app><action>allow</action><rule>out</rule></entry></logs></log>`)
				default:
					xml(`<job><status>FIN</status><id>3</id></job><log><logs count="0" progress="100"/></log>`)
				}
			default:
				xml("")
			}
		case p == "/v1.0/devices":
			if strings.Contains(strings.ToLower(r.URL.Query().Get("$filter")), "'jsmith-laptop'") {
				out(200, J{"value": []J{dev("22222222-2222-3333-4444-555555555555", "JSMITH-LAPTOP", "2026-11-05T09:30:00Z")}})
			} else {
				out(200, J{"value": []J{}})
			}
		case p == "/v1.0/devices/22222222-2222-3333-4444-555555555555/registeredUsers":
			out(200, J{"value": []J{{"id": "11111111-2222-3333-4444-555555555555", "displayName": "Joe Smith", "userPrincipalName": "joe@contoso.com"}}})
		case p == "/v1.0/devices/22222222-2222-3333-4444-555555555555/registeredOwners":
			out(200, J{"value": []J{}})
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
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "app", Username: "APPID", Password: "S3CRET"}, {Name: "key", Token: "KEY"}, {Name: "pan", Token: "PANKEY"}}
	dc.Settings.Devices = []device.Device{
		{Name: "entra", Platform: "entra", Address: host, Port: pn, Credential: "app", Insecure: true, Options: map[string]string{"tenant": "t1", "login_host": srv.Listener.Addr().String()}},
		{Name: "mer", Platform: "meraki", Address: host, Port: pn, Credential: "key", Insecure: true, Options: map[string]string{"org": "1"}},
		{Name: "mer-sw", Platform: "meraki", Address: host, Port: pn, Credential: "key", Insecure: true, Options: map[string]string{"org": "1", "serial": "Q2AB-CDEF-GHIJ"}}}
	if pan {
		dc.Settings.Devices = append(dc.Settings.Devices, device.Device{Name: "pano", Platform: "panorama", Address: host, Port: pn, Credential: "pan", Insecure: true})
	}
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
		"--tshoot":                   "--tshoot",
		"tshoot":                     "tshoot",
		"tshoot user msmith":         "--troubleshoot-user msmith",
		"tshoot user msmith 12":      "--troubleshoot-user msmith --troubleshoot-hours 12",
		"tshoot host PC-123":         "--troubleshoot-host PC-123",
		"troubleshoot host PC-123 3": "--troubleshoot-host PC-123 --troubleshoot-hours 3",
		"troubleshoot user msmith":   "--troubleshoot-user msmith",
		"troubleshoot msmith 12":     "--troubleshoot-user msmith --troubleshoot-hours 12",
		"tshoot host":                "--troubleshoot-user host",
		"tshoot user --yes":          "--troubleshoot-user user --yes",
		"troubleshoot":               "troubleshoot",
		"troubleshoot --all-nodes":   "troubleshoot --all-nodes",
		"tshoot --all-nodes":         "tshoot --all-nodes",
		"--tshoot --all-nodes":       "--tshoot --all-nodes",
	} {
		if got := strings.Join(shortCommand(strings.Fields(in)), " "); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// tsAnswer is the answer of device.troubleshoot as JSON text and as a tree.
func tsAnswer(t *testing.T, e *webEnv, args string) (string, map[string]any) {
	t.Helper()
	v, err := e.mg.Op("device.troubleshoot", json.RawMessage(args), "alice")
	if err != nil {
		t.Fatalf("%s: %v", args, err)
	}
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return string(b), m
}

func TestTroubleshootUserWithFirewallLogs(t *testing.T) {
	e, _ := troubleEnvWith(t, true)
	txt, m := tsAnswer(t, e, `{"user":"joe@contoso.com"}`)
	if m["entra_device"] != "entra" || m["panorama_device"] != "pano" || m["meraki_device"] != "mer" {
		t.Fatalf("the systems asked: %s", txt)
	}
	vpn := m["vpn"].(map[string]any)
	if vpn["query"] != "(srcuser contains 'joe')" || vpn["last"].(map[string]any)["machinename"] != "JSMITH-LAPTOP" || len(vpn["events"].([]any)) != 2 {
		t.Errorf("vpn: %s", txt)
	}
	// the Entra device and the VPN's machine are one; the machine only the VPN log knows is followed too
	ds := m["devices"].([]any)
	if len(ds) != 2 || ds[0].(map[string]any)["name"] != "JSMITH-LAPTOP" || ds[0].(map[string]any)["entra"] == nil || ds[1].(map[string]any)["name"] != "JSMITH-HOME" || ds[1].(map[string]any)["entra"] != nil {
		t.Errorf("devices: %s", txt)
	}
	fw := m["firewall"].(map[string]any)
	if got := fmt.Sprint(fw["addresses"]); got != "[10.9.9.9 10.9.9.8 10.1.1.5]" {
		t.Errorf("addresses: %s", got)
	}
	if fw["query"] != "(addr in 10.9.9.9) or (addr in 10.9.9.8) or (addr in 10.1.1.5)" || len(fw["traffic"].([]any)) != 1 || len(fw["threat"].([]any)) != 0 {
		t.Errorf("firewall: %s", txt)
	}
	if got := strings.Join(troubleLogQueries, " | "); got != "globalprotect: (srcuser contains 'joe') | traffic: "+fw["query"].(string)+" | threat: "+fw["query"].(string) {
		t.Errorf("the searches the firewall got: %s", got)
	}
	if strings.Contains(txt, "PANKEY") || strings.Contains(txt, "S3CRET") {
		t.Error("a secret in the answer")
	}
}

func TestTroubleshootHost(t *testing.T) {
	e, _ := troubleEnvWith(t, true)
	txt, m := tsAnswer(t, e, `{"host":"jsmith-laptop","hours":"12"}`)
	lu, _ := m["last_user"].(map[string]any)
	if m["host"] != "jsmith-laptop" || lu["name"] != `contoso\joe` || !strings.Contains(fmt.Sprint(lu["from"]), "VPN") {
		t.Fatalf("last user: %s", txt)
	}
	if m["vpn"].(map[string]any)["query"] != "(machinename contains 'jsmith-laptop')" {
		t.Errorf("vpn query: %s", txt)
	}
	ds := m["devices"].([]any)
	d0 := ds[0].(map[string]any)
	if len(ds) != 1 || d0["entra"].(map[string]any)["displayName"] != "JSMITH-LAPTOP" || !strings.Contains(txt, `"registered_users":[{"displayName":"Joe Smith"`) {
		t.Errorf("the Entra device and its users: %s", txt)
	}
	if !strings.Contains(txt, `"ip":"10.1.1.5"`) || m["firewall"] == nil || m["window_hours"] != float64(12) {
		t.Errorf("network and firewall: %s", txt)
	}
	// without a Panorama the users registered on the Entra device say who
	e, _ = troubleEnvWith(t, false)
	txt, m = tsAnswer(t, e, `{"host":"jsmith-laptop"}`)
	lu, _ = m["last_user"].(map[string]any)
	if lu["name"] != "joe@contoso.com" || !strings.Contains(fmt.Sprint(lu["from"]), "Entra") || m["vpn"] != nil || m["firewall"] != nil || !strings.Contains(txt, "no firewall logs") {
		t.Errorf("Entra only: %s", txt)
	}
	// a host nobody knows is an answer with notes, not an error
	txt, _ = tsAnswer(t, e, `{"host":"nosuch-pc"}`)
	if !strings.Contains(txt, "Entra has no device named nosuch-pc") || !strings.Contains(txt, "no Meraki client by that name") {
		t.Errorf("an unknown host: %s", txt)
	}
	for _, bad := range []string{`{"user":"joe@contoso.com","host":"pc"}`, `{"host":"a'b"}`, `{"host":"a b"}`, `{"host":"x) or (addr in 0.0.0.0/0"}`, `{"host":"pc","panorama":"mer"}`, `{"host":"pc","hours":"0"}`} {
		if _, err := e.mg.Op("device.troubleshoot", json.RawMessage(bad), "alice"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTroubleshootHostOverMCPReadOnly(t *testing.T) {
	_, post := troubleEnvWith(t, true, "127.0.0.1") // a read-only source
	_, m := post(mcpCall("device_troubleshoot_user", `{"host":"JSMITH-LAPTOP"}`))
	txt, isErr := toolResult(t, m)
	if isErr || !strings.Contains(txt, "last_user") || !strings.Contains(txt, "gateway-connected") {
		t.Fatalf("ro call: %v %s", isErr, txt)
	}
	if strings.Contains(txt, "PANKEY") || strings.Contains(txt, "151.101.1.7") {
		t.Errorf("a secret or a public address in the answer: %s", txt)
	}
}

func TestTroubleshootNames(t *testing.T) {
	for in, want := range map[string]string{"joe.smith@contoso.com": "joe.smith", `CORP\msmith`: "msmith", "msmith": "msmith", "Joe Smith": "", "11111111-2222-3333-4444-555555555555": "", "a'b": ""} {
		if got := tsShortUser(in); got != want {
			t.Errorf("tsShortUser(%q) = %q, want %q", in, got, want)
		}
	}
	devs := []device.Device{{Name: "fw1", Platform: "panos"}, {Name: "fw2", Platform: "panos"}, {Name: "pano", Platform: "panorama"}, {Name: "old", Platform: "panorama", Disabled: true}}
	if d, err := pickLogDevice(devs, ""); err != nil || d.Name != "pano" {
		t.Errorf("the Panorama comes first: %v %v", d.Name, err)
	}
	if d, err := pickLogDevice(devs, "fw2"); err != nil || d.Name != "fw2" {
		t.Errorf("a named firewall: %v %v", d.Name, err)
	}
	if _, err := pickLogDevice(devs[:2], ""); err == nil {
		t.Error("two firewalls and no name: one was picked")
	}
	if _, err := pickLogDevice(nil, ""); err == nil || !strings.Contains(err.Error(), "no enabled panorama or panos") {
		t.Errorf("none: %v", err)
	}
}
