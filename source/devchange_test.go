package main

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
	"time"

	"netdir/device"
)

type chgSwitch struct {
	mu    sync.Mutex
	desc  map[string]string // "1/0/1" -> description
	down  map[string]bool
	calls []string
}

// chgEnv is mcpEnv with a stub IOS-XE switch that keeps its interface configuration and takes RESTCONF PATCH and DELETE, in the
// inventory (the config file, which Mgmt.deviceChange reads).
func chgEnv(t *testing.T, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any), *chgSwitch) {
	t.Helper()
	sw := &chgSwitch{desc: map[string]string{"1/0/1": "old", "1/0/2": "", "1/0/3": "devices"}, down: map[string]bool{}}
	const base = "/restconf/data/Cisco-IOS-XE-native:native/interface"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "admin" || p != "sw-secret-pw" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sw.mu.Lock()
		defer sw.mu.Unlock()
		ep := r.URL.EscapedPath()
		switch {
		case r.Method == http.MethodGet && ep == base:
			var l []any
			for _, n := range []string{"1/0/1", "1/0/2", "1/0/3"} {
				e := map[string]any{"name": n}
				if sw.desc[n] != "" {
					e["description"] = sw.desc[n]
				}
				if sw.down[n] {
					e["shutdown"] = []any{nil}
				}
				l = append(l, e)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Cisco-IOS-XE-native:interface": map[string]any{"GigabitEthernet": l}})
		case r.Method == http.MethodGet && ep == "/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface":
			_, _ = w.Write([]byte(`{"Cisco-IOS-XE-interfaces-oper:interface":[]}`))
		case r.Method == http.MethodPatch && ep == base:
			sw.calls = append(sw.calls, "PATCH")
			b, _ := io.ReadAll(r.Body)
			var body struct {
				I map[string][]map[string]any `json:"Cisco-IOS-XE-native:interface"`
			}
			_ = json.Unmarshal(b, &body)
			for _, e := range body.I["GigabitEthernet"] {
				n := e["name"].(string)
				if d, ok := e["description"]; ok {
					sw.desc[n] = d.(string)
				}
				if _, ok := e["shutdown"]; ok {
					sw.down[n] = true
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(ep, base+"/GigabitEthernet="):
			sw.calls = append(sw.calls, "DELETE")
			parts := strings.Split(strings.TrimPrefix(ep, base+"/GigabitEthernet="), "/")
			n := strings.ReplaceAll(parts[0], "%2F", "/")
			if parts[1] == "description" {
				sw.desc[n] = ""
			} else {
				sw.down[n] = false
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	e, post := mcpEnv(t, acl...)
	dc, _, err := e.mg.LiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "admin", Password: "sw-secret-pw"}}
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: host, Port: p, Credential: "lab", Insecure: true, Tags: []string{"site=home"}},
		{Name: "fw1", Platform: "nxos", Address: host, Port: p, Credential: "lab", Insecure: true}}
	if err := e.mg.PutConfig(dc, "test", "devices"); err != nil {
		t.Fatal(err)
	}
	return e, post, sw
}

func TestMCPDeviceChange(t *testing.T) {
	// ro: the tool is not listed and a call is refused; nothing reaches the switch
	_, post, sw := chgEnv(t, "127.0.0.1")
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if strings.Contains(strings.Join(toolNames(t, m), ","), "device_change") {
		t.Error("a read-only caller is offered device_change")
	}
	_, m = post(mcpCall("device_change", `{"target":"sw1","text":"shut down gi1/0/1"}`))
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "read-only") || len(sw.calls) != 0 || sw.down["1/0/1"] {
		t.Errorf("ro call: %v %s %v", isErr, txt, sw.calls)
	}
	// rw: the tool is listed, a plan changes nothing, the change happens, in English or typed
	_, post, sw = chgEnv(t, "127.0.0.1 rw")
	_, m = post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if !strings.Contains(strings.Join(toolNames(t, m), ","), "device_change") {
		t.Fatal("device_change is not offered to an rw caller")
	}
	call := func(args string) (string, bool) {
		_, m := post(mcpCall("device_change", args))
		return toolResult(t, m)
	}
	txt, isErr := call(`{"target":"sw1","text":"change the description for ports gi1/0/1-3 to read \"devices\"","dry_run":true}`)
	if isErr || !strings.Contains(txt, `"dry_run": true`) && !strings.Contains(txt, `"dry_run":true`) || !strings.Contains(txt, "old") || len(sw.calls) != 0 || sw.desc["1/0/1"] != "old" {
		t.Fatalf("plan: %v %s %v", isErr, txt, sw.calls)
	}
	txt, isErr = call(`{"target":"sw1","text":"change the description for ports gi1/0/1-3 to read \"devices\""}`)
	if isErr || sw.desc["1/0/1"] != "devices" || sw.desc["1/0/2"] != "devices" || len(sw.calls) != 1 {
		t.Fatalf("change: %v %s %v %+v", isErr, txt, sw.calls, sw.desc)
	}
	if txt, isErr = call(`{"target":"sw1","action":"clear_description","ports":"gi1/0/1-2"}`); isErr || sw.desc["1/0/1"] != "" || sw.desc["1/0/3"] != "devices" {
		t.Fatalf("typed: %v %s %+v", isErr, txt, sw.desc)
	}
	if txt, isErr = call(`{"target":"sw1","text":"shut down gi1/0/3"}`); isErr || !sw.down["1/0/3"] {
		t.Fatalf("shutdown: %v %s", isErr, txt)
	}
	// refused before any device is asked
	sw.calls = nil
	for _, bad := range []string{
		`{"target":"sw1"}`, `{"text":"shut down gi1/0/1"}`, `{"target":"sw1","text":"reload the switch"}`, `{"target":"nosuch","text":"shut down gi1/0/1"}`,
		`{"target":"sw1","text":"shut down gi1/0/1","action":"shutdown","ports":"gi1/0/1"}`, `{"target":"sw1","action":"reload","ports":"gi1/0/1"}`,
		`{"target":"sw1","action":"description","ports":"gi1/0/1","value":"a\nb"}`, `{"target":"sw1","action":"shutdown","ports":"gi1/0/99"}`,
	} {
		if txt, isErr := call(bad); !isErr && !strings.Contains(txt, `"failed": 1`) && !strings.Contains(txt, `"failed":1`) {
			t.Errorf("%s was accepted: %s", bad, txt)
		}
	}
	for _, c := range sw.calls {
		if c != "" {
			t.Errorf("a refused request reached the switch: %v", sw.calls)
		}
	}
	// a device of a platform with no writer answers its own error and does not stop the others
	txt, isErr = call(`{"target":"sw1,fw1","text":"clear the description on gi1/0/3"}`)
	if isErr || !strings.Contains(txt, "device_change_raw") || sw.desc["1/0/3"] != "" {
		t.Errorf("mixed: %v %s", isErr, txt)
	}
}

func TestDeviceChangeRouteReadOnlySession(t *testing.T) {
	e, _, sw := chgEnv(t)
	body := `{"target":"sw1","text":"shut down gi1/0/1"}`
	for _, ro := range []bool{true, false} {
		req := httptest.NewRequest("POST", "/api/devices/change", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), proxyCtxKey{}, &session{user: "u", readOnly: ro, created: time.Now()})
		rec := httptest.NewRecorder()
		e.ws.Handler().ServeHTTP(rec, req.WithContext(ctx))
		if ro && (rec.Code != http.StatusForbidden || sw.down["1/0/1"]) {
			t.Errorf("read-only: %d %s %v", rec.Code, rec.Body, sw.down)
		}
		if !ro && (rec.Code != http.StatusOK || !sw.down["1/0/1"]) {
			t.Errorf("rw: %d %s", rec.Code, rec.Body)
		}
	}
}
