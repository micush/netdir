package main

import (
	"context"
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

type rawSwitch struct {
	mu    sync.Mutex
	ntp   string
	calls []string
}

// rawEnv is mcpEnv with a stub IOS-XE switch holding one RESTCONF resource (ntp) that takes GET and PATCH.
func rawEnv(t *testing.T, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any), *rawSwitch) {
	t.Helper()
	sw := &rawSwitch{ntp: `{"Cisco-IOS-XE-native:ntp":{"server":"alpha"}}`}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw.mu.Lock()
		defer sw.mu.Unlock()
		const ntp = "/restconf/data/Cisco-IOS-XE-native:native/ntp"
		switch {
		case r.URL.Path == "/restconf/data/Cisco-IOS-XE-native:native/hostname":
			_, _ = w.Write([]byte(`{"Cisco-IOS-XE-native:hostname":"sw1"}`))
		case r.URL.Path == ntp && r.Method == "GET":
			_, _ = w.Write([]byte(sw.ntp))
		case r.URL.Path == ntp && r.Method == "PATCH":
			b, _ := io.ReadAll(r.Body)
			sw.calls = append(sw.calls, "PATCH")
			sw.ntp = string(b)
			w.WriteHeader(204)
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
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: host, Port: p, Credential: "lab", Insecure: true},
		{Name: "n9k", Platform: "nxos", Address: host, Port: p, Credential: "lab", Insecure: true}}
	if err := e.mg.PutConfig(dc, "test", "devices"); err != nil {
		t.Fatal(err)
	}
	return e, post, sw
}

func TestMCPDeviceChangeRaw(t *testing.T) {
	_, post, sw := rawEnv(t, "127.0.0.1")
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if strings.Contains(strings.Join(toolNames(t, m), ","), "device_change_raw") {
		t.Error("a read-only caller is offered device_change_raw")
	}
	args := `{"target":"sw1","method":"PATCH","path":"/restconf/data/Cisco-IOS-XE-native:native/ntp","body":"{\"Cisco-IOS-XE-native:ntp\":{\"server\":\"beta\"}}"`
	_, m = post(mcpCall("device_change_raw", args+`}`))
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "read-only") || len(sw.calls) != 0 {
		t.Errorf("ro call: %v %s", isErr, txt)
	}

	_, post, sw = rawEnv(t, "127.0.0.1 rw")
	_, m = post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if !strings.Contains(strings.Join(toolNames(t, m), ","), "device_change_raw") {
		t.Fatal("device_change_raw is not offered to an rw caller")
	}
	call := func(a string) (string, bool) {
		_, m := post(mcpCall("device_change_raw", a))
		return toolResult(t, m)
	}
	txt, isErr := call(args + `,"dry_run":true}`)
	if isErr || !strings.Contains(txt, "alpha") || len(sw.calls) != 0 {
		t.Fatalf("plan: %v %s %v", isErr, txt, sw.calls)
	}
	txt, isErr = call(args + `}`)
	if isErr || len(sw.calls) != 1 || !strings.Contains(sw.ntp, "beta") {
		t.Fatalf("change: %v %s %v", isErr, txt, sw.calls)
	}
	// refused: nothing reaches the switch
	sw.calls = nil
	for _, bad := range []string{`{"target":"sw1"}`, `{"method":"PATCH","path":"/restconf/data/x","body":"{}"}`,
		`{"target":"sw1","method":"POST","path":"/restconf/operations/cisco-ia:save-config"}`,
		`{"target":"sw1","method":"PATCH","path":"/restconf/data/x","lines":"a"}`,
		`{"target":"sw1","method":"PATCH","path":"/restconf/data/x"}`} {
		if txt, isErr := call(bad); !isErr && !strings.Contains(txt, `"failed": 1`) && !strings.Contains(txt, `"failed":1`) {
			t.Errorf("%s was accepted: %s", bad, txt)
		}
	}
	if len(sw.calls) != 0 {
		t.Errorf("a refused request reached the switch: %v", sw.calls)
	}
	// one device failing does not stop the other: n9k is asked for a REST path and says so
	txt, isErr = call(`{"target":"sw1,n9k","method":"PATCH","path":"/restconf/data/Cisco-IOS-XE-native:native/ntp","body":"{\"a\":1}"}`)
	if isErr || !strings.Contains(txt, "lines of configuration") || len(sw.calls) != 1 {
		t.Errorf("mixed: %v %s %v", isErr, txt, sw.calls)
	}
}

func TestDeviceRawRouteReadOnlySession(t *testing.T) {
	e, _, sw := rawEnv(t)
	body := `{"target":"sw1","method":"PATCH","path":"/restconf/data/Cisco-IOS-XE-native:native/ntp","body":"{\"a\":1}"}`
	for _, ro := range []bool{true, false} {
		req := httptest.NewRequest("POST", "/api/devices/raw", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), proxyCtxKey{}, &session{user: "u", readOnly: ro, created: time.Now()})
		rec := httptest.NewRecorder()
		e.ws.Handler().ServeHTTP(rec, req.WithContext(ctx))
		if ro && (rec.Code != http.StatusForbidden || len(sw.calls) != 0) {
			t.Errorf("read-only: %d %s", rec.Code, rec.Body)
		}
		if !ro && (rec.Code != http.StatusOK || len(sw.calls) != 1) {
			t.Errorf("rw: %d %s", rec.Code, rec.Body)
		}
	}
}
