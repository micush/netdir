package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"netdir/device"
)

// "show the observium device ipam2" through the MCP endpoint: device_show on the Observium device with "show device ipam2" answers
// everything about that monitored device, and what the MCP layer hides stays hidden (SNMP secrets, public addresses, serial
// numbers).  The stub is a minimal Observium: its field names are the ones the driver reads, not a recording of a real one.
func TestMCPObserviumShowDevice(t *testing.T) {
	obs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer OBSTOKEN" {
			http.Error(w, `{"status":"failed","message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request: %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/api/v0/devices/" && q.Get("fields") != "":
			_, _ = w.Write([]byte(`{"status":"ok","count":1,"devices":{"12":{"device_id":"12","hostname":"ipam2.example.com","sysName":"ipam2"}}}`))
		case r.URL.Path == "/api/v0/devices/12/":
			_, _ = w.Write([]byte(`{"status":"ok","count":1,"devices":{"12":{"device_id":"12","hostname":"ipam2.example.com","sysName":"ipam2","hardware":"VMware","version":"Ubuntu 22.04","serial":"SN-SECRET-12","snmp_community":"obs-community-secret","snmp_authpass":"obs-authpass-secret"}}}`))
		case strings.HasPrefix(r.URL.Path, "/api/v0/devices/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"failed","message":"Device not found"}`))
		case r.URL.Path == "/api/v0/ports/" && q.Get("device_id") == "12":
			_, _ = w.Write([]byte(`{"status":"ok","count":1,"ports":{"101":{"port_id":"101","ifName":"eth0","ifOperStatus":"up","ifSpeed":"1000000000"}}}`))
		case r.URL.Path == "/api/v0/neighbours/" && q.Get("device_id") == "12":
			_, _ = w.Write([]byte(`{"status":"ok","count":1,"neighbours":[{"port_id":"101","remote_hostname":"edge1","remote_address":"8.8.4.4","protocol":"LLDP","active":"1"},{"port_id":"101","remote_hostname":"core1","remote_address":"10.0.0.1","protocol":"LLDP","active":"1"}]}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok","count":0}`))
		}
	}))
	t.Cleanup(obs.Close)
	host, port, _ := net.SplitHostPort(obs.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	e, post := mcpEnv(t, "127.0.0.1")
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.DeviceCredentials = []device.Credential{{Name: "obskey", Token: "OBSTOKEN"}}
	sup.dc.Settings.Devices = []device.Device{{Name: "obs", Platform: "observium", Address: host, Port: p, Credential: "obskey", Insecure: true}}
	sup.mu.Unlock()

	_, m := post(mcpCall("device_show", `{"target":"obs","command":"show device ipam2"}`))
	txt, isErr := toolResult(t, m)
	if isErr {
		t.Fatalf("device_show: %s", txt)
	}
	for _, want := range []string{"ipam2.example.com", "eth0", "edge1", "core1", "10.0.0.1", "VMware", "Ubuntu 22.04"} {
		if !strings.Contains(txt, want) {
			t.Errorf("the answer lacks %q: %s", want, txt)
		}
	}
	for _, secret := range []string{"obs-community-secret", "obs-authpass-secret", "SN-SECRET-12", "8.8.4.4"} {
		if strings.Contains(txt, secret) {
			t.Errorf("the answer shows %q: %s", secret, txt)
		}
	}
	if !strings.Contains(txt, "PUBLIC-IP-") || !strings.Contains(txt, "****T-12") {
		t.Errorf("the public address is not a token or the serial number is not shown by its last four characters: %s", txt)
	}
	// the other reads of the same driver
	_, m = post(mcpCall("device_facts", `{"target":"obs"}`))
	if txt, isErr = toolResult(t, m); isErr || !strings.Contains(txt, "Observium") {
		t.Errorf("device_facts: %s", txt)
	}
	_, m = post(mcpCall("device_api_get", `{"target":"obs","path":"/devices/12/"}`))
	if txt, isErr = toolResult(t, m); isErr || !strings.Contains(txt, "ipam2.example.com") || strings.Contains(txt, "obs-community-secret") {
		t.Errorf("device_api_get: %s", txt)
	}
	// nothing that writes is a tool for it
	_, m = post(mcpCall("device_show", `{"target":"obs","command":"reload"}`))
	if _, isErr = toolResult(t, m); !isErr {
		t.Error("a command that is not a show was not refused")
	}
}
