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

// merakiClientStub is a dashboard with two networks: HQ (JSMITH-LAPTOP on Wi-Fi, an unrelated client) and Branch (the same laptop,
// wired, on port 5 of a switch, under its name with a domain).  Anything not listed is a test failure, and so is any request but a GET.
func merakiClientStub(t *testing.T) (Device, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		out := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if r.Method != "GET" {
			t.Errorf("%s %s", r.Method, r.URL)
		}
		p := strings.TrimPrefix(r.URL.Path, "/api/v1")
		seen = append(seen, p)
		switch p {
		case "/organizations/1/networks":
			out(200, []J{{"id": "L_1", "name": "HQ", "productTypes": []string{"wireless", "switch"}}, {"id": "L_2", "name": "Branch", "productTypes": []string{"switch"}},
				{"id": "L_3", "name": "Cameras", "productTypes": []string{"camera", "sensor"}}, {"id": "L_4", "name": "Broken", "productTypes": []string{"wireless"}}})
		case "/networks/L_4/clients": // a network the dashboard fails on: the others still answer
			out(502, J{"errors": []string{"Internal server error"}})
		case "/networks/L_1/wireless/signalQualityHistory":
			if q := r.URL.Query(); q.Get("clientId") != "k1" && q.Get("clientId") != "k7" || q.Get("timespan") != "21600" || q.Get("autoResolution") != "true" {
				t.Errorf("signalQualityHistory %v", q)
			}
			out(200, []J{{"startTs": "2026-11-05T09:00:00Z", "endTs": "2026-11-05T09:05:00Z", "snr": nil, "rssi": nil}, {"startTs": "2026-11-05T09:05:00Z", "endTs": "2026-11-05T09:10:00Z", "snr": 31, "rssi": -58},
				{"startTs": "2026-11-05T09:10:00Z", "endTs": "2026-11-05T09:15:00Z", "snr": 12, "rssi": -81}})
		case "/networks/L_1/wireless/dataRateHistory":
			out(200, []J{{"startTs": "2026-11-05T09:10:00Z", "endTs": "2026-11-05T09:15:00Z", "averageKbps": 86000, "downloadKbps": 120000, "uploadKbps": 52000}, {"startTs": "x", "endTs": "y", "averageKbps": nil}})
		case "/networks/L_1/wireless/latencyHistory":
			out(404, J{})
		case "/networks/L_1/clients/k7/usageHistory", "/networks/L_1/clients/k7/policy", "/networks/L_1/wireless/clients/k7/connectionStats", "/networks/L_1/wireless/clients/k7/latencyStats", "/networks/L_1/wireless/clients/k7/connectivityEvents":
			out(200, []J{})
		case "/networks/L_1/clients":
			if r.URL.Query().Get("timespan") != "21600" {
				t.Errorf("timespan %q", r.URL.Query().Get("timespan"))
			}
			out(200, []J{{"id": "k1", "mac": "aa:bb:cc:00:00:01", "description": "JSMITH-LAPTOP", "ip": "10.1.1.5", "recentDeviceSerial": "Q2AB-CDEF-GHIJ", "recentDeviceConnection": "Wireless", "ssid": "corp", "lastSeen": 1000},
				{"id": "k9", "description": "OTHER-PC", "lastSeen": 3000},
				{"id": "k7", "mac": "aa:bb:cc:00:00:07", "description": "Joes-iPhone", "user": "CORP\\jsmith", "ip": "10.1.1.77", "recentDeviceSerial": "Q2AB-CDEF-GHIJ", "recentDeviceName": "AP-Lobby", "recentDeviceConnection": "Wireless", "ssid": "corp", "lastSeen": 900}})
		case "/networks/L_2/clients":
			out(200, []J{{"id": "k3", "mac": "aa:bb:cc:00:00:01", "description": "jsmith-laptop.corp.local", "ip": "10.2.2.9", "switchport": "5", "recentDeviceSerial": "Q2SW-ITCH-0001", "recentDeviceConnection": "Wired", "lastSeen": 2000}})
		case "/networks/L_1/clients/k1/usageHistory", "/networks/L_2/clients/k3/usageHistory":
			out(200, []J{{"ts": 1, "sent": 10, "received": 20}})
		case "/networks/L_1/clients/k1/policy":
			out(200, J{"devicePolicy": "Normal"})
		case "/networks/L_2/clients/k3/policy":
			out(404, J{})
		case "/networks/L_1/wireless/clients/k1/connectionStats":
			out(200, J{"connectionStats": J{"assoc": 0, "auth": 0, "dhcp": 2, "dns": 0, "success": 40}})
		case "/networks/L_1/wireless/clients/k1/latencyStats":
			out(400, J{"errors": []string{"no latency stats"}})
		case "/networks/L_1/wireless/clients/k1/connectivityEvents":
			out(200, []J{{"type": "dhcp", "subtype": "timeout"}})
		case "/networks/L_1/wireless/failedConnections":
			if id := r.URL.Query().Get("clientId"); id != "k1" && id != "k7" {
				t.Errorf("failedConnections %v", r.URL.Query())
			}
			out(200, []J{})
		case "/devices/Q2SW-ITCH-0001/switch/ports/statuses":
			out(200, []J{{"portId": "4", "status": "Disconnected"}, {"portId": "5", "status": "Connected", "speed": "1 Gbps", "duplex": "full", "errors": []string{"CRC align errors"}}})
		case "/organizations/1/devices/statuses":
			out(200, []J{{"serial": r.URL.Query().Get("serials[]"), "status": "online", "lastReportedAt": "2026-11-05T10:00:00Z"}})
		default:
			t.Errorf("unexpected GET %s", r.URL)
			out(404, J{})
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "mer", Platform: "meraki", Address: h, Port: pn, Insecure: true, Options: map[string]string{"org": "1"}}, &seen
}

func TestMerakiClientReport(t *testing.T) {
	merakiWait = 1
	d, seen := merakiClientStub(t)
	drv, err := Open(d, Credential{Name: "k", Token: "KEY"})
	if err != nil {
		t.Fatal(err)
	}
	cr, ok := drv.(ClientReporter)
	if !ok {
		t.Fatal("no ClientReporter")
	}
	rep, err := cr.ClientReport(context.Background(), ClientQuery{Names: []string{"jsmith-laptop"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep)
	js := string(b)
	ms, _ := rep["matches"].([]map[string]any)
	if len(ms) != 2 || rep["networks_searched"] != 2 || rep["window_hours"] != 6 {
		t.Fatalf("report: %s", js)
	}
	// the camera network is not asked, and the one the dashboard fails on is named without costing the others
	for _, p := range *seen {
		if strings.Contains(p, "L_3") {
			t.Errorf("a network without clients was asked: %s", p)
		}
	}
	if !strings.Contains(js, "network L_4 could not be searched") {
		t.Errorf("the network that failed is not named: %v", rep["notes"])
	}
	// the one seen last (the wired one at Branch) comes first? both are reported; find them by network
	byNet := map[string]map[string]any{}
	for _, m := range ms {
		byNet[m["network"].(map[string]any)["id"].(string)] = m
	}
	w, c := byNet["L_1"], byNet["L_2"]
	if w == nil || c == nil {
		t.Fatalf("matches: %s", js)
	}
	conn := w["connection"].(map[string]any)
	if conn["stats"].(map[string]any)["connectionStats"] == nil || conn["latency"].(map[string]any)["unavailable"] == nil || conn["connectivity_events"] == nil || conn["failed_connections"] == nil {
		t.Errorf("wireless parts: %v", conn)
	}
	// the Wi-Fi: the signal over time without the empty intervals, the newest reading as "now", the data rate, and a part
	// the dashboard does not have said as such
	now := conn["now"].(map[string]any)
	if sig := conn["signal_quality"].([]any); len(sig) != 2 || now["rssi_dbm"] != float64(-81) || now["snr_db"] != float64(12) || now["ssid"] != "corp" {
		t.Errorf("signal: %v now %v", conn["signal_quality"], now)
	}
	if dr := conn["data_rate"].([]any); len(dr) != 1 || conn["latency_history"].(map[string]any)["unavailable"] == nil {
		t.Errorf("data rate and latency history: %v %v", conn["data_rate"], conn["latency_history"])
	}
	if w["switch_port"] != nil {
		t.Errorf("a wireless client got a switch port: %v", w["switch_port"])
	}
	if w["upstream"].(map[string]any)["status"] != "online" || w["policy"].(map[string]any)["devicePolicy"] != "Normal" {
		t.Errorf("parts: %v", w)
	}
	if c["connection"] != nil {
		t.Errorf("a wired client got wireless statistics")
	}
	sp := c["switch_port"].(map[string]any)
	if sp["portId"] != "5" || sp["speed"] != "1 Gbps" {
		t.Errorf("switch port: %v", sp)
	}
	if c["policy"].(map[string]any)["unavailable"] == nil {
		t.Errorf("a missing part is not said: %v", c["policy"])
	}
	if strings.Contains(js, "OTHER-PC") {
		t.Error("an unrelated client was reported")
	}
	// by the account a client signed in to the network with: the phone, whatever its name; the laptop is left out when it is
	// reported under its name already
	rep, err = cr.ClientReport(context.Background(), ClientQuery{Users: []string{"jsmith"}, NotNames: []string{"JSMITH-LAPTOP"}})
	if ms, _ := rep["matches"].([]map[string]any); err != nil || len(ms) != 1 || ms[0]["client"].(map[string]any)["description"] != "Joes-iPhone" ||
		ms[0]["connection"].(map[string]any)["now"].(map[string]any)["ap"] != "AP-Lobby" {
		t.Fatalf("by user: %v %v", rep, err)
	}
	// by MAC alone; one network; a window of 6 hours is the default, other windows are sent as seconds
	*seen = nil
	rep, err = cr.ClientReport(context.Background(), ClientQuery{MACs: []string{"AA-BB-CC-00-00-01"}, Network: "L_2", Hours: 6})
	if err != nil || len(rep["matches"].([]map[string]any)) != 1 {
		t.Fatalf("by mac: %v %v", rep, err)
	}
	for _, p := range *seen {
		if strings.Contains(p, "L_1") || p == "/organizations/1/networks" {
			t.Errorf("one network was asked for but %s was read", p)
		}
	}
	for _, bad := range []ClientQuery{{}, {Names: []string{"x"}, Network: "../x"}} {
		if _, err := cr.ClientReport(context.Background(), bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	d2 := d
	d2.Options = map[string]string{"org": "1", "serial": "Q2AB-CDEF-GHIJ"}
	drv2, _ := Open(d2, Credential{Name: "k", Token: "KEY"})
	if _, err := drv2.(ClientReporter).ClientReport(context.Background(), ClientQuery{Names: []string{"x"}}); err == nil {
		t.Error("a single Meraki device gave a client report")
	}
}
