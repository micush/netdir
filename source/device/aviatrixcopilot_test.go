package device

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const avcStatusText = `# HELP status gateway and tunnel status
status{gateway="transit-gw-1"} 1 1734006896789
status{gateway="spoke-gw-1"} 0 1734006896789
status{gateway="spoke-gw-2"} -1 1734006896789
status{tunnel="spoke-gw-1.transit-gw-1"} 1 1734006896789
status{tunnel="s2c-branch-office"} 0 1734006896789
bgp_status{gateway="transit-gw-1",bgp_neighbor="vgw(169.254.254.185)"} 1 1734006896789
bgp_status{gateway="transit-gw-1",bgp_neighbor="peer(10.0.0.1)"} 0 1734006896789
`

const avcMetricsText = `cpu_idle{gateway="spoke-gw-us-east-1"} 74.3 1734006896789
cpu_used_per{gateway="spoke-gw-us-east-1"} 25.7 1734006896789
memory_available{gateway="spoke-gw-us-east-1"} 3221225472 1734006896789
rate_received{gateway="spoke-gw-us-east-1", interface="eth0"} 125400.5 1734006896789
rate_pkt_drop{gateway="spoke-gw-us-east-1", interface="eth0"} 0 1734006896789
vcpu_avg_usage{gateway="spoke-gw-us-east-1", vcpu_name="0"} 30.5 1734006896789
cpu_idle{gateway="transit-gw-1"} 90 1734006896789
`

// avcStub is a CoPilot's Network Insights API: Bearer key, Prometheus text, JSON with ?format=json.
func avcStub(t *testing.T, key string, hits *[]string) (Device, Credential) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits = append(*hits, r.Method+" "+r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet || strings.Contains(r.URL.RawQuery, key) {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		json := r.URL.Query().Get("format") == "json"
		switch r.URL.Path {
		case "/status-api/v1/":
			if json {
				w.Write([]byte(`{"gateways":{"transit-gw-1":{"status":"up","lastUpdatedTimestamp":"2024-12-12T19:47:01.000Z"}}}`))
				return
			}
			w.Write([]byte(avcStatusText))
		case "/metrics-api/v1/gateways":
			w.Write([]byte(avcMetricsText))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return Device{Name: "cp", Platform: "aviatrixcopilot", Address: host, Port: p, Insecure: true}, Credential{Token: key}
}

func TestAviatrixCoPilotReads(t *testing.T) {
	var hits []string
	d, c := avcStub(t, "k3y", &hits)
	drv, err := Open(d, c)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Aviatrix" || !strings.Contains(f.Model, "3 gateways (1 up, 1 down, 1 degraded), 2 tunnels (1 up), 2 BGP neighbors (1 established)") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 3 || ifs[0].Name != "spoke-gw-1" || *ifs[0].OperUp || ifs[2].Name != "transit-gw-1" || !*ifs[2].OperUp {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	for show, want := range map[string]string{
		"show status":                       `"neighbor": "peer(10.0.0.1)"`,
		"show gateways":                     `"state": "degraded"`,
		"show tunnels":                      `s2c-branch-office`,
		"show bgp":                          `"state": "established"`,
		"show metrics":                      `"rate_received": 125400.5`,
		"show metrics gateway=transit-gw-1": `"cpu_idle": 90`,
		"show gateway transit-gw-1":         `"state": "up"`,
	} {
		out, err := drv.Show(ctx, show)
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("%s: %v\n%s", show, err, out)
		}
	}
	if out, _ := drv.Show(ctx, "show metrics"); strings.Contains(out, "transit-gw-1") != true || !strings.Contains(out, `"vcpus"`) {
		t.Errorf("metrics grouping: %s", out)
	}
	for _, bad := range []string{"show", "show nothing", "show gateway", "show gateway a b", "show metrics gateway=a;b", "show metrics x=1", "show status | grep x", "show gateway nosuch"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, h := range hits {
		if !strings.HasPrefix(h, "GET /status-api/v1/") && !strings.HasPrefix(h, "GET /metrics-api/v1/gateways") {
			t.Errorf("a request outside the two reads: %s", h)
		}
	}
}

func TestAviatrixCoPilotAPIAndRefusals(t *testing.T) {
	d, c := avcStub(t, "k3y", nil)
	drv, _ := Open(d, c)
	defer drv.Close(context.Background())
	api := drv.(APIer)
	ctx := context.Background()
	v, text, err := api.APIGet(ctx, "/status-api/v1/")
	if err != nil || text || v.(*avcStatusView).Gateways[0].Name != "spoke-gw-1" {
		t.Fatalf("status %v %v", v, err)
	}
	if _, _, err := api.APIGet(ctx, "/status-api/v1"); err != nil {
		t.Fatalf("without the final slash: %v", err)
	}
	if v, _, err := api.APIGet(ctx, "/status-api/v1/?format=json"); err != nil || !strings.Contains(toJSONString(v), "transit-gw-1") {
		t.Fatalf("json %v %v", v, err)
	}
	if v, _, err := api.APIGet(ctx, "/metrics-api/v1/gateways"); err != nil || !strings.Contains(toJSONString(v), "spoke-gw-us-east-1") {
		t.Fatalf("metrics %v %v", v, err)
	}
	for _, bad := range []string{"/", "/api/v1/users", "/status-api/v1/../x", "/metrics-api/v1/gateways?format=xml", "/metrics-api/v1/gateways?a=b", "//evil.example/status-api/v1/", "/status-api/v1/x"} {
		if _, _, err := api.APIGet(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if cat, err := api.APICatalog(ctx); err != nil || cat == nil {
		t.Errorf("catalog %v %v", cat, err)
	}
	// nothing can be changed
	rc := drv.(RawChanger)
	if _, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/status-api/v1/"}, false); err == nil || !strings.Contains(err.Error(), "only reads") {
		t.Errorf("a change was not refused: %v", err)
	}
	if _, err := drv.Config(ctx); err == nil {
		t.Error("config")
	}
	if _, err := drv.Neighbors(ctx); err == nil {
		t.Error("neighbors")
	}
}

func TestAviatrixCoPilotWrongKeyAndMissingAPI(t *testing.T) {
	d, _ := avcStub(t, "k3y", nil)
	drv, _ := Open(d, Credential{Token: "SECRETWRONG"})
	defer drv.Close(context.Background())
	_, err := drv.Facts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refused the API key") || strings.Contains(err.Error(), "SECRETWRONG") {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Open(d, Credential{Username: "u", Password: "p"}); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("no token: %v", err)
	}
	// a server that answers other text is not a CoPilot
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hello</html>")) }))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p := 0
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	drv2, _ := Open(Device{Name: "x", Platform: "aviatrixcopilot", Address: host, Port: p, Insecure: true}, Credential{Token: "k"})
	defer drv2.Close(context.Background())
	if _, err := drv2.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "not the CoPilot Network Insights API") {
		t.Fatalf("not a copilot: %v", err)
	}
	srv404 := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv404.Close()
	host, port, _ = net.SplitHostPort(srv404.Listener.Addr().String())
	p = 0
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	drv3, _ := Open(Device{Name: "y", Platform: "aviatrixcopilot", Address: host, Port: p, Insecure: true}, Credential{Token: "k"})
	defer drv3.Close(context.Background())
	if _, err := drv3.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "no Network Insights API") {
		t.Fatalf("404: %v", err)
	}
}

func TestAviatrixCoPilotParse(t *testing.T) {
	ss, err := avcParse([]byte("# c\nm{a=\"x y\", b=\"q\\\"r\"} 1.5e3 1734006896789\nplain 7\nbad line\nm{} NaNx\n"))
	if err != nil || len(ss) != 2 || ss[0].Labels["a"] != "x y" || ss[0].Labels["b"] != `q"r` || ss[0].Value != 1500 || ss[1].Name != "plain" {
		t.Fatalf("%+v %v", ss, err)
	}
	if _, err := avcParse([]byte("<html>\n")); err == nil {
		t.Error("html parsed")
	}
}
