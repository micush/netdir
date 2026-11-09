package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const uniTok = "uni-tok-9x4kq"
const uniDevUUID = "11111111-2222-3333-4444-555555555555"

type uniState struct {
	mu    sync.Mutex
	calls []string
	posts []string
}

func uniStub(t *testing.T, st *uniState, opts map[string]string) Device {
	cfg := "hostname sw1\nusername admin secret 9 $9$UNIPASS\nsnmp-server community unicomm RO\ninterface Vlan10\n ip address 10.1.1.1 255.255.255.0\n"
	d := tlsDevice(t, "uni", "unimus", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+uniTok {
			jout(w, 401, map[string]any{"error": "no"})
			return
		}
		st.calls = append(st.calls, r.Method+" "+r.URL.RequestURI())
		if r.Method != http.MethodGet {
			st.posts = append(st.posts, r.Method+" "+r.URL.Path)
			jout(w, 200, map[string]any{"id": "job1"})
			return
		}
		switch r.URL.Path {
		case "/api/v3/health":
			jout(w, 200, map[string]any{"status": "OK"})
		case "/api/v3/devices":
			if a := r.URL.Query().Get("addresses"); a != "" && a != "10.0.0.5" {
				jout(w, 200, map[string]any{"devices": []any{}, "paginator": map[string]any{"totalCount": 0, "totalPages": 0, "page": 0, "size": 100}})
				return
			}
			all := []any{
				map[string]any{"uuid": uniDevUUID, "address": "10.0.0.5", "description": "core1", "managed": true, "deviceVendor": "Cisco", "deviceType": "IOS-XE", "deviceModel": "C9300"},
				map[string]any{"uuid": "a", "address": "10.0.0.6", "description": "fw 1 main", "managed": false, "deviceVendor": "Fortinet", "deviceType": "FortiOS"},
				map[string]any{"uuid": "b", "address": "10.0.0.7", "deviceVendor": "Mikrotik", "deviceType": "RouterOS"},
			}
			if a := r.URL.Query().Get("addresses"); a != "" {
				all = all[:1]
			}
			jout(w, 200, map[string]any{"devices": all, "paginator": map[string]any{"totalCount": 3, "totalPages": 1, "page": 0, "size": 100}})
		case "/api/v3/devices/backups":
			jout(w, 200, map[string]any{"backups": []any{map[string]any{"uuid": "bk1", "type": "TEXT", "deviceUuid": uniDevUUID,
				"bytes": base64.StdEncoding.EncodeToString([]byte(cfg))}}, "paginator": map[string]any{"totalCount": 1, "totalPages": 1}})
		case "/api/v3/devices/" + uniDevUUID:
			jout(w, 200, map[string]any{"uuid": uniDevUUID, "address": "10.0.0.5", "description": "core1", "deviceVendor": "Cisco", "deviceModel": "C9300"})
		default:
			jout(w, 404, map[string]any{"error": "nope"})
		}
	}))
	d.Options = opts
	return d
}

func TestUnimusServer(t *testing.T) {
	st := &uniState{}
	d := uniStub(t, st, nil)
	if _, err := Open(d, Credential{Token: "wrong"}); err == nil {
		// Open may not call anything; Facts will.
		t.Log("open ok")
	}
	drv, err := Open(d, Credential{Token: uniTok})
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	f, err := drv.Facts(context.Background())
	if err != nil || !strings.Contains(f.Model, "3 device") || !strings.Contains(f.Model, "ok") {
		t.Fatalf("facts %+v %v", f, err)
	}
	out, err := drv.Show(context.Background(), "show devices vendors=Cisco")
	if err != nil || !strings.Contains(out, "core1") {
		t.Fatalf("show: %v %s", err, out)
	}
	if _, err := drv.Show(context.Background(), "show connections"); err == nil {
		t.Error("connections must not be shown")
	}
	if _, err := drv.Config(context.Background()); err == nil {
		t.Error("a server has no configuration")
	}
	api := drv.(APIer)
	for _, p := range []string{"/devices/" + uniDevUUID + "/connections", "/credentials", "/users", "/devices/x/../../y", "/api/v3/devices/credentialUuids"} {
		if _, _, err := api.APIGet(context.Background(), p); err == nil {
			t.Errorf("APIGet %s must be refused", p)
		}
	}
	v, _, err := api.APIGet(context.Background(), "/devices/backups?deviceUuids="+uniDevUUID+"&latest=true")
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.ToLower(fmtAny(v)); strings.Contains(s, "unipass") || strings.Contains(s, base64.StdEncoding.EncodeToString([]byte("hostname sw1"))[:12]) {
		t.Errorf("backup text leaked through the API read: %s", s)
	}
}

func fmtAny(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestUnimusConfig(t *testing.T) {
	st := &uniState{}
	d := uniStub(t, st, map[string]string{"device": "10.0.0.5"})
	drv, err := Open(d, Credential{Token: uniTok})
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	c, err := drv.Config(context.Background())
	if err != nil || !strings.Contains(c, "hostname sw1") {
		t.Fatalf("config: %v %q", err, c)
	}
	f, err := drv.Facts(context.Background())
	if err != nil || f.Hostname != "core1" || f.Vendor != "Cisco" {
		t.Fatalf("facts %+v %v", f, err)
	}
	if red := RedactConfig(c); strings.Contains(red, "UNIPASS") || strings.Contains(red, "unicomm") {
		t.Errorf("filter left secrets: %s", red)
	}
	d2 := uniStub(t, st, map[string]string{"device": "10.9.9.9"})
	drv2, _ := Open(d2, Credential{Token: uniTok})
	defer drv2.Close(context.Background())
	if _, err := drv2.Config(context.Background()); err == nil {
		t.Error("an unknown address must fail")
	}
}

func TestUnimusRawGuard(t *testing.T) {
	bad := [][2]string{
		{"POST", "/api/v3/jobs/push"}, {"POST", "/api/v3/jobs/push/preset/x"}, {"POST", "/api/v3/devices/x/backups"},
		{"POST", "/api/v3/devices:bind_credentials"}, {"PUT", "/api/v3/devices/x/connections"}, {"DELETE", "/api/v3/devices"},
		{"DELETE", "/api/v3/zones/x"}, {"POST", "/api/v3/credentials"}, {"POST", "/other/path"}, {"POST", "/api/v3/devices?x=1"},
	}
	for _, b := range bad {
		if uniRawGuard(b[0], b[1]) == nil {
			t.Errorf("%s %s must be refused", b[0], b[1])
		}
	}
	for _, g := range [][2]string{{"POST", "/api/v3/jobs/backup"}, {"POST", "/api/v3/devices:tag"}, {"POST", "/api/v3/jobs/discovery"}, {"PUT", "/api/v3/devices/x"}} {
		if err := uniRawGuard(g[0], g[1]); err != nil {
			t.Errorf("%s %s: %v", g[0], g[1], err)
		}
	}
	st := &uniState{}
	drv, _ := Open(uniStub(t, st, nil), Credential{Token: uniTok})
	defer drv.Close(context.Background())
	rc := drv.(RawChanger)
	res, err := rc.RawChange(context.Background(), Raw{Method: "POST", Path: "/jobs/backup", Body: `{"deviceUuids":["x"]}`}, false)
	if err != nil || !res.Applied || len(st.posts) != 1 || st.posts[0] != "POST /api/v3/jobs/backup" {
		t.Fatalf("raw: %+v %v %v", res, err, st.posts)
	}
	if _, err := rc.RawChange(context.Background(), Raw{Method: "POST", Path: "/jobs/push", Body: `{}`}, false); err == nil {
		t.Error("push must be refused")
	}
}

func TestUnimusImport(t *testing.T) {
	st := &uniState{}
	d := uniStub(t, st, nil)
	got, skipped, err := ImportDevices(context.Background(), d, Credential{Token: uniTok}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "core1" || got[0].Platform != "iosxe" || got[0].Address != "10.0.0.5" || !got[0].Disabled {
		t.Fatalf("got %+v", got)
	}
	if got[1].Platform != "fortios" || got[1].Name != "10.0.0.6" {
		t.Errorf("second %+v", got[1])
	}
	hasTag := func(d Device, tg string) bool {
		for _, x := range d.Tags {
			if x == tg {
				return true
			}
		}
		return false
	}
	if !hasTag(got[0], "source=unimus") || !hasTag(got[0], "vendor=Cisco") || !hasTag(got[1], "unmanaged") {
		t.Errorf("tags %v %v", got[0].Tags, got[1].Tags)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "no driver") {
		t.Errorf("skipped %+v", skipped)
	}
}

func TestUnimusPlatform(t *testing.T) {
	for in, want := range map[[3]string]string{
		{"Cisco", "IOS", ""}: "ios", {"Cisco", "NX-OS", ""}: "nxos", {"Cisco", "IOS-XE", "C9300"}: "iosxe", {"Cisco", "ASA", ""}: "",
		{"Arista", "EOS", ""}: "eos", {"Aruba", "AOS-CX", ""}: "aoscx", {"Juniper", "JunOS", ""}: "junos", {"Palo Alto", "PAN-OS", ""}: "panos",
		{"Mikrotik", "RouterOS", ""}: "",
	} {
		if g := uniPlatform(in[0], in[1], in[2]); g != want {
			t.Errorf("%v: %q, want %q", in, g, want)
		}
	}
}

// An older Unimus (before 2.2) has no /api/v3: the driver finds /api/v2 by itself.
func TestUnimusFallsBackToV2(t *testing.T) {
	cfg := "hostname old1\nenable secret 5 $1$V2SECRET\n"
	d := tlsDevice(t, "uni", "unimus", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+uniTok {
			jout(w, 401, map[string]any{"error": "no"})
			return
		}
		switch r.URL.Path {
		case "/api/v2/health":
			jout(w, 200, map[string]any{"data": map[string]any{"status": "OK"}})
		case "/api/v2/devices":
			jout(w, 200, map[string]any{"data": []any{map[string]any{"id": 7, "address": "10.0.0.5", "description": "old1", "vendor": "Cisco", "type": "IOS"}},
				"paging": map[string]any{"page": 0, "size": 100, "totalPages": 1}})
		case "/api/v2/devices/findByAddress/10.0.0.5":
			jout(w, 200, map[string]any{"data": map[string]any{"id": 7, "address": "10.0.0.5", "vendor": "Cisco"}})
		case "/api/v2/devices/7/backups/latest":
			jout(w, 200, map[string]any{"data": map[string]any{"id": 9, "type": "TEXT", "bytes": base64.StdEncoding.EncodeToString([]byte(cfg))}})
		default:
			jout(w, 404, map[string]any{"timestamp": 1, "code": 404, "error": "Not Found", "message": "URL is not supported by the API"})
		}
	}))
	drv, err := Open(d, Credential{Token: uniTok})
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	f, err := drv.Facts(context.Background())
	if err != nil || !strings.Contains(f.Model, "1 device") {
		t.Fatalf("facts %+v %v", f, err)
	}
	out, err := drv.Show(context.Background(), "show devices")
	if err != nil || !strings.Contains(out, "old1") {
		t.Fatalf("show %v %s", err, out)
	}
	d.Options = map[string]string{"device": "10.0.0.5"}
	drv2, _ := Open(d, Credential{Token: uniTok})
	defer drv2.Close(context.Background())
	c, err := drv2.Config(context.Background())
	if err != nil || !strings.Contains(c, "hostname old1") {
		t.Fatalf("config %v %q", err, c)
	}
	if out, err := drv.Show(context.Background(), "show backup old1"); err != nil || !strings.Contains(RedactConfig(cfg), "hostname old1") || !strings.Contains(out, "hostname old1") || strings.Contains(out, "V2SECRET") {
		t.Errorf("v2 show backup by name: %v %q", err, out)
	}
	rows, _ := drv.(*unimus).list(context.Background(), "/devices", "devices", 0)
	if rows := uniImportRows(rows); len(rows) != 1 || rows[0].Platform != "ios" || rows[0].ID != "7" {
		t.Errorf("import rows %+v", rows)
	}
}

func TestUnimusShowBackupByName(t *testing.T) {
	st := &uniState{}
	d := uniStub(t, st, nil)
	drv, err := Open(d, Credential{Token: uniTok})
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	for _, ref := range []string{"core1", "CORE1", "10.0.0.5", uniDevUUID} {
		out, err := drv.Show(context.Background(), "show backup "+ref)
		if err != nil || !strings.Contains(out, "hostname sw1") {
			t.Fatalf("%s: %v %q", ref, err, out)
		}
		if strings.Contains(out, "UNIPASS") || strings.Contains(out, "unicomm") {
			t.Errorf("%s: secrets in the answer: %s", ref, out)
		}
	}
	if _, err := drv.Show(context.Background(), "show backup nosuch"); err == nil {
		t.Error("an unknown device must fail")
	}
	if out, err := drv.Show(context.Background(), "show backups device=core1"); err != nil || strings.Contains(out, "hostname sw1") {
		t.Errorf("metadata only: %v %s", err, out)
	}
}
