package device

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
)

type cxW struct {
	mu      sync.Mutex
	desc    map[string]string
	admin   map[string]string
	extra   map[string]any // user_config keys other than admin, which a change must keep
	patches []string
	mgmt    string
}

// cxWriteStub is an AOS-CX REST API with 48 ports (1/1/1 … 1/1/48), all down with no description except 1/1/1.  It takes the login,
// GET of the interface list and of one interface (selector=configuration|status), and PATCH of one interface; anything else fails the test.
func cxWriteStub(t *testing.T) (Device, *cxW) {
	t.Helper()
	st := &cxW{desc: map[string]string{"1/1/1": "old"}, admin: map[string]string{}, extra: map[string]any{"autoneg": "on"}}
	for i := 1; i <= 48; i++ {
		st.admin["1/1/"+strconv.Itoa(i)] = "down"
	}
	cfg := func(n string) map[string]any {
		return map[string]any{"name": n, "description": st.desc[n], "user_config": map[string]any{"admin": st.admin[n], "autoneg": st.extra["autoneg"]}}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		_, below, _ := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/rest/"), "/")
		below = "/" + below
		switch {
		case below == "/login" && r.Method == http.MethodPost:
			http.SetCookie(w, &http.Cookie{Name: "id", Value: "s", Secure: true, Path: "/"})
		case below == "/logout":
		case below == "/system/interfaces" && r.Method == http.MethodGet:
			out := map[string]any{}
			for n := range st.admin {
				if r.URL.Query().Get("selector") == "status" {
					out[strings.ReplaceAll(n, "/", "%2F")] = map[string]any{"name": n, "admin_state": st.admin[n]}
				} else {
					c := cfg(n)
					if n == st.mgmt {
						c["ip4_address"] = "127.0.0.1/24"
					}
					out[strings.ReplaceAll(n, "/", "%2F")] = c
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(below, "/system/interfaces/") && r.Method == http.MethodGet:
			n := strings.ReplaceAll(strings.TrimPrefix(below, "/system/interfaces/"), "%2F", "/")
			if _, ok := st.admin[n]; !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(cfg(n))
		case strings.HasPrefix(below, "/system/interfaces/") && r.Method == http.MethodPatch:
			n := strings.ReplaceAll(strings.TrimPrefix(below, "/system/interfaces/"), "%2F", "/")
			b, _ := io.ReadAll(r.Body)
			st.patches = append(st.patches, n+" "+string(b))
			var m struct {
				Description *string
				UC          map[string]any `json:"user_config"`
			}
			_ = json.Unmarshal(b, &m)
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(b, &raw)
			if d, ok := raw["description"]; ok {
				var s string
				_ = json.Unmarshal(d, &s)
				st.desc[n] = s
			}
			if m.UC != nil {
				st.admin[n] = m.UC["admin"].(string)
				st.extra["autoneg"] = m.UC["autoneg"]
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "cx1", Platform: "aoscx", Address: host, Port: pn, Insecure: true}, st
}

func TestAOSCXChange(t *testing.T) {
	d, st := cxWriteStub(t)
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"}).(Changer)
	ctx := context.Background()
	c, err := ParseChange("shut port 1/1/1 down")
	if err != nil || c.Action != ActShutdown || len(c.Ports) != 1 || c.Ports[0] != "1/1/1" {
		t.Fatalf("parse: %v %+v", err, c)
	}
	// 1/1/1 is already down: nothing to do
	r, err := drv.Change(ctx, c, false)
	if err != nil || len(r.Changes) != 0 || len(r.Unchanged) != 1 || len(st.patches) != 0 {
		t.Fatalf("already down: %v %+v %v", err, r, st.patches)
	}
	// bring up a range of 48, in the sentence the user gave, with a range in the AOS-CX form
	c, err = ParseChange("bring up ports 1/1/1-1/1/48")
	if err != nil || len(c.Ports) != 48 || c.Ports[47] != "1/1/48" {
		t.Fatalf("range: %v %d", err, len(c.Ports))
	}
	r, err = drv.Change(ctx, c, true)
	if err != nil || !r.DryRun || len(r.Changes) != 48 || len(st.patches) != 0 || r.Changes[0].Before != "shutdown" || r.Changes[0].After != "up" {
		t.Fatalf("plan: %v %d %+v", err, len(r.Changes), r.Changes[:1])
	}
	r, err = drv.Change(ctx, c, false)
	if err != nil || len(r.Changes) != 48 || len(st.patches) != 48 || st.admin["1/1/37"] != "up" || r.RolledBack {
		t.Fatalf("apply: %v %+v", err, r)
	}
	if st.extra["autoneg"] != "on" || !strings.Contains(st.patches[0], `"autoneg":"on"`) {
		t.Errorf("another user_config setting was dropped: %v %s", st.extra, st.patches[0])
	}
	// description, then clear it
	c, _ = ParseChange(`change the description for ports 1/1/2-1/1/3 to read "devices"`)
	if r, err = drv.Change(ctx, c, false); err != nil || len(r.Changes) != 2 || st.desc["1/1/3"] != "devices" {
		t.Fatalf("describe: %v %+v", err, r)
	}
	c, _ = ParseChange(`clear the description on 1/1/1-1/1/3`)
	if r, err = drv.Change(ctx, c, false); err != nil || st.desc["1/1/1"] != "" || st.desc["1/1/3"] != "" {
		t.Fatalf("clear: %v %+v %v", err, r, st.desc)
	}
	// a port the switch lacks cancels the whole change
	n := len(st.patches)
	c, _ = ParseChange("shut down 1/1/47-1/1/49")
	if _, err = drv.Change(ctx, c, false); err == nil || !strings.Contains(err.Error(), "1/1/49") || len(st.patches) != n {
		t.Fatalf("missing port: %v %v", err, st.patches[n:])
	}
	// the port that holds the address the gateway uses is never shut down, however it is written
	st.mgmt = "1/1/5"
	c, _ = ParseChange("shut port 1/1/4-1/1/6 down")
	if _, err = drv.Change(ctx, c, false); err == nil || !strings.Contains(err.Error(), "cut the gateway off") || len(st.patches) != n {
		t.Fatalf("management port: %v", err)
	}
}

func TestParseBarePortsAndWordOrder(t *testing.T) {
	ok := map[string]struct {
		act   string
		first string
		n     int
	}{
		"shut port 1/1/1 down":              {ActShutdown, "1/1/1", 1},
		"shut gi1/0/1 down":                 {ActShutdown, "GigabitEthernet1/0/1", 1},
		"turn ports 1/1/1-1/1/48 off":       {ActShutdown, "1/1/1", 48},
		"bring port 1/1/5 up":               {ActNoShutdown, "1/1/5", 1},
		"turn gi1/0/1-3 on":                 {ActNoShutdown, "GigabitEthernet1/0/1", 3},
		"shut down 1/1/1-48":                {ActShutdown, "1/1/1", 48},
		"shut down gi1/0/1-gi1/0/3":         {},
		"shutdown gi1/0/1-1/0/3":            {ActShutdown, "GigabitEthernet1/0/1", 3},
		"describe 1/1/7 as \"uplink\"":      {ActDescription, "1/1/7", 1},
		"clear the description on lag1":     {ActClearDescription, "lag1", 1},
		"shut down port gi1/1/1":            {ActShutdown, "GigabitEthernet1/1/1", 1},
		"no shutdown 1/1/10, 1/1/12-1/1/13": {ActNoShutdown, "1/1/10", 3},
	}
	for s, w := range ok {
		c, err := ParseChange(s)
		if w.act == "" {
			if err == nil {
				t.Errorf("%q was accepted: %+v", s, c)
			}
			continue
		}
		if err != nil || c.Action != w.act || c.Ports[0] != w.first || len(c.Ports) != w.n {
			t.Errorf("%q: %v %+v", s, err, c)
		}
	}
	for _, bad := range []string{"shut port 1/1/1", "shut port 1/1/1-1/2/48 down", "shut port 1/1/48-1/1/1 down", "turn it off"} {
		if c, err := ParseChange(bad); err == nil {
			t.Errorf("%q was accepted: %+v", bad, c)
		}
	}
}

func TestResolveBarePort(t *testing.T) {
	have := map[string]portState{"GigabitEthernet1/1/1": {}, "TenGigabitEthernet1/1/2": {}, "GigabitEthernet1/1/2": {}, "1/1/9": {}}
	if got, err := resolve(have, []string{"1/1/1", "1/1/9", "gigabitethernet1/1/2"}); err != nil || strings.Join(got, ",") != "GigabitEthernet1/1/1,1/1/9,GigabitEthernet1/1/2" {
		t.Errorf("resolve: %v %v", got, err)
	}
	if _, err := resolve(have, []string{"1/1/2"}); err == nil || !strings.Contains(err.Error(), "say which port") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := resolve(have, []string{"1/1/7"}); err == nil || !strings.Contains(err.Error(), "no port 1/1/7") {
		t.Errorf("missing: %v", err)
	}
}
