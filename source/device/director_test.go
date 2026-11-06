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

type dirState struct {
	mu    sync.Mutex
	calls []string // tool name and its arguments as JSON
}

func (s *dirState) count(tool string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, tool+" ") {
			n++
		}
	}
	return n
}

// dirStub is a director's MCP endpoint (POST /mcp) on loopback: Bearer key RWKEY (read-write) or ROKEY (read-only), tools answered
// from a table (the answer is the text of the tool's result), write tools refused for the read-only key as the directors do.
func dirStub(t *testing.T, tools map[string]any) (Device, *dirState) {
	t.Helper()
	st := &dirState{}
	write := map[string]bool{"edit_config": true, "api_request": true}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
			return
		}
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if key != "RWKEY" && key != "ROKEY" {
			http.Error(w, "the Authorization header must be: Bearer KEY", http.StatusUnauthorized)
			return
		}
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &q)
		st.mu.Lock()
		st.calls = append(st.calls, q.Params.Name+" "+string(q.Params.Arguments))
		st.mu.Unlock()
		reply := func(text string, isErr bool) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isErr}})
		}
		if write[q.Params.Name] && key == "ROKEY" {
			reply("refused: this caller has read-only access (Configure ▸ Monitoring ▸ MCP)", true)
			return
		}
		v, ok := tools[q.Params.Name]
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32602, "message": "unknown tool " + q.Params.Name}})
			return
		}
		j, _ := json.Marshal(v)
		reply(string(j), false)
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "d1", Platform: "dnsdir", Address: host, Port: pn, Insecure: true}, st
}

func dirTools() map[string]any {
	return map[string]any{
		"list_nodes": []any{
			J{"addr": "ns1:53854", "name": "ns1", "paused": false, "primary": true, "reachable": true, "this_node": true, "version": "635"},
			J{"addr": "ns2:53854", "name": "ns2", "paused": false, "primary": false, "reachable": true, "this_node": false, "version": "635"}},
		"get_host_stats": J{"now": J{"cores": 4, "cpu_pct": 25.5, "load": []any{1.5, 1.2, 1.0}, "mem_pct": 12.0, "mem_total": 4000, "mem_used": 480, "swap_total": 0,
			"fs":     []any{J{"mount": "/", "pct": 20.1, "total": 1000, "used": 201}},
			"ifaces": []any{J{"name": "eth0", "up": true, "speed_mbps": 10000, "rx_bps": 1.0}, J{"name": "lo", "up": true}}}},
		"get_lldp": J{"neighbors": []any{J{"interface": "eth0", "system_name": "pve10", "port_descr": "veth1", "port_id": "fe:d8", "mgmt_ips": []any{"fe80::1", "192.168.5.10"},
			"system_descr": "Debian", "protocol": "LLDP", "chassis_id": "84:a9"}}},
		"get_topology": J{"gateways": []any{J{"group_id": 1, "vip4": "192.168.5.56/24", "password": "hunter2"}}},
		"get_dns":      J{"queries": 28907},
		"get_config":   J{"ok": true, "config": J{"dns": J{"cache_entries": 1000, "web_password": "(hidden)"}}},
		"list_api":     []any{J{"method": "GET", "path": "/api/config"}},
		"api_get":      J{"ok": true, "data": J{"x": 1}},
		"edit_config":  J{"saved": true},
		"api_request":  J{"ok": true},
	}
}

func TestDirectorReads(t *testing.T) {
	d, st := dirStub(t, dirTools())
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "ROKEY"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "ns1" || f.Vendor != "AnyName" || f.OSVersion != "v635" || !strings.Contains(f.Model, "2 node") {
		t.Fatalf("facts: %v %+v", err, f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].Name != "eth0" || ifs[0].SpeedMbps != 10000 || ifs[0].OperUp == nil || !*ifs[0].OperUp {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	ns, err := drv.Neighbors(ctx)
	if err != nil || len(ns) != 1 || ns[0].RemoteName != "pve10" || ns[0].RemoteAddr != "192.168.5.10" || ns[0].RemotePort != "veth1" || ns[0].Protocol != "lldp" || ns[0].LocalPort != "eth0" {
		t.Fatalf("neighbors: %v %+v", err, ns)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 25.5 || r.CPU.OneMin != 1.5 || len(r.Memory) != 1 || r.Memory[0].Free != 3520 || len(r.Storage) != 1 || r.Storage[0].Free != 799 {
		t.Fatalf("resources: %v %+v", err, r)
	}
	out, err := drv.Show(ctx, "show topology")
	if err != nil || !strings.Contains(out, "192.168.5.56") || strings.Contains(out, "hunter2") {
		t.Fatalf("show topology: %v %s", err, out)
	}
	if _, err := drv.Show(ctx, "show dns node=ns2 range=1h"); err != nil || st.count("get_dns") != 1 || !strings.Contains(st.calls[len(st.calls)-1], `"node":"ns2"`) {
		t.Fatalf("show dns: %v %v", err, st.calls)
	}
	for _, bad := range []string{"show ntp", "show time", "show nothing", "show dns | include x", "show dns node=a;b", "show dns top=x", "show dns foo=1", "reload"} {
		n := len(st.calls)
		if _, err := drv.Show(ctx, bad); err == nil || len(st.calls) != n {
			t.Errorf("%q: %v (calls %v)", bad, err, st.calls[n:])
		}
	}
	c, err := drv.Config(ctx)
	if err != nil || !strings.Contains(c, "cache_entries") {
		t.Fatalf("config: %v %s", err, c)
	}
	v, text, err := drv.(APIer).APIGet(ctx, "/api/config")
	if err != nil || text || v == nil {
		t.Fatalf("api: %v %v", err, v)
	}
	for _, bad := range []string{"/config", "/api/../x", "/api/x y", "api/x"} {
		if _, _, err := drv.(APIer).APIGet(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if cat, err := drv.(APIer).APICatalog(ctx); err != nil || cat == nil {
		t.Fatalf("catalog: %v", err)
	}
	// a wrong key is refused, without the key in the error; the node option is passed on
	_, err = open(t, d, Credential{Token: "WRONGKEY"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "WRONGKEY") {
		t.Errorf("wrong key: %v", err)
	}
	d.Options = map[string]string{"node": "ns2"}
	if _, err := open(t, d, Credential{Token: "ROKEY"}).Interfaces(ctx); err != nil || !strings.Contains(st.calls[len(st.calls)-1], `"node":"ns2"`) {
		t.Errorf("node option: %v %v", err, st.calls[len(st.calls)-1])
	}
	d.Options = map[string]string{"node": "a b"}
	if _, err := Open(d, Credential{Token: "ROKEY"}); err == nil {
		t.Error("a node option that is not a name was accepted")
	}
	d.Options = nil
	if _, err := Open(d, Credential{Username: "u", Password: "p"}); err == nil || !strings.Contains(err.Error(), "MCP key") {
		t.Errorf("a director opened without a key: %v", err)
	}
}

func TestDirectorNTPOnlyReads(t *testing.T) {
	tools := dirTools()
	tools["get_time"] = J{"synced": true, "stratum": 3}
	d, _ := dirStub(t, tools)
	d.Platform = "ntpdir"
	drv := open(t, d, Credential{Token: "ROKEY"})
	if f, err := drv.Facts(context.Background()); err != nil || f.Vendor != "NTP Director" {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if out, err := drv.Show(context.Background(), "show time"); err != nil || !strings.Contains(out, "stratum") {
		t.Fatalf("show time: %v %s", err, out)
	}
	if _, err := drv.Show(context.Background(), "show dns"); err == nil {
		t.Error("an NTP director answered show dns")
	}
}

func TestDirectorRawChange(t *testing.T) {
	d, st := dirStub(t, dirTools())
	ctx := context.Background()
	rw := open(t, d, Credential{Token: "RWKEY"}).(RawChanger)
	set := `{"dns":{"cache_entries":200000}}`
	r, err := rw.RawChange(ctx, Raw{Method: "set", Body: set}, true)
	if err != nil || r.Applied || !strings.Contains(st.calls[len(st.calls)-1], `"dry_run":true`) {
		t.Fatalf("dry: %v %+v %v", err, r, st.calls)
	}
	r, err = rw.RawChange(ctx, Raw{Method: "SET", Body: set}, false)
	if err != nil || !r.Applied || !strings.Contains(st.calls[len(st.calls)-1], `"dry_run":false`) || !strings.Contains(st.calls[len(st.calls)-1], "200000") {
		t.Fatalf("apply: %v %+v %v", err, r, st.calls)
	}
	r, err = rw.RawChange(ctx, Raw{Method: "POST", Path: "/api/cache/flush", Body: `{"name":"x.example"}`}, false)
	if err != nil || !r.Applied || !strings.Contains(st.calls[len(st.calls)-1], `"method":"POST"`) {
		t.Fatalf("post: %v %+v", err, r)
	}
	n := len(st.calls)
	for _, bad := range []Raw{{Method: "SET"}, {Method: "SET", Body: "[]"}, {Method: "SET", Body: "nope"}, {Method: "DELETE", Path: "/api/x"},
		{Method: "POST", Path: "/auth/x"}, {Method: "POST", Path: "/api/login"}, {Method: "POST", Path: "/api/sso/start"}, {Lines: []string{"x"}}} {
		if _, err := rw.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if len(st.calls) != n {
		t.Errorf("a refused change reached the director: %v", st.calls[n:])
	}
	// a read-only key is refused by the director, and the error says so
	ro := open(t, d, Credential{Token: "ROKEY"}).(RawChanger)
	if _, err := ro.RawChange(ctx, Raw{Method: "SET", Body: set}, false); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("ro: %v", err)
	}
}
