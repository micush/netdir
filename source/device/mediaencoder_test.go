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

type meState struct {
	mu    sync.Mutex
	calls []string // "method tool args"
}

func (s *meState) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return ""
	}
	return s.calls[len(s.calls)-1]
}

func (s *meState) count(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// meStub is an encoder's MCP endpoint (POST /mcp) on loopback: Bearer TOKEN, initialize answered like the real one, tools answered from
// a table, and the encoder's own refusal (isError) for a tool in refuse.
func meStub(t *testing.T, tools map[string]any, refuse map[string]string) (Device, *meState) {
	t.Helper()
	st := &meState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer TOKEN" {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
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
		st.calls = append(st.calls, q.Method+" "+q.Params.Name+" "+string(q.Params.Arguments))
		st.mu.Unlock()
		enc := json.NewEncoder(w)
		if q.Method == "initialize" {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": map[string]any{"protocolVersion": "2025-06-18",
				"serverInfo": map[string]any{"name": "multi-mediaencoder", "version": "23"}}})
			return
		}
		reply := func(text string, isErr bool) {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isErr}})
		}
		if msg, ok := refuse[q.Params.Name]; ok {
			reply(msg, true)
			return
		}
		v, ok := tools[q.Params.Name]
		if !ok {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32602, "message": "Unknown tool: " + q.Params.Name}})
			return
		}
		j, _ := json.Marshal(v)
		reply(string(j), false)
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "enc1", Platform: "mediaencoder", Address: host, Port: pn, Insecure: true}, st
}

func meTools() map[string]any {
	return map[string]any{
		"get_status": J{"scanning": false, "encoding": true, "queue_size": 3, "current_file": "Movie.mkv"},
		"get_cluster": J{"enabled": true, "name": "enc-a", "nodes": []any{
			J{"id": "1", "name": "enc-a", "self": true, "alive": true}, J{"id": "2", "name": "enc-b", "alive": true}}},
		"get_metrics": J{
			"system": J{"available": true, "ncpu": 8, "history": []any{
				J{"t": 1, "cpu": -1, "mem_used": 1, "mem_total": 2, "swap_used": 0, "swap_total": 0, "load1": 0.1, "load5": 0.1, "load15": 0.1},
				J{"t": 2, "cpu": 37.5, "mem_used": 2048, "mem_total": 8192, "swap_used": 100, "swap_total": 1024, "load1": 1.5, "load5": 1.2, "load15": 1.0}}},
			"gpu": J{"available": true, "name": "NVIDIA T400", "procs": []any{J{"pid": 1, "name": "ffmpeg", "mem": 300}}, "history": []any{
				J{"t": 2, "util": 55, "enc": 80, "dec": 10, "mem_used": 900, "mem_total": 4096, "temp": 61, "power": 28.5, "power_limit": 31, "fan": 40, "clk_sm": 1200, "clk_mem": 5000}}},
		},
		"get_config":       J{"encode_preset": "medium", "video_quality": 28, "cluster_secret_set": true, "plex_url": "http://plex", "api_secret": "hunter2"},
		"list_schedules":   J{"schedules": []any{J{"id": "ab12", "label": "Nightly", "enabled": true}}},
		"get_log":          J{"lines": []any{"a", "b"}},
		"list_history":     J{"sessions": []any{J{"id": "cd34"}}},
		"get_history_log":  J{"lines": []any{"x"}},
		"get_queue":        J{"waiting": []any{}},
		"set_config":       J{"ok": true},
		"start_job":        J{"ok": true, "paths": []any{"/media/movies"}},
		"stop_job":         J{"ok": true},
		"toggle_schedule":  J{"ok": true, "enabled": false},
		"scan_library":     J{"ok": true, "scan_only": true, "to_encode": 2, "bytes_to_encode": 1500},
		"get_quarantine":   J{"auto": true, "quarantine_days": 14, "due": J{"files": 3, "selected": 1}},
		"purge_quarantine": J{"ok": true, "result": J{"deleted": 2, "freed_bytes": 3000000}},
		"clear_history":    J{"ok": true},
	}
}

func TestMediaEncoderRegistered(t *testing.T) {
	found := false
	for _, p := range Platforms() {
		found = found || p == "mediaencoder"
	}
	if !found {
		t.Fatal("platform mediaencoder is not registered")
	}
	if DefaultPort("mediaencoder") != 8765 {
		t.Errorf("default port %d", DefaultPort("mediaencoder"))
	}
	if err := Validate([]Device{{Name: "e", Platform: "MediaEncoder", Address: "10.0.0.5", Credential: "k"}}, []Credential{{Name: "k", Token: "t"}}); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestMediaEncoderReads(t *testing.T) {
	d, st := meStub(t, meTools(), nil)
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOKEN"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Hostname != "enc-a" || f.Vendor != "multi-mediaencoder" || f.OSVersion != "v23" || !strings.Contains(f.Model, "2 node") || !strings.Contains(f.Model, "T400") {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if _, err := drv.Interfaces(ctx); err != ErrUnsupported {
		t.Errorf("interfaces: %v", err)
	}
	if _, err := drv.Neighbors(ctx); err != ErrUnsupported {
		t.Errorf("neighbors: %v", err)
	}
	r, err := drv.(Resourcer).Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.Now != 37.5 {
		t.Fatalf("resources: %v %+v", err, r)
	}
	if len(r.Memory) != 3 || r.Memory[0].Total != 8192<<20 || r.Memory[0].Used != 2048<<20 || r.Memory[0].UsedPercent != 25 || r.Memory[1].Name != "swap" || r.Memory[2].Name != "gpu memory" {
		t.Fatalf("memory: %+v", r.Memory)
	}
	kinds := map[string]float64{}
	for _, s := range r.Sensors {
		kinds[s.Kind] = *s.Reading
	}
	if kinds["temperature"] != 61 || kinds["psu"] != 28.5 || kinds["fan"] != 40 {
		t.Fatalf("sensors: %+v", r.Sensors)
	}
	if g, _ := r.Details.Protocols["gpu"].(map[string]any); g["nvenc_percent"] != 80.0 || r.Details.Unavailable != nil {
		t.Fatalf("details: %+v", r.Details)
	}
	out, err := drv.Show(ctx, "show status")
	if err != nil || !strings.Contains(out, "Movie.mkv") {
		t.Fatalf("show status: %v %s", err, out)
	}
	if _, err := drv.Show(ctx, "show log lines=50"); err != nil || !strings.Contains(st.last(), `"lines":50`) {
		t.Fatalf("show log: %v %s", err, st.last())
	}
	if _, err := drv.Show(ctx, "show history-log id=cd34"); err != nil || !strings.Contains(st.last(), `"id":"cd34"`) {
		t.Fatalf("show history-log: %v %s", err, st.last())
	}
	for _, bad := range []string{"show", "show nothing", "show status | include x", "show log lines=0", "show log lines=99999", "show log lines=x",
		"show status lines=5", "show history-log", "show history-log id=../x", "show history-log id=AB", "show log foo=1", "reload", "show config x"} {
		n := len(st.calls)
		if _, err := drv.Show(ctx, bad); err == nil || len(st.calls) != n {
			t.Errorf("%q: %v (calls %v)", bad, err, st.calls[n:])
		}
	}
	c, err := drv.Config(ctx)
	if err != nil || !strings.Contains(c, "encode_preset") || strings.Contains(c, "hunter2") {
		t.Fatalf("config: %v %s", err, c)
	}
}

func TestMediaEncoderAPI(t *testing.T) {
	d, st := meStub(t, meTools(), nil)
	ctx := context.Background()
	api := open(t, d, Credential{Token: "TOKEN"}).(APIer)
	if v, text, err := api.APIGet(ctx, "/api/gpu"); err != nil || text || v.(map[string]any)["name"] != "NVIDIA T400" {
		t.Fatalf("gpu: %v %v %v", err, text, v)
	}
	if v, _, err := api.APIGet(ctx, "/api/sys"); err != nil || v.(map[string]any)["ncpu"] != 8.0 {
		t.Fatalf("sys: %v %v", err, v)
	}
	if _, _, err := api.APIGet(ctx, "/api/log?n=7"); err != nil || !strings.Contains(st.last(), `"lines":7`) {
		t.Fatalf("log: %v %s", err, st.last())
	}
	if _, _, err := api.APIGet(ctx, "/api/sessions/cd34/lines"); err != nil || !strings.Contains(st.last(), "get_history_log") {
		t.Fatalf("session lines: %v %s", err, st.last())
	}
	if v, _, err := api.APIGet(ctx, "/api/config"); err != nil || strings.Contains(meJSON(v), "hunter2") {
		t.Fatalf("config: %v %v", err, v)
	}
	for _, bad := range []string{"/status", "/api/../x", "/api/x y", "/api/mcp/token", "/api/cluster/secret", "/api/cert", "/api/events", "/api/log?n=0", "/api/sessions/XY/lines", "//api/status"} {
		n := len(st.calls)
		if _, _, err := api.APIGet(ctx, bad); err == nil || len(st.calls) != n {
			t.Errorf("%q accepted (calls %v)", bad, st.calls[n:])
		}
	}
	if cat, err := api.APICatalog(ctx); err != nil || len(cat.([]any)) < 10 {
		t.Fatalf("catalog: %v %v", err, cat)
	}
}

func TestMediaEncoderErrors(t *testing.T) {
	d, _ := meStub(t, meTools(), nil)
	ctx := context.Background()
	// a wrong token is refused, and the token is in no error text
	_, err := open(t, d, Credential{Token: "WRONGTOKEN123"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "WRONGTOKEN123") {
		t.Errorf("wrong token: %v", err)
	}
	if _, err := Open(d, Credential{Username: "u", Password: "p"}); err == nil || !strings.Contains(err.Error(), "MCP token") {
		t.Errorf("opened without a token: %v", err)
	}
	// MCP off on the encoder is the encoder's 404
	off := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, `{"error":"Not found"}`, 404) }))
	defer off.Close()
	host, port, _ := net.SplitHostPort(off.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	_, err = open(t, Device{Name: "e", Platform: "mediaencoder", Address: host, Port: pn, Insecure: true}, Credential{Token: "TOKEN"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "MCP endpoint is off") {
		t.Errorf("mcp off: %v", err)
	}
	// something else that speaks MCP is not an encoder
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"other","version":"1"}}}`))
	}))
	defer other.Close()
	host, port, _ = net.SplitHostPort(other.Listener.Addr().String())
	pn, _ = strconv.Atoi(port)
	_, err = open(t, Device{Name: "e", Platform: "mediaencoder", Address: host, Port: pn, Insecure: true}, Credential{Token: "TOKEN"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "not a multi-media[encoder]") {
		t.Errorf("other server: %v", err)
	}
}

func TestMediaEncoderRawChange(t *testing.T) {
	d, st := meStub(t, meTools(), map[string]string{"update_schedule": "refused: run_time must be \"HH:MM\""})
	ctx := context.Background()
	rw := open(t, d, Credential{Token: "TOKEN"}).(RawChanger)
	set := `{"encode_preset":"slow","video_quality":24}`

	// dry run: reads the settings it would replace, sends nothing that changes
	r, err := rw.RawChange(ctx, Raw{Method: "set", Body: set}, true)
	if err != nil || r.Applied || !r.DryRun || !strings.Contains(r.Before, "medium") || st.count("tools/call set_config") != 0 {
		t.Fatalf("dry set: %v %+v %v", err, r, st.calls)
	}
	r, err = rw.RawChange(ctx, Raw{Method: "SET", Body: set}, false)
	if err != nil || !r.Applied || st.count("tools/call set_config") != 1 || !strings.Contains(st.last(), `"settings":{"encode_preset":"slow"`) || !strings.Contains(r.Before, "medium") {
		t.Fatalf("set: %v %+v %v", err, r, st.calls)
	}
	// secrets and shapes are refused before anything is sent
	for name, raw := range map[string]Raw{
		"secret":    {Method: "SET", Body: `{"cluster_secret":"x"}`},
		"token":     {Method: "SET", Body: `{"mcp_token":"x"}`},
		"plex":      {Method: "SET", Body: `{"plex_token":"x"}`},
		"empty":     {Method: "SET", Body: `{}`},
		"not json":  {Method: "SET", Body: `nope`},
		"lines":     {Method: "SET", Body: set, Lines: []string{"x"}},
		"method":    {Method: "DELETE", Path: "/x"},
		"no action": {Method: "CALL", Path: "get_status"},
		"cert":      {Method: "CALL", Path: "generate_cert"},
		"bad id":    {Method: "CALL", Path: "toggle_schedule", Body: `{"id":"../x"}`},
	} {
		n := len(st.calls)
		if _, err := rw.RawChange(ctx, raw, false); err == nil || st.count("tools/call set_config") != 1 || len(st.calls) != n {
			t.Errorf("%s accepted: %v (calls %v)", name, err, st.calls[n:])
		}
	}
	// CALL: dry reads the status, the call runs only when applied
	n := st.count("tools/call start_job")
	r, err = rw.RawChange(ctx, Raw{Method: "call", Path: "start_job", Body: `{"target":"movies"}`}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "Movie.mkv") || st.count("tools/call start_job") != n {
		t.Fatalf("dry call: %v %+v", err, r)
	}
	r, err = rw.RawChange(ctx, Raw{Method: "CALL", Path: "start_job", Body: `{"target":"movies"}`}, false)
	if err != nil || !r.Applied || st.count("tools/call start_job") != n+1 || !strings.Contains(st.last(), `"target":"movies"`) {
		t.Fatalf("call: %v %+v", err, r)
	}
	if r, err = rw.RawChange(ctx, Raw{Method: "CALL", Path: "toggle_schedule", Body: `{"id":"ab12"}`}, false); err != nil || !r.Applied {
		t.Fatalf("toggle: %v %+v", err, r)
	}
	// the encoder's own refusal comes back as the error
	if _, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "update_schedule", Body: `{"id":"ab12","run_time":"99"}`}, false); err == nil || !strings.Contains(err.Error(), "HH:MM") {
		t.Errorf("remote refusal: %v", err)
	}
	// the guard lists refuse what erases records; with them off it is allowed
	SetGuards(true)
	if _, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "clear_history"}, false); err == nil || !strings.Contains(err.Error(), "guard") {
		t.Errorf("guards on: %v", err)
	}
	if _, err := rw.RawChange(ctx, Raw{Method: "SET", Body: `{"allowed_groups":[]}`}, false); err == nil {
		t.Error("guards on: allowed_groups changed")
	}
	SetGuards(false)
	defer SetGuards(true)
	if r, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "clear_history"}, false); err != nil || !r.Applied {
		t.Errorf("guards off: %v %+v", err, r)
	}
}

func TestMediaEncoderQuarantine(t *testing.T) {
	SetGuards(false) // the guard lists are on by default in tests; the pass-through checks turn them off
	defer SetGuards(true)
	d, st := meStub(t, meTools(), nil)
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOKEN"})
	rw := drv.(RawChanger)
	if out, err := drv.Show(ctx, "show quarantine"); err != nil || !strings.Contains(out, "quarantine_days") {
		t.Fatalf("show quarantine: %v %s", err, out)
	}
	if v, _, err := drv.(APIer).APIGet(ctx, "/api/quarantine"); err != nil || v == nil {
		t.Fatalf("api quarantine: %v %v", err, v)
	}
	purges := func() int { return st.count("tools/call purge_quarantine") }

	// a dry run asks the encoder's own dry run: nothing is deleted, Before says what would be
	r, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine"}, true)
	if err != nil || r.Applied || !r.DryRun || !strings.Contains(r.Before, "freed_bytes") || !strings.Contains(st.last(), `"dry_run":true`) {
		t.Fatalf("dry: %v %+v %s", err, r, st.last())
	}
	// no arguments: every file goes
	r, err = rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine"}, false)
	if err != nil || !r.Applied || r.DryRun || !strings.Contains(r.Answer, "deleted") || !strings.Contains(st.last(), `"dry_run":false`) || strings.Contains(st.last(), "older_than_days") {
		t.Fatalf("purge all: %v %+v %s", err, r, st.last())
	}
	// older_than_days is passed on
	if r, err = rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine", Body: `{"older_than_days":30}`}, false); err != nil || !r.Applied || !strings.Contains(st.last(), `"older_than_days":30`) {
		t.Fatalf("older than: %v %+v %s", err, r, st.last())
	}
	// "dry_run": true in the body is a dry run, and the result says so
	if r, err = rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine", Body: `{"dry_run":true}`}, false); err != nil || r.Applied || !r.DryRun {
		t.Fatalf("body dry_run: %v %+v", err, r)
	}
	n := purges()
	for name, body := range map[string]string{"text": `{"older_than_days":"x"}`, "negative": `{"older_than_days":-1}`, "huge": `{"older_than_days":99999}`,
		"dry text": `{"dry_run":"yes"}`, "other key": `{"path":"/"}`} {
		if _, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine", Body: body}, false); err == nil || purges() != n {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	// guards on: only a dry run goes through
	SetGuards(true)
	if _, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine"}, false); err == nil || !strings.Contains(err.Error(), "guard") || purges() != n {
		t.Errorf("guards on, apply: %v", err)
	}
	if r, err := rw.RawChange(ctx, Raw{Method: "CALL", Path: "purge_quarantine"}, true); err != nil || r.Applied {
		t.Errorf("guards on, dry run: %v %+v", err, r)
	}
	SetGuards(false)
}

func TestMediaEncoderScan(t *testing.T) {
	d, st := meStub(t, meTools(), nil)
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "TOKEN"})
	out, err := drv.Show(ctx, "show scan target=movies")
	if err != nil || !strings.Contains(out, "to_encode") || !strings.Contains(st.last(), `"target":"movies"`) {
		t.Fatalf("show scan: %v %s", err, out)
	}
	if _, err := drv.Show(ctx, "show scan target=/mnt/my media/tv"); err != nil || !strings.Contains(st.last(), `"target":"/mnt/my media/tv"`) {
		t.Fatalf("show scan with a path: %v %s", err, st.last())
	}
	n := st.count("tools/call scan_library")
	for _, bad := range []string{"show scan", "show scan target=", "show scan target=relative/dir", "show scan lines=5"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Fatalf("%q should be refused", bad)
		}
	}
	if st.count("tools/call scan_library") != n {
		t.Fatal("a refused scan reached the encoder")
	}
	// a scan is a read: it works with the guard lists on and is not a CALL action
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "scan_library"}, true); err == nil {
		t.Fatal("scan_library is read with show scan, not run as an action")
	}
}
