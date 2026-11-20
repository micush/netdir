package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fdState struct {
	mu    sync.Mutex
	calls []string // tool name and its arguments as JSON
}

func (s *fdState) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return ""
	}
	return s.calls[len(s.calls)-1]
}

func (s *fdState) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// fdStub is a FlowDirector's MCP endpoint (POST /mcp) on loopback: Bearer key FLOWKEY, tools answered from a table.
func fdStub(t *testing.T, tools map[string]any) (Device, *fdState) {
	t.Helper()
	st := &fdState{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer FLOWKEY" {
			http.Error(w, "the Authorization header must be: Bearer KEY", http.StatusUnauthorized)
			return
		}
		var q struct {
			ID     json.RawMessage `json:"id"`
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
		v, ok := tools[q.Params.Name]
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32602, "message": "unknown tool " + q.Params.Name}})
			return
		}
		j, _ := json.Marshal(v)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": string(j)}}, "isError": false}})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "flow1", Platform: "flowdir", Address: host, Port: pn, Insecure: true}, st
}

func fdTools() map[string]any {
	return map[string]any{
		"list_nodes": []any{
			J{"name": "fd-b", "addr": "10.0.0.12:19997", "this_node": false, "version": "12"},
			J{"name": "fd-a", "addr": "10.0.0.11:19997", "this_node": true, "version": "13"}},
		"get_topology":    []any{J{"id": 230, "name": "flows", "status": "ok"}},
		"flow_exporters":  J{"exporters": []any{J{"addr": "10.9.0.1", "name": "core-sw1", "format": "ipfix", "records": 1234, "api_secret": "hunter2"}}},
		"flow_status":     J{"nodes": []any{J{"node": "fd-a", "records": 99, "dir_bytes": 12345}}},
		"flow_top":        J{"rows": []any{J{"group": J{"a": "10.1.1.1", "b": "8.8.8.8"}, "bytes": 5000}}, "total": J{"bytes": 5000}},
		"flow_timeseries": J{"points": []any{J{"t": 1, "bytes": 10}}},
	}
}

func TestFlowdirRegisteredWithItsPort(t *testing.T) {
	found := false
	for _, p := range Platforms() {
		found = found || p == "flowdir"
	}
	if !found {
		t.Fatal("platform flowdir is not registered")
	}
	if DefaultPort("flowdir") != 19996 {
		t.Errorf("default port %d", DefaultPort("flowdir"))
	}
	if err := Validate([]Device{{Name: "f", Platform: "FlowDir", Address: "10.0.0.11", Credential: "k"}}, []Credential{{Name: "k", Token: "x"}}); err != nil {
		t.Errorf("a flowdir device does not validate: %v", err)
	}
}

func TestFlowdirFacts(t *testing.T) {
	d, st := fdStub(t, fdTools())
	f, err := open(t, d, Credential{Token: "FLOWKEY"}).Facts(context.Background())
	if err != nil || f.Hostname != "fd-a" || f.Vendor != "FlowDirector" || f.OSVersion != "v13" || !strings.Contains(f.Model, "2 node") {
		t.Errorf("facts: %+v %v", f, err)
	}
	if st.last() != "list_nodes {}" {
		t.Errorf("asked %q", st.last())
	}
}

func TestFlowdirNeedsAKeyAndSaysWhenItIsWrong(t *testing.T) {
	d, _ := fdStub(t, fdTools())
	if _, err := Open(d, Credential{Password: "pw"}); err == nil || !strings.Contains(err.Error(), "MCP key") {
		t.Errorf("no token: %v", err)
	}
	_, err := open(t, d, Credential{Token: "WRONG"}).Facts(context.Background())
	var se *statusError
	if !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Errorf("a wrong key: %v", err)
	}
}

func TestFlowdirNotANetworkDevice(t *testing.T) {
	d, st := fdStub(t, fdTools())
	drv := open(t, d, Credential{Token: "FLOWKEY"})
	ctx := context.Background()
	if _, err := drv.Interfaces(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("interfaces: %v", err)
	}
	if _, err := drv.Neighbors(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("neighbors: %v", err)
	}
	if _, err := drv.Config(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("config: %v", err)
	}
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("no RawChange")
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "SET", Body: `{"flow":{"max_keys":1}}`}, false); err == nil || !strings.Contains(err.Error(), "only read") {
		t.Errorf("a change was not refused: %v", err)
	}
	if st.count() != 0 {
		t.Errorf("%d calls reached FlowDirector for things it does not do", st.count())
	}
}

func TestFlowdirShow(t *testing.T) {
	d, st := fdStub(t, fdTools())
	drv := open(t, d, Credential{Token: "FLOWKEY"})
	ctx := context.Background()
	for cmd, tool := range map[string]string{"show nodes": "list_nodes", "show topology": "get_topology", "show exporters": "flow_exporters", "show status": "flow_status", "SHOW Top": "flow_top"} {
		out, err := drv.Show(ctx, cmd)
		if err != nil || !strings.HasPrefix(st.last(), tool+" ") || len(out) < 5 {
			t.Errorf("%s: %v (asked %q)", cmd, err, st.last())
		}
	}
	// a secret in an answer is hidden
	out, _ := drv.Show(ctx, "show exporters")
	if strings.Contains(out, "hunter2") {
		t.Errorf("a secret passed through:\n%s", out)
	}
	// arguments, with a quoted filter that holds spaces and a wildcard
	if _, err := drv.Show(ctx, `show top by=host range=1d limit=5 metric=packets dedupe=off filter="host=10.1.*.* AND !port=53" port=443`); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(st.last(), "flow_top ")), &got); err != nil {
		t.Fatal(err)
	}
	if got["by"] != "host" || got["range"] != "1d" || got["limit"] != float64(5) || got["metric"] != "packets" || got["dedupe"] != "off" || got["port"] != "443" || got["filter"] != "host=10.1.*.* AND !port=53" {
		t.Errorf("arguments: %v", got)
	}
	if _, err := drv.Show(ctx, "show timeseries by=src step=5m range=all"); err != nil || !strings.HasPrefix(st.last(), "flow_timeseries ") {
		t.Errorf("timeseries: %v %q", err, st.last())
	}
}

func TestFlowdirShowRefusesWhatItDoesNotKnow(t *testing.T) {
	d, st := fdStub(t, fdTools())
	drv := open(t, d, Credential{Token: "FLOWKEY"})
	for _, cmd := range []string{
		"", "show", "status", "show config", "show top | grep x", "show nodes node=x", "show top by=nonsense", "show top limit=0", "show top limit=1001",
		"show top limit=x", "show top range=forever", "show top metric=money", "show top dedupe=maybe", "show top step=5m", "show timeseries step=soon",
		"show top bogus=1", "show top by", "show top from=yesterday", "show top filter=\"a\x01b\"", `show top filter="host=1`, "show top filter=",
		"show top " + `filter="` + strings.Repeat("a", 1001) + `"`,
	} {
		if _, err := drv.Show(context.Background(), cmd); err == nil {
			t.Errorf("%q was accepted", cmd)
		}
	}
	if st.count() != 0 {
		t.Errorf("%d bad commands reached FlowDirector", st.count())
	}
}
