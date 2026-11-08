package main

import (
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

// netdirStub is another Network Director's MCP endpoint: list_devices (one device of its own, one below the director it has as a
// device) and device_facts, which answers for the names it is asked.
func netdirStub(t *testing.T, calls *[]string, mu *sync.Mutex) device.Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Header.Get("Authorization") != "Bearer KEY" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		var q struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &q)
		mu.Lock()
		*calls = append(*calls, q.Params.Name+" "+toStr(q.Params.Arguments["target"]))
		mu.Unlock()
		var v any
		switch q.Params.Name {
		case "list_devices":
			v = map[string]any{"instance": "child1", "platforms": []string{"observium"},
				"devices": []any{map[string]any{"name": "obs", "platform": "observium", "address": "10.9.0.5"}, map[string]any{"name": "sw1", "platform": "eos", "address": "10.9.0.6"}},
				"health":  map[string]any{"obs": map[string]any{"status": "ok", "detail": "answers"}},
				"remote": []any{map[string]any{"name": "vcenter", "orig": "vcenter", "platform": "vcenter", "address": "10.20.0.2", "via": []string{"nd4"}, "inst": "grand1", "status": "bad", "detail": "no answer"},
					map[string]any{"name": "looped", "platform": "eos", "address": "10.0.0.99", "via": []string{"x"}, "inst": "parent1"}}}
		case "device_facts":
			var rs []any
			for _, n := range strings.Split(toStr(q.Params.Arguments["target"]), ",") {
				rs = append(rs, map[string]any{"device": n, "platform": "vcenter", "ok": true, "data": map[string]any{"hostname": "host-of-" + n}, "ms": 5})
			}
			v = map[string]any{"op": "facts", "asked": len(rs), "failed": 0, "results": rs}
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32602, "message": "unknown tool"}})
			return
		}
		j, _ := json.Marshal(v)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": string(j)}}}})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return device.Device{Name: "nd3", Platform: "netdir", Address: host, Port: p, Credential: "k", Insecure: true}
}

func toStr(v any) string { s, _ := v.(string); return s }

func resetDown(t *testing.T) {
	t.Helper()
	down.mu.Lock()
	down.list, down.errs, down.at = nil, nil, time.Time{}
	down.mu.Unlock()
	t.Cleanup(func() {
		down.mu.Lock()
		down.list, down.errs, down.at = nil, nil, time.Time{}
		down.mu.Unlock()
	})
}

func TestChainedDirectorsAnswerForDevicesBelow(t *testing.T) {
	resetDown(t)
	old := instanceOf
	instanceOf = func() string { return "parent1" }
	t.Cleanup(func() { instanceOf = old })
	var calls []string
	var mu sync.Mutex
	nd3 := netdirStub(t, &calls, &mu)
	e, post := mcpEnv(t, "127.0.0.1")
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.DeviceCredentials = []device.Credential{{Name: "k", Token: "KEY"}}
	sup.dc.Settings.Devices = []device.Device{nd3, {Name: "sw1", Platform: "iosxe", Address: "10.0.0.1", Credential: "k", Insecure: true}}
	sup.mu.Unlock()

	_, m := post(mcpCall("list_devices", `{}`))
	txt, isErr := toolResult(t, m)
	if isErr {
		t.Fatalf("list_devices: %s", txt)
	}
	var got struct {
		Remote []RemoteDevice    `json:"remote"`
		Errs   map[string]string `json:"remote_errors"`
	}
	if err := json.Unmarshal([]byte(txt), &got); err != nil {
		t.Fatalf("%v: %s", err, txt)
	}
	by := map[string]RemoteDevice{}
	for _, r := range got.Remote {
		by[r.Name] = r
	}
	if len(got.Remote) != 3 || by["obs"].Status != "ok" || strings.Join(by["obs"].Via, ">") != "nd3" {
		t.Fatalf("what is below nd3: %+v errs %v", got.Remote, got.Errs)
	}
	if v := by["vcenter"]; strings.Join(v.Via, ">") != "nd3>nd4" || v.Status != "bad" || v.Orig != "vcenter" {
		t.Errorf("a device two directors down: %+v", v)
	}
	if q, ok := by["sw1@nd3"]; !ok || q.Orig != "sw1" {
		t.Errorf("sw1 is the name of a local device: the one below is sw1@nd3: %+v", got.Remote)
	}
	if _, ok := by["looped"]; ok {
		t.Error("a device of this installation that came back through the chain is listed")
	}

	// a read for a device below goes down to the director that has it, by the name that director knows
	mu.Lock()
	calls = nil
	mu.Unlock()
	_, m = post(mcpCall("device_facts", `{"target":"vcenter,sw1@nd3,sw1"}`))
	txt, isErr = toolResult(t, m)
	if isErr || !strings.Contains(txt, "host-of-vcenter") || !strings.Contains(txt, "host-of-sw1") || !strings.Contains(txt, `"sw1@nd3"`) {
		t.Fatalf("device_facts: %v %s", isErr, txt)
	}
	mu.Lock()
	last := calls[len(calls)-1]
	mu.Unlock()
	if last != "device_facts sw1,vcenter" {
		t.Errorf("sent down: %q (all calls %v)", last, calls)
	}

	// a name nobody has is an error, after a new look
	_, m = post(mcpCall("device_facts", `{"target":"nosuch"}`))
	if _, isErr = toolResult(t, m); !isErr {
		t.Error("a device nobody has was not an error")
	}

	// a change or a capture is made on the director that owns the device
	if err := refuseRemote("vcenter"); err == nil || !strings.Contains(err.Error(), "nd4") {
		t.Errorf("a change for a device below: %v", err)
	}
	if err := refuseRemote("sw1,tag:x"); err != nil {
		t.Errorf("a local device: %v", err)
	}
}

func TestDirectorBelowThatIsDown(t *testing.T) {
	resetDown(t)
	e, _ := mcpEnv(t, "127.0.0.1")
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.DeviceCredentials = []device.Credential{{Name: "k", Token: "KEY"}}
	sup.dc.Settings.Devices = []device.Device{{Name: "nd9", Platform: "netdir", Address: "127.0.0.1", Port: 1, Credential: "k", Insecure: true}}
	sup.mu.Unlock()
	list, errs := sup.remoteDevices(5*time.Second, true)
	if len(list) != 0 || errs["nd9"] == "" {
		t.Errorf("a director that does not answer: %v %v", list, errs)
	}
}

func TestBuildRemote(t *testing.T) {
	dir := device.Device{Name: "nd3", Platform: "netdir"}
	dir2 := device.Device{Name: "nd2", Platform: "netdir"}
	local := []device.Device{{Name: "sw1"}}
	parts := []downPart{
		{dir: dir, below: []device.Below{
			{Name: "a", Platform: "eos", Address: "10.0.0.1", Inst: "i1"},
			{Name: "sw1", Platform: "eos", Address: "10.0.0.2", Inst: "i1"},
			{Name: "deep", Platform: "eos", Address: "10.0.0.3", Inst: "i2", Via: []string{"n4", "n5", "n6", "n7", "n8"}}, // too long a chain
			{Name: "back", Platform: "eos", Address: "10.0.0.4", Inst: "me"},                                              // this installation's own
		}},
		{dir: dir2, below: []device.Below{
			{Name: "a-again", Platform: "eos", Address: "10.0.0.1", Inst: "i1", Via: []string{"x"}}, // the same device by a longer way
			{Name: "a", Platform: "eos", Address: "10.1.0.1", Inst: "i3"},                           // another device with the name taken
		}},
	}
	out := buildRemote(local, parts, "me")
	var names []string
	for _, r := range out {
		names = append(names, r.Name+"="+strings.Join(r.Via, ">"))
	}
	want := "a=nd2,a@nd3=nd3,sw1@nd3=nd3"
	if strings.Join(names, ",") != want {
		t.Errorf("index:\n got %v\nwant %s", names, want)
	}
	// the same address under another installation is another device; with no installation named, only the same name on the same director is the same
	again := buildRemote(nil, []downPart{{dir: dir, below: []device.Below{{Name: "a", Platform: "eos", Address: "10.0.0.1"}, {Name: "b", Platform: "eos", Address: "10.0.0.1"}}}}, "")
	if len(again) != 2 {
		t.Errorf("unnamed owner: %+v", again)
	}
}
