package main

import (
	"encoding/json"
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestMCPNeverShowsSecretsEvenToRW(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	call := func(name, args string) (string, bool) {
		t.Helper()
		_, m := post(mcpCall(name, args))
		return toolResult(t, m)
	}
	gw := func(id int, name, key string) string {
		b, _ := json.Marshal(map[string]any{"group_id": id, "name": name, "interface": "lo", "vip4": "127.0.0." + map[int]string{100: "50", 101: "51"}[id] + "/8", "key": key})
		return string(b)
	}
	// the GUI saves the secrets; MCP is not shown them in any way of reading the configuration
	guiEditConfig(t, e, `{"groups":[`+gw(100, "a", "first-gateway-secret")+`,`+gw(101, "b", "second-gateway-secret")+`]}`)
	dc, err := core.LoadConfig(e.conf)
	if err != nil || len(dc.Groups) != 2 {
		t.Fatalf("not saved: %v", err)
	}
	for _, name := range []string{"get_config", "api_get"} {
		if _, m := post(mcpCall(name, `{"path":"/api/config"}`)); m["error"] == nil {
			t.Fatalf("%s still answers: %v", name, m)
		}
	}
	list, _ := call("list_devices", `{}`)
	if strings.Contains(list, "gateway-secret") {
		t.Fatalf("list_devices: %s", list)
	}
	// and nothing sent over MCP can change the configuration, the secrets included
	for _, name := range []string{"edit_config", "api_request"} {
		if _, m := post(mcpCall(name, `{"set":{"log_level":"debug"}}`)); m["error"] == nil {
			t.Fatalf("%s still answers: %v", name, m)
		}
	}
	after, _ := core.LoadConfig(e.conf)
	for i := range dc.Groups {
		if after.Groups[i].Key != dc.Groups[i].Key {
			t.Fatalf("a key changed: %+v", after.Groups)
		}
	}
}
