package main

import (
	"strings"
	"testing"
)

func TestMCPBarredRoutes(t *testing.T) {
	_, post := mcpEnv(t, "127.0.0.0/8 rw")
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if names := strings.Join(toolNames(t, m), " "); strings.Contains(names, "get_log") {
		t.Fatalf("get_log still offered: %s", names)
	}
	for _, p := range []string{"/api/log", "/api/log?n=5", "/api/tshoot/download", "/api/users", "/api/users/add", "/api/backup", "/api/mcpusage", "/api/cluster/token"} {
		_, m := post(mcpCall("api_get", `{"path":"`+p+`"}`))
		if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "not available over MCP") {
			t.Fatalf("%s: %s", p, txt)
		}
	}
	_, m = post(mcpCall("list_api", `{}`))
	if txt, _ := toolResult(t, m); strings.Contains(txt, "/api/log") || strings.Contains(txt, "/api/users") || strings.Contains(txt, "/api/tshoot") {
		t.Fatalf("list_api shows barred routes: %s", txt)
	}
}

func TestMCPDropAccounts(t *testing.T) {
	v := map[string]any{"settings": map[string]any{"mcp_keys": []any{"k"}, "mcp_acl": []any{"a"}, "snmp": 1, "ldap_servers": []any{"x"}, "sso_oidc_issuer": "i"},
		"web": map[string]any{"listen": ":1", "group": "g", "read_group": "r"}, "groups": []any{map[string]any{"group_id": 1}}}
	got := mcpDropAccounts(v).(map[string]any)
	s := got["settings"].(map[string]any)
	w := got["web"].(map[string]any)
	if len(s) != 1 || s["snmp"] != 1 || len(w) != 1 || w["listen"] != ":1" || len(got["groups"].([]any)) != 1 {
		t.Fatalf("%v", got)
	}
}
