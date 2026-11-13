package main

import (
	"testing"
)

func TestMCPBarredRoutes(t *testing.T) {
	_, post := mcpEnv(t, "127.0.0.0/8 rw")
	requireGateTools(t, post) // no get_log, api_get or list_api: the logs, users, backups and tokens have no way in
	for _, p := range []string{"/api/log", "/api/log?n=5", "/api/tshoot/download", "/api/users", "/api/users/add", "/api/backup", "/api/mcpusage", "/api/cluster/token"} {
		_, m := post(mcpCall("api_get", `{"path":"`+p+`"}`))
		if m["error"] == nil {
			t.Fatalf("%s: api_get answered: %v", p, m)
		}
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
