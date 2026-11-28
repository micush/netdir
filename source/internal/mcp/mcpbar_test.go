package mcp

import (
	"testing"
)

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
