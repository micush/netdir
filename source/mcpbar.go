package main

import (
	"encoding/json"
	"strings"
)

// mcpRouteBarred: the routes an MCP caller never reaches, whatever its access: the logs (the daemon's, and the
// troubleshooting bundle with the MCP content log in it), the accounts (users, groups, their access) and the keys and
// backups.  The GUI and the CLI keep them.
func mcpRouteBarred(path string) bool {
	for _, p := range []string{"/api/log", "/api/tshoot", "/api/users", "/api/backup", "/api/mcpusage", "/api/cluster/token"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// mcpDropAccounts removes from an answer what names who may sign in or call: the MCP keys and allowed sources, the login
// groups, and the LDAP and SSO settings.  v is generic JSON; it is changed in place and returned.
func mcpDropAccounts(v any) any {
	switch t := v.(type) {
	case map[string]any:
		_, web := t["read_group"]
		for k, e := range t {
			lk := strings.ToLower(k)
			if lk == "mcp_keys" || lk == "mcp_acl" || lk == "ldap" || lk == "sso" || strings.HasPrefix(lk, "ldap_") || strings.HasPrefix(lk, "sso_") ||
				(web && (lk == "group" || lk == "read_group" || lk == "pam_service")) {
				delete(t, k)
				continue
			}
			mcpDropAccounts(e)
		}
	case []any:
		for _, e := range t {
			mcpDropAccounts(e)
		}
	}
	return v
}

// mcpAsAny turns any value into generic JSON.
func mcpAsAny(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}
