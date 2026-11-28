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
