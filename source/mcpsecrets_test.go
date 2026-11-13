package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPRedactHidesEverySecretKind(t *testing.T) {
	in := map[string]any{
		"groups": []any{map[string]any{"group_id": 100, "key": "gw-secret"}},
		"bgp":    map[string]any{"neighbors": []any{map[string]any{"peer": "192.0.2.1", "password": "bgp-secret"}}},
		"settings": map[string]any{"snmp_communities": []any{"comm-secret"}, "metrics_acl": []any{"192.0.2.9"},
			"device_credentials": []any{map[string]any{"name": "lab", "username": "admin", "password": "dev-secret", "token": "devtok-secret"}}},
		"web":   map[string]any{"ldap_bind_password": "ldap-secret", "key_file": "/etc/k.pem", "sso_oidc_client_secret": ""},
		"pools": []any{map[string]any{"key": 100}},
		"join":  map[string]any{"code": "join-secret", "token": "tok-secret"},
	}
	b, _ := json.Marshal(mcpRedact(in))
	s := string(b)
	for _, secret := range []string{"gw-secret", "bgp-secret", "comm-secret", "dev-secret", "devtok-secret", "ldap-secret", "join-secret", "tok-secret"} {
		if strings.Contains(s, secret) {
			t.Errorf("%s is shown: %s", secret, s)
		}
	}
	// what is not a secret stays: an access list, a user name, a file name, a numeric key, an empty secret (none set)
	for _, keep := range []string{`"192.0.2.9"`, `"username":"admin"`, `"key_file":"/etc/k.pem"`, `"key":100`, `"sso_oidc_client_secret":""`, `"peer":"192.0.2.1"`} {
		if !strings.Contains(s, keep) {
			t.Errorf("%s was hidden: %s", keep, s)
		}
	}
	if in["groups"].([]any)[0].(map[string]any)["key"] != "gw-secret" {
		t.Fatal("the input was changed")
	}
}

func TestMCPRestoreHiddenMatchesByIdentity(t *testing.T) {
	cur := map[string]any{
		"neighbors": []any{map[string]any{"peer": "192.0.2.1", "password": "one"}, map[string]any{"peer": "192.0.2.2", "password": "two"}},
		"key":       "top",
	}
	// the list came back reordered: each secret follows its peer, not its place
	v := map[string]any{
		"neighbors": []any{map[string]any{"peer": "192.0.2.2", "password": mcpHidden}, map[string]any{"peer": "192.0.2.1", "password": mcpHidden}},
		"key":       mcpHidden,
	}
	var miss []string
	mcpRestoreHidden(v, cur, "", &miss)
	n := v["neighbors"].([]any)
	if len(miss) != 0 || n[0].(map[string]any)["password"] != "two" || n[1].(map[string]any)["password"] != "one" || v["key"] != "top" {
		t.Fatalf("restored: %v, missing %v", v, miss)
	}
	// a new neighbor with "(hidden)" has nothing to keep: refused, and the path says where
	v = map[string]any{"neighbors": []any{map[string]any{"peer": "192.0.2.3", "password": mcpHidden}}}
	miss = nil
	mcpRestoreHidden(v, cur, "", &miss)
	if len(miss) != 1 || miss[0] != "neighbors[0].password" {
		t.Fatalf("unmatched: %v", miss)
	}
	// without an identity field, an entry is matched by place only when the list kept its length
	cur = map[string]any{"l": []any{map[string]any{"secret": "a"}, map[string]any{"secret": "b"}}}
	v = map[string]any{"l": []any{map[string]any{"secret": mcpHidden}}}
	miss = nil
	mcpRestoreHidden(v, cur, "", &miss)
	if len(miss) != 1 {
		t.Fatalf("a shorter list matched by place: %v", v)
	}
	// "(hidden)" under a key that is no secret is left for mcpFindHidden to refuse
	v = map[string]any{"name": mcpHidden}
	miss = nil
	mcpRestoreHidden(v, map[string]any{"name": "x"}, "", &miss)
	mcpFindHidden(v, "", &miss)
	if len(miss) != 1 || miss[0] != "name" {
		t.Fatalf("not a secret: %v", miss)
	}
}

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
	dc, err := loadConfig(e.conf)
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
	after, _ := loadConfig(e.conf)
	for i := range dc.Groups {
		if after.Groups[i].Key != dc.Groups[i].Key {
			t.Fatalf("a key changed: %+v", after.Groups)
		}
	}
}
