package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// roAuth: alice is in the login group, bob only in the read-only group "view".
type roAuth struct{ fakeAuth }

func (a *roAuth) InGroup(user, group string) (bool, error) {
	switch group {
	case "netdir,netdir-users":
		return user == "alice", nil
	case "view":
		return user == "bob", nil
	}
	return false, nil
}

func TestRedactSecrets(t *testing.T) {
	in := map[string]any{"a": map[string]any{"key": "abc", "password": "pw", "name": "n", "list": []any{map[string]any{"secret": "s", "key": ""}}}}
	out := redactSecrets(in)
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "abc") || strings.Contains(string(b), `"pw"`) || !strings.Contains(string(b), `"name":"n"`) || !strings.Contains(string(b), `"secret":"(hidden)"`) {
		t.Fatalf("redacted: %s", b)
	}
	if in["a"].(map[string]any)["key"] != "abc" {
		t.Fatal("the input was changed")
	}
}
