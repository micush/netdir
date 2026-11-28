package web

import (
	"encoding/json"
	"strings"
	"testing"
)

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
