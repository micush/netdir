package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func testMCPKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "netdir_" + base64.RawURLEncoding.EncodeToString(b)
}

func TestNormMCPKeys(t *testing.T) {
	k := testMCPKey()
	out, err := normMCPKeys([]MCPKey{{Name: "laptop", Key: k}, {Name: "ops-1", Access: "RW", Hash: strings.ToUpper(mcpKeyHash(testMCPKey()))}})
	if err != nil || len(out) != 2 {
		t.Fatal(err, out)
	}
	if out[0].Key != k || out[0].Hash != mcpKeyHash(k) || out[0].Access != "ro" || out[0].Created == 0 {
		t.Fatalf("new key: %+v", out[0])
	}
	if out[1].Access != "rw" || !strings.HasPrefix(out[1].Hash, "sha256:") || out[1].Hash != strings.ToLower(out[1].Hash) || out[1].Created != 0 {
		t.Fatalf("kept key: %+v", out[1])
	}
	if l, err := normMCPKeys(nil); l != nil || err != nil {
		t.Fatal("empty")
	}
	for name, bad := range map[string][]MCPKey{
		"no name":      {{Key: k}},
		"bad name":     {{Name: "my laptop", Key: k}},
		"same name":    {{Name: "a", Key: k}, {Name: "A", Key: testMCPKey()}},
		"same key":     {{Name: "a", Key: k}, {Name: "b", Key: k}},
		"short key":    {{Name: "a", Key: "short"}},
		"spaces":       {{Name: "a", Key: " " + k}},
		"no key, hash": {{Name: "a"}},
		"bad hash":     {{Name: "a", Hash: "sha256:abcd"}},
		"bad access":   {{Name: "a", Key: k, Access: "admin"}},
	} {
		if _, err := normMCPKeys(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMCPKeyOpensFromAnyAddress(t *testing.T) {
	roKey, rwKey := testMCPKey(), testMCPKey()
	e, post := mcpEnv(t) // no address may use it
	keys, err := normMCPKeys([]MCPKey{{Name: "reader", Key: roKey}, {Name: "laptop", Access: "rw", Key: rwKey}})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.MCPKeys = keys
	sup.mu.Unlock()
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	if code, _ := post(init); code != 403 {
		t.Fatalf("no key, no address: %d", code)
	}
	if code, _ := post(init, "Authorization", "Bearer "+testMCPKey()); code != 401 {
		t.Fatalf("wrong key: %d", code)
	}
	if code, _ := post(init, "Authorization", "Basic "+roKey); code != 401 {
		t.Fatalf("not Bearer: %d", code)
	}
	// read-only key: the read tools only, and a write is refused
	code, m := post(list, "Authorization", "Bearer "+roKey)
	if code != 200 || containsStr(toolNames(t, m), "device_change") || !containsStr(toolNames(t, m), "get_config") {
		t.Fatalf("ro key: %d %v", code, m)
	}
	// read-write key: the device tools that change, and still nothing that edits netdir
	_, m = post(list, "Authorization", "bearer "+rwKey)
	if !containsStr(toolNames(t, m), "device_change") || containsStr(toolNames(t, m), "edit_config") {
		t.Fatalf("rw key tools: %v", toolNames(t, m))
	}
	// the address list still counts, and the higher access wins
	sup.mu.Lock()
	sup.dc.Settings.MCPACL = []string{"127.0.0.1"}
	sup.mu.Unlock()
	if code, m := post(list); code != 200 || containsStr(toolNames(t, m), "device_change") {
		t.Fatalf("address only: %d", code)
	}
	if _, m := post(list, "Authorization", "Bearer "+rwKey); !containsStr(toolNames(t, m), "device_change") {
		t.Fatal("ro address + rw key is not rw")
	}
	if code, _ := post(list, "Authorization", "Bearer "+testMCPKey()); code != 401 {
		t.Fatalf("a wrong key from an allowed address: %d", code)
	}
}

// A key added through the configuration is kept (to be shown again in the GUI) with its hash, and is in no MCP answer.
func TestMCPKeyIsKeptAndHidden(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	k := testMCPKey()
	set, _ := json.Marshal(map[string]any{"settings": map[string]any{"mcp_keys": []any{map[string]any{"name": "laptop", "access": "rw", "key": k}}}})
	guiEditConfig(t, e, string(set))
	var m map[string]any
	dc, err := loadConfig(e.conf)
	if err != nil || len(dc.Settings.MCPKeys) != 1 || dc.Settings.MCPKeys[0].Hash != mcpKeyHash(k) || dc.Settings.MCPKeys[0].Key != k {
		t.Fatalf("saved: %v %+v", err, dc.Settings.MCPKeys)
	}
	if b, _ := os.ReadFile(e.conf); !strings.Contains(string(b), k) {
		t.Error("the key is not kept in the configuration, so it could not be shown again")
	}
	// but no MCP caller is shown it, and neither is a read-only account
	_, m = post(mcpCall("get_config", `{}`))
	if txt, _ := toolResult(t, m); strings.Contains(txt, k) {
		t.Fatalf("get_config shows the key: %s", txt)
	}
	// and it opens the endpoint, once the daemon has the configuration
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.MCPACL, sup.dc.Settings.MCPKeys = nil, dc.Settings.MCPKeys
	sup.mu.Unlock()
	if code, _ := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "Authorization", "Bearer "+k); code != 200 {
		t.Fatalf("the saved key: %d", code)
	}
}
