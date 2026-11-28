package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"netdir/internal/core"
)

func testMCPKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "netdir_" + base64.RawURLEncoding.EncodeToString(b)
}

func TestMCPKeyOpensFromAnyAddress(t *testing.T) {
	roKey, rwKey := testMCPKey(), testMCPKey()
	e, post := mcpEnv(t) // no address may use it
	keys, err := core.NormMCPKeys([]core.MCPKey{{Name: "reader", Key: roKey}, {Name: "laptop", Access: "rw", Key: rwKey}})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPKeys = keys
	sup.Mu.Unlock()
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
	if code != 200 || core.ContainsStr(toolNames(t, m), "device_change") || !core.ContainsStr(toolNames(t, m), "list_devices") {
		t.Fatalf("ro key: %d %v", code, m)
	}
	// read-write key: the device tools that change, and still nothing that edits netdir
	_, m = post(list, "Authorization", "bearer "+rwKey)
	if !core.ContainsStr(toolNames(t, m), "device_change") || core.ContainsStr(toolNames(t, m), "edit_config") {
		t.Fatalf("rw key tools: %v", toolNames(t, m))
	}
	// the address list still counts, and the higher access wins
	sup.Mu.Lock()
	sup.Dc.Settings.MCPACL = []string{"127.0.0.1"}
	sup.Mu.Unlock()
	if code, m := post(list); code != 200 || core.ContainsStr(toolNames(t, m), "device_change") {
		t.Fatalf("address only: %d", code)
	}
	if _, m := post(list, "Authorization", "Bearer "+rwKey); !core.ContainsStr(toolNames(t, m), "device_change") {
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
	dc, err := core.LoadConfig(e.conf)
	if err != nil || len(dc.Settings.MCPKeys) != 1 || dc.Settings.MCPKeys[0].Hash != core.McpKeyHash(k) || dc.Settings.MCPKeys[0].Key != k {
		t.Fatalf("saved: %v %+v", err, dc.Settings.MCPKeys)
	}
	if b, _ := os.ReadFile(e.conf); !strings.Contains(string(b), k) {
		t.Error("the key is not kept in the configuration, so it could not be shown again")
	}
	// but no MCP caller is shown it, and neither is a read-only account
	_, m = post(mcpCall("list_devices", `{}`))
	if txt, _ := toolResult(t, m); strings.Contains(txt, k) {
		t.Fatalf("list_devices shows the key: %s", txt)
	}
	if _, m = post(mcpCall("get_config", `{}`)); m["error"] == nil {
		t.Fatalf("get_config answered: %v", m)
	}
	// and it opens the endpoint, once the daemon has the configuration
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPACL, sup.Dc.Settings.MCPKeys = nil, dc.Settings.MCPKeys
	sup.Mu.Unlock()
	if code, _ := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "Authorization", "Bearer "+k); code != 200 {
		t.Fatalf("the saved key: %d", code)
	}
}

// A key with an expiry stops working at that time; the entry stays in the list.
func TestMCPKeyExpires(t *testing.T) {
	key := testMCPKey()
	e, post := mcpEnv(t)
	now := time.Now()
	keys, err := core.NormMCPKeys([]core.MCPKey{{Name: "temp", Key: key, Expires: now.Add(time.Hour).Unix()}})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPKeys = keys
	sup.Mu.Unlock()
	defer func() { core.McpNow = time.Now }()
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	if code, _ := post(list, "Authorization", "Bearer "+key); code != 200 {
		t.Fatalf("before the expiry: %d", code)
	}
	core.McpNow = func() time.Time { return now.Add(2 * time.Hour) }
	if code, _ := post(list, "Authorization", "Bearer "+key); code != 401 {
		t.Fatalf("after the expiry: %d", code)
	}
	if len(sup.McpKeys()) != 1 || !sup.McpKeys()[0].Expired() {
		t.Error("the key must stay in the list, expired")
	}
	if _, err := core.NormMCPKeys([]core.MCPKey{{Name: "bad", Key: testMCPKey(), Expires: -5}}); err == nil {
		t.Error("a negative expiry must be refused")
	}
}

// An address-list entry with until= allows its address until then; the list keeps it.
func TestMCPACLExpires(t *testing.T) {
	got, err := core.NormMCPACL([]string{"127.0.0.1 rw until=2026-12-31", "10.0.0.0/24 until=2030-01-02T03:04", "10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1 rw until=2026-12-31T23:59Z", "10.0.0.0/24 until=2030-01-02T03:04Z", "10.0.0.0/24"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q want %q", got, want)
	}
	if again, err := core.NormMCPACL(got); err != nil || strings.Join(again, "|") != strings.Join(got, "|") {
		t.Errorf("not stable: %q %v", again, err)
	}
	for _, bad := range []string{"127.0.0.1 until=tomorrow", "127.0.0.1 until=2026-13-01"} {
		if _, err := core.NormMCPACL([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	e, post := mcpEnv(t, "127.0.0.1 until=2026-12-31")
	_ = e
	defer func() { core.McpNow = time.Now }()
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	core.McpNow = func() time.Time { return time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC) }
	if code, _ := post(list); code != 200 {
		t.Fatalf("before the end: %d", code)
	}
	core.McpNow = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	if code, _ := post(list); code != 403 {
		t.Fatalf("after the end: %d", code)
	}
	if !core.AclExpired("127.0.0.1 until=2026-12-31T23:59Z") || core.AclExpired("127.0.0.1 rw") {
		t.Error("aclExpired")
	}
}
