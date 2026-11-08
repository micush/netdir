package main

import (
	"net/netip"
	"strings"
	"testing"
)

// right-click ▸ Disable on an allowed source: it stays in the list and allows nothing
func TestMCPACLDisabledEntries(t *testing.T) {
	out, err := normMCPACL([]string{"10.1.1.50 rw disabled", "10.1.0.0/24 strict disabled", "10.1.0.0/24", "10.1.1.50 rw", "10.1.1.50 RW  Disabled", "192.0.2.5 disabled"})
	if err != nil {
		t.Fatal(err)
	}
	want := "10.1.1.50 rw disabled|10.1.0.0/24 strict disabled|10.1.0.0/24|10.1.1.50 rw|192.0.2.5 disabled"
	if strings.Join(out, "|") != want {
		t.Errorf("written:\n got %q\nwant %q", strings.Join(out, "|"), want)
	}
	again, err := normMCPACL(out) // writing it again changes nothing
	if err != nil || strings.Join(again, "|") != want {
		t.Errorf("second pass: %v %v", err, again)
	}
	for _, bad := range []string{"10.0.0.0/8 rw disabled", "10.1.1.50 rw strict extra disabled", "disabled"} {
		if _, err := normMCPACL([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}

	e, _ := mcpEnv(t, "10.1.1.50 rw disabled", "10.1.0.0/24 strict disabled", "10.0.0.0/8", "192.0.2.5 disabled")
	sup := e.ws.status.sup
	for from, want := range map[string]string{"10.1.1.50": "ro", "10.1.0.7": "ro", "192.0.2.5": "", "10.9.9.9": "ro", "172.16.0.1": ""} {
		acc, lvl := sup.mcpAccessLevel(netip.MustParseAddr(from))
		if acc != want || lvl != "" {
			t.Errorf("%s: %q %q, want %q and no level", from, acc, lvl, want)
		}
	}
	// enabled again, the same entries allow
	sup.mu.Lock()
	sup.dc.Settings.MCPACL = []string{"10.1.1.50 rw", "10.1.0.0/24 strict"}
	sup.mu.Unlock()
	if acc, lvl := sup.mcpAccessLevel(netip.MustParseAddr("10.1.1.50")); acc != "rw" || lvl != "" {
		t.Errorf("enabled: %q %q", acc, lvl)
	}
}

func TestMCPKeyDisabled(t *testing.T) {
	k1, k2 := testMCPKey(), testMCPKey()
	keys, err := normMCPKeys([]MCPKey{{Name: "a", Key: k1, Disabled: true}, {Name: "b", Access: "rw", Key: k2}})
	if err != nil || !keys[0].Disabled || keys[1].Disabled {
		t.Fatalf("%v %+v", err, keys)
	}
	if n, a := mcpKeyAccess(keys, k1); n != "" || a != "" {
		t.Errorf("a disabled key: %q %q", n, a)
	}
	if n, a := mcpKeyAccess(keys, k2); n != "b" || a != "rw" {
		t.Errorf("an enabled key: %q %q", n, a)
	}
	keys[0].Disabled = false
	if n, a := mcpKeyAccess(keys, k1); n != "a" || a != "ro" {
		t.Errorf("enabled again: %q %q", n, a)
	}

	// over the endpoint: refused like an unknown key, and let in again once enabled
	e, post := mcpEnv(t)
	sup := e.ws.status.sup
	set := func(off bool) {
		ks, _ := normMCPKeys([]MCPKey{{Name: "a", Key: k1, Disabled: off}})
		sup.mu.Lock()
		sup.dc.Settings.MCPKeys = ks
		sup.mu.Unlock()
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	set(true)
	if code, _ := post(init, "Authorization", "Bearer "+k1); code != 401 {
		t.Errorf("a disabled key: %d", code)
	}
	set(false)
	if code, _ := post(init, "Authorization", "Bearer "+k1); code != 200 {
		t.Errorf("an enabled key: %d", code)
	}
}
