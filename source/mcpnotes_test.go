package main

import (
	"net/netip"
	"testing"

	"netdir/internal/core"
)

func TestACLNoteChangesNothing(t *testing.T) {
	// words in a note that look like settings must not act as settings
	list, err := core.NormMCPACL([]string{"10.1.1.50 # rw disabled until=2020-01-01 devices=none strict"})
	if err != nil {
		t.Fatal(err)
	}
	e := list[0]
	if core.AclOff(e) || core.AclExpired(e) || core.T0(e) != "10.1.1.50" {
		t.Fatalf("a note acted as a setting: %q", e)
	}
	e2 := "10.1.1.50 rw disabled # " + "x"
	if !core.AclOff(e2) || core.AclBody(e2) != "10.1.1.50 rw disabled" {
		t.Fatal("disabled before a note is not seen")
	}
	if !core.AclExpired("10.1.1.50 until=2020-01-01 # still valid") {
		t.Fatal("an expiry before a note is not seen")
	}
	// the live check sees the same: ro from the address, whatever the note says
	_, e0 := mcpEnv(t, "127.0.0.1 # rw")
	_ = e0
	e3, _ := mcpEnv(t, "127.0.0.1 # rw strict disabled")
	acc, lvl := e3.ws.Status.Sup().McpAccessLevel(netip.MustParseAddr("127.0.0.1"))
	if acc != "ro" || lvl != "" {
		t.Fatalf("access %q level %q: the note must not change them", acc, lvl)
	}
	e4, _ := mcpEnv(t, "127.0.0.1 rw # ro disabled")
	if acc, _ = e4.ws.Status.Sup().McpAccessLevel(netip.MustParseAddr("127.0.0.1")); acc != "rw" {
		t.Fatalf("access %q", acc)
	}
}
