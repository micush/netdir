package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestACLNotesAreKeptAndMerged(t *testing.T) {
	got, err := normMCPACL([]string{"10.1.1.50 rw # mike's laptop", "10.1.1.50 rw # for the audit", "10.1.1.50 # mike's laptop", "10.1.0.0/24 strict # the lab", "10.2.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.1.1.50 rw devices=none # mike's laptop; for the audit", "10.1.0.0/24 strict devices=none # the lab", "10.2.0.0/24 devices=none"}
	_ = want
	if len(got) != 3 || !strings.HasSuffix(got[0], "# mike's laptop; for the audit") || !strings.HasSuffix(got[1], "# the lab") || strings.Contains(got[2], "#") {
		t.Fatalf("%q", got)
	}
	again, err := normMCPACL(got)
	if err != nil || strings.Join(again, "|") != strings.Join(got, "|") {
		t.Fatalf("not stable: %q then %q (%v)", got, again, err)
	}
}

func TestACLNoteChangesNothing(t *testing.T) {
	// words in a note that look like settings must not act as settings
	list, err := normMCPACL([]string{"10.1.1.50 # rw disabled until=2020-01-01 devices=none strict"})
	if err != nil {
		t.Fatal(err)
	}
	e := list[0]
	if aclOff(e) || aclExpired(e) || t0(e) != "10.1.1.50" {
		t.Fatalf("a note acted as a setting: %q", e)
	}
	e2 := "10.1.1.50 rw disabled # " + "x"
	if !aclOff(e2) || aclBody(e2) != "10.1.1.50 rw disabled" {
		t.Fatal("disabled before a note is not seen")
	}
	if !aclExpired("10.1.1.50 until=2020-01-01 # still valid") {
		t.Fatal("an expiry before a note is not seen")
	}
	// the live check sees the same: ro from the address, whatever the note says
	_, e0 := mcpEnv(t, "127.0.0.1 # rw")
	_ = e0
	e3, _ := mcpEnv(t, "127.0.0.1 # rw strict disabled")
	acc, lvl := e3.ws.status.sup.mcpAccessLevel(netip.MustParseAddr("127.0.0.1"))
	if acc != "ro" || lvl != "" {
		t.Fatalf("access %q level %q: the note must not change them", acc, lvl)
	}
	e4, _ := mcpEnv(t, "127.0.0.1 rw # ro disabled")
	if acc, _ = e4.ws.status.sup.mcpAccessLevel(netip.MustParseAddr("127.0.0.1")); acc != "rw" {
		t.Fatalf("access %q", acc)
	}
}

func TestACLNoteRules(t *testing.T) {
	if _, err := normMCPACL([]string{"10.1.1.50 # " + strings.Repeat("x", 201)}); err == nil {
		t.Error("a note of 201 characters was accepted")
	}
	if _, err := normMCPACL([]string{"10.1.1.50 # a\x07b"}); err == nil {
		t.Error("a control character in a note was accepted")
	}
	if got, err := normMCPACL([]string{"10.1.1.50 # " + strings.Repeat("x", 200)}); err != nil || len(got) != 1 {
		t.Errorf("a note of 200 characters: %v %v", got, err)
	}
	if got, _ := normMCPACL([]string{"10.1.1.50 disabled   #   spaced   out  "}); len(got) != 1 || !strings.HasSuffix(got[0], "disabled # spaced out") {
		t.Errorf("%q", got)
	}
	if got, err := normMCPACL([]string{"# only a note"}); err != nil || len(got) != 0 {
		t.Errorf("a line that is only a note is ignored: %q %v", got, err)
	}
}

func TestKeyNotes(t *testing.T) {
	keys, err := normMCPKeys([]MCPKey{{Name: "laptop", Access: "ro", Key: testMCPKey(), Notes: "  mike's   laptop,  for the audit "}})
	if err != nil || keys[0].Notes != "mike's laptop, for the audit" {
		t.Fatalf("%+v %v", keys, err)
	}
	for _, bad := range []string{strings.Repeat("x", 201), "a\x07b"} {
		if _, err := normMCPKeys([]MCPKey{{Name: "k", Access: "ro", Key: testMCPKey(), Notes: bad}}); err == nil {
			t.Errorf("note %q was accepted", bad)
		}
	}
	if k, err := normMCPKeys([]MCPKey{{Name: "k", Access: "ro", Key: testMCPKey(), Notes: "a\nb"}}); err != nil || k[0].Notes != "a b" {
		t.Errorf("a line break becomes a space: %+v %v", k, err)
	}
	// the note is stored and is not the key
	if keys[0].Hash == "" || strings.Contains(keys[0].Hash, "laptop") {
		t.Fatalf("%+v", keys[0])
	}
}
