package core

import (
	"strings"
	"testing"
)

func TestACLNotesAreKeptAndMerged(t *testing.T) {
	got, err := NormMCPACL([]string{"10.1.1.50 rw # mike's laptop", "10.1.1.50 rw # for the audit", "10.1.1.50 # mike's laptop", "10.1.0.0/24 strict # the lab", "10.2.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.1.1.50 rw devices=none # mike's laptop; for the audit", "10.1.0.0/24 strict devices=none # the lab", "10.2.0.0/24 devices=none"}
	_ = want
	if len(got) != 3 || !strings.HasSuffix(got[0], "# mike's laptop; for the audit") || !strings.HasSuffix(got[1], "# the lab") || strings.Contains(got[2], "#") {
		t.Fatalf("%q", got)
	}
	again, err := NormMCPACL(got)
	if err != nil || strings.Join(again, "|") != strings.Join(got, "|") {
		t.Fatalf("not stable: %q then %q (%v)", got, again, err)
	}
}

func TestACLNoteRules(t *testing.T) {
	if _, err := NormMCPACL([]string{"10.1.1.50 # " + strings.Repeat("x", 201)}); err == nil {
		t.Error("a note of 201 characters was accepted")
	}
	if _, err := NormMCPACL([]string{"10.1.1.50 # a\x07b"}); err == nil {
		t.Error("a control character in a note was accepted")
	}
	if got, err := NormMCPACL([]string{"10.1.1.50 # " + strings.Repeat("x", 200)}); err != nil || len(got) != 1 {
		t.Errorf("a note of 200 characters: %v %v", got, err)
	}
	if got, _ := NormMCPACL([]string{"10.1.1.50 disabled   #   spaced   out  "}); len(got) != 1 || !strings.HasSuffix(got[0], "disabled # spaced out") {
		t.Errorf("%q", got)
	}
	if got, err := NormMCPACL([]string{"# only a note"}); err != nil || len(got) != 0 {
		t.Errorf("a line that is only a note is ignored: %q %v", got, err)
	}
}

func TestKeyNotes(t *testing.T) {
	keys, err := NormMCPKeys([]MCPKey{{Name: "laptop", Access: "ro", Key: testMCPKey(), Notes: "  mike's   laptop,  for the audit "}})
	if err != nil || keys[0].Notes != "mike's laptop, for the audit" {
		t.Fatalf("%+v %v", keys, err)
	}
	for _, bad := range []string{strings.Repeat("x", 201), "a\x07b"} {
		if _, err := NormMCPKeys([]MCPKey{{Name: "k", Access: "ro", Key: testMCPKey(), Notes: bad}}); err == nil {
			t.Errorf("note %q was accepted", bad)
		}
	}
	if k, err := NormMCPKeys([]MCPKey{{Name: "k", Access: "ro", Key: testMCPKey(), Notes: "a\nb"}}); err != nil || k[0].Notes != "a b" {
		t.Errorf("a line break becomes a space: %+v %v", k, err)
	}
	// the note is stored and is not the key
	if keys[0].Hash == "" || strings.Contains(keys[0].Hash, "laptop") {
		t.Fatalf("%+v", keys[0])
	}
}
