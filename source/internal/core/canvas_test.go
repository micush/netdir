package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGroupsKeyMeaning(t *testing.T) {
	load := func(js string) *DaemonConfig {
		t.Helper()
		dc := NewDaemonConfig()
		if err := json.Unmarshal([]byte(js), dc); err != nil {
			t.Fatal(err)
		}
		return dc
	}
	if n := len(load(`{}`).Groups); n != 1 {
		t.Fatalf("absent groups = default group, got %d", n)
	}
	if n := len(load(`{"groups":null}`).Groups); n != 1 {
		t.Fatalf("null groups = default group, got %d", n)
	}
	dc := load(`{"groups":[]}`)
	if dc.Groups == nil || len(dc.Groups) != 0 {
		t.Fatalf("explicit empty groups must stay empty: %v", dc.Groups)
	}
	if err := dc.Validate(); err != nil {
		t.Fatalf("a config with no gateways is valid: %v", err)
	}
	// and it survives a save/load round trip as [] (not null, not the default)
	path := t.TempDir() + "/c.json"
	if err := dc.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadConfig(path)
	if err != nil || len(back.Groups) != 0 {
		t.Fatalf("round trip: %v %v", back, err)
	}
}

func TestDuplicateSharedAddressRefused(t *testing.T) {
	dc := NewDaemonConfig()
	g2 := DefaultGroup()
	g2.GroupID = 2
	dc.Groups = append(dc.Groups, g2) // same 10.0.0.1/24 as group 1
	err := dc.Validate()
	if err == nil || !strings.Contains(err.Error(), "shared address") {
		t.Fatalf("two gateways on one address must be refused: %v", err)
	}
	dc.Groups[1].VIP4 = "10.0.1.1/24"
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}
