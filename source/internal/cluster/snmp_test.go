package cluster

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestSNMPConfigHistoryHidesTheStrings(t *testing.T) {
	a, b := core.NewDaemonConfig(), core.NewDaemonConfig()
	b.Settings.SNMPCommunities = []string{"verysecret"}
	b.SNMP = &core.SNMPConfig{Location: "lab"}
	var text string
	for _, s := range configSections(a, b) {
		text += s.Label + ": " + s.Detail + "\n"
	}
	if !strings.Contains(text, "SNMP switched on with 1 community string(s)") || !strings.Contains(text, "location changed") || strings.Contains(text, "verysecret") {
		t.Fatalf("%q", text)
	}
}

func TestSNMPCommunitiesAndContactAreSharedLocationIsNot(t *testing.T) {
	a := core.NewDaemonConfig()
	a.Settings.SNMPCommunities = []string{"public", "ro2"}
	a.Settings.SNMPContact = "noc@example.com"
	a.SNMP = &core.SNMPConfig{Location: "rack A"}
	sh := core.SharedOf(a)
	if len(sh.Settings.SNMPCommunities) != 2 || sh.Settings.SNMPContact != "noc@example.com" {
		t.Fatalf("not replicated: %+v", sh.Settings)
	}
	b := core.NewDaemonConfig()
	b.SNMP = &core.SNMPConfig{Location: "rack B"}
	if _, err := MergeShared(b, sh, nil); err != nil {
		t.Fatal(err)
	}
	got := b.SnmpSettings()
	if len(got.Communities) != 2 || got.Contact != "noc@example.com" || got.Location != "rack B" {
		t.Fatalf("%+v", got)
	}
	// emptying on the primary empties the replica
	a.Settings.SNMPCommunities = nil
	if _, err := MergeShared(b, core.SharedOf(a), nil); err != nil {
		t.Fatal(err)
	}
	if b.SnmpSettings().Enabled() {
		t.Fatal("communities should be gone")
	}
}
