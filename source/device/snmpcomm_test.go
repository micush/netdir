package device

import (
	"strings"
	"testing"
)

// The plural names (snmp_communities, snmp-communities) hold community strings too; BGP communities are not secrets.
func TestSNMPCommunitiesAreHidden(t *testing.T) {
	m := Redact(map[string]any{"snmp_communities": []any{"public", "s3cr3tRO"}, "snmp-communities": "s3cr3tRO", "snmpCommunities": "s3cr3tRO",
		"read_community": "s3cr3tRO", "bgp_communities": "65000:100"}).(map[string]any)
	for _, k := range []string{"snmp_communities", "snmp-communities", "snmpCommunities", "read_community"} {
		if v := toJSONString(m[k]); strings.Contains(v, "s3cr3tRO") || strings.Contains(v, "public") {
			t.Errorf("%s leaked: %v", k, m[k])
		}
	}
	if m["bgp_communities"] != "65000:100" {
		t.Errorf("a BGP community was hidden: %v", m["bgp_communities"])
	}
	if out := redactLine(`  "snmp_communities": "s3cr3tRO",`); strings.Contains(out, "s3cr3tRO") {
		t.Errorf("line leaked: %q", out)
	}
	if out := redactLine("snmp-server community s3cr3tRO RO"); strings.Contains(out, "s3cr3tRO") {
		t.Errorf("CLI line leaked: %q", out)
	}
}

func TestListUnderSecretNameIsHidden(t *testing.T) {
	m := Redact(map[string]any{"radius_passwords": []any{"hunter2", "hunter3"}, "servers": []any{"10.0.0.1"}}).(map[string]any)
	if v := toJSONString(m["radius_passwords"]); strings.Contains(v, "hunter") {
		t.Errorf("list leaked: %v", v)
	}
	if toJSONString(m["servers"]) != `["10.0.0.1"]` {
		t.Errorf("a plain list was hidden: %v", m["servers"])
	}
}
