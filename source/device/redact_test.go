package device

import (
	"strings"
	"testing"
)

// No path is refused for the words in it, so the answer is what keeps a secret from an MCP caller: the pre-shared keys, passwords and
// communities of a tunnel's configuration read (hidden) whichever path they came from.
func TestSecretsHiddenInPathsThatAreNowReadable(t *testing.T) {
	for _, p := range []string{"/api/v2/cmdb/vpn.ipsec/phase1-interface", "/mgmt/tm/net/ipsec/ike-peer", "/organizations/1/appliance/vpn/thirdPartyVPNPeers",
		"/api/v2/cmdb/system/snmp/community", "/api/v2/cmdb/user/local", "/rest/v10.09/system/users"} {
		if err := CheckAPIPathMCPFor("fortios", p); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	in := map[string]any{"results": []any{map[string]any{"name": "to-hq", "psksecret": "ENC abc123", "remote-gw": "10.1.1.1",
		"sharedSecret": "s3cret!", "pre-shared-key": "xyz789", "community": map[string]any{"name": "public", "authpass": "hunter2"}, "password": "p@ss"}}}
	out := toJSON(Redact(in))
	for _, leak := range []string{"abc123", "s3cret!", "xyz789", "hunter2", "p@ss"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	if !strings.Contains(out, "to-hq") || !strings.Contains(out, "10.1.1.1") {
		t.Errorf("the rest was hidden too: %s", out)
	}
	x := RedactConfig(`<entry name="gw1"><authentication><pre-shared-key><key>-AQ==abc123</key></pre-shared-key></authentication><phash>$1$xyz</phash></entry>`)
	if strings.Contains(x, "abc123") || strings.Contains(x, "$1$xyz") {
		t.Errorf("XML leaked: %s", x)
	}
}
