package device

import "testing"

// A FortiGate's VPN status and event log may be read over MCP; the configuration of a tunnel (its pre-shared key) may not.
func TestFortiVPNStatusReadable(t *testing.T) {
	for _, p := range []string{"/api/v2/monitor/vpn/ipsec", "/api/v2/monitor/vpn/ipsec/select?count=20", "/api/v2/monitor/vpn/ssl", "/api/v2/monitor/vpn/ssl/stats",
		"/api/v2/monitor/vpn/ike", "/api/v2/log/disk/event/vpn?rows=50", "/api/v2/log/memory/event/vpn/raw", "/api/v2/Monitor/VPN/IPsec"} {
		if err := CheckAPIPathMCPFor("fortios", p); err != nil {
			t.Errorf("%s: refused: %v", p, err)
		}
	}
	for _, p := range []string{"/api/v2/cmdb/vpn.ipsec/phase1-interface", "/api/v2/cmdb/vpn/ipsec", "/api/v2/monitor/vpn/ipsec/../../system/snmp", "/api/v2/monitor/vpn/certificate/local",
		"/api/v2/cmdb/system/snmp/community", "/api/v2/monitor/vpn/ipsec/tunnel_down", "/api/v2/monitor/vpn/ssl/clear_tunnel"} {
		if err := CheckAPIPathMCPFor("fortios", p); err == nil {
			t.Errorf("%s: allowed", p)
		}
	}
	// only FortiOS has these paths: another platform still refuses the word
	if err := CheckAPIPathMCPFor("panos", "/api/v2/monitor/vpn/ipsec"); err == nil {
		t.Error("vpn path allowed for another platform")
	}
}
