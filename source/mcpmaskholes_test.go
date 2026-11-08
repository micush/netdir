package main

import (
	"strings"
	"testing"
)

// the forms an address or a MAC can be written in that the first masker did not see
func TestMaskOddForms(t *testing.T) {
	r := newMaskRules(PrivacyRules{PublicIPs: true, PrivateIPs: true, IPKeep: -2, MACs: "nic"})
	for _, c := range []struct{ in, gone string }{
		{"ip=192.168.005.005/24", "192.168"},
		{"gw=010.001.002.003", "10.1"},
		{"addr 0xc0a80505", "c0a8"},
		{"mac bc2411.3d2dd8 up", "bc2411"},
		{"mac bc24113d2dd8 up", "bc2411"},
		{"MAC:BC:24:11:3D:2D:D8", "BC:24:11"},
		{"hwaddr-bc-24-11-3d-2d-d8", "bc-24-11"},
		{"virtio=BC:24:11:3D:2D:D8,bridge=vmbr0", "BC:24:11"},
		{"bc24.113d.2dd8", "bc24"},
		{"ip=3232236805", "3232236805"},
		{"gateway: 3232236801", "3232236801"},
		{"next hop 167772161", "167772161"},
	} {
		out := r.text(c.in)
		if strings.Contains(strings.ToLower(out), strings.ToLower(c.gone)) {
			t.Errorf("%q came out as %q", c.in, out)
		}
	}
	if got := r.text("ip=192.168.005.005/24"); !strings.Contains(got, "PRIVATE-IP-") || !strings.HasSuffix(got, ".5.5/24") {
		t.Errorf("padded: %q", got)
	}
	// what is not an address stays
	for _, in := range []string{"count 123456789012 bytes", "sha 0123456789abcdef0123456789abcdef", "2001:db8::dead:beef", "at 12:30:45", "id deadbeefcafe0000", "rx bytes 3232236805", "uptime=1700000000", "description 1700000000", "ship=1700000000"} {
		if out := r.text(in); out != in {
			// a public documentation IPv6 address is allowed to change; the rest must not
			if !strings.Contains(in, "2001:db8") {
				t.Errorf("%q changed to %q", in, out)
			}
		}
	}
}

// an address as one decimal number in JSON: under a key that names an address it is hidden, a counter is not
func TestMaskDecimalAddressInJSON(t *testing.T) {
	r := newMaskRules(PrivacyRules{PublicIPs: true, PrivateIPs: true, IPKeep: -2})
	out := string(r.json([]byte(`{"ip":3232236805,"gw_addr":"3232236801","rx_bytes":3232236805,"next-hop":134744072}`)))
	if strings.Contains(out, "3232236805") && !strings.Contains(out, `"rx_bytes":3232236805`) || strings.Contains(out, "3232236801") || strings.Contains(out, "134744072") {
		t.Errorf("%s", out)
	}
	if !strings.Contains(out, `"rx_bytes":3232236805`) || strings.Count(out, "3232236805") != 1 {
		t.Errorf("a counter must stay, the address must go: %s", out)
	}
}
