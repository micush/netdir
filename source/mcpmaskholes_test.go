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
	for _, in := range []string{"count 123456789012 bytes", "sha 0123456789abcdef0123456789abcdef", "2001:db8::dead:beef", "at 12:30:45", "id deadbeefcafe0000"} {
		if out := r.text(in); out != in {
			// a public documentation IPv6 address is allowed to change; the rest must not
			if !strings.Contains(in, "2001:db8") {
				t.Errorf("%q changed to %q", in, out)
			}
		}
	}
}
