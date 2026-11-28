package mcp

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestPrivacyStrictText(t *testing.T) {
	m := core.NewMaskRules(core.StrictRules())
	in := "gw 10.1.2.3 and 8.8.8.8, lo 127.0.0.1 mask 255.255.255.0 mac aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff. v6 fe80::1 AS65001 AS15169 v6addr 2001:db8::1"
	out := m.Text(in)
	for _, gone := range []string{"10.1.2.3", "8.8.8.8", "aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff", "fe80::1", "65001", "15169"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q leaked: %s", gone, out)
		}
	}
	for _, keep := range []string{"127.0.0.1", "255.255.255.0", "2001:db8::1", "gw x.x.x.x and x.x.x.x", "mac xx:xx:xx:xx:xx:xx or xxxx.xxxx.xxxx", "v6 x:x:x:x:x:x:x:x", "ASxx001 ASxx169"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q missing: %s", keep, out)
		}
	}
	// standard still shows private things and MACs
	std := core.NewMaskRules(core.StandardRules()).Text(in)
	for _, keep := range []string{"10.1.2.3", "aa:bb:cc:dd:ee:ff", "AS65001", "fe80::1"} {
		if !strings.Contains(std, keep) {
			t.Errorf("standard hid %q: %s", keep, std)
		}
	}
	if core.NewMaskRules(core.StandardRules()).Text(in) != maskText(in) {
		t.Errorf("standard rules are not what maskText does")
	}
	if core.MaskNone.Text(in) != in {
		t.Errorf("none changed the text")
	}
}

func TestPrivacyKeepDigits(t *testing.T) {
	r := core.StandardRules()
	r.IPKeep = 2
	r.PrivateIPs = true
	m := core.NewMaskRules(r)
	out := m.Text("a 203.0.114.7 b 10.20.30.40 c 2001:4860:4860::8888")
	for _, want := range []string{"203.0.x.x", "10.20.x.x", "2001:4860:x:x:x:x:x:x"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing: %s", want, out)
		}
	}
	if strings.Contains(out, "114.7") || strings.Contains(out, "30.40") || strings.Contains(out, "8888") {
		t.Errorf("leaked: %s", out)
	}
	// a masked value sent back is restored from the configuration
	body := map[string]any{"a": strings.Fields(out)[1]}
	mcpUnmask(body)
	if body["a"] != mcpHidden {
		t.Errorf("%v", body)
	}
}
