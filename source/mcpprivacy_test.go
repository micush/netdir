package main

import (
	"strings"
	"testing"

	"netdir/device"
)

func TestPrivacyStrictText(t *testing.T) {
	m := newMaskRules(strictRules())
	in := "gw 10.1.2.3 and 8.8.8.8, lo 127.0.0.1 mask 255.255.255.0 mac aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff. v6 fe80::1 AS65001 AS15169 v6addr 2001:db8::1"
	out := m.text(in)
	for _, gone := range []string{"10.1.2.3", "8.8.8.8", "aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff", "fe80::1", "65001", "15169"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q leaked: %s", gone, out)
		}
	}
	for _, keep := range []string{"127.0.0.1", "255.255.255.0", "2001:db8::1", "PRIVATE-IP-", "PUBLIC-IP-", "MASKED-MAC-", "PRIVATE-AS-", "PUBLIC-AS-", "PRIVATE-IP6-"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q missing: %s", keep, out)
		}
	}
	// standard still shows private things and MACs
	std := newMaskRules(standardRules()).text(in)
	for _, keep := range []string{"10.1.2.3", "aa:bb:cc:dd:ee:ff", "AS65001", "fe80::1"} {
		if !strings.Contains(std, keep) {
			t.Errorf("standard hid %q: %s", keep, std)
		}
	}
	if newMaskRules(standardRules()).text(in) != maskText(in) {
		t.Errorf("standard rules are not what maskText does")
	}
	if maskNone.text(in) != in {
		t.Errorf("none changed the text")
	}
}

func TestPrivacyKeepDigits(t *testing.T) {
	r := standardRules()
	r.IPKeep = 2
	r.PrivateIPs = true
	m := newMaskRules(r)
	out := m.text("a 203.0.114.7 b 10.20.30.40 c 2001:4860:4860::8888")
	for _, want := range []string{"203.0.PUBLIC-IP-", "10.20.PRIVATE-IP-", "2001:4860:PUBLIC-IP6-"} {
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

func TestPrivacyMACModes(t *testing.T) {
	r := standardRules()
	r.MACs = "oui"
	out := newMaskRules(r).text("mac 00:1a:2b:3c:4d:5e and 001a.2b3c.4d5e and ipv6 2001:db8:1:2:3:4:5:6")
	if !strings.Contains(out, "00:1a:2b:MASKED-MAC-") || !strings.Contains(out, "001a.MASKED-MAC-") || strings.Contains(out, "3c:4d:5e") {
		t.Errorf("oui: %s", out)
	}
	if !strings.Contains(out, "2001:db8:1:2:3:4:5:6") {
		t.Errorf("an IPv6 address was taken for a MAC: %s", out)
	}
	r.MACs = "hide"
	if out = newMaskRules(r).text("00-1a-2b-3c-4d-5e"); strings.Contains(out, "00-1a") || !strings.HasPrefix(out, "MASKED-MAC-") {
		t.Errorf("hide: %s", out)
	}
}

func TestPrivacyWordsAndSerials(t *testing.T) {
	r := standardRules()
	r.Words = []string{"Contoso", "public", "corp-edge"}
	r.Serials = "hide"
	m := newMaskRules(r)
	out := m.text("Contoso CONTOSO at corp-edge-1 uses 8.8.8.8 and public dns")
	if strings.Contains(strings.ToLower(out), "contoso") || strings.Contains(out, "corp-edge") {
		t.Errorf("words leaked: %s", out)
	}
	if !strings.Contains(out, "PUBLIC-IP-") {
		t.Errorf("the address token was broken by the word \"public\": %s", out)
	}
	f := strings.Fields(out)
	if f[0] != f[1] {
		t.Errorf("the same word, in another case, must give the same token: %s", out)
	}
	j := string(m.json([]byte(`{"serial":"FOC1234X0AB","note":"Contoso lab"}`)))
	if strings.Contains(j, "X0AB") || strings.Contains(j, "Contoso") || !strings.Contains(j, "MASKED-SERIAL-") {
		t.Errorf("%s", j)
	}
	r.Serials = "show"
	if j = string(newMaskRules(r).json([]byte(`{"serial":"FOC1234X0AB"}`))); !strings.Contains(j, "FOC1234X0AB") {
		t.Errorf("show: %s", j)
	}
}

func TestPrivacyNormalize(t *testing.T) {
	if c, err := normPrivacy(&PrivacyConfig{Default: " Standard "}); c != nil || err != nil {
		t.Errorf("the defaults leave no key: %v %v", c, err)
	}
	c, err := normPrivacy(&PrivacyConfig{Default: "STRICT", Standard: &PrivacyRules{Serials: "TAIL", Words: []string{" acme ", "ACME", "", "lab-sw"}}})
	if err != nil || c.Default != "strict" || c.Standard.Serials != "tail" || c.Standard.MACs != "show" || strings.Join(c.Standard.Words, ",") != "acme,lab-sw" {
		t.Errorf("%+v %v", c, err)
	}
	for _, bad := range []*PrivacyConfig{
		{Default: "paranoid"}, {Standard: &PrivacyRules{IPKeep: 4}}, {Strict: &PrivacyRules{Serials: "some"}}, {Strict: &PrivacyRules{MACs: "x"}},
		{Standard: &PrivacyRules{Words: []string{"ab"}}}, {Standard: &PrivacyRules{Words: []string{"bad\nword"}}},
	} {
		if _, err := normPrivacy(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestPrivacyACLAndKeys(t *testing.T) {
	got, err := normMCPACL([]string{"10.1.1.50 rw Strict", "10.1.1.50 none", "10.1.0.0/24 standard", "10.2.0.0/24 ro", "10.3.0.0/24 STRICT"})
	want := "10.1.1.50 rw strict,10.1.0.0/24 standard,10.2.0.0/24,10.3.0.0/24 strict"
	if err != nil || strings.Join(got, ",") != want {
		t.Errorf("%v %v (want %s)", got, err, want)
	}
	for _, bad := range []string{"10.1.1.1 rw strict extra", "10.1.1.1 paranoid", "10.1.1.1 strict none", "10.1.0.0/24 rw strict"} {
		if _, err := normMCPACL([]string{bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	k := testMCPKey()
	out, err := normMCPKeys([]MCPKey{{Name: "a", Key: k, Privacy: "Strict"}})
	if err != nil || out[0].Privacy != "strict" {
		t.Errorf("%+v %v", out, err)
	}
	if _, err := normMCPKeys([]MCPKey{{Name: "a", Key: k, Privacy: "x"}}); err == nil {
		t.Errorf("a bad key level was accepted")
	}
	if strictestLevel("", "none", "strict", "standard") != "strict" || strictestLevel("", "") != "" || strictestLevel("none", "") != "none" {
		t.Errorf("strictest")
	}
}

// Through the real tool path: the level of the address and the default decide what a caller is told.
func TestMCPPrivacyLevels(t *testing.T) {
	setDev := func(e *webEnv, addr string) {
		sup := e.ws.status.sup
		sup.mu.Lock()
		sup.dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
		sup.dc.Settings.Devices = []device.Device{{Name: "edge", Platform: "iosxe", Address: addr, Credential: "lab", Insecure: true}}
		sup.mu.Unlock()
	}
	list := func(post func(string, ...string) (int, map[string]any)) string {
		_, m := post(mcpCall("list_devices", `{}`))
		txt, _ := toolResult(t, m)
		return txt
	}
	// the default level (standard): a private address is shown, a public one is not
	e, post := mcpEnv(t, "127.0.0.1")
	setDev(e, "10.9.8.7")
	if txt := list(post); !strings.Contains(txt, "10.9.8.7") {
		t.Errorf("standard hid a private address: %s", txt)
	}
	// strict on the source
	e, post = mcpEnv(t, "127.0.0.1 strict")
	setDev(e, "10.9.8.7")
	if txt := list(post); strings.Contains(txt, "10.9.8.7") || !strings.Contains(txt, "PRIVATE-IP-") {
		t.Errorf("strict source: %s", txt)
	}
	// strict as the default, none on the source: the source's own level wins
	e, post = mcpEnv(t, "127.0.0.1 none")
	e.ws.status.sup.mu.Lock()
	e.ws.status.sup.dc.Settings.Privacy = &PrivacyConfig{Default: "strict"}
	e.ws.status.sup.mu.Unlock()
	setDev(e, "8.8.8.8")
	if txt := list(post); !strings.Contains(txt, "8.8.8.8") {
		t.Errorf("none on the source was not honoured: %s", txt)
	}
	// a source with no level of its own gets the default
	e, post = mcpEnv(t, "127.0.0.1")
	e.ws.status.sup.mu.Lock()
	e.ws.status.sup.dc.Settings.Privacy = &PrivacyConfig{Default: "strict"}
	e.ws.status.sup.mu.Unlock()
	setDev(e, "10.9.8.7")
	if txt := list(post); strings.Contains(txt, "10.9.8.7") {
		t.Errorf("the default level did not apply: %s", txt)
	}
}
