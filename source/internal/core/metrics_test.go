package core

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSNMPAccessListRestrictsSources(t *testing.T) {
	c := SNMPConfig{Communities: []string{"public"}, ACL: []string{"10.0.0.0/8", " 192.0.2.5 ", "2001:db8::/32", "192.0.2.5"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.ACL, ","); got != "10.0.0.0/8,192.0.2.5,2001:db8::/32" {
		t.Fatalf("ACL %s", got)
	}
	body := snmpdConfBody(c)
	for _, want := range []string{"rocommunity public 10.0.0.0/8\n", "rocommunity public 192.0.2.5\n", "rocommunity6 public 2001:db8::/32\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "rocommunity public\n") || strings.Contains(body, "rocommunity6 public\n") {
		t.Errorf("an open community is left in\n%s", body)
	}
	none := snmpdConfBody(SNMPConfig{Communities: []string{"public"}})
	if strings.Contains(none, "rocommunity") {
		t.Errorf("no list must allow nobody:\n%s", none)
	}
	bad := SNMPConfig{Communities: []string{"x"}, ACL: []string{"not-an-address"}}
	if bad.Validate() == nil {
		t.Fatal("a bad source was accepted")
	}
}

func TestACLTakesAddressesNetworksAndNames(t *testing.T) {
	got, err := normACL("x", []string{"10.1.1.1", "10.1.1.1/32", "10.1.1.1/24", "2620::/128", "2620::", "2620::/64", "Prom.Example.COM.", "prom.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(got, " "); s != "10.1.1.1 10.1.1.0/24 2620:: 2620::/64 prom.example.com" {
		t.Fatalf("got %s", s)
	}
	for _, bad := range []string{"fqdn", "a b.example.com", "-x.example.com", "10.1.1.1/33", "http://x.example.com"} {
		if _, err := normACL("x", []string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	old := aclLookup
	t.Cleanup(func() { aclLookup = old })
	aclLookup = func(n string) []netip.Addr {
		if n == "prom.example.com" {
			return []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")}
		}
		return nil
	}
	nets := expandACL(got)
	for _, a := range []string{"10.1.1.1", "10.1.1.77", "2620::", "2620::1:2", "192.0.2.9", "2001:db8::9"} {
		if !inNets(nets, netip.MustParseAddr(a)) {
			t.Errorf("%s is not in %v", a, nets)
		}
	}
	for _, a := range []string{"10.1.2.1", "2620:0:0:1::1", "192.0.2.10"} {
		if inNets(nets, netip.MustParseAddr(a)) {
			t.Errorf("%s is in %v", a, nets)
		}
	}
	// a name that cannot be looked up allows nobody, and SNMP then writes no open community
	body := snmpdConfBody(SNMPConfig{Communities: []string{"c"}, ACL: []string{"gone.example.com"}})
	if strings.Contains(body, "rocommunity c\n") || strings.Contains(body, "rocommunity c ") {
		t.Fatalf("an unresolved name opened the community:\n%s", body)
	}
	body = snmpdConfBody(SNMPConfig{Communities: []string{"c"}, ACL: []string{"prom.example.com"}})
	if !strings.Contains(body, "rocommunity c 192.0.2.9\n") || !strings.Contains(body, "rocommunity6 c 2001:db8::9\n") {
		t.Fatalf("name not written as addresses:\n%s", body)
	}
}
