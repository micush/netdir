package cluster

import (
	"net"
	"strings"
	"testing"
)

func TestNodeAddrCandidatesLeaveOutSharedAddresses(t *testing.T) {
	ipn := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	ifs := []ifaceAddrs{
		{Name: "lo", Loopback: true, Addrs: []net.Addr{ipn("127.0.0.1/8"), ipn("192.168.168.168/32")}}, // the anycast address is on lo
		{Name: "eth0", Addrs: []net.Addr{ipn("192.0.2.5/24"), ipn("2001:db8::5/64"), ipn("fe80::1/64"), ipn("192.0.2.9/24")}},
		{Name: "netdir1.2", Addrs: []net.Addr{ipn("192.0.2.9/24"), ipn("2001:db8::9/64")}}, // the VIPs, on the virtual-MAC interface
		{Name: "eth1", Addrs: []net.Addr{ipn("198.51.100.7/24")}},
	}
	got := nodeAddrCandidates("192.0.2.5:22162", "ns1", ifs, map[string]bool{"192.0.2.9": true, "2001:db8::9": true, "192.168.168.168": true})
	want := []string{"192.0.2.5:22162", "ns1:22162", "[2001:db8::5]:22162", "198.51.100.7:22162"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", got, want)
	}
	// the VIP is left out even if it is on a physical interface and the interface name says nothing
	for _, a := range got {
		if strings.Contains(a, "192.0.2.9") || strings.Contains(a, "168.168") || strings.Contains(a, "2001:db8::9") {
			t.Errorf("a shared address is advertised: %s", a)
		}
	}
}
