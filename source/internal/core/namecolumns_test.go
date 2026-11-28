package core

import (
	"net"
	"reflect"
	"testing"
)

func TestAddrListAndUniqueLocalAddresses(t *testing.T) {
	ipn := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	old := nodeIfacesFn
	t.Cleanup(func() { nodeIfacesFn = old })
	nodeIfacesFn = func() []nodeIfaceRaw {
		return []nodeIfaceRaw{
			{Name: "lo", Loopback: true, Addrs: []net.Addr{ipn("127.0.0.1/8"), ipn("::1/128")}},
			{Name: "eth0", Ethernet: true, Addrs: []net.Addr{ipn("192.168.5.5/24"), ipn("fdf5:168:5::5/64"), ipn("2001:db8::5/64"), ipn("fe80::1/64")}},
			{Name: "eth1", Ethernet: true, Addrs: []net.Addr{ipn("fd00::9/64")}}, // only a unique local address
		}
	}
	got := EthernetAddrs()
	if len(got) != 2 || got[0].Name != "eth0" || got[1].Name != "eth1" {
		t.Fatalf("interfaces: %+v", got)
	}
	if !reflect.DeepEqual(got[0].V4, []string{"192.168.5.5/24"}) || !reflect.DeepEqual(got[0].V6, []string{"2001:db8::5/64"}) ||
		!reflect.DeepEqual(got[0].ULA, []string{"fdf5:168:5::5/64"}) {
		t.Fatalf("eth0: %+v (the global ones stay apart from the unique local ones)", got[0])
	}
	want := []string{"192.168.5.5", "2001:db8::5", "fdf5:168:5::5", "fd00::9"}
	if l := AddrList(got); !reflect.DeepEqual(l, want) {
		t.Fatalf("addrList %v, want %v (IPv4, then global, then unique local; no prefix lengths)", l, want)
	}
}

func TestNodeNamesByIP(t *testing.T) {
	peers := []PeerView{
		{Addr: "ns1:22162", Hostname: "ns1", Self: true, GwIPs: []string{"192.168.5.5", "fe80::be24:11ff:fe3d:2dd8"}, IPs: []string{"192.168.5.5", "fdf5:168:5::5"}},
		{Addr: "ns2:22162", Hostname: "ns2", GwIPs: []string{"192.168.5.55", "fe80::be24:11ff:fe3d:2dd9"}, IPs: []string{"192.168.5.55"}},
		{Addr: "ns3:22162", Hostname: "ns3", IPs: []string{"192.168.5.12", "fdf5:168:5::12"}}, // a node that does not report its gateway addresses yet
		{Addr: "10.9.9.1:22162", Hostname: "twin", GwIPs: []string{"10.9.9.1"}},
		{Addr: "10.9.9.2:22162", Hostname: "twin", GwIPs: []string{"10.9.9.2"}},
	}
	n := NodeNamesByIP(peers)
	for ip, want := range map[string]string{
		"192.168.5.5": "ns1", "fe80::be24:11ff:fe3d:2dd8": "ns1", "fdf5:168:5::5": "ns1",
		"192.168.5.55": "ns2", "fe80::be24:11ff:fe3d:2dd9": "ns2",
		"192.168.5.12": "ns3", "fdf5:168:5::12": "ns3", // from its interface addresses
		"10.9.9.1": "10.9.9.1:22162", "10.9.9.2": "10.9.9.2:22162", // one host name on two nodes: told apart by address
	} {
		if n[ip] != want {
			t.Errorf("%s: %q, want %q", ip, n[ip], want)
		}
	}
	// the gateway address wins over an interface address when two nodes claim one
	n = NodeNamesByIP([]PeerView{{Addr: "a:1", Hostname: "a", IPs: []string{"10.0.0.7"}}, {Addr: "b:1", Hostname: "b", GwIPs: []string{"10.0.0.7"}}})
	if n["10.0.0.7"] != "b" {
		t.Errorf("gateway address should win: %v", n)
	}
}

func TestNameMembersPutsTheNodeNameOnTheRows(t *testing.T) {
	gs := []GatewayGroup{{GroupID: 1, AF: "v4", Members: []GatewayMember{{IP: "192.168.5.5"}, {IP: "192.168.5.99"}}},
		{GroupID: 1, AF: "v6", Members: []GatewayMember{{IP: "fe80::be24:11ff:fe3d:2dd8"}}}}
	NameMembers(gs, map[string]string{"192.168.5.5": "ns1", "fe80::be24:11ff:fe3d:2dd8": "ns1"})
	if gs[0].Members[0].Name != "ns1" || gs[0].Members[1].Name != "" || gs[1].Members[0].Name != "ns1" {
		t.Fatalf("%+v", gs)
	}
}
