package core

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderFRRDisabledNeighborAndProcess(t *testing.T) {
	b := &BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{
		{Peer: "192.0.2.1", RemoteAS: 64500, Disabled: true},
		{Peer: "192.0.2.2", RemoteAS: 64500},
	}}
	conf := renderFRR(b, []string{"203.0.113.53"}, nil, "h")
	if !strings.Contains(conf, " neighbor 192.0.2.1 shutdown\n") || strings.Contains(conf, " neighbor 192.0.2.2 shutdown") {
		t.Fatalf("only the disabled neighbor is shut down:\n%s", conf)
	}
	if !strings.Contains(conf, " neighbor 192.0.2.1 remote-as 64500\n") {
		t.Fatalf("the disabled neighbor must stay configured:\n%s", conf)
	}
	b.Disabled = true
	if conf := renderFRR(b, nil, nil, "h"); strings.Contains(conf, "router bgp") {
		t.Fatalf("a disabled process must leave no BGP section:\n%s", conf)
	}
	if b.Active() || !b.Configured() {
		t.Fatal("a disabled process is configured but not active")
	}
}

func TestNodeEthernetAddrs(t *testing.T) {
	ipn := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	old := nodeIfacesFn
	t.Cleanup(func() { nodeIfacesFn = old })
	nodeIfacesFn = func() []nodeIfaceRaw {
		return []nodeIfaceRaw{
			{Name: "lo", Loopback: true, Ethernet: false, Addrs: []net.Addr{ipn("127.0.0.1/8")}},
			{Name: "veth1", Ethernet: false, Addrs: []net.Addr{ipn("10.9.9.1/24")}},
			{Name: "eth1", Ethernet: true, Addrs: []net.Addr{ipn("fe80::1/64")}},
			{Name: "eth0", Ethernet: true, Addrs: []net.Addr{
				ipn("fe80::1234/64"), ipn("fd00::5/64"), ipn("2001:db8::5/64"), ipn("10.0.0.5/24"), ipn("169.254.1.1/16"), ipn("3fff::9/48")}},
		}
	}
	got := EthernetAddrs()
	if len(got) != 1 || got[0].Name != "eth0" {
		t.Fatalf("only an Ethernet interface with a usable address is listed: %+v", got)
	}
	if strings.Join(got[0].V4, ",") != "10.0.0.5/24" || strings.Join(got[0].V6, ",") != "2001:db8::5/64,3fff::9/48" {
		t.Fatalf("addresses: %+v (link-local, ULA and 169.254 must be left out)", got[0])
	}
}

// A made-up /sys/class/net: which interfaces count as Ethernet.
func TestIsEthernetIfaceKinds(t *testing.T) {
	root := t.TempDir()
	cls, virt := filepath.Join(root, "class")+"/", filepath.Join(root, "virtual")+"/"
	oldC, oldV := sysClassNet, sysVirtualNet
	sysClassNet, sysVirtualNet = cls, virt
	t.Cleanup(func() { sysClassNet, sysVirtualNet = oldC, oldV })
	mk := func(name, typ string, virtual bool, devtype string, subdirs ...string) {
		d := filepath.Join(cls, name)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "type"), []byte(typ+"\n"), 0o644)
		uev := "INTERFACE=" + name + "\n"
		if devtype != "" {
			uev += "DEVTYPE=" + devtype + "\n"
		}
		os.WriteFile(filepath.Join(d, "uevent"), []byte(uev), 0o644)
		for _, s := range subdirs {
			os.MkdirAll(filepath.Join(d, s), 0o755)
		}
		if virtual {
			os.MkdirAll(filepath.Join(virt, name), 0o755)
		}
	}
	mk("ens18", "1", false, "")           // a physical (or virtio) card
	mk("eth0", "1", true, "veth")         // a container's network card
	mk("vmbr0", "1", true, "bridge")      // a bridge
	mk("bond0", "1", true, "bond")        // a bond
	mk("eth0.5", "1", true, "vlan")       // a VLAN
	mk("br9", "1", true, "", "bridge")    // a bridge seen only by its directory
	mk("bondx", "1", true, "", "bonding") // a bond seen only by its directory
	mk("mv0", "1", true, "macvlan")       // someone's macvlan
	mk("netdir1.1", "1", true, "macvlan") // netdir's own
	mk("netdirlike", "1", false, "")      // anything named netdir* is netdir's
	mk("vxlan0", "1", true, "vxlan")      // an overlay
	mk("tap0", "1", true, "")             // a tap
	mk("dummy0", "1", true, "")           // a dummy
	mk("tun0", "65534", true, "")         // not Ethernet at all
	mk("lo", "772", true, "")             // loopback
	want := map[string]bool{"ens18": true, "eth0": true, "vmbr0": true, "bond0": true, "eth0.5": true, "br9": true, "bondx": true}
	for _, n := range []string{"ens18", "eth0", "vmbr0", "bond0", "eth0.5", "br9", "bondx", "mv0", "netdir1.1", "netdirlike", "vxlan0", "tap0", "dummy0", "tun0", "lo", "missing"} {
		if got := isEthernetIface(n); got != want[n] {
			t.Errorf("%s: Ethernet = %v, want %v", n, got, want[n])
		}
	}
}

// When no interface of a kind that counts as Ethernet has an address, the others (not loopback, not netdir's) are listed.
func TestEthernetAddrsFallsBackToOtherInterfaces(t *testing.T) {
	ipn := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	old := nodeIfacesFn
	t.Cleanup(func() { nodeIfacesFn = old })
	nodeIfacesFn = func() []nodeIfaceRaw {
		return []nodeIfaceRaw{
			{Name: "lo", Loopback: true, Addrs: []net.Addr{ipn("127.0.0.1/8")}},
			{Name: "netdir1.1", Addrs: []net.Addr{ipn("10.0.0.56/24")}},
			{Name: "eth0", Ethernet: true, Addrs: []net.Addr{ipn("fe80::1/64")}}, // Ethernet, but nothing usable
			{Name: "odd0", Addrs: []net.Addr{ipn("10.5.5.5/24"), ipn("2001:db8::5/64")}},
		}
	}
	got := EthernetAddrs()
	if len(got) != 1 || got[0].Name != "odd0" || strings.Join(got[0].V4, ",") != "10.5.5.5/24" || strings.Join(got[0].V6, ",") != "2001:db8::5/64" {
		t.Fatalf("fallback: %+v (netdir's own interface and the loopback must stay out)", got)
	}
}
