package main

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

// The Anyname DNS Director (dnsdir) can live on the same host.  The two products cannot share BGP (each owns
// /etc/frr/frr.conf, see bgp.go), so while dnsdir is installed netdir does no BGP of its own; instead a gateway may
// answer on chosen addresses of dnsdir: anycast addresses it holds on lo and announces, or the shared address of one of its
// gateways (GroupConfig.DNSDirVIPs).  netdir only listens on them: it never adds or removes them and never announces them.

// dnsdirMarkers are what an installed dnsdir leaves behind (a variable for the tests).  The state directory is not
// one of them: it stays after an uninstall without --purge.
var dnsdirMarkers = []string{"/usr/local/sbin/dnsdir", "/usr/local/share/dnsdir", "/etc/systemd/system/dnsdir.service"}

// dnsdirConfPath is dnsdir's configuration, where its anycast addresses are listed (a variable for the tests).
var dnsdirConfPath = "/var/lib/dnsdir/dnsdir.conf"

// dnsdirMu guards dnsdirMarkers and dnsdirConfPath: they are only ever changed by the tests, but a goroutine left over from
// an earlier test may still be reading them.
var dnsdirMu sync.RWMutex

func dnsdirPaths() (markers []string, conf string) {
	dnsdirMu.RLock()
	defer dnsdirMu.RUnlock()
	return dnsdirMarkers, dnsdirConfPath
}

// dnsdirPresent says whether dnsdir is installed on this host.
func dnsdirPresent() bool {
	markers, _ := dnsdirPaths()
	for _, p := range markers {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// dnsdirOffered lists the addresses dnsdir has that a gateway may answer on, sorted: the anycast addresses of its
// gateways (extra_vips) and their shared addresses (vip4, vip6, more_vip4, more_vip6, without the prefix length).
// Nothing when dnsdir is not installed or its configuration cannot be read.
func dnsdirOffered() []string {
	any, shared := dnsdirAddrs()
	out := append(any, shared...)
	sort.Strings(out)
	return out
}

// dnsdirSharedSet is the set of dnsdir's gateway shared addresses (see dnsdirAddrs).
func dnsdirSharedSet() map[string]bool {
	_, shared := dnsdirAddrs()
	m := map[string]bool{}
	for _, a := range shared {
		m[a] = true
	}
	return m
}

// dnsdirGateway is one gateway of dnsdir: its id, name, its shared addresses and its anycast addresses (bare, sorted).
type dnsdirGateway struct {
	ID      int
	Name    string
	Shared  []string
	Anycast []string
	VIP4    string // the primary shared addresses, for the circle
	VIP6    string
}

// dnsdirGateways reads dnsdir's configuration: its gateways with their shared and anycast addresses.  The shared ones are
// held by dnsdir on whichever node serves the gateway (they are not on lo everywhere), and netdir only listens on them.
// Nothing when dnsdir is not installed or its configuration cannot be read.
func dnsdirGateways() []dnsdirGateway {
	if !dnsdirPresent() {
		return nil
	}
	_, confPath := dnsdirPaths()
	b, err := os.ReadFile(confPath)
	if err != nil {
		return nil
	}
	var c struct {
		Groups []struct {
			GroupID   int      `json:"group_id"`
			Name      string   `json:"name"`
			ExtraVIPs []string `json:"extra_vips"`
			VIP4      string   `json:"vip4"`
			VIP6      string   `json:"vip6"`
			MoreVIP4  []string `json:"more_vip4"`
			MoreVIP6  []string `json:"more_vip6"`
		} `json:"groups"`
	}
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	bare := func(a string) string {
		a = strings.TrimSpace(a)
		if ip, _, err := net.ParseCIDR(a); err == nil {
			a = ip.String()
		}
		n, err := normalizeAnycast(a)
		if err != nil {
			return ""
		}
		return n
	}
	var out []dnsdirGateway
	for _, g := range c.Groups {
		gw := dnsdirGateway{ID: g.GroupID, Name: strings.TrimSpace(g.Name), VIP4: bare(g.VIP4), VIP6: bare(g.VIP6)}
		seen := map[string]bool{}
		add := func(dst *[]string, a string) {
			if n := bare(a); n != "" && !seen[n] {
				seen[n] = true
				*dst = append(*dst, n)
			}
		}
		for _, a := range append(append([]string{g.VIP4, g.VIP6}, g.MoreVIP4...), g.MoreVIP6...) {
			if a != "" {
				add(&gw.Shared, a)
			}
		}
		for _, a := range g.ExtraVIPs {
			add(&gw.Anycast, a)
		}
		sort.Strings(gw.Shared)
		sort.Strings(gw.Anycast)
		out = append(out, gw)
	}
	return out
}

// dnsdirAddrs is every anycast address and every shared address of dnsdir's gateways, each sorted and without repeats.
func dnsdirAddrs() (anycast, shared []string) {
	anycast, shared = []string{}, []string{}
	seenA, seenS := map[string]bool{}, map[string]bool{}
	for _, g := range dnsdirGateways() {
		for _, a := range g.Anycast {
			if !seenA[a] {
				seenA[a] = true
				anycast = append(anycast, a)
			}
		}
		for _, a := range g.Shared {
			if !seenS[a] {
				seenS[a] = true
				shared = append(shared, a)
			}
		}
	}
	sort.Strings(anycast)
	sort.Strings(shared)
	return
}

// DNSDirInfo is what the GUI needs to offer dnsdir's addresses.
type DNSDirInfo struct {
	Present bool     `json:"present"`
	Offered []string `json:"offered"`
}

func dnsdirInfo() DNSDirInfo { return DNSDirInfo{Present: dnsdirPresent(), Offered: dnsdirOffered()} }

type errDNSDir string

func (e errDNSDir) Error() string { return "AnyName address: " + string(e) }
