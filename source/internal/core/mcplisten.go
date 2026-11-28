package core

import (
	"net"
	"net/netip"
	"sort"
)

// The MCP endpoint on the gateways' addresses.  /mcp is not served by the web GUI's listener to a caller who came in on a
// gateway address; it has a listener of its own on every address a gateway carries (the VIPs, the further addresses and the
// anycast addresses), on settings.mcp_port (443 by default), and that listener serves /mcp and nothing else.  The GUI
// keeps its own port and refuses a connection that arrived on a gateway address (noGatewayListener), so the page and the
// API are reached on the node's own address only.
//
// Each listener is bound with IP_FREEBIND, so it exists before the address does (an address that moves to this node with
// the election, or is added by BGP) and keeps working while it comes and goes.  The set follows the configuration every few
// seconds.  A gateway that is paused here, or that this node does not serve, has no listener.
//
// A node is fit to carry the gateways' traffic while these listeners serve (mcpServing, health.go).

const defaultMCPPort = 443

// mcpPort is the port of the MCP listeners.
func (s Settings) McpPort() int {
	if s.MCPPort == 0 {
		return defaultMCPPort
	}
	return s.MCPPort
}

// gatewayAddrs is every address the gateways of dc carry, as plain addresses.  serving limits it to the gateways this node
// serves now (not paused here or everywhere, not excluded).
func GatewayAddrs(dc *DaemonConfig, serving bool) []netip.Addr {
	if dc == nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(s string) {
		if s == "" {
			return
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			s = p.Addr().String()
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	self := LocalNodeID()
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if serving {
			if g.Paused || g.PausedAll {
				continue
			}
			out2 := false
			for _, id := range g.ExcludedNodes {
				if id == self {
					out2 = true
				}
			}
			if out2 {
				continue
			}
		}
		add(g.VIP4)
		add(g.VIP6)
		for _, a := range g.MoreVIP4 {
			add(a)
		}
		for _, a := range g.MoreVIP6 {
			add(a)
		}
		for _, a := range g.ExtraVIPs {
			add(a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// noGatewayListener hands the GUI no connection that came in on a gateway address.
type NoGatewayListener struct {
	net.Listener
	Blocked func(netip.Addr) bool `json:"-"`
}

func (l NoGatewayListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
			if a, ok := netip.AddrFromSlice(ta.IP); ok && l.Blocked(a.Unmap()) {
				c.Close()
				continue
			}
		}
		return c, nil
	}
}
