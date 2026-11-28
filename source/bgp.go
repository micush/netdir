package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"netdir/internal/core"
)

// Status gathers the node's BGP configuration, what was applied and live neighbor state.
func (m *Mgmt) BGPStatus() (*core.BGPStatus, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	st := &core.BGPStatus{Config: core.BGPConfig{Neighbors: []core.BGPNeighbor{}}, Peers: []core.BGPPeer{}, Announce: []string{}, Addresses: []core.AnycastState{}, Notes: []string{}}
	if dc.BGP != nil {
		st.Config = *dc.BGP.Clone()
	}
	st.Applied = m.bgp.Last()
	st.Blocked = core.BgpBlocked()
	if _, err := os.Stat(core.FrrDir); err == nil {
		st.Installed = true
	}
	v4, v6 := core.AnycastAddresses(dc)
	st.Announce = append(append(st.Announce, v4...), v6...)
	if m.anycastFn != nil {
		st.Addresses = append(st.Addresses, m.anycastFn()...)
	}
	if st.Config.Active() && st.Installed {
		if raw, err := core.VtyshBGP(); err == nil {
			if peers, err := core.ParseBGPSummary(raw); err == nil {
				st.Running = true
				st.Peers = peers
				if raw, err := core.VtyshBFD(); err == nil {
					core.AddBFD(st.Peers, raw)
				}
			}
		}
	}
	if st.Config.Active() {
		if st.Installed && !core.FrrCanReload() {
			st.Notes = append(st.Notes, "FRR cannot reload its config here (frr-reload.py is missing; on Debian and Ubuntu install frr-pythontools), so every BGP change restarts FRR and drops the sessions briefly.")
		}
		if len(st.Announce) == 0 {
			st.Notes = append(st.Notes, "Nothing is announced yet: add an anycast address to a gateway on the Topology page.")
		}
	}
	return st, nil
}

// BGPSet replaces this node's BGP settings.  The disabled flags (Operate ▸ Anycast) are not part of the settings
// and are carried over from the running config, so editing the settings never switches anything on or off.
func (m *Mgmt) BGPSet(c core.BGPConfig, actor string) error {
	if why := core.BgpBlocked(); why != "" && (c.ASN != 0 || len(c.Neighbors) > 0) {
		return fmt.Errorf("bgp: %s", why) // clearing the settings is still allowed
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if c.ASN == 0 && strings.TrimSpace(c.RouterID) != "" {
		return fmt.Errorf("bgp: a router id needs a local AS number; set the AS first")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	was := map[string]bool{}
	if dc.BGP != nil {
		for _, n := range dc.BGP.Neighbors {
			was[n.Peer] = n.Disabled
		}
		if c.ASN != 0 {
			c.Disabled = dc.BGP.Disabled
		}
	}
	for i := range c.Neighbors {
		n := &c.Neighbors[i]
		key := n.Peer
		if _, renamed := was[n.Was]; renamed && n.Was != "" {
			key = n.Was // its address is being changed: it is the same neighbor
		}
		n.Disabled, n.Was = was[key], ""
	}
	note := "bgp: "
	switch {
	case dc.BGP == nil && c.ASN == 0 && len(c.Neighbors) == 0:
		return nil
	case c.Active():
		note += fmt.Sprintf("AS %d, %d neighbor(s)", c.ASN, len(c.Neighbors))
	default:
		note += "off"
	}
	cc := c
	dc.BGP = &cc
	return m.PutConfig(dc, actor, note)
}

// BGPOperate enables or disables BGP on this node, or one of its neighbors, without touching the settings.
// A disabled process leaves frr.conf as if the AS were cleared; a disabled neighbor stays in frr.conf, shut down.
func (m *Mgmt) BGPOperate(a core.BGPOperateArgs, actor string) error {
	if why := core.BgpBlocked(); why != "" && a.Enabled {
		return fmt.Errorf("bgp: %s", why)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if !dc.BGP.Configured() {
		return fmt.Errorf("bgp: set a local AS number first")
	}
	c := dc.BGP.Clone()
	var note string
	if p := strings.TrimSpace(a.Peer); p == "" {
		if c.Disabled == !a.Enabled {
			return nil
		}
		c.Disabled = !a.Enabled
		note = "bgp: " + map[bool]string{true: "enabled", false: "disabled"}[a.Enabled]
	} else {
		ip, err := netip.ParseAddr(p)
		if err != nil {
			return fmt.Errorf("bgp: %q is not a neighbor address", a.Peer)
		}
		p = ip.Unmap().String()
		found := false
		for i := range c.Neighbors {
			if c.Neighbors[i].Peer != p {
				continue
			}
			found = true
			if c.Neighbors[i].Disabled == !a.Enabled {
				return nil
			}
			c.Neighbors[i].Disabled = !a.Enabled
		}
		if !found {
			return fmt.Errorf("bgp: there is no neighbor %s", p)
		}
		note = "bgp: neighbor " + p + map[bool]string{true: " enabled", false: " disabled"}[a.Enabled]
	}
	dc.BGP = c
	return m.PutConfig(dc, actor, note)
}
