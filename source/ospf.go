package main

import (
	"fmt"
	"os"
	"strings"

	"netdir/internal/core"
)

// Status gathers the node's OSPF configuration, what was applied and live neighbor state.
func (m *Mgmt) OSPFStatus() (*core.OSPFStatus, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	st := &core.OSPFStatus{Config: core.OSPFConfig{Interfaces: []core.OSPFInterface{}}, Peers: []core.OSPFPeer{}, Announce: []string{}, Addresses: []core.AnycastState{}, Interfaces: core.HostInterfaceNames(), Notes: []string{}}
	if dc.OSPF != nil {
		st.Config = *dc.OSPF.Clone()
	}
	st.Blocked = core.FrrBlocked()
	st.Applied = m.bgp.Last()
	if _, err := os.Stat(core.FrrDir); err == nil {
		st.Installed = true
	}
	v4, v6 := core.AnycastAddresses(dc)
	st.Announce = append(append(st.Announce, v4...), v6...)
	if m.anycastFn != nil {
		st.Addresses = append(st.Addresses, m.anycastFn()...)
	}
	if st.Config.Active() && st.Installed {
		if peers, ok := core.OspfNeighbors(); ok {
			st.Running = true
			st.Peers = peers
			if raw, err := core.VtyshBFD(); err == nil {
				if bfd, err := core.ParseBFDPeers(raw); err == nil {
					for i := range st.Peers {
						st.Peers[i].BFD = bfd[st.Peers[i].Address]
					}
				}
			}
		}
	}
	if st.Config.Active() {
		if st.Installed && !core.FrrCanReload() {
			st.Notes = append(st.Notes, "FRR cannot reload its config here (frr-reload.py was not found; Debian and Ubuntu have it in the frr-pythontools package), so every OSPF change restarts FRR and drops the sessions briefly.")
		}
		if len(st.Announce) == 0 {
			st.Notes = append(st.Notes, "Nothing is announced yet: add an anycast address to a gateway on the Topology page.")
		}
	}
	return st, nil
}

// OSPFSet replaces this node's OSPF settings.  The disabled flags (Operate ▸ Anycast) are not part of the settings and
// are carried over from the running config, so editing the settings never switches anything on or off.
func (m *Mgmt) OSPFSet(c core.OSPFConfig, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if len(c.Interfaces) == 0 && strings.TrimSpace(c.RouterID) != "" {
		return fmt.Errorf("ospf: a router id needs an interface; add one first")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if why := core.FrrBlocked(); why != "" && len(c.Interfaces) > 0 {
		return fmt.Errorf("ospf: %s", why) // clearing the settings is still allowed
	}
	was := map[string]bool{}
	if dc.OSPF != nil {
		for _, f := range dc.OSPF.Interfaces {
			was[f.Name] = f.Disabled
		}
		if c.Configured() {
			c.Disabled = dc.OSPF.Disabled
		}
	}
	for i := range c.Interfaces {
		c.Interfaces[i].Disabled = was[c.Interfaces[i].Name]
	}
	note := "ospf: "
	switch {
	case dc.OSPF == nil && len(c.Interfaces) == 0:
		return nil
	case c.Active():
		note += fmt.Sprintf("%d interface(s)", len(c.Interfaces))
	default:
		note += "off"
	}
	cc := c
	if len(cc.Interfaces) == 0 {
		dc.OSPF = nil
	} else {
		dc.OSPF = &cc
	}
	return m.PutConfig(dc, actor, note)
}

// OSPFOperate enables or disables OSPF on this node, or one of its interfaces, without touching the settings.
func (m *Mgmt) OSPFOperate(a core.OSPFOperateArgs, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if !dc.OSPF.Configured() {
		return fmt.Errorf("ospf: add an interface first")
	}
	if why := core.FrrBlocked(); why != "" && a.Enabled {
		return fmt.Errorf("ospf: %s", why)
	}
	c := dc.OSPF.Clone()
	var note string
	if n := strings.TrimSpace(a.Interface); n == "" {
		if c.Disabled == !a.Enabled {
			return nil
		}
		c.Disabled = !a.Enabled
		note = "ospf: " + map[bool]string{true: "enabled", false: "disabled"}[a.Enabled]
	} else {
		found := false
		for i := range c.Interfaces {
			if c.Interfaces[i].Name != n {
				continue
			}
			found = true
			if c.Interfaces[i].Disabled == !a.Enabled {
				return nil
			}
			c.Interfaces[i].Disabled = !a.Enabled
		}
		if !found {
			return fmt.Errorf("ospf: there is no interface %s", n)
		}
		note = "ospf: interface " + n + map[bool]string{true: " enabled", false: " disabled"}[a.Enabled]
	}
	dc.OSPF = c
	return m.PutConfig(dc, actor, note)
}
