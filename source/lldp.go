package main

// LLDPSet switches LLDP on or off for the whole cluster (--lldp-enable / --lldp-disable).
func (m *Mgmt) LLDPSet(on bool, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if dc.Settings.LLDP == on {
		return nil
	}
	dc.Settings.LLDP = on
	return m.PutConfig(dc, actor, map[bool]string{true: "lldp: on", false: "lldp: off"}[on])
}
