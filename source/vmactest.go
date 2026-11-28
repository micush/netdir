package main

import (
	"errors"

	"netdir/internal/core"
)

// VmacTest runs the test for one gateway (group > 0) or all of them on this node.
func (m *Mgmt) VmacTest(group int) ([]core.VmacResult, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	var out []core.VmacResult
	for _, g := range dc.Groups {
		if group != 0 && g.GroupID != group {
			continue
		}
		out = append(out, core.VmacTestGroup(g))
	}
	if len(out) == 0 {
		if group != 0 {
			return nil, core.ErrNoGroup
		}
		return nil, errors.New("there is no gateway to test")
	}
	return out, nil
}
