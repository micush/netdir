package main

import (
	"errors"

	"netdir/internal/core"
)

// NodePauseStatus says whether this node is paused.
func (m *Mgmt) NodePauseStatus() (core.NodePauseState, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return core.NodePauseState{}, err
	}
	return core.NodePauseState{Paused: dc.NodePaused}, nil
}

// NodePause takes this whole node out of service (or puts it back): every gateway
// on it resigns and stops answering, and the other nodes carry on, the
// same as pausing each gateway but in one step and covering gateways added later.
// The flag is local to the node and is never replicated.
func (m *Mgmt) NodePause(pause bool, actor string) (string, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return "", err
	}
	if dc.NodePaused == pause {
		if pause {
			return "this node is already paused", nil
		}
		return "this node is already running", nil
	}
	if pause && m.othersInService() == 0 {
		return "", errors.New("this is the only node in service (the others are paused or not answering), so pausing it would stop every gateway — resume or repair another node first; to stop a gateway everywhere, pause the gateway instead")
	}
	if pause {
		if why := m.lastServerOf(); why != "" {
			return "", errors.New(why)
		}
	}
	dc.NodePaused = pause
	note := "node: resume"
	if pause {
		note = "node: pause"
	}
	if err := m.PutConfig(dc, actor, note); err != nil {
		return "", err
	}
	if pause {
		msg := "node paused — its gateways stop serving and the other nodes take over; resume it when maintenance is done"
		// the primary role moves too (the controller role moves by itself when the gateways resign)
		if m.cl != nil {
			if to, err := m.cl.HandOverPrimary(actor, "pausing the node"); err != nil {
				msg += "; the primary role could not be moved (" + err.Error() + ")"
			} else if to != "" {
				msg += "; " + to + " is now the primary"
			}
		}
		return msg, nil
	}
	return "node resumed — its gateways rejoin", nil
}

func (m *Mgmt) othersInService() int {
	if m.othersFn != nil {
		return m.othersFn()
	}
	return m.cl.OtherNodesInService()
}

// lastServerOf names a gateway this node serves that no other member serves, so pausing the node would leave it with nobody.
// Unlike the update check, a member on another subnet or removed from the gateway is no cover and is not excused: pausing
// the last node of a gateway is refused whatever else the cluster is doing.  "" when it may be paused.
func (m *Mgmt) lastServerOf() string {
	if m.lastFn != nil {
		return m.lastFn()
	}
	if m.gwFn == nil || m.cl == nil || !m.cl.Enabled() {
		return ""
	}
	return core.LastServing(m.LocalGateways(), m.cl.PeerGateways())
}
