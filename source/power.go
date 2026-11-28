package main

import (
	"errors"
	"fmt"
	"time"

	"netdir/internal/core"
)

// powerHandoverTick hands the primary role over shortly before a scheduled restart or shut down (one made here with --power in/at,
// or with shutdown(8) directly: the schedule is read from systemd's file, so it also survives a restart of netdir).  Nothing
// happens on a replica, or when no member can take the role.
func (m *Mgmt) PowerHandoverTick() {
	p := m.PowerStatus()
	if !p.Scheduled {
		return
	}
	at, err := time.Parse(time.RFC3339, p.At)
	if err != nil || time.Until(at) > core.PowerHandoverLead {
		return
	}
	verb := map[string]string{"restart": "restart", "shutdown": "shut down"}[p.Action]
	m.handOver("scheduled power action", "the scheduled host "+verb)
}

// PowerStatus reports a pending scheduled power action, if there is one.
func (m *Mgmt) PowerStatus() core.PowerPending { return core.ReadPowerPending(core.PowerScheduledFile) }

// Power carries out a request.  by is the actor, for the log.
func (m *Mgmt) Power(r core.PowerReq, by string) (core.PowerResult, error) {
	if r.Action == "cancel" {
		if err := core.PowerRun("shutdown", "-c"); err != nil {
			return core.PowerResult{}, errors.New("nothing to cancel (no power action is scheduled)")
		}
		core.Warnf("power: scheduled power action cancelled by %s", by)
		return core.PowerResult{Action: "cancel"}, nil
	}
	var flag, sysctl, verb string
	switch r.Action {
	case "restart", "reboot":
		flag, sysctl, verb, r.Action = "-r", "reboot", "restart", "restart"
	case "shutdown", "poweroff":
		flag, sysctl, verb, r.Action = "-h", "poweroff", "shut down", "shutdown"
	default:
		return core.PowerResult{}, errors.New("action must be restart, shutdown or cancel")
	}
	spec, human := "now", "now"
	switch r.When {
	case "", "now":
		// An immediate action must not take the last serving member of a gateway down.
		if ok, why := m.updateSafe(); !ok && !r.Force {
			return core.PowerResult{}, fmt.Errorf("not safe to %s this node now: %s (to go ahead anyway: netdir --power %s --yes, or confirm in the GUI)", verb, why, r.Action)
		}
	case "in":
		if r.Minutes < 1 || r.Minutes > core.MaxPowerMinutes {
			return core.PowerResult{}, fmt.Errorf("minutes must be between 1 and %d (7 days)", core.MaxPowerMinutes)
		}
		spec, human = fmt.Sprintf("+%d", r.Minutes), fmt.Sprintf("in %d minute(s)", r.Minutes)
	case "at":
		if !core.ValidHHMM(r.Time) {
			return core.PowerResult{}, errors.New("time must be 24-hour HH:MM")
		}
		spec, human = r.Time, "at "+r.Time
	default:
		return core.PowerResult{}, errors.New("when must be now, in or at")
	}
	core.Warnf("power: host %s %s requested by %s", verb, human, by)
	if spec == "now" {
		m.handOver(by, "host "+verb)
	}
	go func() {
		time.Sleep(core.PowerDelay)
		if spec == "now" && core.PowerStart("systemctl", sysctl) == nil {
			return
		}
		if err := core.PowerStart("shutdown", flag, spec); err != nil {
			core.Errorf("power: could not run shutdown: %v", err)
		}
	}()
	return core.PowerResult{Action: r.Action, When: human}, nil
}
