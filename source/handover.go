package main

import (
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// returnPrimaryHome runs on every sync of every node: the primary, when it holds a home that is not itself and the update is over
// (primaryReturnTarget for primaryReturnAfter in a row), gives the role back to it.
func (m *Mgmt) returnPrimaryHome() {
	c := m.cl
	if c == nil || !c.Enabled() {
		return
	}
	home := c.PrimaryHome()
	if home == "" {
		return
	}
	snap := c.Node.Snapshot()
	if snap.Role != core.RolePrimary || home == snap.SelfAddr {
		c.SetPrimaryHome("")
		c.Mu.Lock()
		c.ReturnSince = time.Time{}
		c.Mu.Unlock()
		return
	}
	ready, drop, why := cluster.PrimaryReturnTarget(c.View().Peers, home, m.upd.Intent(), m.upd.Busy())
	if drop {
		core.Warnf("cluster: the primary role stays here: %s cannot take it back (%s)", home, why)
		c.SetPrimaryHome("")
		return
	}
	c.Mu.Lock()
	if !ready {
		c.ReturnSince = time.Time{}
		c.Mu.Unlock()
		return
	}
	if c.ReturnSince.IsZero() {
		c.ReturnSince = time.Now()
	}
	wait := time.Since(c.ReturnSince) < cluster.PrimaryReturnAfter
	c.Mu.Unlock()
	if wait {
		return
	}
	if _, err := c.HandOverTo(home, "update", "the update is over", ""); err != nil {
		core.Warnf("cluster: could not give the primary role back to %s: %v", home, err)
		return
	}
	core.Infof("cluster: the update is over: the primary role is back at %s", home)
	c.Mu.Lock()
	c.ReturnSince = time.Time{}
	c.Mu.Unlock()
}

// handOver is the daemon's side of it: the primary role moves before a restart, shut down or update, and a failure is logged,
// never a reason to stop (the administrator asked for the restart).
func (m *Mgmt) handOver(by, why string) {
	if m == nil || m.cl == nil {
		return
	}
	if _, err := m.cl.HandOverPrimary(by, why); err != nil {
		core.Warnf("cluster: could not hand the primary role over before %s: %v", why, err)
	}
}

// handOverForUpdate is handOver for a node about to restart into an update: the role goes back to its home afterwards.
func (m *Mgmt) handOverForUpdate(by, why string) {
	if m == nil || m.cl == nil {
		return
	}
	if _, err := m.cl.HandOverPrimaryForUpdate(by, why); err != nil {
		core.Warnf("cluster: could not hand the primary role over before %s: %v", why, err)
	}
}
