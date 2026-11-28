package main

import (
	"context"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// updateTick decides whether this node should update now (see umiss's
// maybeSelfUpdateManager).  Called every sync interval on every node.
func (m *Mgmt) UpdateTick(ctx context.Context) {
	m.returnPrimaryHome() // after an update, the primary role goes back to the node that had it
	self := m.cl.SelfAddrForEvents()
	run := core.Version()
	intent := m.upd.Intent()

	// a node that is up to date clears its own queue entry
	// "up to date" must take the cluster's sources into account, or a node
	// that has no source of its own would drop its entry before it could pull.
	best := m.bestKnownSource(run)
	if core.ContainsStr(intent.Pending, self) && !core.VersionGreater(best, run) && m.upd.RolledBackNotice() == "" {
		if _, err := m.runOnPrimary("update-done", "self", adminNodes{Nodes: []string{self}}); err != nil {
			core.Debugf("update: could not clear queue entry: %v", err)
		}
	}
	if m.upd.Busy() || !intent.Wants(self) {
		return
	}
	target := m.upd.SourceVersion()
	var srcPeer core.ClusterPeer
	havePeer := false
	if m.cl.Enabled() {
		if p, v, ok := m.cl.BestSourcePeer(cluster.Max2(target, run)); ok {
			srcPeer, target, havePeer = p, v, true
		}
	}
	if !core.VersionGreater(target, run) {
		return
	}
	if m.upd.FailedFor() == target {
		return
	}
	if m.cl.Enabled() && m.cl.ShouldWaitForOthers(target, intent) {
		return
	}
	if m.cl.Enabled() {
		if why := m.cl.CanaryHold(target); why != "" {
			m.upd.SetWaiting(why)
			return
		}
	}
	if ok, why := m.updateSafeToApply(); !ok {
		m.upd.SetWaiting(why)
		return
	}
	m.upd.SetWaiting("")
	if havePeer {
		core.Infof("update: pulling source v%s from %s", target, srcPeer.Addr)
		v, err := m.cl.PullSource(ctx, srcPeer)
		if err != nil {
			m.upd.NoteFailure(self, run, target, "pulling source from "+srcPeer.Addr+": "+err.Error())
			return
		}
		m.upd.Record(core.UpdateEvent{Node: self, Kind: "pulled", To: v, Detail: "source from " + srcPeer.Addr})
	}
	if _, err := m.upd.Apply(ctx, self, "queued update"); err != nil {
		core.Debugf("update: %v", err)
		return
	}
	m.scheduleRestart(false)
}

// bestKnownSource is the highest source version this node could install: its
// own staged source or the best one a reachable peer offers.
func (m *Mgmt) bestKnownSource(run string) string {
	best := m.upd.SourceVersion()
	if m.cl.Enabled() {
		if _, v, ok := m.cl.BestSourcePeer(cluster.Max2(best, run)); ok {
			best = v
		}
	}
	return best
}

func (m *Mgmt) LocalGateways() []core.GwState {
	if m.gwFn == nil {
		return nil
	}
	gs := m.gwFn()
	m.servMu.Lock()
	defer m.servMu.Unlock()
	if m.servSince == nil {
		m.servSince = map[int]time.Time{}
	}
	seen := map[int]bool{}
	for i := range gs {
		gid := gs[i].GroupID
		seen[gid] = true
		if !gs[i].Serving {
			delete(m.servSince, gid)
			continue
		}
		since, ok := m.servSince[gid]
		if !ok {
			since = time.Now()
			m.servSince[gid] = since
		}
		gs[i].Fresh = time.Since(since) < cluster.ServingSettle
		gs[i].ServingSec = int64(time.Since(since) / time.Second)
	}
	for gid := range m.servSince {
		if !seen[gid] {
			delete(m.servSince, gid)
		}
	}
	if m.cl != nil {
		m.cl.FillUpSince(gs)
	}
	return gs
}

// updateSafe applies safeToTakeDown with what the other members last reported.
// A node that is not clustered, or serves nothing, can always update.
func (m *Mgmt) updateSafe() (bool, string) {
	if m.gwFn == nil || !m.cl.Enabled() {
		return true, ""
	}
	peers := m.cl.PeerGateways()
	if dc, _, err := m.LiveConfig(); err == nil {
		cluster.MarkGatewayExcluded(peers, dc.Groups)
	}
	return cluster.SafeToTakeDown(m.LocalGateways(), peers)
}

// updateSafeToApply is updateSafe for installing an update: a node that knows no other member is never held back, since no
// node exists that could ever cover its gateways and waiting would be for ever (a brief restart is the price of updating
// a single node).  Power actions keep the stricter updateSafe: rebooting the only server of a gateway stays a decision.
func (m *Mgmt) updateSafeToApply() (bool, string) {
	if m.cl != nil && len(m.cl.Node.Snapshot().Peers) == 0 {
		return true, ""
	}
	return m.updateSafe()
}

// holdBackFromNewGateways makes a gateway that did not exist before (its number is not in known) serve on this node only: every other
// cluster node is put on its removed-nodes list, so a new gateway does not change what the other nodes do.  An administrator adds
// the nodes it should run on (right-click the gateway ▸ Add ▸ Node).  A gateway that arrives with its own list is left as it is.
func (m *Mgmt) HoldBackFromNewGateways(dc *core.DaemonConfig, known map[int]bool) {
	if m.cl == nil || !m.cl.Enabled() {
		return
	}
	self := core.LocalNodeID()
	var others []string
	for _, p := range m.cl.View().Peers {
		if p.NodeID != "" && p.NodeID != self {
			others = append(others, p.NodeID)
		}
	}
	if len(others) == 0 {
		return
	}
	for i := range dc.Groups {
		if g := &dc.Groups[i]; !known[g.GroupID] && len(g.ExcludedNodes) == 0 {
			g.ExcludedNodes = append([]string(nil), others...)
		}
	}
}

// excludeNewNode leaves a node that has just joined the cluster out of every gateway (the shared excluded_nodes list), so
// that joining does not change which nodes answer for a gateway; an administrator adds it where it should serve.
func (m *Mgmt) ExcludeNewNode(id string) {
	dc, _, err := m.LiveConfig()
	if err != nil || dc == nil {
		return
	}
	changed := false
	for i := range dc.Groups {
		if !core.ContainsStr(dc.Groups[i].ExcludedNodes, id) {
			dc.Groups[i].ExcludedNodes = append(dc.Groups[i].ExcludedNodes, id)
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := m.PutConfig(dc, "cluster join", "a new node is not added to the gateways"); err != nil {
		core.Warnf("cluster: could not leave the new node %s out of the gateways: %v", id, err)
		return
	}
	core.Infof("cluster: node %s joined; it serves no gateway until it is added (right-click the gateway ▸ Add node)", id)
}
