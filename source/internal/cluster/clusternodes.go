package cluster

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"netdir/internal/core"
)

var circleLabel = map[string]string{"ok": "serving", "warn": "degraded", "bad": "not serving", "paused": "paused", "idle": "starting"}

// canvasNodes lists the cluster for one gateway: this node first (its state is the gateway's own), then the others by
// address. selfStatus/selfDetail are the gateway's colour and reason on this node; selfPaused says the node itself is paused.
func (c *Cluster) CanvasNodes(gid int, selfStatus, selfDetail string, selfPaused bool) []core.CanvasNode {
	return c.CanvasNodesEx(gid, selfStatus, selfDetail, selfPaused, nil)
}

// canvasNodesEx is canvasNodes with the node IDs removed from the gateway: those nodes read "removed" whichever node is asked.
func (c *Cluster) CanvasNodesEx(gid int, selfStatus, selfDetail string, selfPaused bool, excluded []string) []core.CanvasNode {
	var view ClusterView
	if c != nil && c.Enabled() {
		view = c.View()
	}
	if len(view.Peers) < 2 {
		// a single node is still drawn, so the gateway is seen to be served by something: this node, with the same shape
		// and menu as in a cluster (its Remove from this gateway refuses to leave the gateway with no node)
		host, _ := os.Hostname()
		addr := view.Self
		if addr == "" {
			addr = host
		}
		view.Peers = []core.PeerView{{Addr: addr, NodeID: core.LocalNodeID(), Self: true, Reachable: true, Role: core.RolePrimary, IsPrimary: true,
			Hostname: host, Version: core.Version()}}
	}
	var primaryRev uint64
	for _, p := range view.Peers {
		if p.IsPrimary || (p.Self && p.Role == core.RolePrimary) {
			primaryRev = p.SharedRev
		}
	}
	infos := map[string]peerInfo{}
	if c != nil {
		c.Mu.Lock()
		for addr, pi := range c.Info {
			if pi != nil {
				infos[addr] = *pi
			}
		}
		c.Mu.Unlock()
	}
	out := make([]core.CanvasNode, 0, len(view.Peers))
	for _, p := range view.Peers {
		n := core.CanvasNode{Addr: p.Addr, Name: p.Hostname, Self: p.Self, Role: p.Role, Reachable: p.Reachable, Version: p.Version,
			Updating: p.Updating, SoakSec: p.SoakSec, UpdateErr: p.UpdateFailed, Error: p.Error}
		n.Hostname = p.Hostname
		n.NodeID = p.NodeID
		n.Excluded = p.NodeID != "" && core.ContainsStr(excluded, p.NodeID)
		if n.Name == "" {
			n.Name = p.Addr
		}
		if p.IsPrimary {
			n.Role = core.RolePrimary
		}
		if !p.LastSeen.IsZero() && !p.Self {
			n.LastSeen = p.LastSeen.Unix()
		}
		n.VerDiff = !p.Self && p.Version != "" && p.Version != core.Version()
		n.Behind = primaryRev > 0 && p.SharedRev < primaryRev
		if p.Self {
			n.Host = hostLoadPtr()
			n.Addrs = core.EthernetAddrs()
			n.UptimeSec = int64(time.Since(processStart) / time.Second)
		} else if pi, ok := infos[p.Addr]; ok && p.Reachable {
			n.UptimeSec = pi.Msg.UptimeSec
		}
		switch {
		case p.Self:
			n.Status, n.Detail, n.Paused = selfStatus, selfDetail, selfPaused
			n.Label = circleLabel[selfStatus]
			n.Gw = c.selfGw(gid, selfStatus, selfPaused)
			n.ServingSec = c.selfServingSec(gid)
			if n.Excluded {
				n.Status, n.Label, n.Gw = "paused", "removed", "removed"
			}
			if selfStatus == "idle" && strings.HasPrefix(selfDetail, "not running here") {
				// held back because this node has no address in the gateway's subnet (markOffnet): the other nodes see
				// "not serving" (amber) for it, so say the same here instead of "starting", which is for a node joining
				n.Status, n.Label = "warn", "not serving"
			}
			if selfStatus == "ok" && !selfPaused {
				// healthy: the same words as the other nodes' tooltips (what is said about a node should not depend on
				// which node you ask); in any other state the gateway's own reason on this node is the more useful text
				n.Detail = "Serving this gateway"
			}
		case !p.Reachable && !n.Excluded && p.Restarting:
			// installing an update and restarting into it: not down, and not shown red (it is back in about a minute)
			n.Gw = "updating"
			n.Status, n.Label = "idle", "updating"
			n.Detail = "Updating: restarting into the new version"
			if !p.LastSeen.IsZero() {
				n.Detail += " (last seen " + p.LastSeen.Format("15:04:05") + ")"
			}
		case !p.Reachable && !n.Excluded:
			n.Gw = "down"
			n.Status, n.Label = "bad", "not answering"
			n.Detail = "Not answering"
			if !p.LastSeen.IsZero() {
				n.Detail += " since " + p.LastSeen.Format("15:04:05")
			}
			if p.Error != "" {
				n.Detail += ": " + p.Error
			}
		case n.Excluded:
			n.Gw = "removed"
			n.Status, n.Label, n.Detail = "paused", "removed", "Removed from this gateway: it does not serve it; the other nodes carry on"
			if !p.Reachable {
				n.Detail += " (and is not answering)"
			}
		default:
			pi := infos[p.Addr]
			n.Host = pi.Msg.Host
			n.Addrs = pi.Msg.Addrs
			var gs *core.GwState
			for i := range pi.Msg.Gateways {
				if pi.Msg.Gateways[i].GroupID == gid {
					gs = &pi.Msg.Gateways[i]
				}
			}
			n.Paused = pi.Msg.NodePaused
			if gs != nil && gs.Serving {
				n.ServingSec = gs.ServingSec
			}
			n.Gw = "ok"
			if pi.Msg.GwKnown {
				n.Gw = gwStateOf(gs, pi.Msg.NodePaused)
			} else if pi.Msg.NodePaused {
				n.Gw = "paused"
			}
			switch {
			case pi.Msg.NodePaused:
				n.Status, n.Label, n.Detail = "paused", "paused", "This node is paused (Operate ▸ Node): it is not serving; the others carry on"
			case !pi.Msg.GwKnown:
				n.Status, n.Label, n.Detail = "idle", "online", "Running an older version that does not say what it serves"
			case gs == nil:
				n.Status, n.Label, n.Detail = "paused", "not serving", "This gateway is paused or not set up on that node"
			case !gs.Serving:
				n.Status, n.Label, n.Detail = "warn", "not serving", "That node is up but is not serving this gateway (yet)"
			case gs.Fresh:
				n.Status, n.Label, n.Detail = "ok", "serving", "Serving, but only for the last few seconds"
			default:
				n.Status, n.Label, n.Detail = "ok", "serving", "Serving this gateway"
			}
			// serving, but that node's own view of the gateway is not healthy (its listener not serving, say):
			// show it the way this node's own shape shows it
			if n.Status == "ok" && (gs.Health == "warn" || gs.Health == "bad") {
				n.Status, n.Label = gs.Health, circleLabel[gs.Health]
				if gs.Health == "warn" {
					n.Label = "degraded"
				}
				n.Detail = "Serving, but its view of the gateway is " + circleLabel[gs.Health] + ": " + strings.TrimSpace(gs.HealthWhy)
			}
		}
		// a node whose CPU, memory or disk is over the limit is yellow (degraded) until all are back under it
		if n.Host != nil && (p.Self || p.Reachable) {
			if n.Strain = n.Host.Strained(true); len(n.Strain) > 0 {
				n.Status = "warn"
				n.Label = strings.Join(n.Host.Strained(false), " · ") // the mount is in the tooltip
				n.Detail = fmt.Sprintf("Over %.0f%%: %s (yellow until all are back under it). %s", core.HostStrainPct, strings.Join(n.Strain, ", "), n.Detail)
			}
		}
		out = append(out, n)
	}
	same := map[string]int{}
	for _, n := range out {
		same[n.Name]++
	}
	for i := range out {
		if same[out[i].Name] > 1 {
			out[i].Name = out[i].Addr // two nodes with one host name: told apart by address
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Self != out[j].Self {
			return out[i].Self
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

// clusterUpSec is the gateway's uptime for the whole cluster: the longest unbroken time any node that serves it now has
// served it (a lower bound: the gateway was served at least that long, by that node, however the others came and went).
func ClusterUpSec(nodes []core.CanvasNode) int64 {
	var best int64
	for _, n := range nodes {
		if (n.Gw == "ok" || n.Gw == "degraded") && !n.Excluded && n.ServingSec > best {
			best = n.ServingSec
		}
	}
	return best
}

// labelPausedAll words the nodes of a gateway that is paused on every node (a shared setting): a node that answers and
// does not serve it is "paused", as this node's own shape says, not the "not serving" it reads when only that node lacks it.
// A node that does not answer stays "not answering", and a removed one "removed".
func LabelPausedAll(nodes []core.CanvasNode) {
	const old, now = "This gateway is paused or not set up on that node", "Paused on all nodes — none of them serves it until it is resumed"
	for i := range nodes {
		n := &nodes[i]
		if n.Self || n.Excluded || !n.Reachable || n.Paused || n.Gw != "paused" {
			continue
		}
		if n.Label == "not serving" { // not when the label is a host-load warning, which says something else
			n.Label = "paused"
		}
		n.Detail = strings.Replace(n.Detail, old, now, 1)
	}
}

func hostLoadPtr() *core.HostLoad {
	if l, ok := core.HostLoadFn(); ok {
		return &l
	}
	return nil
}

// gwStateOf is one node's state for a gateway from what it reports (nil: the gateway is paused or not set up there).
func gwStateOf(gs *core.GwState, nodePaused bool) string {
	switch {
	case nodePaused || gs == nil:
		return "paused"
	case !gs.Serving:
		if strings.HasPrefix(gs.HealthWhy, "starting") {
			return "starting"
		}
		return "notserving"
	case gs.Health == "warn":
		return "degraded"
	case gs.Health == "bad":
		return "bad"
	}
	return "ok"
}

// selfGw is this node's own state for the gateway, worked out the same way as the other nodes' (from the same numbers it
// reports to them); without them (before the daemon wires them up) from the gateway's colour here.
// selfServingSec is how long this node has served the gateway without a break (0: not serving).
func (c *Cluster) selfServingSec(gid int) int64 {
	if c == nil || c.Mg == nil || !c.Mg.KnowsGateways() {
		return 0
	}
	for _, g := range c.Mg.LocalGateways() {
		if g.GroupID == gid && g.Serving {
			return g.ServingSec
		}
	}
	return 0
}

func (c *Cluster) selfGw(gid int, selfStatus string, selfPaused bool) string {
	if c != nil && c.Mg != nil && c.Mg.KnowsGateways() {
		var gs *core.GwState
		for _, g := range c.Mg.LocalGateways() {
			if g.GroupID == gid {
				g := g
				gs = &g
			}
		}
		return gwStateOf(gs, selfPaused)
	}
	switch selfStatus {
	case "ok":
		return "ok"
	case "warn":
		return "degraded"
	case "bad":
		return "bad"
	case "paused":
		return "paused"
	}
	return "starting"
}

// clusterGateway is the gateway's state for the cluster as a whole, from its nodes' own states and no node's point of view:
// green while any node serves it (amber when only one of two or more that could serve it does), amber while it is only served degraded, grey dashed when every node has it paused, grey
// while the nodes are still starting, red when no node is serving it.  Nodes removed from the gateway do not count.
func ClusterGateway(nodes []core.CanvasNode) (status, detail string) {
	cnt := map[string]int{}
	total := 0
	for _, n := range nodes {
		if n.Gw == "removed" || n.Excluded {
			continue
		}
		total++
		g := n.Gw
		if g == "" {
			g = "ok"
		}
		cnt[g]++
	}
	of := func(k int) string {
		return fmt.Sprintf("%d of %d node%s", k, total, map[bool]string{true: "", false: "s"}[total == 1])
	}
	switch {
	case total == 0:
		return "idle", "No node is set to serve this gateway"
	case cnt["ok"] == 1 && cnt["degraded"] == 0 && total-cnt["notserving"]-cnt["updating"] >= 2: // a node on another subnet could never serve it and one restarting into an update is not lost
		return "warn", "Served by only " + of(1) + " — the others are paused, not serving or not answering"
	case cnt["ok"] > 0:
		detail = "Served by " + of(cnt["ok"])
		if cnt["degraded"] > 0 {
			detail += fmt.Sprintf(", degraded on %d more", cnt["degraded"])
		}
		return "ok", detail
	case cnt["degraded"] > 0:
		return "warn", "Served, but degraded, by " + of(cnt["degraded"])
	case cnt["paused"] == total:
		return "paused", "Paused on every node"
	case cnt["updating"] > 0 && cnt["bad"] == 0 && cnt["starting"]+cnt["updating"] == total:
		return "idle", "Updating — the node is restarting into the new version"
	case cnt["starting"] > 0 && cnt["bad"] == 0:
		return "idle", "Starting — the nodes are joining the gateway"
	}
	return "bad", "No node is serving this gateway"
}

// otherNodesInService counts the other members of the cluster that answer and are not paused: the nodes that would carry
// on if this one were paused.  A node that is down (not answering) or paused does not count.
func (c *Cluster) OtherNodesInService() int {
	if c == nil || !c.Enabled() {
		return 0
	}
	infos := map[string]peerInfo{}
	c.Mu.Lock()
	for addr, pi := range c.Info {
		if pi != nil {
			infos[addr] = *pi
		}
	}
	c.Mu.Unlock()
	n := 0
	for _, p := range c.View().Peers {
		if p.Self || !p.Reachable {
			continue
		}
		if pi, ok := infos[p.Addr]; ok && pi.Msg.NodePaused {
			continue
		}
		n++
	}
	return n
}
