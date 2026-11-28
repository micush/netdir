package core

import (
	"sort"
)

// servingPeers lists the nodes that can say how the gateway is doing, best first: those serving it well, then those
// serving it degraded.  Empty when this node serves it itself or nobody does.
func ServingPeers(g CanvasGateway) []CanvasNode {
	self := ""
	for _, n := range g.Nodes {
		if n.Self {
			self = n.Gw
		}
	}
	switch self {
	case "notserving", "paused", "removed":
	default:
		return nil // this node serves it (or is starting it): its own view is the picture
	}
	var ok, degraded []CanvasNode
	for _, n := range g.Nodes {
		if n.Self || !n.Reachable || n.Excluded {
			continue
		}
		switch n.Gw {
		case "ok":
			ok = append(ok, n)
		case "degraded":
			degraded = append(degraded, n)
		}
	}
	byAddr := func(l []CanvasNode) { sort.SliceStable(l, func(i, j int) bool { return l[i].Addr < l[j].Addr }) }
	byAddr(ok)
	byAddr(degraded)
	return append(ok, degraded...)
}

// takeFrom puts the serving node's picture of the gateway in place of this node's: its colour, anycast
// addresses, members and uptime; the cluster's nodes and everything about this node's own entry stay.
func (g *CanvasGateway) TakeFrom(p CanvasGateway, from CanvasNode) {
	g.Status, g.Detail, g.Families = p.Status, p.Detail, p.Families
	g.Members, g.Anycast, g.Uptime = p.Members, p.Anycast, p.Uptime
	// the serving node's own entry is "local" to it, not to this node: nobody is this node here, or the
	// page would put the controller mark (and the star) on the node it is open on
	g.Members = make([]CanvasMember, len(p.Members))
	copy(g.Members, p.Members)
	for i := range g.Members {
		g.Members[i].ViaLocal = g.Members[i].Local
		g.Members[i].Local = false
	}
	g.Via, g.ViaAddr = from.Name, from.Addr
}
