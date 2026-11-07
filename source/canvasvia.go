package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// A gateway this node does not serve (another subnet, removed from it, paused here) has nothing of its own to show: no
// servers probed, no domains tested.  The drawing is the gateway, not this node, so for such a gateway the picture is the
// one the nodes that serve it have: asked of one of them, over the cluster channel, and shown with the name of the node it
// came from.  The node's own entry among the cluster's nodes stays what this node says about itself.

// viaFetchTimeout bounds the ask: a slow node must not hold the Topology page up (it falls back to this node's own view).
var viaFetchTimeout = 4 * time.Second

// servingPeers lists the nodes that can say how the gateway is doing, best first: those serving it well, then those
// serving it degraded.  Empty when this node serves it itself or nobody does.
func servingPeers(g CanvasGateway) []CanvasNode {
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
func (g *CanvasGateway) takeFrom(p CanvasGateway, from CanvasNode) {
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

// viaServing replaces, in place, each gateway this node does not serve with the picture of a node that does.
func (s *StatusServer) viaServing(ctx context.Context, groups []CanvasGateway) {
	if s.mg == nil || s.mg.cl == nil {
		return
	}
	fetched := map[string][]CanvasGateway{} // by node address; nil: could not be asked
	ask := func(n CanvasNode) []CanvasGateway {
		if l, done := fetched[n.Addr]; done {
			return l
		}
		cctx, cancel := context.WithTimeout(ctx, viaFetchTimeout)
		defer cancel()
		resp, err := s.mg.cl.Relay(cctx, n.Addr, proxyReq{User: "topology", Method: http.MethodGet, Path: "/api/canvas?own=1"})
		var out struct {
			Data []CanvasGateway `json:"data"`
		}
		if err == nil && resp.Status == http.StatusOK && json.Unmarshal(resp.Body, &out) == nil {
			fetched[n.Addr] = out.Data
		} else {
			fetched[n.Addr] = nil
		}
		return fetched[n.Addr]
	}
	for i := range groups {
	peers:
		for _, n := range servingPeers(groups[i]) {
			for _, p := range ask(n) {
				if p.GroupID == groups[i].GroupID {
					groups[i].takeFrom(p, n)
					break peers
				}
			}
		}
	}
}

// The callers each serving node has seen, asked of it and kept for a few seconds (the Topology page polls).
var (
	peerCallersMu sync.Mutex
	peerCallers   = map[string]struct {
		at   time.Time
		byGW map[int][]string
	}{}
)

const peerCallersFor = 5 * time.Second

// addPeerClients makes each gateway's Clients the callers of every node that serves it, counted once each: this node's own
// (already in the gateway) and those the other nodes report in their own view (?own=1).  A node that cannot be asked counts as it was.
func (s *StatusServer) addPeerClients(ctx context.Context, groups []CanvasGateway) {
	if s.mg == nil || s.mg.cl == nil || !s.mg.cl.Enabled() {
		return
	}
	peers := map[string]bool{}
	for _, g := range groups {
		for _, n := range g.Nodes {
			if !n.Self && n.Reachable && !n.Excluded && (n.Gw == "ok" || n.Gw == "degraded") {
				peers[n.Addr] = true
			}
		}
	}
	var wg sync.WaitGroup
	for addr := range peers {
		peerCallersMu.Lock()
		c, ok := peerCallers[addr]
		peerCallersMu.Unlock()
		if ok && time.Since(c.at) < peerCallersFor {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			resp, err := s.mg.cl.Relay(cctx, addr, proxyReq{User: "topology", Method: http.MethodGet, Path: "/api/canvas?own=1"})
			var out struct {
				Data []CanvasGateway `json:"data"`
			}
			if err != nil || resp.Status != http.StatusOK || json.Unmarshal(resp.Body, &out) != nil {
				return
			}
			by := map[int][]string{}
			for _, p := range out.Data {
				by[p.GroupID] = p.MCPCallers
			}
			peerCallersMu.Lock()
			peerCallers[addr] = struct {
				at   time.Time
				byGW map[int][]string
			}{time.Now(), by}
			peerCallersMu.Unlock()
		}(addr)
	}
	wg.Wait()
	peerCallersMu.Lock()
	defer peerCallersMu.Unlock()
	for i := range groups {
		set := map[string]bool{}
		for _, c := range groups[i].MCPCallers {
			set[c] = true
		}
		for _, n := range groups[i].Nodes {
			if n.Self || !n.Reachable || n.Excluded || (n.Gw != "ok" && n.Gw != "degraded") {
				continue
			}
			if c, ok := peerCallers[n.Addr]; ok && time.Since(c.at) < 10*peerCallersFor {
				for _, id := range c.byGW[groups[i].GroupID] {
					set[id] = true
				}
			}
		}
		groups[i].MCPClients = len(set)
	}
}
