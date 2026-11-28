package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"netdir/internal/core"
)

// A gateway this node does not serve (another subnet, removed from it, paused here) has nothing of its own to show: no
// servers probed, no domains tested.  The drawing is the gateway, not this node, so for such a gateway the picture is the
// one the nodes that serve it have: asked of one of them, over the cluster channel, and shown with the name of the node it
// came from.  The node's own entry among the cluster's nodes stays what this node says about itself.

// viaFetchTimeout bounds the ask: a slow node must not hold the Topology page up (it falls back to this node's own view).
var viaFetchTimeout = 4 * time.Second

// peerCanvases keeps, for a few seconds, the picture each serving node gave of its own gateways, so a poll asks no node that was
// asked a moment ago, and a slow node never holds the page up: a stale picture is used while a new one is fetched in the background.
var (
	peerCanvasMu sync.Mutex
	peerCanvases = map[string]*peerCanvas{}
	// viaColdWait is how long a request waits for a node it has no picture from yet; then it shows this node's own view.
	viaColdWait = 1500 * time.Millisecond
)

const peerCanvasFor = 3 * time.Second

type peerCanvas struct {
	at       time.Time
	data     []core.CanvasGateway
	fetching bool
	tried    bool // a fetch has ended (well or not): later requests do not wait for the next one
	done     chan struct{}
}

// askPeerCanvas asks a node, over the cluster channel, for its own picture of its gateways.
var askPeerCanvas = func(s *StatusServer, ctx context.Context, addr string) ([]core.CanvasGateway, bool) {
	resp, err := s.mg.cl.Relay(ctx, addr, core.ProxyReq{User: "topology", Method: http.MethodGet, Path: "/api/canvas?own=1"})
	var out struct {
		Data []core.CanvasGateway `json:"data"`
	}
	if err != nil || resp.Status != http.StatusOK || json.Unmarshal(resp.Body, &out) != nil {
		return nil, false
	}
	return out.Data, true
}

func (s *StatusServer) peerCanvasOf(n core.CanvasNode) []core.CanvasGateway {
	peerCanvasMu.Lock()
	e := peerCanvases[n.Addr]
	if e == nil {
		e = &peerCanvas{}
		peerCanvases[n.Addr] = e
	}
	if time.Since(e.at) >= peerCanvasFor && !e.fetching {
		e.fetching = true
		e.done = make(chan struct{})
		done := e.done
		go func() {
			t0 := time.Now()
			cctx, cancel := context.WithTimeout(context.Background(), viaFetchTimeout)
			defer cancel()
			data, good := askPeerCanvas(s, cctx, n.Addr)
			if took := time.Since(t0); took > time.Second {
				core.Warnf("topology: node %s took %s to give its picture of its gateways (answered: %v)", n.Addr, took.Round(100*time.Millisecond), good)
			}
			peerCanvasMu.Lock()
			defer peerCanvasMu.Unlock()
			e.fetching, e.tried = false, true
			close(done)
			if good {
				e.data, e.at = data, time.Now()
			} else {
				e.at = time.Now().Add(-(peerCanvasFor - time.Second)) // counts as 2 s old: asked again in a second, not at once
			}
		}()
	}
	data, done, at, tried := e.data, e.done, e.at, e.tried
	peerCanvasMu.Unlock()
	if data == nil && !tried && done != nil { // only the very first ask is waited for: a node that does not answer is not waited for again
		select {
		case <-done:
		case <-time.After(viaColdWait):
		}
		peerCanvasMu.Lock()
		data, at = e.data, e.at
		peerCanvasMu.Unlock()
	}
	if time.Since(at) > time.Minute {
		return nil // too old to say how the gateway is doing now
	}
	return data
}

// viaServing replaces, in place, each gateway this node does not serve with the picture of a node that does.
func (s *StatusServer) ViaServing(ctx context.Context, groups []core.CanvasGateway) {
	if s.mg == nil || s.mg.cl == nil {
		return
	}
	for i := range groups {
	peers:
		for _, n := range core.ServingPeers(groups[i]) {
			for _, p := range s.peerCanvasOf(n) {
				if p.GroupID == groups[i].GroupID {
					groups[i].TakeFrom(p, n)
					break peers
				}
			}
		}
	}
}

// addPeerClients makes each gateway's Clients the callers of every node that serves it, counted once each: this node's own
// (already in the gateway) and those the other nodes report in their own view (?own=1), from the picture peerCanvasOf keeps of each
// (so a node that is slow or does not answer is asked once in a while, in the background, and never holds a poll up).  A node that
// cannot be asked counts as it was.
func (s *StatusServer) AddPeerClients(ctx context.Context, groups []core.CanvasGateway) {
	if s.mg == nil || s.mg.cl == nil || !s.mg.cl.Enabled() {
		return
	}
	for i := range groups {
		set := map[string]bool{}
		for _, c := range groups[i].MCPCallers {
			set[c] = true
		}
		for _, n := range groups[i].Nodes {
			if n.Self || !n.Reachable || n.Excluded || (n.Gw != "ok" && n.Gw != "degraded") {
				continue
			}
			for _, p := range s.peerCanvasOf(n) {
				if p.GroupID == groups[i].GroupID {
					for _, id := range p.MCPCallers {
						set[id] = true
					}
				}
			}
		}
		groups[i].MCPClients = len(set)
	}
}
