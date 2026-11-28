package cluster

import (
	"sync"
	"time"

	"netdir/internal/core"
)

// AnycastUp is what a node says about one anycast address it is announcing now: since when this node has had it up without
// a break (Since) and since when somebody in the cluster has (UpSince, as this node knows it; see sampleAnycastUp).
type AnycastUp struct {
	Addr    string `json:"addr"`
	Since   int64  `json:"since"`
	UpSince int64  `json:"up_since,omitempty"`
}

// anycastLocal is this node's anycast addresses that are up and announced, as the last topology sample saw them.
var AnycastLocal struct {
	Mu   sync.Mutex  `json:"-"`
	List []AnycastUp `json:"-"`
}

// storeAnycastLocal notes from a topology sample (canvasGroups) which anycast addresses this node has up, for the status
// message and for sampleAnycastUp.
func StoreAnycastLocal(groups []core.CanvasGateway) {
	best := map[string]int64{}
	var order []string
	for _, g := range groups {
		for _, a := range g.Anycast {
			if a.External || !a.Up || a.Paused != "" || a.Status == "bad" || a.Uptime == nil || !a.Uptime.Up {
				continue
			}
			if t, ok := best[a.Addr]; !ok {
				best[a.Addr] = a.Uptime.Since
				order = append(order, a.Addr)
			} else if a.Uptime.Since < t {
				best[a.Addr] = a.Uptime.Since
			}
		}
	}
	list := make([]AnycastUp, 0, len(order))
	for _, ad := range order {
		list = append(list, AnycastUp{Addr: ad, Since: best[ad]})
	}
	AnycastLocal.Mu.Lock()
	AnycastLocal.List = list
	AnycastLocal.Mu.Unlock()
}

// anycastReport is this node's list for the status message, with the cluster-wide start this node knows.
func (c *Cluster) AnycastReport() []AnycastUp {
	AnycastLocal.Mu.Lock()
	out := append([]AnycastUp(nil), AnycastLocal.List...)
	AnycastLocal.Mu.Unlock()
	c.upMu.Lock()
	for i := range out {
		if t, ok := c.anyUp[out[i].Addr]; ok {
			out[i].UpSince = t.Unix()
		}
	}
	c.upMu.Unlock()
	return out
}

// anyUpSeconds is how long somebody in the cluster has had the anycast address up without a break (0: nobody now, or not known yet).
func (c *Cluster) AnyUpSeconds(addr string) int64 {
	if c == nil {
		return 0
	}
	c.upMu.Lock()
	defer c.upMu.Unlock()
	if t, ok := c.anyUp[addr]; ok {
		return int64(time.Since(t) / time.Second)
	}
	return 0
}

// sampleAnycastUp does for the anycast addresses what sampleGwUp does for gateways: it keeps since when somebody in the
// cluster has had each one up without a break, takes the earliest of its own and what the members report, and drops it
// when no node announces the address (so a rolling update does not reset it; a real outage does).
func (c *Cluster) SampleAnycastUp() {
	m := c.Mg
	if m == nil {
		return
	}
	AnycastLocal.Mu.Lock()
	mine := append([]AnycastUp(nil), AnycastLocal.List...)
	AnycastLocal.Mu.Unlock()
	best := map[string]time.Time{}
	note := func(addr string, unix int64) {
		if unix <= 0 {
			return
		}
		t := time.Unix(unix, 0)
		if old, ok := best[addr]; !ok || t.Before(old) {
			best[addr] = t
		}
	}
	for _, a := range mine {
		note(a.Addr, a.Since)
	}
	c.Mu.Lock()
	for _, pi := range c.Info {
		if pi == nil || !pi.Reachable {
			continue
		}
		for _, a := range pi.Msg.AnycastUp {
			note(a.Addr, a.Since)
			note(a.Addr, a.UpSince)
		}
	}
	c.Mu.Unlock()
	c.upMu.Lock()
	defer c.upMu.Unlock()
	next := map[string]time.Time{}
	for addr, t := range best {
		if old, ok := c.anyUp[addr]; ok && old.Before(t) {
			t = old
		}
		next[addr] = t
	}
	c.anyUp = next
}
