package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"netdir/device"
)

type engineKey struct {
	group int
	af    AF
}

// Supervisor owns the running engines, the anycast addresses, and hot reload.
//
// Live fields (no engine restart): priority, lb_method, weight, hello_ms,
// hold_ms, preempt, max_afns.  Restart fields: interface, vip4, vip6,
// group_id, key, neighbors.
type Supervisor struct {
	ctx context.Context

	reloadMu sync.Mutex // serialises Start/Reload/Stop
	mu       sync.Mutex // guards dc and engines
	pausedMu sync.RWMutex
	bgpAC    *BGPConfig                // BGP settings, for the anycast loops' announce gate (guarded by pausedMu)
	ospfAC   *OSPFConfig               // OSPF settings, likewise (guarded by pausedMu)
	pausedAC map[int]map[string]string // gateway -> anycast address -> where it is paused; read by the anycast loops without s.mu
	dc       *DaemonConfig

	metricsMu    sync.Mutex // the /metrics access list as networks (metrics.go)
	metricsKey   string
	metricsAt    time.Time
	metricsCache []netip.Prefix
	engines      map[engineKey]*Engine

	// Groups held back because this node has no address in the gateway's subnet
	// (guarded by mu); the value identifies one wait so a reload can cancel it.
	offnet map[int]*offnetWait

	// Anycast address sets of the running groups (guarded by mu).
	anycast map[int]*anycastSet
}

type offnetWait struct {
	why string
}

func NewSupervisor(ctx context.Context, dc *DaemonConfig) *Supervisor {
	s := &Supervisor{ctx: ctx, dc: dc.effective(), engines: map[engineKey]*Engine{},
		offnet: map[int]*offnetWait{}, anycast: map[int]*anycastSet{}}
	s.notePausedAnycast(s.dc)
	device.SetSecretWords(secretWordsOf(s.dc))
	return s
}

// notePausedAnycast records where each anycast address is paused, for the anycast loops (which run while s.mu is held).
func (s *Supervisor) notePausedAnycast(dc *DaemonConfig) {
	m := map[int]map[string]string{}
	for _, g := range dc.Groups {
		if p := g.pausedAnycast(); len(p) > 0 {
			m[g.GroupID] = p
		}
	}
	s.pausedMu.Lock()
	s.pausedAC = m
	s.bgpAC = dc.BGP.clone()
	s.ospfAC = dc.OSPF.clone()
	s.pausedMu.Unlock()
}

// groupName is the name given to a gateway ("" when it has none).
func (s *Supervisor) groupName(gid int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dc != nil {
		for i := range s.dc.Groups {
			if s.dc.Groups[i].GroupID == gid {
				return s.dc.Groups[i].Name
			}
		}
	}
	return ""
}

func (s *Supervisor) newEngine(gc GroupConfig, af AF) *Engine {
	gid := gc.GroupID
	_ = gid
	return NewEngine(gc, af)
}

func (s *Supervisor) StartAll() {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.mu.Lock()
	for _, gc := range s.dc.Groups {
		s.startGroupWhenReadyLocked(gc)
	}
	s.mu.Unlock()
}

func (s *Supervisor) StopAll() {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.mu.Lock()
	engines := make([]*Engine, 0, len(s.engines))
	for _, e := range s.engines {
		engines = append(engines, e)
	}
	s.engines = map[engineKey]*Engine{}
	s.offnet = map[int]*offnetWait{}
	for gid := range s.anycast {
		s.stopAnycastLocked(gid)
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, e := range engines {
		wg.Add(1)
		go func() { defer wg.Done(); e.Stop() }()
	}
	wg.Wait()
}

func (s *Supervisor) startGroupLocked(gc GroupConfig) {
	if gc.Paused {
		infof("Group %d is paused on this node — not starting", gc.GroupID)
		return
	}
	for _, af := range []AF{afIPv4, afIPv6} {
		if gc.wants(af) {
			e := s.newEngine(gc, af)
			s.engines[engineKey{gc.GroupID, af}] = e
			e.Start(s.ctx)
		}
	}
	s.startAnycastLocked(gc)
}

// startAnycastLocked holds and serves the gateway's anycast addresses (see anycast.go).
func (s *Supervisor) startAnycastLocked(gc GroupConfig) {
	if len(gc.ExtraVIPs) == 0 || s.anycast[gc.GroupID] != nil {
		return
	}
	gid := gc.GroupID
	a := newAnycastSet(gid, gc.ExtraVIPs)
	a.paused = func() map[string]string { return s.pausedAnycast(gid) }
	a.bgp = func() (*BGPConfig, bool) { s.pausedMu.RLock(); defer s.pausedMu.RUnlock(); return s.bgpAC, true }
	a.ospf = func() *OSPFConfig { s.pausedMu.RLock(); defer s.pausedMu.RUnlock(); return s.ospfAC }
	s.anycast[gid] = a
	a.start(s.ctx)
}

func (s *Supervisor) stopAnycastLocked(gid int) {
	if a := s.anycast[gid]; a != nil {
		delete(s.anycast, gid)
		a.stop()
	}
}

// pausedAnycast is where each anycast address of the gateway is paused, from the live configuration.
func (s *Supervisor) pausedAnycast(gid int) map[string]string {
	s.pausedMu.RLock()
	defer s.pausedMu.RUnlock()
	return s.pausedAC[gid]
}

// AnycastStates lists the anycast addresses of a group and whether each is announced now.
func (s *Supervisor) AnycastStates(gid int) []AnycastState {
	s.mu.Lock()
	a := s.anycast[gid]
	s.mu.Unlock()
	if a == nil {
		return nil
	}
	st := a.state()
	paused := s.pausedAnycast(gid)
	for i := range st {
		st[i].Paused = paused[st[i].Addr]
	}
	return st
}

// AllAnycastStates lists every anycast address of every gateway with whether this
// node announces it now.  An address of a gateway that is not running here is
// listed as withdrawn.
// AllAnycastStates lists every anycast address of every gateway with whether this
// node announces it now.  An address of a gateway that is not running here is
// listed as withdrawn.
func (s *Supervisor) AllAnycastStates() []AnycastState {
	var out []AnycastState
	at := map[string]int{} // address -> index in out
	rank := map[string]int{}
	for _, g := range s.config().Groups {
		if g.ExcludedHere {
			continue // this node was removed from the gateway: its anycast addresses are not this node's, so they are not listed
		}
		st := s.AnycastStates(g.GroupID)
		have := map[string]AnycastState{}
		for _, a := range st {
			have[a.Addr] = a
		}
		for _, addr := range g.ExtraVIPs {
			a, ok := have[addr]
			if !ok {
				why := "gateway not running on this node"
				if g.Paused {
					why = "gateway paused"
				}
				a = AnycastState{Addr: addr, Reason: why}
			}
			a.Paused = g.pausedAnycast()[addr]
			// one address may be carried by several gateways: it is shown once, as its best gateway has it (announced, else
			// one that is running and says why not, else one that is not running, else one that is paused)
			r := 1
			switch {
			case a.Up:
				r = 4
			case a.Paused == "" && !g.Paused && ok:
				r = 3
			case a.Paused == "" && !g.Paused:
				r = 2
			}
			if i, dup := at[addr]; dup {
				if r > rank[addr] {
					out[i], rank[addr] = a, r
				} else if a.Paused == "" && out[i].Paused != "" && r == rank[addr] {
					out[i].Paused = ""
				}
				continue
			}
			at[addr], rank[addr] = len(out), r
			out = append(out, a)
		}
	}
	return out
}

// startGroupWhenReadyLocked starts a gateway on this node once this node has an address in the gateway's subnet (the
// wait runs in the background; a reload that pauses, restarts or removes the group cancels it).
func (s *Supervisor) startGroupWhenReadyLocked(gc GroupConfig) {
	if !gc.Paused {
		if ok, why := onGatewaySubnet(gc); !ok {
			w := &offnetWait{why: why}
			s.offnet[gc.GroupID] = w
			warnf("Group %d: %s — not starting here until it is", gc.GroupID, why)
			go s.waitForSubnet(gc.GroupID, w)
			return
		}
	}
	s.startAfterSubnetLocked(gc)
}

// startAfterSubnetLocked is the rest of the start.
func (s *Supervisor) startAfterSubnetLocked(gc GroupConfig) {
	vmacAtStart(gc) // a background check that clients' replies can reach this node; no-op in tests
	s.startGroupLocked(gc)
}

// waitForSubnet holds a gateway back while this node has no address in the
// gateway's subnet, and carries on when it gets one.
// A node on another subnet is still a full cluster member; it just does not
// join an election it cannot hear, nor claim an address it cannot serve.
func (s *Supervisor) waitForSubnet(gid int, w *offnetWait) {
	t := time.NewTicker(offnetEvery)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		if s.offnet[gid] != w || s.ctx.Err() != nil {
			s.mu.Unlock() // cancelled: paused, changed, removed or stopping
			return
		}
		for i := range s.dc.Groups {
			gc := s.dc.Groups[i]
			if gc.GroupID != gid {
				continue
			}
			if ok, _ := onGatewaySubnet(gc); ok {
				delete(s.offnet, gid)
				infof("Group %d: this node is on the gateway's subnet now — starting", gid)
				s.startAfterSubnetLocked(gc)
				s.mu.Unlock()
				return
			}
		}
		s.mu.Unlock()
	}
}

// offnetGroups maps the groups held back for being on the wrong subnet to the reason.
func (s *Supervisor) offnetGroups() map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int]string{}
	for gid, w := range s.offnet {
		out[gid] = w.why
	}
	return out
}

func (s *Supervisor) stopGroupLocked(gid int) []*Engine {
	delete(s.offnet, gid) // a pending wait for the subnet must not start a group that was stopped
	s.stopAnycastLocked(gid)
	var out []*Engine
	for _, af := range []AF{afIPv4, afIPv6} {
		k := engineKey{gid, af}
		if e := s.engines[k]; e != nil {
			delete(s.engines, k)
			out = append(out, e)
		}
	}
	return out
}

func (s *Supervisor) Reload(nu *DaemonConfig) {
	nu = nu.effective()
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	s.mu.Lock()
	cur := s.dc
	s.mu.Unlock()

	if !strings.EqualFold(nu.LogLevel, cur.LogLevel) {
		logLevel.Set(parseLevel(nu.LogLevel))
		infof("Log level → %s", nu.LogLevel)
	}

	s.notePausedAnycast(nu)

	oldGroups := map[int]*GroupConfig{}
	for i := range cur.Groups {
		oldGroups[cur.Groups[i].GroupID] = &cur.Groups[i]
	}
	newGroups := map[int]*GroupConfig{}
	for i := range nu.Groups {
		newGroups[nu.Groups[i].GroupID] = &nu.Groups[i]
	}

	type restartJob struct {
		gc      GroupConfig
		engines []*Engine
	}
	var restarts []restartJob
	var stopped []*Engine
	s.mu.Lock()
	for gid := range oldGroups {
		if _, ok := newGroups[gid]; !ok {
			infof("Group %d removed — stopping engines", gid)
			stopped = append(stopped, s.stopGroupLocked(gid)...)
		}
	}
	gids := make([]int, 0, len(newGroups))
	for gid := range newGroups {
		gids = append(gids, gid)
	}
	sort.Ints(gids)
	for _, gid := range gids {
		gc := newGroups[gid]
		oldGC, existed := oldGroups[gid]
		switch {
		case !existed:
			infof("Group %d added — starting engines", gid)
			s.startGroupWhenReadyLocked(*gc)
		case restartDiffers(oldGC, gc):
			infof("Group %d core config changed — restarting engines", gid)
			// Stop before start (the new engine recreates the same macvlan names), but not while holding s.mu: Stop
			// says goodbye to the group, tears down interfaces and runs commands, and every status request needs
			// s.mu, so a slow or stuck stop used to make the whole node stop answering the cluster.
			restarts = append(restarts, restartJob{*gc, s.stopGroupLocked(gid)})
		default:
			if !sameList(oldGC.ExtraVIPs, gc.ExtraVIPs) {
				// anycast addresses are independent of the election: change them
				// in place, without restarting the gateway
				running := s.anycast[gid] != nil
				for _, af := range []AF{afIPv4, afIPv6} {
					running = running || s.engines[engineKey{gid, af}] != nil
				}
				if running {
					infof("Group %d anycast addresses changed", gid)
					s.stopAnycastLocked(gid)
					s.startAnycastLocked(*gc)
				}
			}
			if liveDiffers(oldGC, gc) {
				infof("Group %d live update", gid)
				for _, af := range []AF{afIPv4, afIPv6} {
					if e := s.engines[engineKey{gid, af}]; e != nil {
						e.UpdateLive(gc)
					}
				}
			}
		}
	}
	s.dc = nu
	s.mu.Unlock()
	device.SetSecretWords(secretWordsOf(nu))

	// Stop outside the lock; Stop tears down interfaces and can be slow.  Gateways that restart are stopped with the
	// removed ones, all at once, and started again when every stop is done.
	for _, r := range restarts {
		stopped = append(stopped, r.engines...)
	}
	var wg sync.WaitGroup
	for _, e := range stopped {
		wg.Add(1)
		go func() { defer wg.Done(); e.Stop() }()
	}
	wg.Wait()
	if len(restarts) > 0 {
		s.mu.Lock()
		for _, r := range restarts {
			s.startGroupWhenReadyLocked(r.gc) // reloadMu is held, so no other Reload has changed the group since
		}
		s.mu.Unlock()
	}
}

func liveDiffers(a, b *GroupConfig) bool {
	return a.Priority != b.Priority || a.LBMethod != b.LBMethod || a.Weight != b.Weight ||
		a.HelloMS != b.HelloMS || a.HoldMS != b.HoldMS || a.Preempt != b.Preempt ||
		a.MaxAFNs != b.MaxAFNs
}

func (s *Supervisor) engineList() []*Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]engineKey, 0, len(s.engines))
	for k := range s.engines {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].group != keys[j].group {
			return keys[i].group < keys[j].group
		}
		return keys[i].af < keys[j].af
	})
	out := make([]*Engine, len(keys))
	for i, k := range keys {
		out[i] = s.engines[k]
	}
	return out
}

// offnetEvery is how often a held-back gateway re-checks the interface's addresses.
var offnetEvery = 5 * time.Second

// ifaceAddrsFn lists an interface's addresses (replaceable in tests).
var ifaceAddrsFn = func(name string) ([]net.Addr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return ifc.Addrs()
}

// onGatewaySubnet reports whether this node can take part in the gateway: for
// each family the gateway has, the node's interface must hold an address inside
// the VIP's subnet (the election runs on that network).  IPv4 is always checked.
// IPv6 is checked only when the interface has a global (non link-local) address
// — a node with only link-local addresses gives nothing to compare, and the
// election itself runs over link-local, so it is let through.  Every family that
// can be checked must match.
func onGatewaySubnet(gc GroupConfig) (bool, string) {
	addrs, err := ifaceAddrsFn(gc.Interface)
	if err != nil {
		return true, "" // no such interface (yet): the engine itself waits for it to appear
	}
	for _, v := range []struct {
		vip string
		v6  bool
	}{{gc.VIP4, false}, {gc.VIP6, true}} {
		if v.vip == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(v.vip)
		if err != nil {
			continue // Validate reports a bad prefix; do not hide it here
		}
		if v.v6 && !hasGlobalV6(addrs) {
			continue
		}
		if !addrsInPrefix(addrs, pfx) {
			return false, fmt.Sprintf("this node has no address in the gateway's subnet %s on %s", pfx.Masked(), gc.Interface)
		}
	}
	return true, ""
}

// hasGlobalV6 reports whether any address is an IPv6 one that is not link-local or loopback.
func hasGlobalV6(addrs []net.Addr) bool {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() != nil {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() && !ip.IsMulticast() {
			return true
		}
	}
	return false
}

func addrsInPrefix(addrs []net.Addr, pfx netip.Prefix) bool {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && pfx.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
