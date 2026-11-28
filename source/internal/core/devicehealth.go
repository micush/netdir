package core

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"netdir/device"
)

// Who looks at the devices.  Each device is checked by one node: the controller of the gateway it is on.  A device on several
// gateways belongs to the one with the lowest ID that is not paused on every node, and a dual-stack gateway's IPv4 controller stands
// for it (its IPv6 controller when there is no IPv4 address).  So the checks stay with the nodes that serve the gateway, and what is
// red is what those nodes cannot reach, not what the primary cannot.  A node that is not in a cluster checks everything itself.
//
// Every node can read every device's health: it asks the other nodes for theirs over the cluster channel (GET /api/devices/health,
// relayed like the node picker) and keeps each answer for a few seconds.  Each device is reported by one node, and the newest report
// wins, so a device that changes controller shows the new one's as soon as it has checked.  A report that is too old to be true (its
// node stopped, or the cluster cannot reach it) is not shown as a colour: the device reads "not checked".
//
// What no controller claims is checked by the primary: a device whose gateway has no controller, or that no other node has reported
// for a while.  A look at the devices on any node (the GUI's Devices or Topology page, a device request over MCP) tells the nodes to
// check more often (?look=1: Monitor.Touch).

const healthCacheFor = 10 * time.Second

const healthFetchTimeout = 5 * time.Second

const controllerHold = 10 * time.Second

const peerListFor = 3 * time.Second

var (
	HealthCl   HealthCluster        // the node's cluster, set at start; nil in tests that have no cluster
	HealthCfg  func() *DaemonConfig // the running configuration (set at start)
	HealthRows func() []SnapshotRow // what this node's engines report (set at start)
)

// HealthCluster is what the device checks need from the node's cluster (a *cluster.Cluster): this package sits below the cluster, so the
// cluster is handed to it at start.
type HealthCluster interface {
	Enabled() bool
	Snapshot() ClusterSnapshot
	PeerList() []PeerView
	Relay(ctx context.Context, addr string, req ProxyReq) (*ProxyResp, error)
	NodeSecret() []byte // the cluster secret; nil before the node has one
}

// clusterOn, isPrimaryHere and healthPeers are variables so the tests can stand in for a cluster.
var ClusterOn = func() bool { return HealthCl != nil && HealthCl.Enabled() }

// isPrimaryHere: this node is the cluster's primary, or has no cluster.
var IsPrimaryHere = func() bool {
	if !ClusterOn() {
		return true
	}
	return HealthCl.Snapshot().IsPrimary()
}

// deviceOwnerGroup is the gateway whose controller checks the device: the lowest ID among the gateways that have it and are not paused
// on every node.
func deviceOwnerGroup(dc *DaemonConfig, name string) (*GroupConfig, bool) {
	var best *GroupConfig
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if g.PausedAll || !ContainsStr(g.Devices, name) {
			continue
		}
		if best == nil || g.GroupID < best.GroupID {
			best = g
		}
	}
	return best, best != nil
}

// controllerHere says whether this node is the controller of the gateway's IPv4 side (its IPv6 side when it has no IPv4 address).
func controllerHere(rows []SnapshotRow, g *GroupConfig) bool {
	af := "v4"
	if g.VIP4 == "" {
		af = "v6"
	}
	for _, r := range rows {
		if r.GroupID == g.GroupID && r.AF == af && r.Local && r.AGCIP != "" && r.AGCIP == r.PeerIP {
			return true
		}
	}
	return false
}

// controlHold keeps, for each gateway, until when this node counts as its controller: it is pushed on while the node is one.
var ControlHold = struct {
	Mu    sync.Mutex        `json:"-"`
	Until map[int]time.Time `json:"-"`
}{Until: map[int]time.Time{}}

func holdControl(gid int, now time.Time, isController bool) bool {
	ControlHold.Mu.Lock()
	defer ControlHold.Mu.Unlock()
	if isController {
		ControlHold.Until[gid] = now.Add(controllerHold)
		return true
	}
	return now.Before(ControlHold.Until[gid])
}

// deviceOwnedHere: this node checks the device because it controls the gateway the device belongs to.
func deviceOwnedHere(dc *DaemonConfig, rows []SnapshotRow, name string, now time.Time) bool {
	g, ok := deviceOwnerGroup(dc, name)
	if !ok {
		return false
	}
	return holdControl(g.GroupID, now, controllerHere(rows, g))
}

// ownedInventory is the inventory this node checks: without a cluster all of it; in one, the devices of the gateways it controls and,
// on the primary, the ones nobody else is reporting.
func (s *Supervisor) OwnedInventory() ([]device.Device, []device.Credential) {
	devs, creds := s.DeviceInventory()
	if !ClusterOn() || HealthCfg == nil || HealthRows == nil {
		return devs, creds
	}
	dc, rows, now := HealthCfg(), HealthRows(), time.Now()
	primary := IsPrimaryHere()
	if primary {
		primeReports() // the primary checks what nobody else reports, so it must know what they report
	}
	out := devs[:0:0]
	for _, d := range devs {
		if deviceOwnedHere(dc, rows, d.Name, now) || (primary && !reportedElsewhere(d.Name, now)) {
			out = append(out, d)
		}
	}
	return out, creds
}

// ── reading the other nodes' health ─────────────────────────────────────────

// peerHealthEntry is the health one node last reported, kept so a poll asks no node that was asked a moment ago and a slow node never
// holds a page up: a stale answer is used while a new one is fetched in the background.
type PeerHealthEntry struct {
	At       time.Time                `json:"-"`
	okAt     time.Time                // the last answer that came
	Data     map[string]device.Health `json:"-"`
	fetching bool
	tried    bool // a fetch has ended (well or not): later requests do not wait for the next one
	done     chan struct{}
	lookSent time.Time // when a fetch last told the node that someone is looking
}

var (
	PeerHealth = struct {
		Mu sync.Mutex                  `json:"-"`
		M  map[string]*PeerHealthEntry `json:"-"`
	}{M: map[string]*PeerHealthEntry{}}
	peerListCache struct {
		mu    sync.Mutex
		at    time.Time
		peers []PeerView
	}
	// healthColdWait is how long a request waits for a node it has no answer from yet.  Longer than that the page is answered without it:
	// the devices show "not checked" for a poll, not the whole page for as long as a slow node takes.
	HealthColdWait = 2 * time.Second
	// askPeerHealth asks a node for the health it holds (replaceable in tests).
	AskPeerHealth = fetchPeerHealth
)

// healthPeers lists the other nodes that answer (kept a few seconds).
var HealthPeers = realHealthPeers

func realHealthPeers() []PeerView {
	if !ClusterOn() {
		return nil
	}
	peerListCache.mu.Lock()
	defer peerListCache.mu.Unlock()
	if time.Since(peerListCache.at) < peerListFor && peerListCache.peers != nil {
		return peerListCache.peers
	}
	var out []PeerView
	for _, p := range HealthCl.PeerList() {
		if !p.Self && p.Reachable {
			out = append(out, p)
		}
	}
	peerListCache.peers, peerListCache.at = out, time.Now()
	if out == nil {
		peerListCache.peers = []PeerView{}
	}
	return peerListCache.peers
}

func fetchPeerHealth(addr string, look bool) (map[string]device.Health, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), healthFetchTimeout)
	defer cancel()
	path := "/api/devices/health"
	if look {
		path += "?look=1"
	}
	resp, err := HealthCl.Relay(ctx, addr, ProxyReq{User: "devices", Method: http.MethodGet, Path: path})
	if err != nil || resp.Status != http.StatusOK {
		return nil, false
	}
	var out struct {
		Data struct {
			Health map[string]device.Health `json:"health"`
		} `json:"data"`
	}
	if json.Unmarshal(resp.Body, &out) != nil {
		return nil, false
	}
	if out.Data.Health == nil {
		out.Data.Health = map[string]device.Health{}
	}
	return out.Data.Health, true
}

// peerReport is what a node last reported, and the channel that closes when a fetch in flight ends (nil when there is none and
// something is there to use).  A new fetch starts when the answer is older than healthCacheFor.
func PeerReport(p PeerView, look bool) (map[string]device.Health, chan struct{}) {
	PeerHealth.Mu.Lock()
	defer PeerHealth.Mu.Unlock()
	e := PeerHealth.M[p.Addr]
	if e == nil {
		e = &PeerHealthEntry{}
		PeerHealth.M[p.Addr] = e
	}
	if (time.Since(e.At) >= healthCacheFor || (look && time.Since(e.lookSent) >= healthCacheFor)) && !e.fetching {
		e.fetching = true
		if look {
			e.lookSent = time.Now()
		}
		e.done = make(chan struct{})
		done := e.done
		ask := AskPeerHealth
		go func() {
			t0 := time.Now()
			data, ok := ask(p.Addr, look)
			if took := time.Since(t0); took > time.Second {
				Warnf("devices: node %s took %s to answer for the device health (answered: %v)", p.Addr, took.Round(100*time.Millisecond), ok)
			}
			PeerHealth.Mu.Lock()
			defer PeerHealth.Mu.Unlock()
			e.fetching, e.tried = false, true
			close(done)
			if ok {
				e.Data, e.At, e.okAt = data, time.Now(), time.Now()
			} else {
				e.At = time.Now().Add(-(healthCacheFor - 2*time.Second)) // asked again in 2 s, not at once
			}
		}()
	}
	if e.Data == nil && !e.tried {
		return nil, e.done
	}
	return e.Data, nil
}

// primeReports asks every node for its report, waiting (a little) for the ones that have never answered.
func primeReports() {
	peers := HealthPeers()
	var wait []chan struct{}
	for _, p := range peers {
		if _, done := PeerReport(p, false); done != nil {
			wait = append(wait, done)
		}
	}
	deadline := time.After(HealthColdWait)
	for _, done := range wait {
		select {
		case <-done:
		case <-deadline:
			return
		}
	}
}

// reportedElsewhere: another node has reported the device lately (the primary then leaves it alone).
func reportedElsewhere(name string, now time.Time) bool {
	stale := DevHealth.StaleAfter()
	PeerHealth.Mu.Lock()
	defer PeerHealth.Mu.Unlock()
	for _, e := range PeerHealth.M {
		if h, ok := e.Data[name]; ok && h.Checked > 0 && now.Sub(time.Unix(h.Checked, 0)) <= stale && now.Sub(e.okAt) <= stale {
			return true
		}
	}
	return false
}
