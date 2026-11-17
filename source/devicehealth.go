package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
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

const (
	healthCacheFor     = 10 * time.Second
	healthFetchTimeout = 5 * time.Second
	recheckTimeout     = 40 * time.Second // one device asked again: the dial, then the facts (device.Monitor.Timeout is 4 s, the facts get five times that)
	controllerHold     = 10 * time.Second // a node that was a gateway's controller goes on checking its devices this long after it stops: a flapping election does not move the checks about
	peerListFor        = 3 * time.Second
)

var (
	healthMg   *Mgmt                // set at start; nil in tests that have no cluster
	healthCfg  func() *DaemonConfig // the running configuration (set at start)
	healthRows func() []SnapshotRow // what this node's engines report (set at start)
)

// clusterOn, isPrimaryHere and healthPeers are variables so the tests can stand in for a cluster.
var clusterOn = func() bool { return healthMg != nil && healthMg.cl != nil && healthMg.cl.Enabled() }

// isPrimaryHere: this node is the cluster's primary, or has no cluster.
var isPrimaryHere = func() bool {
	if !clusterOn() {
		return true
	}
	return healthMg.cl.Snapshot().IsPrimary()
}

// deviceOwnerGroup is the gateway whose controller checks the device: the lowest ID among the gateways that have it and are not paused
// on every node.
func deviceOwnerGroup(dc *DaemonConfig, name string) (*GroupConfig, bool) {
	var best *GroupConfig
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if g.PausedAll || !containsStr(g.Devices, name) {
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
var controlHold = struct {
	mu    sync.Mutex
	until map[int]time.Time
}{until: map[int]time.Time{}}

func holdControl(gid int, now time.Time, isController bool) bool {
	controlHold.mu.Lock()
	defer controlHold.mu.Unlock()
	if isController {
		controlHold.until[gid] = now.Add(controllerHold)
		return true
	}
	return now.Before(controlHold.until[gid])
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
func (s *Supervisor) ownedInventory() ([]device.Device, []device.Credential) {
	devs, creds := s.deviceInventory()
	if !clusterOn() || healthCfg == nil || healthRows == nil {
		return devs, creds
	}
	dc, rows, now := healthCfg(), healthRows(), time.Now()
	primary := isPrimaryHere()
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
type peerHealthEntry struct {
	at       time.Time
	okAt     time.Time // the last answer that came
	data     map[string]device.Health
	fetching bool
	tried    bool // a fetch has ended (well or not): later requests do not wait for the next one
	done     chan struct{}
	lookSent time.Time // when a fetch last told the node that someone is looking
}

var (
	peerHealth = struct {
		mu sync.Mutex
		m  map[string]*peerHealthEntry
	}{m: map[string]*peerHealthEntry{}}
	peerListCache struct {
		mu    sync.Mutex
		at    time.Time
		peers []PeerView
	}
	// healthColdWait is how long a request waits for a node it has no answer from yet.  Longer than that the page is answered without it:
	// the devices show "not checked" for a poll, not the whole page for as long as a slow node takes.
	healthColdWait = 2 * time.Second
	// askPeerHealth asks a node for the health it holds (replaceable in tests).
	askPeerHealth = fetchPeerHealth
)

// healthPeers lists the other nodes that answer (kept a few seconds).
var healthPeers = realHealthPeers

func realHealthPeers() []PeerView {
	if !clusterOn() {
		return nil
	}
	peerListCache.mu.Lock()
	defer peerListCache.mu.Unlock()
	if time.Since(peerListCache.at) < peerListFor && peerListCache.peers != nil {
		return peerListCache.peers
	}
	var out []PeerView
	for _, p := range healthMg.cl.View().Peers {
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
	resp, err := healthMg.cl.Relay(ctx, addr, proxyReq{User: "devices", Method: http.MethodGet, Path: path})
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
func peerReport(p PeerView, look bool) (map[string]device.Health, chan struct{}) {
	peerHealth.mu.Lock()
	defer peerHealth.mu.Unlock()
	e := peerHealth.m[p.Addr]
	if e == nil {
		e = &peerHealthEntry{}
		peerHealth.m[p.Addr] = e
	}
	if (time.Since(e.at) >= healthCacheFor || (look && time.Since(e.lookSent) >= healthCacheFor)) && !e.fetching {
		e.fetching = true
		if look {
			e.lookSent = time.Now()
		}
		e.done = make(chan struct{})
		done := e.done
		ask := askPeerHealth
		go func() {
			t0 := time.Now()
			data, ok := ask(p.Addr, look)
			if took := time.Since(t0); took > time.Second {
				warnf("devices: node %s took %s to answer for the device health (answered: %v)", p.Addr, took.Round(100*time.Millisecond), ok)
			}
			peerHealth.mu.Lock()
			defer peerHealth.mu.Unlock()
			e.fetching, e.tried = false, true
			close(done)
			if ok {
				e.data, e.at, e.okAt = data, time.Now(), time.Now()
			} else {
				e.at = time.Now().Add(-(healthCacheFor - 2*time.Second)) // asked again in 2 s, not at once
			}
		}()
	}
	if e.data == nil && !e.tried {
		return nil, e.done
	}
	return e.data, nil
}

// primeReports asks every node for its report, waiting (a little) for the ones that have never answered.
func primeReports() {
	peers := healthPeers()
	var wait []chan struct{}
	for _, p := range peers {
		if _, done := peerReport(p, false); done != nil {
			wait = append(wait, done)
		}
	}
	deadline := time.After(healthColdWait)
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
	stale := devHealth.StaleAfter()
	peerHealth.mu.Lock()
	defer peerHealth.mu.Unlock()
	for _, e := range peerHealth.m {
		if h, ok := e.data[name]; ok && h.Checked > 0 && now.Sub(time.Unix(h.Checked, 0)) <= stale && now.Sub(e.okAt) <= stale {
			return true
		}
	}
	return false
}

var selfName = func() string { h, _ := os.Hostname(); return h }()

// deviceHealth is the health of every device: this node's own for the devices it checks and the other nodes' for the rest (a few
// seconds old).  look says that someone is looking at the devices, so the checks are on the short intervals.
func deviceHealth(look bool) map[string]device.Health {
	if look {
		devHealth.Touch()
	}
	own := devHealth.Snapshot()
	for k, v := range own {
		v.By = selfName
		own[k] = v
	}
	if !clusterOn() {
		return own
	}
	// ask every node that answers, all at once: the ones with no answer yet are waited for together, not one after the other
	peers := healthPeers()
	reports := make([]map[string]device.Health, len(peers))
	var wait []chan struct{}
	for i, p := range peers {
		d, done := peerReport(p, look)
		reports[i] = d
		if done != nil {
			wait = append(wait, done)
		}
	}
	if len(wait) > 0 {
		deadline := time.After(healthColdWait)
	waiting:
		for _, done := range wait {
			select {
			case <-done:
			case <-deadline:
				break waiting
			}
		}
		for i, p := range peers {
			if reports[i] == nil {
				reports[i], _ = peerReport(p, look)
			}
		}
	}
	now := time.Now()
	for i, p := range peers {
		by := p.Hostname
		if by == "" {
			by = p.Addr
		}
		for k, v := range reports[i] {
			if cur, ok := own[k]; !ok || v.Checked > cur.Checked {
				v.By = by
				own[k] = v
			}
		}
	}
	return staleToUnknown(own, now, devHealth.StaleAfter())
}

// staleToUnknown turns a report that is too old to be true into "not checked": its node stopped, or cannot be reached.
func staleToUnknown(m map[string]device.Health, now time.Time, stale time.Duration) map[string]device.Health {
	for k, v := range m {
		if v.Status == "paused" || v.Checked == 0 || now.Sub(time.Unix(v.Checked, 0)) <= stale {
			continue
		}
		m[k] = device.Health{Status: "idle", Detail: "not checked: the node that checks it has not reported for " + now.Sub(time.Unix(v.Checked, 0)).Round(time.Second).String(), Checked: v.Checked, By: v.By}
	}
	return m
}

// lookAtDevices says that someone asked about the devices (an MCP or GUI request): the nodes check on the short intervals.
func lookAtDevices() {
	devHealth.Touch()
	if clusterOn() {
		go deviceHealth(true)
	}
}

// handleDeviceHealth: GET /api/devices/health[?look=1] — the health this node holds of the devices it checks (what the other nodes ask).
func (w *WebServer) handleDeviceHealth(rw http.ResponseWriter, r *http.Request, s *session) {
	if r.URL.Query().Get("look") == "1" {
		devHealth.Touch()
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"health": devHealth.Snapshot()}})
}

// recheckTarget says who asks the device again: this node when it checks the device (or nobody else is known to), else the node whose
// report of it is the newest, else the primary.  "" means this node.
func recheckTarget(name string) string {
	if !clusterOn() {
		return ""
	}
	own := devHealth.Snapshot()[name].Checked
	best, at := "", own
	peerHealth.mu.Lock()
	for addr, e := range peerHealth.m {
		if h, ok := e.data[name]; ok && h.Checked > at {
			best, at = addr, h.Checked
		}
	}
	peerHealth.mu.Unlock()
	if best != "" {
		return best
	}
	if own > 0 {
		return ""
	}
	if healthMg == nil || healthMg.cl == nil {
		return ""
	}
	snap := healthMg.cl.Snapshot()
	if snap.PrimaryAddr == "" || snap.PrimaryAddr == snap.SelfAddr {
		return ""
	}
	return snap.PrimaryAddr
}

// handleDeviceRecheck: POST /api/devices/recheck {"name"} — ask that device again now, whatever its state: its facts are asked at
// once (one that refused a request is otherwise asked again every few minutes, and one nobody looks at every six hours) and the
// answer is its state from then on.  The page's right-click ▸ Network tools ▸ Recheck, after a login or a firewall rule was
// corrected.  The node that checks the device asks it, so another node hands the request to that one.  A read-only account cannot ask (it is
// a POST: authed refuses it); a caller limited to some devices (devscope.go) can ask only for those.
func (w *WebServer) handleDeviceRecheck(rw http.ResponseWriter, r *http.Request, s *session) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4096)).Decode(&in); err != nil || in.Name == "" {
		jsonError(rw, http.StatusBadRequest, "name: the device to ask again")
		return
	}
	devs, creds := w.status.sup.deviceInventory()
	var dev *device.Device
	for _, d := range scopeOf(s).filter(devs) {
		if d.Name == in.Name {
			dev = &d
			break
		}
	}
	if dev == nil {
		jsonError(rw, http.StatusNotFound, "no such device: "+in.Name)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), recheckTimeout)
	defer cancel()
	if addr := recheckTarget(in.Name); addr != "" {
		user := "devices"
		if f := strings.Fields(s.user); len(f) > 0 { // "user via node" when this request was itself relayed: the user is the first word
			user = f[0]
		}
		body, _ := json.Marshal(map[string]string{"name": in.Name})
		resp, err := healthMg.cl.Relay(ctx, addr, proxyReq{User: user, Method: http.MethodPost, Path: "/api/devices/recheck", CT: "application/json", Body: body, RO: w.ro(s)})
		if err != nil {
			jsonError(rw, http.StatusBadGateway, "the node that checks the device could not be asked: "+err.Error())
			return
		}
		peerHealth.mu.Lock()
		if e := peerHealth.m[addr]; e != nil {
			e.at = time.Time{} // the next look at the devices asks that node again, not this node's few-second-old copy
		}
		peerHealth.mu.Unlock()
		ct := resp.CT
		if ct == "" {
			ct = "application/json"
		}
		rw.Header().Set("Content-Type", ct)
		rw.WriteHeader(resp.Status)
		rw.Write(resp.Body)
		return
	}
	var cred device.Credential
	for _, c := range creds {
		if c.Name == dev.Credential {
			cred = c
			break
		}
	}
	devHealth.Touch() // someone is looking: the rounds that follow are the short ones
	h := devHealth.Recheck(ctx, *dev, cred, time.Now())
	h.Facts = nil // the page wants the state and why, not the device's facts
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"name": dev.Name, "health": h}})
}
