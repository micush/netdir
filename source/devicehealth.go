package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"netdir/device"
)

// Who looks at the devices.  In a cluster only the primary does (device.Monitor's Active): a device is connected to every few
// minutes by one node, not by every node, so 16 nodes do not mean 16 times the load.  The other nodes ask the primary for the
// health over the cluster channel (GET /api/devices/health, relayed like the node picker) and keep the answer for a few seconds.
// A look at the devices on any node (the GUI's Devices or Topology page, a device request over MCP) tells the primary to look
// more often (?look=1: Monitor.Touch).  A node that is not in a cluster is its own primary.

const (
	healthCacheFor     = 10 * time.Second
	healthFetchTimeout = 5 * time.Second
	healthInactiveWait = 15 * time.Second // how often a node that is not the primary asks itself whether it has become it
	recheckTimeout     = 40 * time.Second // one device asked again: the dial, then the facts (device.Monitor.Timeout is 4 s, the facts get five times that)
)

var (
	healthMg    *Mgmt // set at start; nil in tests that have no cluster
	healthCache struct {
		mu       sync.Mutex
		at       time.Time
		data     map[string]device.Health
		fetching bool
		done     chan struct{} // closed when the fetch in flight ends
	}
)

// checksHere reports whether this node does the device checks: the primary, or a node that is not in a cluster.
func checksHere() bool {
	if healthMg == nil || healthMg.cl == nil || !healthMg.cl.Enabled() {
		return true
	}
	return healthMg.cl.Snapshot().IsPrimary()
}

// deviceHealth is the health of every device: this node's own when it does the checks, else the primary's (a few seconds old).
// look says that someone is looking at the devices, so the checks are on the short intervals.
func deviceHealth(look bool) map[string]device.Health {
	if checksHere() {
		if look {
			devHealth.Touch()
		}
		return devHealth.Snapshot()
	}
	return replicaHealth(look, fetchPrimaryHealth)
}

// healthColdWait is how long a request waits for the primary's answer when this node has none at all yet.  Longer than that the page
// is answered without it: the devices show "not checked" for a poll, not the whole page for as long as a slow primary takes.
var healthColdWait = 2 * time.Second

// replicaHealth is the primary's health as this node last heard it; fetch asks the primary.  An answer older than healthCacheFor is
// used at once while a new one is fetched in the background; with no answer yet, the request waits for the fetch, up to healthColdWait.
func replicaHealth(look bool, fetch func(bool) (map[string]device.Health, bool)) map[string]device.Health {
	healthCache.mu.Lock()
	d := healthCache.data
	if time.Since(healthCache.at) >= healthCacheFor && !healthCache.fetching {
		healthCache.fetching = true
		healthCache.done = make(chan struct{})
		done := healthCache.done
		go func() {
			t0 := time.Now()
			data, ok := fetch(look)
			if took := time.Since(t0); took > time.Second {
				warnf("devices: the primary took %s to answer for the device health (answered: %v)", took.Round(100*time.Millisecond), ok)
			}
			healthCache.mu.Lock()
			defer healthCache.mu.Unlock()
			healthCache.fetching = false
			close(done)
			if ok {
				healthCache.data, healthCache.at = data, time.Now()
			} else if healthCache.data == nil {
				healthCache.data = map[string]device.Health{}
				healthCache.at = time.Now().Add(-(healthCacheFor - 2*time.Second)) // counts as 8 s old: asked again in 2 s, not at once (it was set that far into the future: 18 s of nothing)
			}
		}()
	}
	done := healthCache.done
	healthCache.mu.Unlock()
	if d == nil {
		select {
		case <-done:
		case <-time.After(healthColdWait):
		}
		healthCache.mu.Lock()
		d = healthCache.data
		healthCache.mu.Unlock()
	}
	if d == nil {
		d = map[string]device.Health{}
	}
	return d
}

func fetchPrimaryHealth(look bool) (map[string]device.Health, bool) {
	snap := healthMg.cl.Snapshot()
	if snap.PrimaryAddr == "" || snap.PrimaryAddr == snap.SelfAddr {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthFetchTimeout)
	defer cancel()
	path := "/api/devices/health"
	if look {
		path += "?look=1"
	}
	resp, err := healthMg.cl.Relay(ctx, snap.PrimaryAddr, proxyReq{User: "devices", Method: http.MethodGet, Path: path})
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

// lookAtDevices says that someone asked about the devices (an MCP or GUI request): the primary checks on the short intervals.
func lookAtDevices() {
	if checksHere() {
		devHealth.Touch()
		return
	}
	go deviceHealth(true)
}

// handleDeviceHealth: GET /api/devices/health[?look=1] — this node's own health of the devices (what the other nodes ask the primary).
func (w *WebServer) handleDeviceHealth(rw http.ResponseWriter, r *http.Request, s *session) {
	if r.URL.Query().Get("look") == "1" {
		devHealth.Touch()
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"health": devHealth.Snapshot(), "checks_here": checksHere()}})
}

// handleDeviceRecheck: POST /api/devices/recheck {"name"} — ask that device again now, whatever its state: its facts are asked at
// once (one that refused a request is otherwise asked again every few minutes, and one nobody looks at every six hours) and the
// answer is its state from then on.  The page's right-click ▸ Network tools ▸ Recheck, after a login or a firewall rule was
// corrected.  Only the primary does the checks, so another node hands the request to it.  A read-only account cannot ask (it is
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
	if !checksHere() {
		snap := healthMg.cl.Snapshot()
		if snap.PrimaryAddr == "" || snap.PrimaryAddr == snap.SelfAddr {
			jsonError(rw, http.StatusServiceUnavailable, "the cluster has no primary to ask the device just now")
			return
		}
		user := "devices"
		if f := strings.Fields(s.user); len(f) > 0 { // "user via node" when this request was itself relayed: the user is the first word
			user = f[0]
		}
		body, _ := json.Marshal(map[string]string{"name": in.Name})
		resp, err := healthMg.cl.Relay(ctx, snap.PrimaryAddr, proxyReq{User: user, Method: http.MethodPost, Path: "/api/devices/recheck", CT: "application/json", Body: body, RO: w.ro(s)})
		if err != nil {
			jsonError(rw, http.StatusBadGateway, "the primary could not be asked: "+err.Error())
			return
		}
		healthCache.mu.Lock()
		healthCache.at = time.Time{} // the next look at the devices asks the primary again, not this node's few-second-old copy
		healthCache.mu.Unlock()
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
