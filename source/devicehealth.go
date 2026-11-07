package main

import (
	"context"
	"encoding/json"
	"net/http"
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
)

var (
	healthMg    *Mgmt // set at start; nil in tests that have no cluster
	healthCache struct {
		mu       sync.Mutex
		at       time.Time
		data     map[string]device.Health
		fetching bool
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
	healthCache.mu.Lock()
	fresh := time.Since(healthCache.at) < healthCacheFor
	if fresh || healthCache.fetching {
		d := healthCache.data
		healthCache.mu.Unlock()
		if d == nil {
			d = map[string]device.Health{}
		}
		return d
	}
	healthCache.fetching = true
	healthCache.mu.Unlock()

	data, ok := fetchPrimaryHealth(look)
	healthCache.mu.Lock()
	defer healthCache.mu.Unlock()
	healthCache.fetching = false
	if ok {
		healthCache.data, healthCache.at = data, time.Now()
	} else if healthCache.data == nil {
		healthCache.data = map[string]device.Health{}
		healthCache.at = time.Now().Add(healthCacheFor - 2*time.Second) // ask again in a couple of seconds, not at once
	}
	return healthCache.data
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
