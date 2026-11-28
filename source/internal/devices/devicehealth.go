package devices

import (
	"os"
	"time"

	"netdir/device"
	"netdir/internal/core"
)

const RecheckTimeout = 40 * time.Second

var selfName = func() string { h, _ := os.Hostname(); return h }()

// deviceHealth is the health of every device: this node's own for the devices it checks and the other nodes' for the rest (a few
// seconds old).  look says that someone is looking at the devices, so the checks are on the short intervals.
func DeviceHealth(look bool) map[string]device.Health {
	if look {
		core.DevHealth.Touch()
	}
	own := core.DevHealth.Snapshot()
	for k, v := range own {
		v.By = selfName
		own[k] = v
	}
	if !core.ClusterOn() {
		return own
	}
	// ask every node that answers, all at once: the ones with no answer yet are waited for together, not one after the other
	peers := core.HealthPeers()
	reports := make([]map[string]device.Health, len(peers))
	var wait []chan struct{}
	for i, p := range peers {
		d, done := core.PeerReport(p, look)
		reports[i] = d
		if done != nil {
			wait = append(wait, done)
		}
	}
	if len(wait) > 0 {
		deadline := time.After(core.HealthColdWait)
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
				reports[i], _ = core.PeerReport(p, look)
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
	return staleToUnknown(own, now, core.DevHealth.StaleAfter())
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
var LookAtDevices = realLookAtDevices

func realLookAtDevices() {
	core.DevHealth.Touch()
	if core.ClusterOn() {
		go DeviceHealth(true)
	}
}

// recheckTarget says who asks the device again: this node when it checks the device (or nobody else is known to), else the node whose
// report of it is the newest, else the primary.  "" means this node.
func RecheckTarget(name string) string {
	if !core.ClusterOn() {
		return ""
	}
	if best := CheckerOf(name); best != "" {
		return best
	}
	if core.DevHealth.Snapshot()[name].Checked > 0 {
		return ""
	}
	if core.HealthCl == nil {
		return ""
	}
	snap := core.HealthCl.Snapshot()
	if snap.PrimaryAddr == "" || snap.PrimaryAddr == snap.SelfAddr {
		return ""
	}
	return snap.PrimaryAddr
}

// checkerOf is the other node that checks a device: the one whose report of it is the newest, and newer than this node's own.  "" when
// this node checks it, or when no other node has reported it lately (then this node asks the device itself).  A device request goes to
// that node, so it is made from the site the device belongs to.
func CheckerOf(name string) string {
	if !core.ClusterOn() {
		return ""
	}
	own := core.DevHealth.Snapshot()[name].Checked
	best, at := "", own
	stale := core.DevHealth.StaleAfter().Seconds()
	now := time.Now().Unix()
	core.PeerHealth.Mu.Lock()
	for addr, e := range core.PeerHealth.M {
		if h, ok := e.Data[name]; ok && h.Checked > at && float64(now-h.Checked) <= stale {
			best, at = addr, h.Checked
		}
	}
	core.PeerHealth.Mu.Unlock()
	return best
}
