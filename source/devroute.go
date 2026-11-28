package main

import (
	"encoding/json"
	"strings"

	"netdir/internal/core"
	"netdir/internal/devices"
)

// Changes, raw changes and captures are made by the node that checks the device, like the reads (devices.go): the devices of another
// site are handed to a node of that site, which makes the change there, and the answers are put together.  Unlike a read, a device
// whose node does not answer is NOT done from here: a change that may or may not have been made is never made a second time.

// viaCheckers wraps one of this node's own device writes (op: change, raw or capture).
func (m *Mgmt) viaCheckers(op string, here func(json.RawMessage, string) (any, error)) func(json.RawMessage, string) (any, error) {
	return func(raw json.RawMessage, actor string) (any, error) {
		if !core.ClusterOn() || strings.Contains(actor, " via ") { // not in a cluster, or already handed over by another node
			return here(raw, actor)
		}
		dc, _, err := m.LiveConfig()
		if err != nil {
			return here(raw, actor)
		}
		return devices.RouteByChecker(dc, op, raw, actor, here)
	}
}
