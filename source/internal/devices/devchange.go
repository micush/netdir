package devices

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"netdir/device"
)

// Changing the managed devices (device/change.go has the framework and the drivers).  One route, one socket op:
//
//	POST /api/devices/change   {"target": "sw1", "text": "change the description for ports gi1/0/1-24 to read \"devices\"", "dry_run": true}
//	netdir --device-change "…" --target sw1 [--dry-run] [--yes]
//	MCP device_change          (a caller with rw access only)
//
// Who may do it is who may do anything: a session that is read-only (a GUI account in the read-only group, an LDAP or SSO
// account the read-only setting covers, an MCP key or ACL entry with access ro) is refused by the same gate as every other write
// (authed, mcp.go), and the CLI is root on the socket.  There is no separate switch for devices: an ACL entry or key with rw
// is rw to the devices as well.
//
// The change is either English (text, parsed by the fixed grammar in device.ParseChange) or typed (action, ports, value);
// both end as the same device.Change, and nothing else is ever sent to a device.  Each device is changed on its own: one
// that fails (and is put back as it was) does not stop the others.

type DeviceChangeArgs struct {
	Target string `json:"target"`
	Text   string `json:"text"`   // plain English
	Action string `json:"action"` // or typed: description, clear_description, shutdown, no_shutdown, clear_counters
	Ports  string `json:"ports"`  // with ports as the grammar writes them: "gi1/0/1-24, te1/1/1"
	Value  string `json:"value"`  // and the description
	DryRun bool   `json:"dry_run"`
	Save   bool   `json:"save"` // keep the change over a reboot, where the platform has a save (IOS-XE, EOS, Aruba CX); the others keep it on their own
}

// change is the typed change the arguments mean.
func (a DeviceChangeArgs) Change() (device.Change, error) {
	if strings.TrimSpace(a.Text) != "" {
		if a.Action != "" || a.Ports != "" || a.Value != "" {
			return device.Change{}, errors.New("give the change either as text or as action, ports and value, not both")
		}
		return device.ParseChange(a.Text)
	}
	if a.Action == "" {
		return device.Change{}, errors.New("say what to change: text (e.g. change the description for ports gi1/0/1-24 to read \"devices\") or action, ports and value")
	}
	if a.Action == device.ActClearCounters && (strings.TrimSpace(a.Ports) == "" || strings.EqualFold(strings.TrimSpace(a.Ports), device.AllPorts)) {
		c := device.AllPortsChange()
		if a.Value != "" {
			return device.Change{}, errors.New("clear_counters takes no value")
		}
		return c, c.Validate()
	}
	ps, err := device.ParsePorts(a.Ports)
	if err != nil {
		return device.Change{}, err
	}
	c := device.Change{Action: a.Action, Ports: ps, Value: a.Value}
	return c, c.Validate()
}

func DescribeChange(c device.Change) string {
	switch c.Action {
	case device.ActDescription:
		return fmt.Sprintf("set the description of %d ports to %q", len(c.Ports), c.Value)
	case device.ActClearDescription:
		return fmt.Sprintf("clear the description of %d ports", len(c.Ports))
	case device.ActShutdown:
		return fmt.Sprintf("shut down %d ports", len(c.Ports))
	case device.ActClearCounters:
		if c.All() {
			return "clear the counters of all ports"
		}
		return fmt.Sprintf("clear the counters of %d ports", len(c.Ports))
	}
	return fmt.Sprintf("bring up %d ports", len(c.Ports))
}

// saveAfter keeps a change that was made over a reboot, when save was asked for.  A save that fails is the result's error text and the
// change stays made (it is in the running configuration); a platform with no save keeps changes on its own and says so.
func SaveAfter(ctx context.Context, d device.Driver, c device.Change, r device.ChangeResult) device.ChangeResult {
	if c.Action == device.ActClearCounters {
		r.Note = "counters are not configuration: there is nothing to save"
		return r
	}
	if len(r.Changes) == 0 && !r.Applied {
		return r
	}
	s, ok := d.(device.ConfigSaver)
	if !ok {
		r.Note = "this platform keeps a change on its own (there is no separate save)"
		return r
	}
	if err := s.SaveConfig(ctx); err != nil {
		r.Note = "the change is made in the running configuration but the save failed: " + err.Error()
		return r
	}
	r.Saved = true
	return r
}
