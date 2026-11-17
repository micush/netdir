package main

import (
	"context"
	"encoding/json"
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

type deviceChangeArgs struct {
	Target string `json:"target"`
	Text   string `json:"text"`   // plain English
	Action string `json:"action"` // or typed: description, clear_description, shutdown, no_shutdown, clear_counters
	Ports  string `json:"ports"`  // with ports as the grammar writes them: "gi1/0/1-24, te1/1/1"
	Value  string `json:"value"`  // and the description
	DryRun bool   `json:"dry_run"`
	Save   bool   `json:"save"` // keep the change over a reboot, where the platform has a save (IOS-XE, EOS, Aruba CX); the others keep it on their own
}

// change is the typed change the arguments mean.
func (a deviceChangeArgs) change() (device.Change, error) {
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

func describeChange(c device.Change) string {
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

// deviceChange plans or makes the change on the devices the target picks.
func (m *Mgmt) deviceChange(raw json.RawMessage, actor string) (any, error) {
	return m.withBelow("device_change", raw, actor, m.deviceChangeHere)
}

// deviceChangeHere is deviceChange for this director's own devices.
func (m *Mgmt) deviceChangeHere(raw json.RawMessage, actor string) (any, error) {
	var a deviceChangeArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	c, err := a.change()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Target) == "" {
		return nil, errors.New(`target: the devices to change: a name, tag:TAG, platform:PLATFORM, gateway:N or "all", separated by commas`)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	devs, creds := dc.effectiveDevices(), dc.Settings.DeviceCredentials
	if len(devs) == 0 {
		return nil, errors.New("no devices are configured (settings.devices)")
	}
	target, err := expandGatewayTargetsIn(dc, a.Target)
	if err != nil {
		return nil, err
	}
	picked, err := device.Select(devs, target)
	if err != nil {
		return nil, err
	}
	for _, d := range picked {
		if d.Disabled {
			return nil, fmt.Errorf("device %s %s", d.Name, offWhy(d))
		}
	}
	verb := "changes"
	if a.DryRun {
		verb = "plans a change of"
	}
	warnf("devices: %q %s %s (%d devices): %s", actor, verb, a.Target, len(picked), describeChange(c))
	res := device.Fanout(context.Background(), picked, creds, deviceParallel, deviceConfigTO, func(ctx context.Context, d device.Driver) (any, error) {
		ch, ok := d.(device.Changer)
		if !ok {
			return nil, errors.New("typed port changes are for Catalyst IOS-XE, Arista EOS, Aruba CX, a Meraki switch (a device with the option serial), Junos, NX-OS, FortiOS and F5 BIG-IP (PAN-OS: counters only); other platforms and other changes: device_change_raw (--device-raw)")
		}
		r, err := ch.Change(ctx, c, a.DryRun)
		if err == nil && a.Save && !a.DryRun {
			r = saveAfter(ctx, d, c, r)
		}
		return r, err
	})
	failed := 0
	for _, x := range res {
		if !x.OK {
			failed++
			warnf("devices: %q change of %s failed: %s", actor, x.Device, x.Error)
			continue
		}
		if cr, ok := x.Data.(device.ChangeResult); ok && !a.DryRun {
			warnf("devices: %q changed %s: %d changed, %d already as asked", actor, x.Device, len(cr.Changes), len(cr.Unchanged))
			for i, pc := range cr.Changes { // the audit trail: what each port held before and after
				if i >= 100 {
					warnf("devices: audit %s: … and %d more", x.Device, len(cr.Changes)-i)
					break
				}
				warnf("devices: audit %s %s %s: %q -> %q (by %q)", x.Device, pc.Port, pc.Field, pc.Before, pc.After, actor)
			}
		}
	}
	return map[string]any{"op": "change", "dry_run": a.DryRun, "change": c, "asked": len(res), "failed": failed, "results": res}, nil
}

// saveAfter keeps a change that was made over a reboot, when save was asked for.  A save that fails is the result's error text and the
// change stays made (it is in the running configuration); a platform with no save keeps changes on its own and says so.
func saveAfter(ctx context.Context, d device.Driver, c device.Change, r device.ChangeResult) device.ChangeResult {
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

// mcpDeviceChangeTool is the MCP tool that changes devices; it is a write tool, so only a caller with rw access sees it or may call it.
func mcpDeviceChangeTool() mcpTool {
	return mcpTool{name: "device_change", title: "Change device ports", noNode: true, write: true, destructive: true, idempotent: true,
		desc: "Change ports on switches and firewalls (Cisco IOS-XE, Cisco NX-OS, Arista EOS, Aruba AOS-CX, Meraki switches, Juniper Junos, Fortinet FortiOS and F5 BIG-IP): set or clear the description, or shut them down or bring them up, on a range of ports of every device the target picks (Junos ports are written ge-0/0/1, FortiOS port1 or dmz, BIG-IP 1.1). " +
			"Clearing interface counters (clear_counters) works on Cisco IOS-XE and Arista EOS (named ports, or all), and on Juniper Junos and Palo Alto PAN-OS (all ports only); other platforms answer that they cannot. save: true also saves the configuration where the platform has a save (IOS-XE, NX-OS, EOS, Aruba CX, BIG-IP); Junos, FortiOS and Meraki keep a change on their own. A clear is not read back and cannot be undone. " +
			"Give the change as plain English in text, e.g. change the description for ports gi1/0/1-24 to read \"devices\"; clear the description on gi1/0/1-24; shut down gi1/0/5; shut port 1/1/1 down; no shutdown et1-4; clear all port counters; clear counters on gi1/0/1-4; bring up ports 1/1/1-1/1/48 (Aruba CX ports have no type). " +
			"Or give action (description, clear_description, shutdown, no_shutdown, clear_counters), ports (gi1/0/1-24, te1/1/1; et1-48 on Arista; 1/1/1-1/1/48 on Aruba CX; for clear_counters leave it out or say all for every port) and, for a description, value. " +
			"Plan it first with dry_run: true, which changes nothing and says what each port holds now and would hold. A real change is read back, and put back as it was if the device refuses it or does not hold it. " +
			"A port that does not exist on a device cancels the change on that device. A port that holds the address the gateway reaches the device on is never shut down. Each device is changed on its own.",
		props: []mcpProp{
			{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N or \"all\", several separated by commas (list_devices)."},
			{name: "text", typ: "string", desc: "The change in plain English. Use this or action, ports and value."},
			{name: "action", typ: "string", enum: []string{"description", "clear_description", "shutdown", "no_shutdown", "clear_counters"}, desc: "What to do (typed form)."},
			{name: "ports", typ: "string", desc: "The ports (typed form): gi1/0/1-24, te1/1/1, et1-48, po1; several separated by commas."},
			{name: "value", typ: "string", desc: "The description to set (typed form), one line of up to 200 characters."},
			{name: "dry_run", typ: "boolean", desc: "Only plan: say what would change, change nothing."},
			{name: "save", typ: "boolean", desc: "Also save the configuration so the change survives a reboot (IOS-XE, NX-OS, EOS, Aruba CX and BIG-IP; Junos, FortiOS and Meraki keep changes on their own). A change that was refused or put back is not saved."},
		},
		run: func(c *mcpCtx) (any, error) {
			dry, _ := c.flag("dry_run")
			save, _ := c.flag("save")
			body := map[string]any{"target": c.str("target"), "text": c.str("text"), "action": c.str("action"), "ports": c.str("ports"), "value": c.str("value"), "dry_run": dry, "save": save}
			b, err := c.call("POST", "/api/devices/change", body, "")
			return asAny(b), err
		}}
}
