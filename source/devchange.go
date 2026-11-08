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
	Action string `json:"action"` // or typed: description, clear_description, shutdown, no_shutdown
	Ports  string `json:"ports"`  // with ports as the grammar writes them: "gi1/0/1-24, te1/1/1"
	Value  string `json:"value"`  // and the description
	DryRun bool   `json:"dry_run"`
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
	}
	return fmt.Sprintf("bring up %d ports", len(c.Ports))
}

// deviceChange plans or makes the change on the devices the target picks.
func (m *Mgmt) deviceChange(raw json.RawMessage, actor string) (any, error) {
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
	devs, creds := dc.Settings.Devices, dc.Settings.DeviceCredentials
	if len(devs) == 0 {
		return nil, errors.New("no devices are configured (settings.devices)")
	}
	target, err := expandGatewayTargetsIn(dc, a.Target)
	if err != nil {
		return nil, err
	}
	if err := refuseRemote(target); err != nil {
		return nil, err
	}
	picked, err := device.Select(devs, target)
	if err != nil {
		return nil, err
	}
	for _, d := range picked {
		if d.Disabled {
			return nil, fmt.Errorf("device %s is disabled: enable it first (Configure ▸ Devices)", d.Name)
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
			return nil, errors.New("typed port changes are for Catalyst IOS-XE, Arista EOS, Aruba CX and a Meraki switch (a device with the option serial); other platforms and other changes: device_change_raw (--device-raw)")
		}
		r, err := ch.Change(ctx, c, a.DryRun)
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

// mcpDeviceChangeTool is the MCP tool that changes devices; it is a write tool, so only a caller with rw access sees it or may call it.
func mcpDeviceChangeTool() mcpTool {
	return mcpTool{name: "device_change", title: "Change device ports", noNode: true, write: true, destructive: true, idempotent: true,
		desc: "Change ports on switches (Cisco IOS-XE, Arista EOS and Aruba AOS-CX): set or clear the description, or shut them down or bring them up, on a range of ports of every device the target picks. " +
			"Give the change as plain English in text, e.g. change the description for ports gi1/0/1-24 to read \"devices\"; clear the description on gi1/0/1-24; shut down gi1/0/5; shut port 1/1/1 down; no shutdown et1-4; bring up ports 1/1/1-1/1/48 (Aruba CX ports have no type). " +
			"Or give action (description, clear_description, shutdown, no_shutdown), ports (gi1/0/1-24, te1/1/1; et1-48 on Arista; 1/1/1-1/1/48 on Aruba CX) and, for a description, value. " +
			"Plan it first with dry_run: true, which changes nothing and says what each port holds now and would hold. A real change is read back, and put back as it was if the device refuses it or does not hold it. " +
			"A port that does not exist on a device cancels the change on that device. A port that holds the address the gateway reaches the device on is never shut down. Each device is changed on its own.",
		props: []mcpProp{
			{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N or \"all\", several separated by commas (list_devices)."},
			{name: "text", typ: "string", desc: "The change in plain English. Use this or action, ports and value."},
			{name: "action", typ: "string", enum: []string{"description", "clear_description", "shutdown", "no_shutdown"}, desc: "What to do (typed form)."},
			{name: "ports", typ: "string", desc: "The ports (typed form): gi1/0/1-24, te1/1/1, et1-48, po1; several separated by commas."},
			{name: "value", typ: "string", desc: "The description to set (typed form), one line of up to 200 characters."},
			{name: "dry_run", typ: "boolean", desc: "Only plan: say what would change, change nothing."},
		},
		run: func(c *mcpCtx) (any, error) {
			dry, _ := c.flag("dry_run")
			body := map[string]any{"target": c.str("target"), "text": c.str("text"), "action": c.str("action"), "ports": c.str("ports"), "value": c.str("value"), "dry_run": dry}
			b, err := c.call("POST", "/api/devices/change", body, "")
			return asAny(b), err
		}}
}
