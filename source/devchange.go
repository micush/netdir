package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

// deviceChange plans or makes the change on the devices the target picks.
func (m *Mgmt) deviceChange(raw json.RawMessage, actor string) (any, error) {
	return m.withBelow("device_change", raw, actor, m.viaCheckers("change", m.deviceChangeHere))
}

// deviceChangeHere is deviceChange for this director's own devices.
func (m *Mgmt) deviceChangeHere(raw json.RawMessage, actor string) (any, error) {
	var a devices.DeviceChangeArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	c, err := a.Change()
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
	devs, creds := dc.EffectiveDevices(), dc.Settings.DeviceCredentials
	if len(devs) == 0 {
		return nil, errors.New("no devices are configured (settings.devices)")
	}
	target, err := core.ExpandGatewayTargetsIn(dc, a.Target)
	if err != nil {
		return nil, err
	}
	picked, err := device.Select(devs, target)
	if err != nil {
		return nil, err
	}
	for _, d := range picked {
		if d.Disabled {
			return nil, fmt.Errorf("device %s %s", d.Name, devices.OffWhy(d))
		}
	}
	verb := "changes"
	if a.DryRun {
		verb = "plans a change of"
	}
	core.Warnf("devices: %q %s %s (%d devices): %s", actor, verb, a.Target, len(picked), devices.DescribeChange(c))
	res := device.Fanout(context.Background(), picked, creds, devices.DeviceParallel, devices.DeviceConfigTO, func(ctx context.Context, d device.Driver) (any, error) {
		ch, ok := d.(device.Changer)
		if !ok {
			return nil, errors.New("typed port changes are for Catalyst IOS-XE, Arista EOS, Aruba CX, a Meraki switch (a device with the option serial), Junos, NX-OS, FortiOS and F5 BIG-IP (PAN-OS: counters only); other platforms and other changes: device_change_raw (--device-raw)")
		}
		r, err := ch.Change(ctx, c, a.DryRun)
		if err == nil && a.Save && !a.DryRun {
			r = devices.SaveAfter(ctx, d, c, r)
		}
		return r, err
	})
	failed := 0
	for _, x := range res {
		if !x.OK {
			failed++
			core.Warnf("devices: %q change of %s failed: %s", actor, x.Device, x.Error)
			continue
		}
		if cr, ok := x.Data.(device.ChangeResult); ok && !a.DryRun {
			core.Warnf("devices: %q changed %s: %d changed, %d already as asked", actor, x.Device, len(cr.Changes), len(cr.Unchanged))
			for i, pc := range cr.Changes { // the audit trail: what each port held before and after
				if i >= 100 {
					core.Warnf("devices: audit %s: … and %d more", x.Device, len(cr.Changes)-i)
					break
				}
				core.Warnf("devices: audit %s %s %s: %q -> %q (by %q)", x.Device, pc.Port, pc.Field, pc.Before, pc.After, actor)
			}
		}
	}
	return map[string]any{"op": "change", "dry_run": a.DryRun, "change": c, "asked": len(res), "failed": failed, "results": res}, nil
}
