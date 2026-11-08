package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"netdir/device"
)

// deviceImportObservium adds the devices an Observium, IP Fabric or Centreon server knows to the inventory, each one disabled and with no login
// (device/import.go has the rules).  dry_run only lists them.  It runs from the GUI, the CLI and the API; MCP cannot change the
// configuration, so there is no tool for it.
func (m *Mgmt) deviceImportObservium(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		Device string `json:"device"`
		DryRun bool   `json:"dry_run"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	var srv *device.Device
	for i := range dc.Settings.Devices {
		if dc.Settings.Devices[i].Name == a.Device {
			srv = &dc.Settings.Devices[i]
		}
	}
	if srv == nil {
		return nil, fmt.Errorf("device %q: not in the inventory", a.Device)
	}
	if !device.ImportSources[srv.Platform] {
		return nil, fmt.Errorf("device %s: devices are imported from an Observium, IP Fabric, Centreon, Panorama, Proxmox Datacenter Manager or Aruba Fabric Composer device only", srv.Name)
	}
	if srv.Disabled {
		return nil, fmt.Errorf("device %s is disabled: enable it first", srv.Name)
	}
	var cred *device.Credential
	for i := range dc.Settings.DeviceCredentials {
		if dc.Settings.DeviceCredentials[i].Name == srv.Credential {
			cred = &dc.Settings.DeviceCredentials[i]
		}
	}
	if cred == nil {
		return nil, fmt.Errorf("device %s: its login %q does not exist", srv.Name, srv.Credential)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	add, skipped, err := device.ImportDevices(ctx, *srv, *cred, dc.Settings.Devices)
	if err != nil {
		return nil, err
	}
	if len(add) > 0 && !a.DryRun {
		if len(dc.Settings.Devices)+len(add) > 4096 {
			return nil, fmt.Errorf("the inventory would pass 4096 devices")
		}
		dc.Settings.Devices = append(dc.Settings.Devices, add...)
		if err := device.Validate(dc.Settings.Devices, dc.Settings.DeviceCredentials); err != nil {
			return nil, err
		}
		names := make([]string, len(add))
		for i, d := range add {
			names[i] = d.Name
		}
		note := fmt.Sprintf("devices: imported %d from %s (disabled, no login)", len(add), srv.Name)
		if err := m.PutConfig(dc, actor, note); err != nil {
			return nil, err
		}
		warnf("%s imported %d devices from %s: %s", actor, len(add), srv.Name, strings.Join(names, " "))
	}
	if add == nil {
		add = []device.Device{}
	}
	if skipped == nil {
		skipped = []device.Skipped{}
	}
	return map[string]any{"added": add, "skipped": skipped, "dry_run": a.DryRun}, nil
}

// runDeviceImport is netdir --device-import SERVER [--dry-run].
func runDeviceImport(sock, name string, dry bool) {
	var r struct {
		Added   []device.Device  `json:"added"`
		Skipped []device.Skipped `json:"skipped"`
	}
	decode(op(sock, "device.import_observium", map[string]any{"device": name, "dry_run": dry}), &r)
	verb := "Imported"
	if dry {
		verb = "Would import"
	}
	fmt.Printf("%s %d devices from %s (disabled, with no login: give each one a login, then enable it)\n", verb, len(r.Added), name)
	for _, d := range r.Added {
		fmt.Printf("  %-24s %-8s %s\n", d.Name, d.Platform, d.Address)
	}
	for _, s := range r.Skipped {
		fmt.Printf("  skipped %-20s %s\n", s.Name, s.Reason)
	}
}
