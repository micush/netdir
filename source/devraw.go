package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

func (m *Mgmt) deviceRaw(raw json.RawMessage, actor string) (any, error) {
	return m.withBelow("device_change_raw", raw, actor, m.viaCheckers("raw", m.deviceRawHere))
}

// deviceRawHere is deviceRaw for this director's own devices.
func (m *Mgmt) deviceRawHere(raw json.RawMessage, actor string) (any, error) {
	var a devices.DeviceRawArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	if strings.TrimSpace(a.Target) == "" {
		return nil, errors.New(`target: the devices to change: a name, tag:TAG, platform:PLATFORM, gateway:N or "all", separated by commas`)
	}
	if (a.Method == "" && a.Path == "") == (len(a.Lines) == 0) {
		return nil, errors.New("give either method and path (REST platforms, PAN-OS) or lines (Arista EOS, Cisco NX-OS), not both and not neither")
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
	rq := device.Raw{Method: a.Method, Path: a.Path, Body: a.Body, Lines: a.Lines, Save: a.Save}
	what := strings.TrimSpace(a.Method + " " + a.Path)
	if len(a.Lines) > 0 {
		what = fmt.Sprintf("%d lines of configuration", len(a.Lines))
	}
	verb := "changes"
	if a.DryRun {
		verb = "plans a change of"
	}
	core.Warnf("devices: %q %s %s (%d devices) with %s (body %d bytes, save %v)", actor, verb, a.Target, len(picked), what, len(a.Body), a.Save)
	res := device.Fanout(context.Background(), picked, creds, devices.DeviceParallel, devices.DeviceConfigTO, func(ctx context.Context, d device.Driver) (any, error) {
		rc, ok := d.(device.RawChanger)
		if !ok {
			return nil, errors.New("this platform cannot be changed from here")
		}
		r, err := rc.RawChange(ctx, rq, a.DryRun)
		if err != nil {
			// a failed device's data is dropped, so what was and was not done goes into the error
			var st []string
			if r.Applied {
				st = append(st, "the change was applied")
			}
			if r.RolledBack {
				st = append(st, "it was put back")
			}
			if r.Note != "" {
				st = append(st, r.Note)
			}
			if len(st) > 0 {
				err = fmt.Errorf("%w [%s]", err, strings.Join(st, "; "))
			}
		}
		return r, err
	})
	failed := 0
	for _, x := range res {
		if !x.OK {
			failed++
			core.Warnf("devices: audit %s: %q change with %s failed: %s", x.Device, actor, what, x.Error)
			continue
		}
		if r, ok := x.Data.(device.RawResult); ok && !a.DryRun {
			core.Warnf("devices: audit %s: %q applied %s (applied %v, saved %v, rolled back %v)", x.Device, actor, what, r.Applied, r.Saved, r.RolledBack)
			if r.Before != "" {
				core.Warnf("devices: audit %s: before: %s", x.Device, devices.OneLine(r.Before, 1000))
			}
			for _, l := range a.Lines {
				core.Warnf("devices: audit %s: line %q", x.Device, devices.OneLine(l, 200))
			}
		}
	}
	return map[string]any{"op": "raw", "dry_run": a.DryRun, "asked": len(res), "failed": failed, "results": res}, nil
}

// runDeviceRaw is --device-raw / --device-lines: plan first, show it, ask (unless --yes or --dry-run), then change.
func runDeviceRaw(sock string, f *cliFlags) {
	target := *f.deviceTarget
	if strings.TrimSpace(target) == "" {
		core.Fatalf(`--device-raw and --device-lines need --target: a device name, tag:TAG, platform:PLATFORM, gateway:N or "all"`)
	}
	args := map[string]any{"target": target, "dry_run": true, "save": *f.deviceSave}
	if *f.deviceRaw != "" {
		parts := strings.Fields(*f.deviceRaw)
		if len(parts) != 2 {
			core.Fatalf(`--device-raw takes "METHOD PATH", e.g. "PATCH /restconf/data/Cisco-IOS-XE-native:native/ntp"`)
		}
		args["method"], args["path"] = parts[0], parts[1]
		body := *f.deviceBody
		if strings.HasPrefix(body, "@") {
			b, err := os.ReadFile(body[1:])
			if err != nil {
				core.Fatalf("--device-body: %v", err)
			}
			body = string(b)
		}
		args["body"] = body
	} else {
		b, err := os.ReadFile(*f.deviceLines)
		if err != nil {
			core.Fatalf("--device-lines: %v", err)
		}
		args["lines"] = strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	}
	var plan devices.RawAnswer
	core.Decode(core.Op(sock, "device.raw", args), &plan)
	devices.PrintRaw(plan)
	if *f.dryRun {
		if plan.Failed > 0 {
			os.Exit(1)
		}
		return
	}
	if plan.Failed == plan.Asked {
		core.Fatalf("nothing can be changed")
	}
	askYes(fmt.Sprintf("Make this change on %d devices?", plan.Asked-plan.Failed), *f.yes)
	args["dry_run"] = false
	var done devices.RawAnswer
	core.Decode(core.Op(sock, "device.raw", args), &done)
	fmt.Println()
	devices.PrintRaw(done)
	if done.Failed > 0 {
		os.Exit(1)
	}
}
