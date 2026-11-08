package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"netdir/device"
)

// Arbitrary configuration changes of the managed devices (device/rawchange.go has the framework and the drivers):
//
//	POST /api/devices/raw   {"target": "sw1", "method": "PATCH", "path": "/restconf/data/…", "body": "{…}", "dry_run": true}
//	POST /api/devices/raw   {"target": "eos1", "lines": ["interface Ethernet1", "description x"], "save": true}
//	netdir --device-raw "PATCH /restconf/data/…" --device-body '{…}' --target sw1 [--dry-run] [--device-save] [--yes]
//	netdir --device-lines FILE --target eos1,n9k1          (lines of CLI configuration, EOS and NX-OS)
//	MCP device_change_raw       (a caller with rw access only)
//
// The same gate as device.change: read-only sessions are refused by authed, MCP ro keys have no tool.  Every call is logged with
// who made it, to which device, and the request (never the secrets: a body is logged by size).  A dry run asks the devices for the
// "before" copy and sends no change.

type deviceRawArgs struct {
	Target string   `json:"target"`
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Body   string   `json:"body"`
	Lines  []string `json:"lines"`
	Save   bool     `json:"save"`
	DryRun bool     `json:"dry_run"`
}

func (m *Mgmt) deviceRaw(raw json.RawMessage, actor string) (any, error) {
	return m.withBelow("device_change_raw", raw, actor, m.deviceRawHere)
}

// deviceRawHere is deviceRaw for this director's own devices.
func (m *Mgmt) deviceRawHere(raw json.RawMessage, actor string) (any, error) {
	var a deviceRawArgs
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
	devs, creds := dc.Settings.Devices, dc.Settings.DeviceCredentials
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
			return nil, fmt.Errorf("device %s is disabled: enable it first (Configure ▸ Devices)", d.Name)
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
	warnf("devices: %q %s %s (%d devices) with %s (body %d bytes, save %v)", actor, verb, a.Target, len(picked), what, len(a.Body), a.Save)
	res := device.Fanout(context.Background(), picked, creds, deviceParallel, deviceConfigTO, func(ctx context.Context, d device.Driver) (any, error) {
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
			warnf("devices: audit %s: %q change with %s failed: %s", x.Device, actor, what, x.Error)
			continue
		}
		if r, ok := x.Data.(device.RawResult); ok && !a.DryRun {
			warnf("devices: audit %s: %q applied %s (applied %v, saved %v, rolled back %v)", x.Device, actor, what, r.Applied, r.Saved, r.RolledBack)
			if r.Before != "" {
				warnf("devices: audit %s: before: %s", x.Device, oneLine(r.Before, 1000))
			}
			for _, l := range a.Lines {
				warnf("devices: audit %s: line %q", x.Device, oneLine(l, 200))
			}
		}
	}
	return map[string]any{"op": "raw", "dry_run": a.DryRun, "asked": len(res), "failed": failed, "results": res}, nil
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return device.RedactText(s)
}

func mcpDeviceRawTool() mcpTool {
	return mcpTool{name: "device_change_raw", title: "Change device configuration", noNode: true, write: true, destructive: true,
		desc: "Make any configuration change on devices: the platform's own write. REST platforms (Cisco IOS-XE RESTCONF, Aruba AOS-CX, Aruba Fabric Composer, Proxmox VE, FortiOS cmdb, Infoblox WAPI, F5 BIG-IP iControl, Technitium, Cisco Meraki, Observium, Microsoft Entra Graph): method POST, PUT, PATCH or DELETE, " +
			"path and body (JSON; Technitium: name=value&name=value). PAN-OS and Panorama: method is the action (set, edit, delete, rename, move), path the XPath below /config/, body the XML element. " +
			"Arista EOS and Cisco NX-OS: lines of configuration. DNS Director and NTP Director (dnsdir, ntpdir): method SET with a JSON object of settings in body (merged into its configuration), or POST or PUT of a /api/ route. Plan it first with dry_run: true: REST platforms and PAN-OS return what the path holds now, EOS returns the switch's own diff. " +
			"A change is refused for login, users, keys, file operations and what would cut the management access. A reboot is accepted where the platform has one: IOS-XE POST /restconf/operations/Cisco-IOS-XE-rpc:reload, AOS-CX POST <rest root>/boot?image=primary, FortiOS POST /api/v2/monitor/system/os/reboot, BIG-IP POST /mgmt/tm/sys with {\"command\":\"reboot\"}, Meraki POST /devices/SERIAL/reboot, Proxmox POST /nodes/NODE/status with {\"command\":\"reboot\"}, PAN-OS/Panorama method reboot, EOS and NX-OS the single line reload. Nothing is read back after a reboot and nothing is put back; the device is unreachable for a few minutes, and save: true writes the configuration first. Infoblox, Technitium, AFC, the directors, Observium and Entra have no reboot here. REST changes that fail, or after which the device stops answering, are put back with the saved copy (PUT/PATCH only); " +
			"EOS commits with a 3-minute timer and confirms it only when the switch answers; NX-OS rolls back to a checkpoint. A POST or DELETE cannot be undone by this tool, and the result is not read back for equality. save: true makes it survive a reboot (save config, write memory, commit).",
		props: []mcpProp{
			{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N or \"all\" (list_devices)."},
			{name: "method", typ: "string", desc: "REST: POST, PUT, PATCH, DELETE. PAN-OS: set, edit, delete, rename, move."},
			{name: "path", typ: "string", desc: "REST path (as device_api_get takes it, e.g. /restconf/data/Cisco-IOS-XE-native:native/ntp) or PAN-OS XPath."},
			{name: "body", typ: "string", desc: "The request body as text."},
			{name: "lines", typ: "string", desc: "EOS and NX-OS: the configuration lines, one per line of this text."},
			{name: "save", typ: "boolean", desc: "Save the change so it survives a reboot."},
			{name: "dry_run", typ: "boolean", desc: "Only plan: change nothing."},
		},
		run: func(c *mcpCtx) (any, error) {
			dry, _ := c.flag("dry_run")
			save, _ := c.flag("save")
			body := map[string]any{"target": c.str("target"), "method": c.str("method"), "path": c.str("path"), "body": c.str("body"), "save": save, "dry_run": dry}
			if l := strings.TrimSpace(c.str("lines")); l != "" {
				body["lines"] = strings.Split(l, "\n")
			}
			b, err := c.call("POST", "/api/devices/raw", body, "")
			return asAny(b), err
		}}
}

// ---- the CLI ----

type rawAnswer struct {
	DryRun  bool `json:"dry_run"`
	Asked   int  `json:"asked"`
	Failed  int  `json:"failed"`
	Results []struct {
		Device string           `json:"device"`
		OK     bool             `json:"ok"`
		Error  string           `json:"error"`
		Data   device.RawResult `json:"data"`
	} `json:"results"`
}

// runDeviceRaw is --device-raw / --device-lines: plan first, show it, ask (unless --yes or --dry-run), then change.
func runDeviceRaw(sock string, f *cliFlags) {
	target := *f.deviceTarget
	if strings.TrimSpace(target) == "" {
		fatalf(`--device-raw and --device-lines need --target: a device name, tag:TAG, platform:PLATFORM, gateway:N or "all"`)
	}
	args := map[string]any{"target": target, "dry_run": true, "save": *f.deviceSave}
	if *f.deviceRaw != "" {
		parts := strings.Fields(*f.deviceRaw)
		if len(parts) != 2 {
			fatalf(`--device-raw takes "METHOD PATH", e.g. "PATCH /restconf/data/Cisco-IOS-XE-native:native/ntp"`)
		}
		args["method"], args["path"] = parts[0], parts[1]
		body := *f.deviceBody
		if strings.HasPrefix(body, "@") {
			b, err := os.ReadFile(body[1:])
			if err != nil {
				fatalf("--device-body: %v", err)
			}
			body = string(b)
		}
		args["body"] = body
	} else {
		b, err := os.ReadFile(*f.deviceLines)
		if err != nil {
			fatalf("--device-lines: %v", err)
		}
		args["lines"] = strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	}
	var plan rawAnswer
	decode(op(sock, "device.raw", args), &plan)
	printRaw(plan)
	if *f.dryRun {
		if plan.Failed > 0 {
			os.Exit(1)
		}
		return
	}
	if plan.Failed == plan.Asked {
		fatalf("nothing can be changed")
	}
	askYes(fmt.Sprintf("Make this change on %d devices?", plan.Asked-plan.Failed), *f.yes)
	args["dry_run"] = false
	var done rawAnswer
	decode(op(sock, "device.raw", args), &done)
	fmt.Println()
	printRaw(done)
	if done.Failed > 0 {
		os.Exit(1)
	}
}

func printRaw(a rawAnswer) {
	for _, r := range a.Results {
		if !r.OK {
			fmt.Printf("%-20s FAILED: %s\n", r.Device, r.Error)
			continue
		}
		state := "applied"
		switch {
		case a.DryRun:
			state = "planned"
		case r.Data.Saved:
			state = "applied and saved"
		}
		fmt.Printf("%-20s %s\n", r.Device, state)
		if r.Data.Before != "" {
			fmt.Printf("  before: %s\n", oneLine(r.Data.Before, 400))
		}
		if r.Data.Note != "" {
			fmt.Printf("  %s\n", r.Data.Note)
		}
	}
}
