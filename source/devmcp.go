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

func (m *Mgmt) deviceMCP(raw json.RawMessage, actor string) (any, error) {
	var probe devices.DeviceMCPArgs
	tool := "device_mcp"
	if json.Unmarshal(raw, &probe) == nil && probe.Write {
		tool = "device_mcp_write"
	}
	return m.withBelow(tool, raw, actor, m.viaCheckers("mcp", m.deviceMCPHere))
}

func (m *Mgmt) deviceMCPHere(raw json.RawMessage, actor string) (any, error) {
	var a devices.DeviceMCPArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	if strings.TrimSpace(a.Target) == "" {
		return nil, errors.New(`target: the devices to ask: a name, tag:TAG, platform:PLATFORM, gateway:N or "all", separated by commas`)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	devs, creds := dc.EffectiveDevices(), dc.Settings.DeviceCredentials
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
	a.Tool = strings.TrimSpace(a.Tool)
	if a.Tool != "" && a.Write {
		core.Warnf("devices: audit: %q %s the tool %s of %s (%d devices) with %s", actor, map[bool]string{true: "plans", false: "calls"}[a.DryRun], a.Tool, a.Target, len(picked), devices.OneLine(devices.JsonText(a.Args), 1000))
	}
	res := device.Fanout(context.Background(), picked, creds, devices.DeviceParallel, devices.DeviceConfigTO, func(ctx context.Context, d device.Driver) (any, error) {
		mp, ok := d.(device.MCPPassthrough)
		if !ok {
			return nil, errors.New("this device has no MCP endpoint of its own (only dnsdir, ntpdir, netdir, logdir, flowdir and filedir do)")
		}
		tools, err := mp.MCPTools(ctx)
		if err != nil {
			return nil, err
		}
		if a.Tool == "" {
			return map[string]any{"tools": tools}, nil
		}
		if a.DryRun {
			for _, t := range tools {
				if t.Name == a.Tool {
					if err := device.CheckMCPArgs(t, a.Args); err != nil {
						return nil, err
					}
					return map[string]any{"dry_run": true, "would_call": a.Tool, "args": a.Args, "changes_things": !t.ReadOnly, "destructive": t.Destructive}, nil
				}
			}
			return nil, fmt.Errorf("the device has no tool %q", a.Tool)
		}
		v, err := mp.MCPCall(ctx, a.Tool, a.Args, a.Write)
		if err != nil {
			return nil, err
		}
		return map[string]any{"tool": a.Tool, "answer": v}, nil
	})
	failed := 0
	for _, x := range res {
		if !x.OK {
			failed++
			if a.Write {
				core.Warnf("devices: audit %s: %q tool %s failed: %s", x.Device, actor, a.Tool, x.Error)
			}
		} else if a.Write && !a.DryRun && a.Tool != "" {
			core.Warnf("devices: audit %s: %q ran the tool %s", x.Device, actor, a.Tool)
		}
	}
	return map[string]any{"op": "mcp", "dry_run": a.DryRun, "asked": len(res), "failed": failed, "results": res}, nil
}

// runDeviceMCP is --device-mcp: "list" gives the tool list of each device, any other value is a tool, with its arguments as JSON in --device-body
// (or @FILE).  A tool that changes things needs --device-write; it is planned first, shown, and asked about unless --yes or --dry-run.
func runDeviceMCP(sock string, f *cliFlags) {
	target := *f.deviceTarget
	if strings.TrimSpace(target) == "" {
		core.Fatalf(`--device-mcp needs --target: a device name, tag:TAG, platform:PLATFORM, gateway:N or "all"`)
	}
	tool := *f.deviceMCP
	args := map[string]any{"target": target, "write": *f.deviceWrite}
	if tool != "list" {
		args["tool"] = tool
		body := *f.deviceBody
		if strings.HasPrefix(body, "@") {
			b, err := os.ReadFile(body[1:])
			if err != nil {
				core.Fatalf("--device-body: %v", err)
			}
			body = string(b)
		}
		if strings.TrimSpace(body) != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(body), &m); err != nil {
				core.Fatalf("--device-body is not a JSON object: %v", err)
			}
			args["args"] = m
		}
	}
	if *f.deviceWrite && tool != "list" {
		args["dry_run"] = true
		var plan map[string]any
		core.Decode(core.Op(sock, "device.mcp", args), &plan)
		devices.PrintMCP(plan)
		if *f.dryRun {
			return
		}
		if n, _ := plan["failed"].(float64); int(n) == len(plan["results"].([]any)) {
			core.Fatalf("nothing can be run")
		}
		askYes("Run this tool?", *f.yes)
		args["dry_run"] = false
	} else if *f.dryRun {
		args["dry_run"] = true
	}
	var done map[string]any
	core.Decode(core.Op(sock, "device.mcp", args), &done)
	devices.PrintMCP(done)
	if n, _ := done["failed"].(float64); n > 0 {
		os.Exit(1)
	}
}
