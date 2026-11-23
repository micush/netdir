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

// Everything a device's own MCP endpoint offers (dnsdir, ntpdir, netdir, logdir, flowdir, filedir), without a line of code here for each tool:
//
//	POST /api/devices/mcp   {"target": "depot", "tool": "", "args": {}}                         the tool list of each device
//	POST /api/devices/mcp   {"target": "depot", "tool": "files_list", "args": {"folder": "x"}}   one tool, as a read
//	POST /api/devices/mcp   {"target": "depot", "tool": "files_delete", "args": {…}, "write": true, "dry_run": true}
//	netdir --device-mcp [TOOL] [--device-body JSON] --target DEVICES [--device-write] [--dry-run] [--yes]
//	MCP device_mcp (a read; lists the tools or runs one that says it only reads) and device_mcp_write (any tool; rw callers only)
//
// The device's own tool list decides: its input schema checks the arguments, and a tool that does not say readOnlyHint is a change, run
// only with write.  A dry run validates and says what would be called; nothing is sent.  Answers pass the secret filter.

type deviceMCPArgs struct {
	Target string         `json:"target"`
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args"`
	Write  bool           `json:"write"`
	DryRun bool           `json:"dry_run"`
}

func (m *Mgmt) deviceMCP(raw json.RawMessage, actor string) (any, error) {
	var probe deviceMCPArgs
	tool := "device_mcp"
	if json.Unmarshal(raw, &probe) == nil && probe.Write {
		tool = "device_mcp_write"
	}
	return m.withBelow(tool, raw, actor, m.viaCheckers("mcp", m.deviceMCPHere))
}

func (m *Mgmt) deviceMCPHere(raw json.RawMessage, actor string) (any, error) {
	var a deviceMCPArgs
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
	devs, creds := dc.effectiveDevices(), dc.Settings.DeviceCredentials
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
	a.Tool = strings.TrimSpace(a.Tool)
	if a.Tool != "" && a.Write {
		warnf("devices: audit: %q %s the tool %s of %s (%d devices) with %s", actor, map[bool]string{true: "plans", false: "calls"}[a.DryRun], a.Tool, a.Target, len(picked), oneLine(jsonText(a.Args), 1000))
	}
	res := device.Fanout(context.Background(), picked, creds, deviceParallel, deviceConfigTO, func(ctx context.Context, d device.Driver) (any, error) {
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
				warnf("devices: audit %s: %q tool %s failed: %s", x.Device, actor, a.Tool, x.Error)
			}
		} else if a.Write && !a.DryRun && a.Tool != "" {
			warnf("devices: audit %s: %q ran the tool %s", x.Device, actor, a.Tool)
		}
	}
	return map[string]any{"op": "mcp", "dry_run": a.DryRun, "asked": len(res), "failed": failed, "results": res}, nil
}

func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }

func mcpDeviceMCPTools() []mcpTool {
	props := []mcpProp{
		{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N or \"all\" (list_devices). Only the ones that are a dnsdir, ntpdir, netdir, logdir, flowdir or filedir answer."},
		{name: "tool", typ: "string", desc: "The device's tool, by name. Leave empty to get the tool list: each tool's description, arguments (type, enum), which are required and whether it only reads."},
		{name: "args", typ: "string", desc: "The tool's arguments as a JSON object, e.g. {\"folder\":\"docs\"}."},
	}
	run := func(write bool) func(c *mcpCtx) (any, error) {
		return func(c *mcpCtx) (any, error) {
			body := map[string]any{"target": c.str("target"), "tool": c.str("tool"), "write": write}
			if s := strings.TrimSpace(c.str("args")); s != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(s), &m); err != nil {
					return nil, fmt.Errorf("args is not a JSON object: %v", err)
				}
				body["args"] = m
			}
			if write {
				dry, _ := c.flag("dry_run")
				body["dry_run"] = dry
			}
			b, err := c.call("POST", "/api/devices/mcp", body, "")
			return asAny(b), err
		}
	}
	rd := mcpTool{name: "device_mcp", title: "Use a device's own MCP tools", noNode: true,
		desc: "Everything the MCP endpoint of a dnsdir, ntpdir, netdir, logdir, flowdir or filedir device offers, without a tool of its own here: leave tool empty to get the device's tool list (with arguments), or name a tool that only reads (the device marks it readOnlyHint) and give its arguments. " +
			"Tools that change things are refused here: they are device_mcp_write. Arguments are checked against the device's own schema; answers have keys and passwords hidden.",
		props: props, run: run(false)}
	wr := mcpTool{name: "device_mcp_write", title: "Change things through a device's own MCP tools", noNode: true, write: true, destructive: true,
		desc: "Call any tool of a dnsdir, ntpdir, netdir, logdir, flowdir or filedir device's MCP endpoint, including those that change things: files_delete, files_move, files_copy, files_mkdir, trash tools, config edits. device_mcp lists the tools. " +
			"An rw key may do anything the device's own key allows. dry_run checks the arguments against the tool's schema and says what would be called, and sends nothing.",
		props: append(append([]mcpProp{}, props...), mcpProp{name: "dry_run", typ: "boolean", desc: "Only check the arguments: call nothing."}), run: run(true)}
	return []mcpTool{rd, wr}
}

// runDeviceMCP is --device-mcp: "list" gives the tool list of each device, any other value is a tool, with its arguments as JSON in --device-body
// (or @FILE).  A tool that changes things needs --device-write; it is planned first, shown, and asked about unless --yes or --dry-run.
func runDeviceMCP(sock string, f *cliFlags) {
	target := *f.deviceTarget
	if strings.TrimSpace(target) == "" {
		fatalf(`--device-mcp needs --target: a device name, tag:TAG, platform:PLATFORM, gateway:N or "all"`)
	}
	tool := *f.deviceMCP
	args := map[string]any{"target": target, "write": *f.deviceWrite}
	if tool != "list" {
		args["tool"] = tool
		body := *f.deviceBody
		if strings.HasPrefix(body, "@") {
			b, err := os.ReadFile(body[1:])
			if err != nil {
				fatalf("--device-body: %v", err)
			}
			body = string(b)
		}
		if strings.TrimSpace(body) != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(body), &m); err != nil {
				fatalf("--device-body is not a JSON object: %v", err)
			}
			args["args"] = m
		}
	}
	if *f.deviceWrite && tool != "list" {
		args["dry_run"] = true
		var plan map[string]any
		decode(op(sock, "device.mcp", args), &plan)
		printMCP(plan)
		if *f.dryRun {
			return
		}
		if n, _ := plan["failed"].(float64); int(n) == len(plan["results"].([]any)) {
			fatalf("nothing can be run")
		}
		askYes("Run this tool?", *f.yes)
		args["dry_run"] = false
	} else if *f.dryRun {
		args["dry_run"] = true
	}
	var done map[string]any
	decode(op(sock, "device.mcp", args), &done)
	printMCP(done)
	if n, _ := done["failed"].(float64); n > 0 {
		os.Exit(1)
	}
}

func printMCP(a map[string]any) {
	rs, _ := a["results"].([]any)
	for _, r := range rs {
		x, _ := r.(map[string]any)
		if x["ok"] != true {
			fmt.Printf("%-20v FAILED: %v\n", x["device"], x["error"])
			continue
		}
		fmt.Printf("%-20v\n", x["device"])
		b, _ := json.MarshalIndent(x["data"], "  ", "  ")
		fmt.Printf("  %s\n", b)
	}
}
