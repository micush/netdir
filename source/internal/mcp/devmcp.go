package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

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
