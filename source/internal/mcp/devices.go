package mcp

import (
	"net/url"

	"netdir/internal/core"
)

// mcpDeviceTool is the MCP tool that asks the devices of a target for op (GET /api/devices/query).
func mcpDeviceTool(name, title, op, desc string) mcpTool {
	props := []mcpProp{{name: "target", typ: "string", required: true,
		desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N (the devices of gateway N) or \"all\", several separated by commas (list_devices)."}}
	if op == "api" {
		props = append(props, mcpProp{name: "path", typ: "string", required: true, desc: "The path on the device's own API, e.g. /restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces or /api/v2/monitor/system/status, /api/mo/sys.json, /rest/v10.09/system, /wapi/v2.12/network, /eapi/show/version, /api/zones/list or /api/?type=op&cmd=<show><system><info></info></system></show>; device_api_catalog says what a device offers."})
	}
	if op == "show" {
		props = append(props, mcpProp{name: "command", typ: "string", required: true, desc: "The command, e.g. \"show ip interface brief\"."})
	}
	props = append(props, mcpProp{name: "fresh", typ: "boolean", desc: "Ask the devices again even if they answered the same a moment ago (an answer repeated within " + core.AnswerLife.String() + " comes from memory and says cached_s, its age)."})
	return mcpTool{name: name, title: title, noNode: true, idempotent: true,
		desc:  desc + " Every device is asked at once; each answer has ok, error, data and the time it took.",
		props: props,
		run: func(c *mcpCtx) (any, error) {
			q := url.Values{"target": {c.str("target")}, "op": {op}}
			if op == "show" {
				q.Set("cmd", c.str("command"))
			}
			if op == "api" {
				q.Set("path", c.str("path"))
			}
			if f, _ := c.flag("fresh"); f {
				q.Set("fresh", "1")
			}
			b, err := c.call("GET", "/api/devices/query?"+q.Encode(), nil, "")
			return asAny(b), err
		}}
}
