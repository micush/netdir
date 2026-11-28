package devices

import (
	"encoding/json"
	"fmt"
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

type DeviceMCPArgs struct {
	Target string         `json:"target"`
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args"`
	Write  bool           `json:"write"`
	DryRun bool           `json:"dry_run"`
}

func JsonText(v any) string { b, _ := json.Marshal(v); return string(b) }

func PrintMCP(a map[string]any) {
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
