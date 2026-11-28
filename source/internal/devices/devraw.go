package devices

import (
	"fmt"
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

type DeviceRawArgs struct {
	Target string   `json:"target"`
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Body   string   `json:"body"`
	Lines  []string `json:"lines"`
	Save   bool     `json:"save"`
	DryRun bool     `json:"dry_run"`
}

func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return device.RedactText(s)
}

// ---- the CLI ----

type RawAnswer struct {
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

func PrintRaw(a RawAnswer) {
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
			fmt.Printf("  before: %s\n", OneLine(r.Data.Before, 400))
		}
		if r.Data.Note != "" {
			fmt.Printf("  %s\n", r.Data.Note)
		}
	}
}
