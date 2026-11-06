package main

import (
	"fmt"
	"os"
	"strings"

	"netdir/device"
)

// changeAnswer is what POST /api/devices/change and the device.change op answer.
type changeAnswer struct {
	DryRun  bool          `json:"dry_run"`
	Change  device.Change `json:"change"`
	Asked   int           `json:"asked"`
	Failed  int           `json:"failed"`
	Results []struct {
		Device   string              `json:"device"`
		Platform string              `json:"platform"`
		OK       bool                `json:"ok"`
		Error    string              `json:"error"`
		Data     device.ChangeResult `json:"data"`
	} `json:"results"`
}

// runDeviceChange is --device-change: the plan is made and shown first (nothing is sent to a device but reads); unless --dry-run it
// then asks (unless --yes) and makes the change.  The exit status is 1 when any device failed.
func runDeviceChange(sock, text, target string, dry, yes bool) {
	if strings.TrimSpace(target) == "" {
		fatalf(`--device-change needs --target: a device name, tag:TAG, platform:PLATFORM, gateway:N or "all"`)
	}
	args := map[string]any{"target": target, "text": text, "dry_run": true}
	var plan changeAnswer
	decode(op(sock, "device.change", args), &plan)
	printChange(plan)
	if dry {
		if plan.Failed > 0 {
			os.Exit(1)
		}
		return
	}
	n := 0
	for _, r := range plan.Results {
		if r.OK {
			n += len(r.Data.Changes)
		}
	}
	if plan.Failed == plan.Asked {
		fatalf("nothing can be changed")
	}
	if n == 0 {
		fmt.Println("Nothing to change: every port is already as asked.")
		return
	}
	askYes(fmt.Sprintf("Make these %d changes on %d devices?", n, plan.Asked-plan.Failed), yes)
	args["dry_run"] = false
	var done changeAnswer
	decode(op(sock, "device.change", args), &done)
	fmt.Println()
	printChange(done)
	if done.Failed > 0 {
		os.Exit(1)
	}
}

func printChange(a changeAnswer) {
	word := "changed"
	if a.DryRun {
		word = "would change"
	}
	for _, r := range a.Results {
		if !r.OK {
			fmt.Printf("%-20s FAILED: %s\n", r.Device, r.Error)
			continue
		}
		fmt.Printf("%-20s %d %s, %d already as asked\n", r.Device, len(r.Data.Changes), word, len(r.Data.Unchanged))
		for i, c := range r.Data.Changes {
			if i >= 30 {
				fmt.Printf("  … and %d more\n", len(r.Data.Changes)-i)
				break
			}
			fmt.Printf("  %-26s %-12s %q -> %q\n", c.Port, c.Field, c.Before, c.After)
		}
	}
}
