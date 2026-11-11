package main

import (
	"strings"
	"time"

	"netdir/device"
)

// answerLife is how long a device's answer to a read is given again to a caller that asks the same.
const answerLife = 30 * time.Second

// answerCacheable says whether this read may come from the answer cache: only an MCP caller (the GUI always asks the device), never a
// raw caller, never when the caller said fresh, and only the reads that hold no secret and are no search of a log: a configuration, a
// CLI command and a log search are always asked live.
func answerCacheable(s *session, op, cmd, fresh string) bool {
	if !device.CacheOn || !s.mcp || s.raw || fresh != "" && fresh != "0" {
		return false
	}
	switch op {
	case "facts", "interfaces", "neighbors", "neighbor_details", "ports", "routes", "routing", "firewall", "resources", "vlans", "api_catalog":
		return true
	case "api":
		l := strings.ToLower(cmd)
		return !strings.Contains(l, "log") && !strings.Contains(l, "job") && !strings.Contains(l, "capture")
	}
	return false
}

// answerMode separates what callers of different privilege may be given.
func answerMode(s *session) string {
	if s.readOnly {
		return "ro"
	}
	return "rw"
}

func credByName(creds []device.Credential, name string) (device.Credential, bool) {
	for _, c := range creds {
		if c.Name == name {
			return c, true
		}
	}
	return device.Credential{}, false
}
