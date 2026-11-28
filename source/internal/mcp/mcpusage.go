package mcp

import (
	"strings"
)

// callerOf splits the name a call is logged under: KEYNAME@ADDRESS, or just the address.
func mcpCallerOf(who, from string) string {
	if who == from {
		return "(address list)"
	}
	return strings.TrimSuffix(who, "@"+from)
}

// mcpClientID is who a request counts as for the Clients number: the key's name, or the address when there was no key.
func mcpClientID(who, from string) string {
	if who == from {
		return from
	}
	return strings.TrimSuffix(who, "@"+from)
}

// mcpTarget is what a call asked about: the devices of a device tool, as it was written.
func mcpTarget(args map[string]any) string {
	t, _ := args["target"].(string)
	t = strings.TrimSpace(t)
	if len(t) > 120 {
		t = t[:120] + "…"
	}
	return t
}
