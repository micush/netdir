package mcp

import (
	"regexp"
	"strings"

	"netdir/internal/core"
)

// the rules of the standard level as shipped: what the daemon hid before levels existed
var stdMask = core.NewMaskRules(core.StandardRules())

func maskASNText(digits string) (string, bool) { return stdMask.Asn(digits) }

// maskText hides what a piece of text says about the public network, as the standard level does.
func maskText(s string) string { return stdMask.Text(s) }

// reSerialTail is what serialTail makes; sent back in a change it keeps the real value, like a token.
// reMaskedIP is an address as ip4Keep and ip6Keep write it: at least one x among the parts, the others numbers.
var reMaskedIP = regexp.MustCompile(`^(?:(?:x|\d{1,3})(?:\.(?:x|\d{1,3})){3}|(?:x|[0-9a-f]{1,4})(?::(?:x|[0-9a-f]{1,4})){7})$`)

// reMaskedMAC and reMaskedNum are a MAC address, an AS number or a route distinguisher with digits written as x.
var (
	reMaskedMAC = regexp.MustCompile(`(?i)^(?:(?:[0-9a-fx]{2}[:-]){5}[0-9a-fx]{2}|[0-9a-fx]{4}(?:\.[0-9a-fx]{4}){2}|[0-9a-fx]{12})$`)
	reMaskedNum = regexp.MustCompile(`^(?:x+\d{1,3}|(?:x\.x\.x\.x|[\dx.]+):x+\d{0,3}|x+\d{1,3}:x+\d{0,3})$`)
)

// maskedWithX says whether a text is an address, MAC address, AS number or route distinguisher with digits written as x.
// One without an x is a real value.
func maskedWithX(t string) bool {
	return strings.Contains(strings.ToLower(t), "x") && (reMaskedIP.MatchString(t) || reMaskedMAC.MatchString(t) || reMaskedNum.MatchString(t))
}

var reSerialTail = regexp.MustCompile(`^\*{4}[A-Za-z0-9 ._/-]{0,4}$`)

func mcpMaskJSON(b []byte) []byte { return stdMask.Json(b) }

// mcpUnmask turns a caller's hidden-value tokens back into "(hidden)" in a body it sends, so that what the caller read
// (a configuration with PUBLIC-IP-3fa91c in it) can be sent back in a change and the real value is restored from the
// current configuration, like a secret.  A token that matches nothing there is refused like any other "(hidden)".
func mcpUnmask(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = mcpUnmask(x)
		}
	case []any:
		for i, x := range t {
			t[i] = mcpUnmask(x)
		}
	case string:
		if core.ReToken.MatchString(t) || reSerialTail.MatchString(t) || maskedWithX(t) {
			return mcpHidden
		}
	}
	return v
}
