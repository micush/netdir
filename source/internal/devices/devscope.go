package devices

import (
	"strconv"
	"strings"

	"netdir/internal/core"
)

// alertSubjectGateway returns the gateway number of an alert subject written "group N ..." .
func AlertSubjectGateway(subject string) (int, bool) {
	f := strings.Fields(subject)
	if len(f) >= 2 && f[0] == "group" {
		n, err := strconv.Atoi(f[1])
		return n, err == nil
	}
	return 0, false
}

// newDevScope makes the scope of lists, ignoring those that allow everything.
func NewDevScope(lists ...[]string) *core.DevScope {
	sc := &core.DevScope{}
	for _, l := range lists {
		if len(l) > 0 {
			sc.Parts = append(sc.Parts, l)
		}
	}
	if len(sc.Parts) == 0 {
		return nil
	}
	return sc
}

// scopeOf is the scope of a session (nil for the GUI's own users, and for an MCP caller with no limit).
func ScopeOf(s *core.Session) *core.DevScope {
	if s == nil {
		return nil
	}
	return s.Devs
}

// scopedOffTools are the tools a caller limited to some devices is not offered: it reaches every device and the signed-in users.
var ScopedOffTools = map[string]bool{"device_troubleshoot_user": true}

// scopeRefusedPrefixes are the API routes a limited caller may not use: they hold the whole inventory or the keys.
var ScopeRefusedPrefixes = []string{"/api/config", "/api/versions", "/api/canvas/edit", "/api/devices/troubleshoot", "/api/devices/signin"}
