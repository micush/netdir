package mcp

import (
	"testing"
)

// A request that changes anything but a device is refused over MCP, at every route.
func TestMCPWriteGuard(t *testing.T) {
	for _, c := range []struct {
		m, p string
		ok   bool
	}{
		{"GET", "/api/config", true}, {"PUT", "/api/config", false}, {"POST", "/api/canvas/edit", false},
		{"POST", "/api/devices/change", true}, {"POST", "/api/devices/raw", true}, {"POST", "/api/devices/capture", true},
		{"POST", "/api/proxy?node=x&path=/api/devices/change", true}, {"POST", "/api/proxy?node=x&path=/api/config", false},
		{"DELETE", "/api/devices/change", false}, {"POST", "/api/nodepause", false}, {"POST", "/api/schedule", false},
	} {
		if err := McpWriteGuard(c.m, c.p); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.m, c.p, err)
		}
	}
}
