package core

import (
	"testing"
)

func TestContentLogSettingsAreChecked(t *testing.T) {
	for _, bad := range []func(s *Settings){func(s *Settings) { s.MCPLogMB = 1001 }, func(s *Settings) { s.MCPLogMB = -1 }, func(s *Settings) { s.MCPLogEntryKB = 8193 }} {
		dc := NewDaemonConfig()
		bad(&dc.Settings)
		if dc.Validate() == nil {
			t.Error("a bad content log setting was accepted")
		}
	}
	dc := NewDaemonConfig()
	dc.Settings.MCPLogMB, dc.Settings.MCPLogEntryKB = 50, 256
	if err := dc.Validate(); err != nil || dc.Settings.MCPLogMB != 0 || dc.Settings.MCPLogEntryKB != 0 {
		t.Fatalf("the defaults are not written: %v %+v", err, dc.Settings)
	}
}
