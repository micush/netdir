package devices

import (
	"strings"
	"testing"

	"netdir/device"
	"netdir/internal/core"
)

// A device on no gateway is never contacted, listed or offered over MCP: effectiveDevices reads it as disabled (and unattached);
// putting it on a gateway undoes that, and the saved inventory is never changed.
func TestUnattachedDeviceReadsAsDisabled(t *testing.T) {
	dc := &core.DaemonConfig{}
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: "10.0.0.2", Credential: "c"}, {Name: "sw2", Platform: "iosxe", Address: "10.0.0.3", Credential: "c"}}
	dc.Groups = []core.GroupConfig{{GroupID: 1, Devices: []string{"sw1"}}, {GroupID: 2}}
	eff := dc.EffectiveDevices()
	if eff[0].Disabled || eff[0].Unattached {
		t.Errorf("sw1 is on a gateway: %+v", eff[0])
	}
	if !eff[1].Disabled || !eff[1].Unattached {
		t.Errorf("sw2 is on no gateway: %+v", eff[1])
	}
	if dc.Settings.Devices[1].Disabled || dc.Settings.Devices[1].Unattached {
		t.Error("effectiveDevices changed the saved inventory")
	}
	dc.Groups[1].Devices = []string{"sw2"} // on another gateway: live
	if eff = dc.EffectiveDevices(); eff[1].Disabled || eff[1].Unattached {
		t.Errorf("sw2 is on gateway 2: %+v", eff[1])
	}
	dc.Groups = nil // no gateway at all: nothing is attached
	if eff = dc.EffectiveDevices(); !eff[0].Disabled || !eff[1].Disabled {
		t.Errorf("no gateways: %+v", eff)
	}
	// the refusal says what to do
	if got := OffWhy(device.Device{Unattached: true}); !strings.Contains(got, "no gateway") {
		t.Errorf("offWhy: %q", got)
	}
	if got := OffWhy(device.Device{Disabled: true}); !strings.Contains(got, "enable it") {
		t.Errorf("offWhy: %q", got)
	}
}
