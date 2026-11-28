package core

import (
	"testing"

	"netdir/device"
)

// A gateway lists devices of the inventory by name: once each, and only ones that exist.  The list is shared by the cluster.
func TestGatewayDevicesValidatedAndShared(t *testing.T) {
	dc := NewDaemonConfig()
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: "10.0.0.2", Credential: "lab"}, {Name: "fw1", Platform: "iosxe", Address: "10.0.0.1", Credential: "lab"}}
	attachDevices(dc)
	dc.Groups[0].Devices = []string{"sw1", "fw1"}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	h := SharedOf(dc).Hash()
	dc.Groups[0].Devices = []string{"fw1", "sw1"}
	if SharedOf(dc).Hash() == h {
		t.Fatal("the order of a gateway's devices is not in the shared hash")
	}
	for _, bad := range [][]string{{"nosuch"}, {"sw1", "sw1"}} {
		dc.Groups[0].Devices = bad
		if err := dc.Validate(); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	gc := DefaultGroup()
	ApplySharedGroup(&gc, SharedOf(func() *DaemonConfig { dc.Groups[0].Devices = []string{"sw1"}; return dc }()).Groups[0])
	if len(gc.Devices) != 1 || gc.Devices[0] != "sw1" {
		t.Fatalf("not replicated: %v", gc.Devices)
	}
}
