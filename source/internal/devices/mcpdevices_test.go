package devices

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

// A gateway entry gives the gateway and every device on it, now and later; a device-only caller sees no gateway.
func TestGatewayScope(t *testing.T) {
	for _, bad := range []string{"gateway:", "gateway:x", "gateway:0", "gateway:01", "gateway:-1"} {
		if _, err := core.NormDevices([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := core.NormDevices([]string{"gateway:3", "sw9"}); err != nil || strings.Join(got, ",") != "gateway:3,sw9" {
		t.Fatalf("%v %v", got, err)
	}
	dc := &core.DaemonConfig{Groups: []core.GroupConfig{{GroupID: 3, Devices: []string{"sw1", "sw2"}}, {GroupID: 4, Devices: []string{"sw5"}}}}
	sc := NewDevScope([]string{"gateway:3"})
	sc.Bind(func() *core.DaemonConfig { return dc })
	if !sc.Allows("sw1", nil) || !sc.Allows("SW2", nil) || sc.Allows("sw5", nil) || sc.Allows("sw9", nil) {
		t.Error("devices of gateway 3")
	}
	if !sc.AllowsGateway(3) || sc.AllowsGateway(4) {
		t.Error("which gateways")
	}
	dc.Groups[0].Devices = append(dc.Groups[0].Devices, "sw7") // added later
	if !sc.Allows("sw7", nil) {
		t.Error("a device added to the gateway later")
	}
	dev := NewDevScope([]string{"sw1"})
	dev.Bind(func() *core.DaemonConfig { return dc })
	if dev.AllowsGateway(3) || !dev.Allows("sw1", nil) {
		t.Error("a device-only caller")
	}
	// the key and the source both have to name the gateway
	both := NewDevScope([]string{"gateway:3"}, []string{"gateway:4"})
	both.Bind(func() *core.DaemonConfig { return dc })
	if both.AllowsGateway(3) || both.AllowsGateway(4) || both.Allows("sw1", nil) {
		t.Error("the stricter list wins")
	}
	if !((*core.DevScope)(nil)).AllowsGateway(9) {
		t.Error("no limit")
	}
	if n, ok := AlertSubjectGateway("group 12 v4"); !ok || n != 12 {
		t.Errorf("subject %d %v", n, ok)
	}
}
