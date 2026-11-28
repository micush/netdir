package devices

import (
	"context"
	"errors"
	"testing"

	"netdir/device"
)

// fakeDriver is a driver with no detailed requests: they answer ErrUnsupported, and neighbors lose their detail unless asked.
type fakeDriver struct{ device.Driver }

func (fakeDriver) Neighbors(context.Context) ([]device.Neighbor, error) {
	return []device.Neighbor{{LocalPort: "p1", Protocol: "lldp", Detail: map[string]any{"ttl": 120}}}, nil
}

func TestRunDeviceOpDetail(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"ports", "routes", "routing", "firewall", "resources", "vlans", "api", "api_catalog"} {
		if _, err := RunDeviceOp(ctx, fakeDriver{}, op, "", false, false); !errors.Is(err, device.ErrUnsupported) {
			t.Errorf("%s: %v", op, err)
		}
		if _, known := DeviceOps[op]; !known {
			t.Errorf("%s is not an op", op)
		}
	}
	v, _ := RunDeviceOp(ctx, fakeDriver{}, "neighbors", "", false, false)
	if v.([]device.Neighbor)[0].Detail != nil {
		t.Error("neighbors carries the detail")
	}
	v, _ = RunDeviceOp(ctx, fakeDriver{}, "neighbor_details", "", false, false)
	if v.([]device.Neighbor)[0].Detail["ttl"] != 120 {
		t.Error("neighbor_details lost the detail")
	}
}

type textAPIDriver struct{ device.Driver }

func (textAPIDriver) APIGet(context.Context, string) (any, bool, error) { return "a file", true, nil }
func (textAPIDriver) APICatalog(context.Context) (any, error)           { return nil, nil }

func TestAPITextNotForReadOnly(t *testing.T) {
	ctx := context.Background()
	if v, err := RunDeviceOp(ctx, textAPIDriver{}, "api", "/x", false, false); err != nil || v != "a file" {
		t.Errorf("rw: %v %v", v, err)
	}
	if _, err := RunDeviceOp(ctx, textAPIDriver{}, "api", "/x", true, false); err == nil {
		t.Error("a read-only account got a text answer")
	}
}
