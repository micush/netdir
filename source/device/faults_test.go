package device

import (
	"context"
	"net"
	"testing"
	"time"
)

// faultDrv is a device whose only resources are sensors.
type faultDrv struct{ sensors []Sensor }

func (faultDrv) Facts(context.Context) (Facts, error)            { return Facts{Hostname: "sw"}, nil }
func (faultDrv) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (faultDrv) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (faultDrv) Config(context.Context) (string, error)          { return "", ErrUnsupported }
func (faultDrv) Show(context.Context, string) (string, error)    { return "", ErrUnsupported }
func (faultDrv) Close(context.Context)                           {}
func (f faultDrv) Resources(context.Context) (Resources, error) {
	return Resources{Sensors: f.sensors}, nil
}

func TestSensorFault(t *testing.T) {
	for state, want := range map[string]bool{"ok": false, "Normal": false, "": false, "absent": false, "notInserted": false, "Not present": false, "unknown": false,
		"failed": true, "Fail": true, "fault": true, "Critical": true, "alarm": true, "warning": true, "shutdown": true, "nonOperational": true} {
		if sensorFault(state) != want {
			t.Errorf("sensorFault(%q) = %v", state, !want)
		}
	}
}

// Any device that reads sensors gets the purple count of the ones in a fault state, unless it says alerts=off.
func TestMonitorCountsSensorFaults(t *testing.T) {
	regMu.Lock()
	registry["faulttest"] = func(Device, Credential) (Driver, error) {
		return faultDrv{[]Sensor{{Name: "Fan 1", Kind: "fan", State: "ok"}, {Name: "Fan 2", Kind: "fan", State: "failed"},
			{Name: "PSU 2", Kind: "psu", State: "absent"}, {Name: "Temp", Kind: "temperature", State: "Critical"}, {Name: "Temp 2", Kind: "temperature"}}}, nil
	}
	regMu.Unlock()
	t.Cleanup(func() { regMu.Lock(); delete(registry, "faulttest"); regMu.Unlock() }) // the other tests walk the registry
	od := dialFn
	dialFn = func(context.Context, string) (net.Conn, error) { c, _ := net.Pipe(); return c, nil }
	t.Cleanup(func() { dialFn = od })
	d := Device{Name: "sw1", Platform: "faulttest", Address: "192.0.2.1", Credential: "x"}
	quiet := d
	quiet.Name, quiet.Options = "sw2", map[string]string{"alerts": "off"}
	m := NewMonitor()
	m.IdleReach, m.IdleFacts = 0, 0
	now := time.Unix(1_800_000_000, 0)
	m.Check(context.Background(), []Device{d, quiet}, []Credential{{Name: "x", Token: "t"}}, now)
	s := m.Snapshot()
	if h := s["sw1"]; h.Status != "ok" || h.AlertCount != 2 || h.Detail != "faulttest: 2 alerts" {
		t.Errorf("sw1: %+v", h)
	}
	if h := s["sw2"]; h.AlertCount != 0 || h.Detail != "answering" {
		t.Errorf("alerts=off: %+v", h)
	}
}
