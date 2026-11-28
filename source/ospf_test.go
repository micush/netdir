package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netdir/internal/core"
)

func ospfDC(on bool) *core.DaemonConfig {
	dc := core.NewDaemonConfig()
	dc.Groups[0].ExtraVIPs = []string{"203.0.113.53", "2001:db8::53"}
	if on {
		dc.OSPF = &core.OSPFConfig{RouterID: "192.0.2.10", Interfaces: []core.OSPFInterface{{Name: "eth0", Network: "point-to-point"}}}
	}
	return dc
}

func TestOSPFSetOperateAndKeyOmitted(t *testing.T) {
	e := bgpEnv(t)
	if err := e.mg.OSPFSet(core.OSPFConfig{RouterID: "192.0.2.10"}, "t"); err == nil {
		t.Error("router id without interface accepted")
	}
	if err := e.mg.OSPFSet(core.OSPFConfig{RouterID: "192.0.2.10", Interfaces: []core.OSPFInterface{{Name: "eth0"}, {Name: "eth1"}}}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ := e.mg.LiveConfig()
	if !dc.OSPF.Active() || len(dc.OSPF.Interfaces) != 2 {
		t.Fatalf("%+v", dc.OSPF)
	}
	if err := e.mg.OSPFOperate(core.OSPFOperateArgs{Interface: "eth1", Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.mg.OSPFOperate(core.OSPFOperateArgs{Interface: "nope", Enabled: false}, "t"); err == nil {
		t.Error("unknown interface accepted")
	}
	// saving the settings again keeps the disabled flag
	if err := e.mg.OSPFSet(core.OSPFConfig{RouterID: "192.0.2.11", Interfaces: []core.OSPFInterface{{Name: "eth0"}, {Name: "eth1"}}}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ = e.mg.LiveConfig()
	if !dc.OSPF.Interfaces[1].Disabled || dc.OSPF.Interfaces[0].Disabled || dc.OSPF.RouterID != "192.0.2.11" {
		t.Fatalf("flags not carried: %+v", dc.OSPF)
	}
	if err := e.mg.OSPFOperate(core.OSPFOperateArgs{Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.mg.OSPFStatus(); !st.Config.Disabled || st.Config.Active() {
		t.Errorf("not disabled: %+v", st.Config)
	}
	// clearing the interfaces removes the block (and the disabled flag with it)
	if err := e.mg.OSPFSet(core.OSPFConfig{}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ = e.mg.LiveConfig()
	if dc.OSPF != nil {
		t.Errorf("block kept: %+v", dc.OSPF)
	}
	if err := e.mg.OSPFOperate(core.OSPFOperateArgs{Enabled: true}, "t"); err == nil {
		t.Error("operate without interfaces accepted")
	}
	raw, _ := os.ReadFile(e.mg.confPath)
	if strings.Contains(string(raw), `"ospf"`) {
		t.Error("ospf key written while unused")
	}
}

// With dnsdir installed on the host, netdir leaves FRR alone for OSPF as it does for BGP: OSPF is not active, the
// settings are refused (clearing them is still allowed), FRR files are not touched and its daemons are not switched.
func TestOSPFBlockedWithDnsdir(t *testing.T) {
	calls, dir := fakeFRR(t, nil)
	e := bgpEnv(t)
	withDnsdir(t)
	o := &core.OSPFConfig{RouterID: "192.0.2.10", Interfaces: []core.OSPFInterface{{Name: "eth0"}}}
	if o.Active() {
		t.Error("OSPF active with dnsdir installed")
	}
	if err := e.mg.OSPFSet(*o, "t"); err == nil || !strings.Contains(err.Error(), "AnyName") {
		t.Errorf("OSPF settings accepted with dnsdir installed: %v", err)
	}
	if st, _ := e.mg.OSPFStatus(); st.Blocked == "" {
		t.Error("status does not say OSPF is blocked")
	}
	if got := core.AnycastRouteGate(nil, o, "192.0.2.9"); got == "" {
		t.Error("the gate let an address through on OSPF that cannot run")
	}
	m := core.NewBGPManager(t.TempDir())
	n := len(*calls)
	dc := ospfDC(true)
	if r := m.ApplyNow(dc); !r.OK || !strings.Contains(r.Detail, "AnyName") || len(*calls) != n {
		t.Errorf("FRR was touched: %+v %v", r, *calls)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "daemons")); strings.Contains(string(b), "ospfd=yes") {
		t.Errorf("ospfd switched on:\n%s", b)
	}
}
