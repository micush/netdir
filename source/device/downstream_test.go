package device

import (
	"context"
	"strings"
	"testing"
)

func netdirTools() map[string]any {
	return map[string]any{
		"list_devices": J{"instance": "aaa111", "platforms": []any{"iosxe"},
			"devices": []any{J{"name": "obs", "platform": "observium", "address": "10.9.0.5", "tags": []any{"site=dmz"}}, J{"name": "nd4", "platform": "netdir", "address": "10.9.0.9"}},
			"health":  J{"obs": J{"status": "ok", "detail": "answers"}},
			"remote":  []any{J{"name": "vcenter", "orig": "vcenter", "platform": "vcenter", "address": "10.20.0.2", "via": []any{"nd4"}, "inst": "bbb222", "status": "bad", "detail": "no answer"}}},
		"device_facts": J{"op": "facts", "asked": 2, "failed": 0, "results": []any{
			J{"device": "obs", "platform": "observium", "ok": true, "data": J{"hostname": "obs1"}, "ms": 12},
			J{"device": "vcenter", "platform": "vcenter", "ok": true, "data": J{"hostname": "vc1"}, "ms": 40}}},
		"device_show": J{"op": "show", "asked": 1, "failed": 0, "results": []any{J{"device": "obs", "platform": "observium", "ok": true, "data": "up", "ms": 3}}},
	}
}

func TestNetdirBelowAndAsk(t *testing.T) {
	d, st := dirStub(t, netdirTools())
	d.Platform = "netdir"
	d.Options = map[string]string{"node": "n2"} // an option for list_nodes: the device tools take none
	drv := open(t, d, Credential{Token: "ROKEY"})
	ds, ok := drv.(Downstream)
	if !ok {
		t.Fatal("a netdir driver is a Downstream")
	}
	ctx := context.Background()
	inst, below, err := ds.Below(ctx)
	if err != nil || inst != "aaa111" || len(below) != 3 {
		t.Fatalf("below: %v %q %+v", err, inst, below)
	}
	if below[0].Name != "obs" || below[0].Inst != "aaa111" || below[0].Status != "ok" || below[0].Detail != "answers" || len(below[0].Via) != 0 {
		t.Errorf("a device of the director itself: %+v", below[0])
	}
	if v := below[2]; v.Name != "vcenter" || v.Inst != "bbb222" || strings.Join(v.Via, ",") != "nd4" || v.Status != "bad" {
		t.Errorf("a device below it: %+v", v)
	}
	res, err := ds.Ask(ctx, "facts", []string{"vcenter", "obs"}, "")
	if err != nil || len(res) != 2 || res[1].Device != "vcenter" || !res[1].OK {
		t.Fatalf("ask: %v %+v", err, res)
	}
	last := st.calls[len(st.calls)-1]
	if last != `device_facts {"target":"obs,vcenter"}` {
		t.Errorf("the request sent down: %s", last)
	}
	if _, err := ds.Ask(ctx, "show", []string{"obs"}, "show version"); err != nil || !strings.Contains(st.calls[len(st.calls)-1], `"command":"show version"`) {
		t.Errorf("show: %v %v", err, st.calls)
	}
	if _, err := ds.Ask(ctx, "config", []string{"obs"}, ""); err == nil {
		t.Error("a configuration is not asked for down the chain")
	}
	if _, err := ds.Ask(ctx, "facts", nil, ""); err == nil {
		t.Error("no names")
	}
}

func TestOtherDirectorsAreNotDownstream(t *testing.T) {
	d, _ := dirStub(t, dirTools())
	drv := open(t, d, Credential{Token: "ROKEY"}) // dnsdir
	if _, _, err := drv.(Downstream).Below(context.Background()); err != ErrUnsupported {
		t.Errorf("dnsdir: %v", err)
	}
}

func TestNetdirFactsAndShow(t *testing.T) {
	tools := dirTools()
	tools["list_devices"] = netdirTools()["list_devices"]
	d, _ := dirStub(t, tools)
	d.Platform = "netdir"
	drv := open(t, d, Credential{Token: "ROKEY"})
	f, err := drv.Facts(context.Background())
	if err != nil || f.Vendor != "MCP Network Director" || f.Hostname != "ns1" {
		t.Fatalf("facts: %v %+v", err, f)
	}
	out, err := drv.Show(context.Background(), "show devices")
	if err != nil || !strings.Contains(out, "vcenter") {
		t.Fatalf("show devices: %v %s", err, out)
	}
	for _, bad := range []string{"show dns", "show ntp", "show query-stats", "show server-stats"} {
		if _, err := drv.Show(context.Background(), bad); err == nil {
			t.Errorf("%q: a Network Director has no such read", bad)
		}
	}
	if DefaultPort("netdir") != 22161 {
		t.Error("the port of a Network Director's GUI and MCP is 22161")
	}
}
