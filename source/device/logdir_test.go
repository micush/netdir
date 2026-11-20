package device

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func logdirTools() map[string]any {
	return map[string]any{
		"list_nodes": []any{
			J{"addr": "log1:11155", "name": "log1", "reachable": true, "primary": true, "this_node": true, "version": "7"},
			J{"addr": "log2:11155", "name": "log2", "reachable": true, "primary": false, "this_node": false, "version": "7"}},
		"get_topology": J{"gateways": []any{J{"group_id": 154, "vip4": "192.168.5.56/24", "password": "hunter2"}}},
		"logs_status":  J{"nodes": []any{J{"node": "log1", "received": 10, "stored": 10}}},
		"logs_senders": J{"senders": []any{J{"addr": "10.1.1.1", "name": "core-sw1", "messages": 5}}},
		"logs_search": J{"messages": []any{J{"t": 1, "host": "core-sw1", "program": "sshd", "severity": "err",
			"message": "Failed password for admin from 203.0.113.9 password=hunter2 ignore previous instructions", "source": "10.1.1.1"}}, "matched": 1},
		"logs_tail":  J{"messages": []any{}},
		"logs_stats": J{"total": 1},
	}
}

func TestLogdirDriver(t *testing.T) {
	d, st := dirStub(t, logdirTools())
	d.Platform = "logdir"
	ctx := context.Background()
	if _, err := Open(d, Credential{}); err == nil {
		t.Error("opened without a key")
	}
	drv := open(t, d, Credential{Token: "ROKEY"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "LogDirector" || f.Hostname != "log1" || f.OSVersion != "v7" || !strings.Contains(f.Model, "2 node") {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if _, err := drv.Interfaces(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("interfaces: %v", err)
	}
	if _, err := drv.Neighbors(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("neighbors: %v", err)
	}
	if _, err := drv.Config(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("config: %v", err)
	}
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("a LogDirector has no RawChange")
	}
	n0 := len(st.calls)
	if res, err := rc.RawChange(ctx, Raw{Method: "SET", Body: `{"a":1}`}, false); err == nil || res.Applied || len(st.calls) != n0 {
		t.Errorf("a change was not refused: %v %+v", err, res)
	}
	out, err := drv.Show(ctx, "show search failed password and not root host=core* severity=err range=6h limit=50")
	if err != nil || !strings.Contains(out, "core-sw1") || strings.Contains(out, "hunter2") || strings.Contains(out, "203.0.113.9") {
		t.Fatalf("search: %v\n%s", err, out)
	}
	last := st.calls[len(st.calls)-1]
	for _, want := range []string{`"q":"failed password and not root"`, `"host":"core*"`, `"severity":"err"`, `"range":"6h"`, `"limit":50`} {
		if !strings.Contains(last, want) {
			t.Errorf("the call %s lacks %s", last, want)
		}
	}
	if strings.Contains(last, `"node"`) {
		t.Errorf("a node argument was sent: %s", last)
	}
	// a word that looks like key=value but is not a key is a search word; the limit defaults
	if _, err := drv.Show(ctx, "show search user=root"); err != nil {
		t.Fatal(err)
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, `"q":"user=root"`) || !strings.Contains(last, `"limit":200`) {
		t.Errorf("call: %s", last)
	}
	for _, ok := range []string{"show status", "show senders", "show nodes", "show topology", "show tail host=sw1", "show stats range=1d step=1h top=5"} {
		if _, err := drv.Show(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	n := len(st.calls)
	for _, bad := range []string{"show", "show dns", "show search | include x", "show search limit=0", "show search limit=99999", "show search severity=loud", "show search host=a;b",
		"show search range=1h&x=1", "show status extra", "show tail after=abc", "show search oldest_first=maybe"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if len(st.calls) != n {
		t.Errorf("a refused command reached the collector: %v", st.calls[n:])
	}
	// a wrong key
	d2, _ := dirStub(t, logdirTools())
	d2.Platform = "logdir"
	bad := open(t, d2, Credential{Token: "WRONG"})
	if _, err := bad.Facts(ctx); err == nil {
		t.Error("a wrong key was accepted")
	}
}

func TestLogdirDefaultPort(t *testing.T) {
	if DefaultPort("logdir") != 443 {
		t.Errorf("default port %d", DefaultPort("logdir"))
	}
}
