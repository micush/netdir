package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netdir/internal/core"
)

// lldpFake replaces systemctl, the lldpd check, lldpcli and the sibling check for one test, and records what was run.
type lldpFake struct {
	active, enabled, installed, deferred bool
	calls                                []string
	cli                                  []byte
}

func newLLDPFake(t *testing.T) *lldpFake {
	t.Helper()
	f := &lldpFake{installed: true}
	oDir, oRun, oInst, oCli, oDef := core.LldpDir, core.LldpRun, core.LldpInstalled, core.LldpCli, core.LldpDefer
	t.Cleanup(func() {
		core.LldpDir, core.LldpRun, core.LldpInstalled, core.LldpCli, core.LldpDefer = oDir, oRun, oInst, oCli, oDef
	})
	core.LldpDir = filepath.Join(t.TempDir(), "lldpd.d")
	core.LldpRun = func(args ...string) ([]byte, error) {
		switch args[0] {
		case "is-active", "is-enabled":
			if (args[0] == "is-active" && f.active) || (args[0] == "is-enabled" && f.enabled) {
				return nil, nil
			}
			return nil, errors.New("no")
		case "enable":
			f.active, f.enabled = true, true
		case "disable":
			f.active, f.enabled = false, false
		}
		f.calls = append(f.calls, strings.Join(args, " "))
		return nil, nil
	}
	core.LldpInstalled = func() bool { return f.installed }
	core.LldpCli = func(args ...string) ([]byte, error) { return f.cli, nil }
	core.LldpDefer = func() bool { return f.deferred }
	return f
}

func (f *lldpFake) did() string { s := strings.Join(f.calls, "; "); f.calls = nil; return s }

func TestLLDPStatusAndText(t *testing.T) {
	f := newLLDPFake(t)
	f.cli, _ = os.ReadFile("testdata/lldp_neighbors_json0.json")
	if st := core.LldpStatus(false); st.Running || st.ManagedBy != "netdir" || len(st.Neighbors) != 0 || st.Neighbors == nil {
		t.Fatalf("stopped: %+v", st)
	}
	core.ApplyLLDP(true)
	st := core.LldpStatus(true)
	if st.ManagedBy != "netdir" || !st.Running || len(st.Neighbors) != 2 {
		t.Fatalf("on: %+v", st)
	}
	if txt := lldpStatusText(st); !strings.Contains(txt, "lldpd on this node: running") || !strings.Contains(txt, "GigabitEthernet1/0/7 (") || !strings.Contains(txt, "5 (untagged), 20") {
		t.Fatalf("text:\n%s", txt)
	}
	f.deferred = true
	if st := core.LldpStatus(true); st.ManagedBy != "dnsdir" || !strings.Contains(lldpStatusText(st), "AnyName") {
		t.Fatalf("deferred: %+v\n%s", st, lldpStatusText(st))
	}
	f.deferred = false
	f.installed = false
	if txt := lldpStatusText(core.LldpStatus(true)); !strings.Contains(txt, "not installed") || strings.Contains(txt, "INTERFACE") {
		t.Fatalf("not installed:\n%s", txt)
	}
}

func TestLLDPOverTheAPIAndMCP(t *testing.T) {
	f := newLLDPFake(t)
	f.cli, _ = os.ReadFile("testdata/lldp_neighbors_json0.json")
	e, post := mcpEnv(t, "127.0.0.1 rw")
	if _, m := post(mcpCall("get_lldp", `{}`)); m["error"] == nil {
		t.Fatalf("get_lldp is not an MCP tool any more: %v", m)
	}
	if err := e.mg.LLDPSet(true, "test"); err != nil {
		t.Fatal(err)
	}
	if dc, err := core.LoadConfig(e.conf); err != nil || !dc.Settings.LLDP {
		t.Fatalf("not saved: %v", err)
	}
	f.active = true
	if _, m := post(mcpCall("api_get", `{"path":"/api/lldp"}`)); m["error"] == nil {
		t.Fatalf("api_get is not an MCP tool any more: %v", m)
	}
	// the Settings page saves it with the rest of the ntp block
	guiEditConfig(t, e, `{"settings":{"lldp":false}}`)
	if dc, _ := core.LoadConfig(e.conf); dc.Settings.LLDP {
		t.Fatal("not switched off")
	}
	found := false
	for _, v := range e.mg.VersionsList() {
		if strings.Contains(v.Note, "lldp: on") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no history entry: %+v", e.mg.VersionsList())
	}
}
