package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDnsdir makes bgpBlocked see a dnsdir install (a marker file in a temp dir) for the test.
func withDnsdir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dnsdir")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(setDnsdir([]string{p}, ""))
	return p
}

func TestBGPBlockedFollowsDnsdir(t *testing.T) {
	defer setDnsdir([]string{filepath.Join(t.TempDir(), "absent")}, "")()
	if BgpBlocked() != "" {
		t.Fatal("blocked without dnsdir")
	}
	p := withDnsdir(t)
	if BgpBlocked() == "" {
		t.Fatal("not blocked with dnsdir installed")
	}
	os.Remove(p)
	if BgpBlocked() != "" {
		t.Fatal("block did not lift after dnsdir went away")
	}
}

// With dnsdir installed netdir must not touch frr.conf, the daemons file, the marker or the FRR service, even when
// it had managed FRR before and the config still has an AS.
func TestBGPApplyLeavesFRRAloneWithDnsdir(t *testing.T) {
	calls, dir := fakeFRR(t, nil)
	state := t.TempDir()
	m := NewBGPManager(state)
	if r := m.ApplyNow(bgpDC(true)); !r.OK { // netdir managed FRR before dnsdir was installed
		t.Fatalf("%+v", r)
	}
	dm, _ := os.ReadFile(filepath.Join(dir, "daemons"))
	n := len(*calls)
	os.WriteFile(filepath.Join(dir, "frr.conf"), []byte("! dnsdir wrote this\nrouter bgp 65000\n"), 0o640)

	withDnsdir(t)
	for _, enabled := range []bool{true, false} {
		if r := m.ApplyNow(bgpDC(enabled)); !r.OK || !strings.Contains(r.Detail, "AnyName") {
			t.Fatalf("enabled=%v: %+v", enabled, r)
		}
	}
	got, _ := os.ReadFile(filepath.Join(dir, "frr.conf"))
	if string(got) != "! dnsdir wrote this\nrouter bgp 65000\n" {
		t.Fatalf("frr.conf was rewritten:\n%s", got)
	}
	if now, _ := os.ReadFile(filepath.Join(dir, "daemons")); string(now) != string(dm) {
		t.Fatalf("daemons changed:\n%s", now)
	}
	if _, err := os.Stat(m.markerPath()); err != nil {
		t.Fatal("the marker was removed")
	}
	if len(*calls) != n {
		t.Fatalf("FRR was run: %v", (*calls)[n:])
	}
	if bgpDC(true).BGP.Active() {
		t.Fatal("BGP counts as active with dnsdir installed")
	}
}

// setDnsdir points the dnsdir markers (and, when conf is not "", its configuration) somewhere else and returns what puts them back.
func setDnsdir(markers []string, conf string) func() {
	DnsdirMu.Lock()
	om, oc := DnsdirMarkers, DnsdirConfPath
	DnsdirMarkers = markers
	if conf != "" {
		DnsdirConfPath = conf
	}
	DnsdirMu.Unlock()
	return func() {
		DnsdirMu.Lock()
		DnsdirMarkers, DnsdirConfPath = om, oc
		DnsdirMu.Unlock()
	}
}
