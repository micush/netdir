package cluster

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestStrainLogTransitions(t *testing.T) {
	var s strainLog
	say := func(l core.HostLoad) (string, bool) { return s.note("k", "ns1", l) }
	if m, _ := say(core.HostLoad{CPU: 10, Mem: 40, Disk: 50}); m != "" {
		t.Fatalf("quiet: %q", m)
	}
	if m, _ := say(core.HostLoad{CPU: 85, Mem: 85, Disk: 85}); m != "" {
		t.Fatalf("85%% is not over: %q", m)
	}
	m, warn := say(core.HostLoad{CPU: 91, Mem: 40, Disk: 88, DiskMount: "/var"})
	if !warn || !strings.Contains(m, "node ns1 is over 85%: CPU 91%, disk 88% (/var)") || !strings.Contains(m, "amber") {
		t.Fatalf("over: %q", m)
	}
	if m, _ := say(core.HostLoad{CPU: 95, Mem: 40, Disk: 89, DiskMount: "/var"}); m != "" {
		t.Fatalf("a moving reading is not logged again: %q", m)
	}
	m, warn = say(core.HostLoad{CPU: 95, Mem: 90, Disk: 89, DiskMount: "/var"})
	if !warn || !strings.Contains(m, "now over 85%") || !strings.Contains(m, "memory 90%") {
		t.Fatalf("another one over: %q", m)
	}
	m, warn = say(core.HostLoad{CPU: 20, Mem: 41, Disk: 50})
	if warn || !strings.Contains(m, "back at 85% or below") || !strings.Contains(m, "CPU 20%") {
		t.Fatalf("cleared: %q", m)
	}
	if m, _ := say(core.HostLoad{CPU: 20, Mem: 41, Disk: 50}); m != "" {
		t.Fatalf("still clear: %q", m)
	}
}
