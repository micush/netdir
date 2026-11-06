package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemUsageReadsMeminfoAndCgroup(t *testing.T) {
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	oldV2m, oldV2c, oldV2s, oldV1l, oldV1u, oldV1s, oldMI := cgroupV2Max, cgroupV2Current, cgroupV2Stat, cgroupV1Limit, cgroupV1Usage, cgroupV1Stat, procMeminfo
	t.Cleanup(func() {
		cgroupV2Max, cgroupV2Current, cgroupV2Stat, cgroupV1Limit, cgroupV1Usage, cgroupV1Stat, procMeminfo = oldV2m, oldV2c, oldV2s, oldV1l, oldV1u, oldV1s, oldMI
	})
	procMeminfo = w("meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n")
	cgroupV2Max, cgroupV2Current, cgroupV2Stat = filepath.Join(dir, "none1"), filepath.Join(dir, "none2"), filepath.Join(dir, "none3")
	cgroupV1Limit, cgroupV1Usage, cgroupV1Stat = filepath.Join(dir, "none4"), filepath.Join(dir, "none5"), filepath.Join(dir, "none6")
	if p, err := memUsagePercent(); err != nil || p < 59.9 || p > 60.1 {
		t.Fatalf("host only: %v %v", p, err)
	}
	// a container limited to 100 MB that uses 90 MB of which 20 MB is inactive file cache: 70 %, below the host's 60 %? no, above
	cgroupV2Max = w("memory.max", "104857600\n")
	cgroupV2Current = w("memory.current", "94371840\n")
	cgroupV2Stat = w("memory.stat", "anon 1\ninactive_file 20971520\nactive_file 5\n")
	if p, _ := memUsagePercent(); p < 69.9 || p > 70.1 {
		t.Fatalf("cgroup v2: %v", p)
	}
	cgroupV2Max = w("memory.max2", "max\n") // no limit: the host figure again
	if p, _ := memUsagePercent(); p < 59.9 || p > 60.1 {
		t.Fatalf("unlimited cgroup: %v", p)
	}
	cgroupV1Limit, cgroupV1Usage, cgroupV1Stat = w("l", "100000\n"), w("u", "95000\n"), w("s", "total_inactive_file 5000\n")
	if p, _ := memUsagePercent(); p < 89.9 || p > 90.1 {
		t.Fatalf("cgroup v1: %v", p)
	}
	cgroupV1Limit = w("l2", "9223372036854771712\n") // v1 "unlimited"
	if p, _ := memUsagePercent(); p < 59.9 || p > 60.1 {
		t.Fatalf("v1 unlimited: %v", p)
	}
	procMeminfo = w("bad", "nothing here\n")
	if _, err := memUsagePercent(); err == nil {
		t.Fatal("no MemTotal must be an error")
	}
}

func TestMemGuardLimitFromEnvironment(t *testing.T) {
	t.Setenv(memGuardEnv, "70")
	if g := newMemGuard(); g.limit != 70 || g.Info().Limit != 70 {
		t.Fatalf("limit %v", g.limit)
	}
	for _, bad := range []string{"0", "100", "abc", "-5"} {
		t.Setenv(memGuardEnv, bad)
		if g := newMemGuard(); g.limit != memGuardLimit {
			t.Fatalf("%q must be ignored, got %v", bad, g.limit)
		}
	}
	t.Setenv(memGuardEnv, "")
	if g := newMemGuard(); g.limit != 85 {
		t.Fatal("default must be 85")
	}
}
