package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidHHMM(t *testing.T) {
	for _, s := range []string{"00:00", "02:30", "23:59"} {
		if !ValidHHMM(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "2:30", "24:00", "12:60", "ab:cd", "12-30", "12:300"} {
		if ValidHHMM(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestReadPowerPending(t *testing.T) {
	d := t.TempDir()
	if p := ReadPowerPending(filepath.Join(d, "none")); p.Scheduled {
		t.Fatal("nothing scheduled must read as not scheduled")
	}
	f := filepath.Join(d, "scheduled")
	os.WriteFile(f, []byte("USEC=1790873818000000\nWARN_WALL=1\nMODE=reboot\nWALL_MESSAGE=\n"), 0o644)
	p := ReadPowerPending(f)
	if !p.Scheduled || p.Action != "restart" || p.At != "2026-10-01T16:56:58Z" {
		t.Fatalf("%+v", p)
	}
	os.WriteFile(f, []byte("USEC=1790873818000000\nMODE=poweroff\n"), 0o644)
	if p := ReadPowerPending(f); p.Action != "shutdown" {
		t.Fatalf("%+v", p)
	}
}
