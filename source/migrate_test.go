package main

import (
	"path/filepath"
	"testing"

	"netdir/internal/core"
)

func TestDefaultLocations(t *testing.T) {
	if core.ConfPath != "/var/lib/netdir/netdir.conf" || filepath.Dir(core.ConfPath) != defaultStateDir {
		t.Fatalf("the config lives in the state directory: %s vs %s", core.ConfPath, defaultStateDir)
	}
	if core.StatusSocket != "/run/netdir/netdir.sock" {
		t.Fatalf("socket: %s", core.StatusSocket)
	}
}
