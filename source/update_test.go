package main

import (
	"os"
	"path/filepath"
	"testing"

	"netdir/internal/core"
)

// A relative --state-dir used to leak into GOPATH ("must be absolute path")
// and break the native build; paths are made absolute up front.
func TestNewMgmtMakesPathsAbsolute(t *testing.T) {
	d := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	dc := core.NewDaemonConfig()
	mg, err := NewMgmt("netdir.conf", "state", dc)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(mg.stateDir) || !filepath.IsAbs(mg.confPath) {
		t.Fatalf("paths must be absolute: %q %q", mg.stateDir, mg.confPath)
	}
}
