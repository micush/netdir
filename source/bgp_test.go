package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"netdir/internal/core"
)

type frrCall struct{ name, args string }

func fakeFRR(t *testing.T, fail map[string]bool) (*[]frrCall, string) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "daemons"), []byte("zebra=yes\nbgpd=no\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "frr.conf"), []byte("! old\n"), 0o640)
	oldDir, oldRun, oldReload := core.FrrDir, core.FrrRun, core.FrrCanReload
	core.FrrDir = dir
	core.FrrCanReload = func() bool { return true }
	var calls []frrCall
	var mu sync.Mutex
	core.FrrRun = func(name string, args ...string) ([]byte, error) {
		c := frrCall{name, strings.Join(args, " ")}
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		if fail[c.name+" "+c.args] {
			return []byte("boom"), os.ErrInvalid
		}
		return nil, nil
	}
	t.Cleanup(func() { core.FrrDir, core.FrrRun, core.FrrCanReload = oldDir, oldRun, oldReload })
	return &calls, dir
}
