package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeContentLog(t *testing.T, dir, name string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTshootBundleHoldsTheContentLog(t *testing.T) {
	n := newTNode(t, "t1")
	writeContentLog(t, n.mg.stateDir, "mcp-content.log", `{"t":"1","who":"claude-ops@10.0.0.9","request":{"method":"tools/call","params":{"name":"list_devices","arguments":{"token":"zzz-secret"}}},"status":200}`)
	tgz, err := n.mg.TshootNode(false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	files, err := untarFiles(tgz)
	if err != nil {
		t.Fatal(err)
	}
	c := string(files["netdir/mcp-content.log"])
	if !strings.Contains(c, "list_devices") || !strings.Contains(c, "claude-ops@10.0.0.9") || strings.Contains(c, "zzz-secret") {
		t.Fatalf("the bundle's content log: %s", c)
	}
	if !strings.Contains(string(files["README.txt"]), "netdir/mcp-content.log") {
		t.Error("the README does not list the content log")
	}
}
