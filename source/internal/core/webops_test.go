package core

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every operation a web route names must exist in ops.go (one route once pointed at a name that did not).
func TestWebRoutesNameKnownOps(t *testing.T) {
	web := readSource(t, "web_mgmt.go")
	ops := readSource(t, "ops.go")
	ops = append(ops, readSource(t, "alerts_rules.go")...) // the alerts.* operations are handled there (Mgmt.alertsOp)
	ops = append(ops, readSource(t, "backup.go")...)       // so are the backup.* ones
	for _, m := range regexp.MustCompile(`w\.op\("([a-z.\-]+)"`).FindAllSubmatch(web, -1) {
		if !regexp.MustCompile(`"` + regexp.QuoteMeta(string(m[1])) + `"`).Match(ops) {
			t.Errorf("web_mgmt.go uses op %q that ops.go does not handle", m[1])
		}
	}
}

// readSource is a Go file of this program as one text: the file of that name in the source directory and in each of its packages
// under internal/ (a file's code can be in several), found from wherever the test runs.
func readSource(t *testing.T, name string) []byte {
	t.Helper()
	root := sourceRoot(t)
	paths, _ := filepath.Glob(filepath.Join(root, "internal", "*", name))
	paths = append([]string{filepath.Join(root, name)}, paths...)
	var out []byte
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, b...)
			out = append(out, '\n')
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s not found", name)
	}
	return out
}

// sourceRoot is the source directory (the one with go.mod), from wherever the test runs.
func sourceRoot(t *testing.T) string {
	t.Helper()
	root, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
		up := filepath.Dir(root)
		if up == root {
			t.Fatal("no go.mod above the test's directory")
		}
		root = up
	}
}
