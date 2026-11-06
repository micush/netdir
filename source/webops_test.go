package main

import (
	"os"
	"regexp"
	"testing"
)

// Every operation a web route names must exist in ops.go (one route once pointed at a name that did not).
func TestWebRoutesNameKnownOps(t *testing.T) {
	web, _ := os.ReadFile("web_mgmt.go")
	ops, _ := os.ReadFile("ops.go")
	al, _ := os.ReadFile("alerts_rules.go") // the alerts.* operations are handled there (Mgmt.alertsOp)
	ops = append(ops, al...)
	bk, _ := os.ReadFile("backup.go") // so are the backup.* ones
	ops = append(ops, bk...)
	for _, m := range regexp.MustCompile(`w\.op\("([a-z.\-]+)"`).FindAllSubmatch(web, -1) {
		if !regexp.MustCompile(`"` + regexp.QuoteMeta(string(m[1])) + `"`).Match(ops) {
			t.Errorf("web_mgmt.go uses op %q that ops.go does not handle", m[1])
		}
	}
}
