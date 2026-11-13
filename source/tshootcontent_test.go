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

func TestTshootContentLogIsCleaned(t *testing.T) {
	dir := t.TempDir()
	writeContentLog(t, dir, "mcp-content.log",
		`{"t":"1","from":"10.0.0.5","who":"laptop@10.0.0.5","request":{"params":{"arguments":{"password":"hunter2x","note":"keep"}}},"reply":{"result":{"content":[{"text":"neighbor 192.0.2.1 password hunter3y and community public"}]}},"status":200}`,
		`not json at all: secret hunter4z`)
	out, n := tshootContentLog(dir, true)
	s := string(out)
	for _, leak := range []string{"hunter2x", "hunter3y", "hunter4z"} {
		if strings.Contains(s, leak) {
			t.Errorf("%q is in the bundle's copy: %s", leak, s)
		}
	}
	for _, keep := range []string{`"from":"10.0.0.5"`, "keep", "192.0.2.1", `"status":200`, "laptop@10.0.0.5"} {
		if !strings.Contains(s, keep) {
			t.Errorf("%q must stay: %s", keep, s)
		}
	}
	if n < 3 || len(strings.Split(strings.TrimSpace(s), "\n")) != 2 {
		t.Errorf("%d removals, %q", n, s)
	}
}

func TestTshootContentLogStates(t *testing.T) {
	dir := t.TempDir()
	if out, _ := tshootContentLog(dir, false); !strings.Contains(string(out), "log is off") {
		t.Errorf("off: %s", out)
	}
	if out, _ := tshootContentLog(dir, true); !strings.Contains(string(out), "no entries yet") {
		t.Errorf("empty: %s", out)
	}
	// entries kept from before it was turned off are still shown
	writeContentLog(t, dir, "mcp-content.log", `{"t":"1","status":200}`)
	if out, _ := tshootContentLog(dir, false); !strings.Contains(string(out), `"status":200`) {
		t.Errorf("old entries: %s", out)
	}
}

func TestTshootContentLogIsTheNewestPart(t *testing.T) {
	dir := t.TempDir()
	old := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		old = append(old, `{"n":"old","pad":"`+strings.Repeat("o", 50000)+`"}`)
	}
	writeContentLog(t, dir, "mcp-content.log.1", old...)
	writeContentLog(t, dir, "mcp-content.log", `{"n":"first-of-current"}`, `{"n":"newest"}`)
	out, _ := tshootContentLog(dir, true)
	s := string(out)
	if len(out) > tshootContentMax+4096 {
		t.Fatalf("%d bytes, the most is %d", len(out), tshootContentMax)
	}
	if !strings.Contains(s, "newest") || !strings.Contains(s, "first-of-current") || strings.Index(s, "first-of-current") > strings.Index(s, "newest") {
		t.Fatalf("the newest entries must come last and be kept")
	}
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
			t.Fatalf("a line was cut in the middle: %.60s…", l)
		}
	}
}

func TestTshootHalve(t *testing.T) {
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, `{"n":`+string(rune('0'+i))+`}`)
	}
	out := string(tshootHalve([]byte(strings.Join(lines, "\n") + "\n")))
	if !strings.HasPrefix(out, `{"note": "older entries cut to fit"}`) || !strings.Contains(out, `{"n":9}`) || strings.Contains(out, `{"n":0}`) {
		t.Fatalf("%s", out)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
			t.Fatalf("a line was cut in the middle: %q", l)
		}
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
