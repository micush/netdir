package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netdir/internal/core"
	"netdir/internal/mcp"
)

// logEnv is an MCP environment whose content log goes to a temporary directory.
func logEnv(t *testing.T, on bool, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any), string) {
	t.Helper()
	dir := t.TempDir()
	e, post := mcpEnv(t, acl...)
	mcp.StartContentLog(dir)
	mcp.McpContent.Mu.Lock()
	mcp.McpContent.Rf = nil
	mcp.McpContent.Mu.Unlock()
	t.Cleanup(func() { mcp.StartContentLog("") })
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	sup.Dc.Settings.MCPLog = on
	sup.Mu.Unlock()
	return e, post, dir
}

func setLog(e *webEnv, f func(s *core.Settings)) {
	sup := e.ws.Status.Sup()
	sup.Mu.Lock()
	f(&sup.Dc.Settings)
	sup.Mu.Unlock()
}

func readMCPLog(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "mcp-content.log"))
	return string(b)
}

func TestContentLogOffWritesNothing(t *testing.T) {
	_, post, dir := logEnv(t, false, "127.0.0.1 rw")
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if _, err := os.Stat(filepath.Join(dir, "mcp-content.log")); err == nil {
		t.Fatal("a log was written with the setting off")
	}
}

func TestContentLogHasRequestsAndReplies(t *testing.T) {
	_, post, dir := logEnv(t, true, "127.0.0.1 rw")
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	post(mcpCall("list_devices", `{"password":"hunter2x","note":"visible"}`))
	log := readMCPLog(dir)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines: %s", len(lines), log)
	}
	for _, want := range []string{`"method":"initialize"`, "protocolVersion", `"status":200`, `"from":"127.0.0.1"`, `"access":"rw"`, `"name":"list_devices"`, "visible", `"reply"`, `"request"`} {
		if !strings.Contains(log, want) {
			t.Errorf("%q is not in the log: %s", want, log)
		}
	}
	if strings.Contains(log, "hunter2x") {
		t.Fatalf("a secret of a request is in the log: %s", log)
	}
	if st, err := os.Stat(filepath.Join(dir, "mcp-content.log")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
}

func TestContentLogRefusedAndNeverTheKey(t *testing.T) {
	_, post, dir := logEnv(t, true)
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`) // nobody is listed: 403
	post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "Authorization", "Bearer netdirkey-0123456789abcdef-not-a-key")
	log := readMCPLog(dir)
	if !strings.Contains(log, `"status":403`) || !strings.Contains(log, `"status":401`) {
		t.Fatalf("refused requests should be logged: %s", log)
	}
	if strings.Contains(log, "0123456789abcdef") || strings.Contains(log, "netdirkey") {
		t.Fatalf("a key is in the log: %s", log)
	}
}

func TestContentLogKeepsABoundedAmount(t *testing.T) {
	e, post, dir := logEnv(t, true, "127.0.0.1 rw")
	setLog(e, func(s *core.Settings) { s.MCPLogMB = 1 })
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", 20000) + `"}}`
	for i := 0; i < 150; i++ {
		post(big)
	}
	var total int64
	files, _ := filepath.Glob(filepath.Join(dir, "mcp-content.log*"))
	for _, f := range files {
		st, _ := os.Stat(f)
		total += st.Size()
	}
	if len(files) != 2 || total > 1<<20 || total < 1<<19 {
		t.Fatalf("%d files, %d bytes kept; the limit is 1 MB (150 x 20 KB sent)", len(files), total)
	}
}

func TestContentLogCutsLongEntries(t *testing.T) {
	e, post, dir := logEnv(t, true, "127.0.0.1 rw")
	setLog(e, func(s *core.Settings) { s.MCPLogEntryKB = 1 })
	post(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", 5000) + `"}}`)
	log := readMCPLog(dir)
	if !strings.Contains(log, "request cut:") || len(log) > 3000 {
		t.Fatalf("%d bytes: %.300s", len(log), log)
	}
}
