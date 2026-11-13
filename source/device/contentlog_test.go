package device

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clDevice(t *testing.T, opts map[string]string) (Device, string) {
	dir := t.TempDir()
	old := ContentLogDir
	ContentLogDir = dir
	t.Cleanup(func() { ContentLogDir = old })
	st := &smaxState{}
	d := smaxStub(t, st)
	d.Name = "smaxlog"
	for k, v := range opts {
		d.Options[k] = v
	}
	return d, dir
}

func clRead(t *testing.T, dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "smaxlog.log"))
	return string(b)
}

func TestContentLogOffByDefault(t *testing.T) {
	d, dir := clDevice(t, nil)
	drv, _ := Open(d, Credential{Username: "ro", Password: "pw-smax"})
	if _, err := drv.Show(context.Background(), "show requests"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "smaxlog.log")); err == nil {
		t.Fatal("a log was written with the option off")
	}
	d.Options["content_log"] = "off"
	drv, _ = Open(d, Credential{Username: "ro", Password: "pw-smax"})
	drv.Facts(context.Background())
	if clRead(t, dir) != "" {
		t.Fatal("a log was written with the option off")
	}
}

func TestContentLogRecordsRequestsAndReplies(t *testing.T) {
	d, dir := clDevice(t, map[string]string{"content_log": "on"})
	drv, _ := Open(d, Credential{Username: "ro", Password: "pw-smax"})
	if _, err := drv.Show(context.Background(), "show request 5013940"); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.Show(context.Background(), "show request 1"); err == nil { // 404: still logged, with its status
		t.Fatal("expected an error")
	}
	log := clRead(t, dir)
	if !strings.Contains(log, `"path":"/rest/223939732/ems/Request/5013940?`) || !strings.Contains(log, `"status":200`) ||
		!strings.Contains(log, "PROD and Lab server") || !strings.Contains(log, `"status":404`) || !strings.Contains(log, `"method":"GET"`) {
		t.Fatalf("log: %s", log)
	}
	for _, secret := range []string{"pw-smax", smaxTok, "hunter2", "LWSSO"} {
		if strings.Contains(log, secret) {
			t.Fatalf("%q is in the log: %s", secret, log)
		}
	}
	if !strings.Contains(log, "(not logged: sign-in)") || !strings.Contains(log, "authenticate/login") {
		t.Fatalf("the sign-in should be logged without its bodies: %s", log)
	}
	if st, err := os.Stat(filepath.Join(dir, "smaxlog.log")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
}

func TestContentLogKeepsABoundedAmount(t *testing.T) {
	d, dir := clDevice(t, map[string]string{"content_log": "on", "content_log_mb": "1", "content_log_entry_kb": "1"})
	drv, _ := Open(d, Credential{Username: "ro", Password: "pw-smax"})
	for i := 0; i < 3000; i++ {
		drv.Show(context.Background(), "show requests")
	}
	var total int64
	for _, n := range []string{"smaxlog.log", "smaxlog.log.1"} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		total += st.Size()
	}
	if total > 1<<20 {
		t.Fatalf("%d bytes kept, the limit is 1 MB", total)
	}
	if es, _ := filepath.Glob(filepath.Join(dir, "*")); len(es) != 2 {
		t.Fatalf("files: %v", es)
	}
}

func TestContentLogCutsLongBodies(t *testing.T) {
	d, dir := clDevice(t, map[string]string{"content_log": "on", "content_log_entry_kb": "1"})
	l := contentLogFor(d)
	l.record(timeNow(), "GET", "/x", nil, 200, []byte(strings.Repeat("a", 5000)), nil)
	log := clRead(t, dir)
	if !strings.Contains(log, "more bytes") || len(log) > 2000 {
		t.Fatalf("%d bytes: %.200s", len(log), log)
	}
}

func TestContentLogNeedsADirectory(t *testing.T) {
	d, _ := clDevice(t, map[string]string{"content_log": "on"})
	ContentLogDir = ""
	if contentLogFor(d) != nil {
		t.Fatal("a log with no directory")
	}
}

func timeNow() time.Time { return time.Now() }
