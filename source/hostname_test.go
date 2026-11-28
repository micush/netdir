package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netdir/internal/core"
)

func withFakeHost(t *testing.T, old string, run func(name string, args ...string) error) (hosts, hostname string) {
	t.Helper()
	d := t.TempDir()
	hosts, hostname = filepath.Join(d, "hosts"), filepath.Join(d, "hostname")
	sh, sn, sc, scur, sf := core.HostsFile, core.HostnameFile, core.HostCmd, core.HostCurrent, core.HostCmdIsFake
	core.HostsFile, core.HostnameFile, core.HostCmd, core.HostCurrent, core.HostCmdIsFake = hosts, hostname, run, func() string { return old }, true
	t.Cleanup(func() {
		core.HostsFile, core.HostnameFile, core.HostCmd, core.HostCurrent, core.HostCmdIsFake = sh, sn, sc, scur, sf
	})
	return
}

func TestNodeRename(t *testing.T) {
	var calls [][]string
	hosts, _ := withFakeHost(t, "old", func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	})
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n127.0.1.1 old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := &Mgmt{}
	msg, err := m.NodeRename("New", "tester")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hosts)
	if string(b) != "127.0.0.1 localhost\n127.0.1.1\tnew\n" {
		t.Fatalf("hosts: %q", b)
	}
	if st, _ := os.Stat(hosts); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if len(calls) != 1 || strings.Join(calls[0], " ") != "hostnamectl set-hostname new" || !strings.Contains(msg, "new") {
		t.Fatalf("calls %v msg %q", calls, msg)
	}
	// the same name again is a no-op
	withFakeHost(t, "new", func(string, ...string) error { t.Fatal("must not run"); return nil })
	if msg, err := m.NodeRename("NEW", "tester"); err != nil || !strings.Contains(msg, "already") {
		t.Fatalf("same name: %q %v", msg, err)
	}
}

// When the host name cannot be set, /etc/hosts goes back to what it was; a bad name touches nothing.
func TestNodeRenameFailureRestoresHosts(t *testing.T) {
	hosts, _ := withFakeHost(t, "old", func(string, ...string) error { return errors.New("denied") })
	orig := "127.0.0.1 localhost\n127.0.1.1 old\n"
	os.WriteFile(hosts, []byte(orig), 0o644)
	m := &Mgmt{}
	if _, err := m.NodeRename("new", "t"); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(hosts); string(b) != orig {
		t.Fatalf("hosts not restored: %q", b)
	}
	if _, err := m.NodeRename("bad name;", "t"); err == nil {
		t.Fatal("a bad name must be refused")
	}
	if b, _ := os.ReadFile(hosts); string(b) != orig {
		t.Fatalf("hosts changed by a refused name: %q", b)
	}
}
