package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ping gets its options on the command line, from the tool through the node.
func TestMCPNetToolsPingOptions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ping"), []byte("#!/bin/sh\necho \"ping $*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	_, post, k := toolsEnv(t, "paris")
	call := func(key, tool, args string) (string, bool) {
		_, m := post(mcpCall(tool, args), "Authorization", "Bearer "+key)
		return toolResult(t, m)
	}
	txt, isErr := call(k["ro"], "net_ping", `{"host":"10.1.1.1","count":3,"size":1472,"df":true,"family":4}`)
	if isErr || !strings.Contains(txt, "ping -n -c 3 -W 2 -s 1472 -M do -- 10.1.1.1") {
		t.Errorf("ping options: %v %s", isErr, txt)
	}
	for _, bad := range []string{`{"host":"10.1.1.1","count":99}`, `{"host":"10.1.1.1","size":1}`, `{"host":"10.1.1.1","family":"7"}`, `{"host":"10.1.1.1","family":6}`} {
		if txt, isErr := call(k["ro"], "net_ping", bad); !isErr {
			t.Errorf("%s: %s", bad, txt)
		}
	}
	// the new tools: a read-only key has the lookups, not the one that powers a machine on; a refused argument stops before the node is asked
	for _, c := range []struct{ tool, args, want string }{
		{"net_port", `{"host":"10.1.1.1","ports":"0"}`, "ports:"},
		{"net_tls", `{"host":"10.1.1.1","port":"99999"}`, "port:"},
		{"net_arp", `{"ip":"nope"}`, "ip:"},
	} {
		if txt, isErr := call(k["ro"], c.tool, c.args); !isErr || !strings.Contains(txt, c.want) {
			t.Errorf("%s: %v %s", c.tool, isErr, txt)
		}
	}
	if txt, isErr := call(k["ro"], "net_wake", `{"mac":"aa:bb:cc:dd:ee:ff"}`); !isErr || !strings.Contains(strings.ToLower(txt), "read") {
		t.Errorf("a read-only key woke a machine: %v %s", isErr, txt)
	}
	if txt, isErr := call(k["ro"], "net_arp", `{"ip":"192.0.2.77"}`); isErr || !strings.Contains(txt, `"found":false`) {
		t.Errorf("net_arp: %v %s", isErr, txt)
	}
}
