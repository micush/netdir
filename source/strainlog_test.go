package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"netdir/internal/core"
	"netdir/internal/web"
)

// A cluster node (this one or another) going over the limit is logged by the cluster loop, and again when it clears.
func TestClusterLogsHostStrain(t *testing.T) {
	web.FailDelay = 0
	old, oldLog := core.HostLoadFn, slog.Default()
	t.Cleanup(func() { core.HostLoadFn = old; slog.SetDefault(oldLog) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	load := core.HostLoad{CPU: 10, Mem: 40, Disk: 50, DiskMount: "/"}
	core.HostLoadFn = func() (core.HostLoad, bool) { return load, true }
	a, b := newTNode(t, "A"), newTNode(t, "B")
	a.join2(t, b)
	a.sync()
	a.mg.cl.LogStrain()
	if strings.Contains(buf.String(), "host load") {
		t.Fatalf("quiet cluster logged: %s", buf.String())
	}
	load = core.HostLoad{CPU: 10, Mem: 92, Disk: 50, DiskMount: "/"} // both test nodes share this reading
	a.sync()
	a.mg.cl.LogStrain()
	out := buf.String()
	if strings.Count(out, "is over 85%: memory 92%") != 2 || !strings.Contains(out, "level=WARN") {
		t.Fatalf("over the limit (this node and its peer): %s", out)
	}
	buf.Reset()
	a.mg.cl.LogStrain()
	if strings.Contains(buf.String(), "host load") {
		t.Fatalf("logged again with nothing new: %s", buf.String())
	}
	load = core.HostLoad{CPU: 10, Mem: 40, Disk: 50, DiskMount: "/"}
	a.sync()
	a.mg.cl.LogStrain()
	if out := buf.String(); strings.Count(out, "back at 85% or below") != 2 || !strings.Contains(out, "level=INFO") {
		t.Fatalf("cleared: %s", out)
	}
}
