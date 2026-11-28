package cluster

import (
	"testing"

	"netdir/internal/core"
)

func infosOf(names ...string) []core.ClusterNodeInfo {
	var out []core.ClusterNodeInfo
	for _, n := range names {
		out = append(out, core.ClusterNodeInfo{Name: n, Addr: n + ":1", OK: true})
	}
	return out
}

func hpart(name string, cores int, memTotal uint64, mk func(h *core.HostResult)) clusterPart[core.HostResult] {
	h := &core.HostResult{Start: 0, Step: 60, Since: 1,
		CPU: []float64{-1, -1}, CPUMax: []float64{-1, -1}, Mem: []float64{-1, -1}, IO: []float64{-1, -1}, IOMax: []float64{-1, -1},
		Rx: []float64{-1, -1}, RxMax: []float64{-1, -1}, Tx: []float64{-1, -1}, TxMax: []float64{-1, -1}, FS: []core.HostFSSeries{}}
	h.Now = core.HostNow{At: 1000, Cores: cores, MemTotal: memTotal, NetUtil: -1}
	mk(h)
	return clusterPart[core.HostResult]{Name: name, Addr: name + ":1", R: h}
}

func TestMergeHostAddsWhatAddsAndWeightsWhatDoesNot(t *testing.T) {
	a := hpart("A", 4, 8<<30, func(h *core.HostResult) {
		h.CPU, h.CPUMax = []float64{50, 40}, []float64{80, 60}
		h.Mem = []float64{50, 50}
		h.IO, h.IOMax = []float64{10, -1}, []float64{20, -1}
		h.Rx, h.RxMax, h.Tx, h.TxMax = []float64{1000, 2000}, []float64{3000, 4000}, []float64{100, 200}, []float64{300, 400}
		h.FS = []core.HostFSSeries{{Mount: "/", Pct: []float64{50, 50}}}
		h.Now.CPU, h.Now.Load = 50, [3]float64{1, 2, 3}
		h.Now.MemUsed, h.Now.MemPct = 4<<30, 50
		h.Now.SwapTotal, h.Now.SwapUsed = 1<<30, 1<<28
		h.Now.IO, h.Now.Rx, h.Now.Tx, h.Now.NetUtil = 10, 1000, 100, 5
		h.Now.FS = []core.FsUsage{{Mount: "/", Device: "/dev/sda1", Type: "ext4", Total: 100, Used: 50, Pct: 50}}
		h.Now.Ifaces = []core.IfaceNow{{Name: "eth0", Up: true, Rx: 1000, Tx: 100, UtilPct: 5}}
	})
	b := hpart("B", 12, 24<<30, func(h *core.HostResult) {
		h.CPU, h.CPUMax = []float64{10, -1}, []float64{30, -1}
		h.Mem = []float64{10, 10}
		h.IO, h.IOMax = []float64{30, 40}, []float64{50, 60}
		h.Rx, h.RxMax, h.Tx, h.TxMax = []float64{500, 600}, []float64{700, 800}, []float64{50, 60}, []float64{70, 80}
		h.FS = []core.HostFSSeries{{Mount: "/", Pct: []float64{10, 10}}, {Mount: "/var", Pct: []float64{70, 70}}}
		h.Now.CPU, h.Now.Load = 10, [3]float64{4, 5, 6}
		h.Now.MemUsed, h.Now.MemPct = 2<<30, 10
		h.Now.IO, h.Now.Rx, h.Now.Tx, h.Now.NetUtil = 30, 500, 50, 40
		h.Now.FS = []core.FsUsage{{Mount: "/", Device: "/dev/vda1", Type: "ext4", Total: 300, Used: 30, Pct: 10}, {Mount: "/var", Device: "/dev/vdb", Type: "xfs", Total: 100, Used: 70, Pct: 70}}
		h.Now.Ifaces = []core.IfaceNow{{Name: "eth0", Up: true, Rx: 500, Tx: 50, UtilPct: 40}}
	})
	r := MergeHost([]clusterPart[core.HostResult]{a, b}, infosOf("A", "B"))
	near := func(got, want float64, what string) {
		t.Helper()
		if d := got - want; d > 0.01 || d < -0.01 {
			t.Errorf("%s = %v, want %v", what, got, want)
		}
	}
	near(r.CPU[0], (50*4+10*12)/16.0, "cpu (weighted by cores)")
	near(r.CPU[1], 40, "cpu where only one node has a point")
	near(r.CPUMax[0], 80, "cpu peak (the busiest node)")
	near(r.Mem[0], (50*8+10*24)/32.0, "memory (weighted by size)")
	near(r.IO[0], 20, "disk busy (mean)")
	near(r.IO[1], 40, "disk busy where one node has a point")
	near(r.IOMax[0], 50, "disk busy peak")
	near(r.Rx[0], 1500, "in (sum)")
	near(r.Tx[1], 260, "out (sum)")
	near(r.RxMax[0], 3700, "in peak (sum of peaks)")
	if len(r.FS) != 2 || r.FS[0].Mount != "/" || r.FS[1].Mount != "/var" {
		t.Fatalf("filesystems %+v", r.FS)
	}
	near(r.FS[0].Pct[0], (50*100+10*300)/400.0, "/ use (weighted by size)")
	near(r.FS[1].Pct[0], 70, "/var use (one node)")
	n := r.Now
	if n.Cores != 16 || n.Load != [3]float64{5, 7, 9} || n.MemTotal != 32<<30 || n.MemUsed != 6<<30 || n.SwapTotal != 1<<30 || n.Rx != 1500 || n.Tx != 150 {
		t.Fatalf("now: %+v", n)
	}
	near(n.CPU, 20, "now cpu")
	near(n.MemPct, 100*6.0/32.0, "now memory")
	near(n.IO, 20, "now disk busy")
	near(n.NetUtil, 40, "busiest link")
	if len(n.FS) != 3 || n.FS[0].Mount != "A /" || n.FS[1].Mount != "B /" || n.FS[2].Mount != "B /var" {
		t.Fatalf("filesystems now (one row per node and mount): %+v", n.FS)
	}
	near(n.FS[0].Pct, 50, "A / now (the node's own figure)")
	near(n.FS[1].Pct, 10, "B / now (the node's own figure)")
	if len(n.Ifaces) != 2 || n.Ifaces[0].Name != "A eth0" || n.Ifaces[1].Name != "B eth0" {
		t.Fatalf("interfaces %+v", n.Ifaces)
	}
	if r.Cluster == nil || len(r.Cluster.Nodes) != 2 {
		t.Fatalf("cluster info %+v", r.Cluster)
	}
}

// A node that has no sample yet is not counted in the tiles (its cores, memory and rates would be zero anyway).
func TestMergeHostIgnoresANodeWithoutASample(t *testing.T) {
	a := hpart("A", 4, 8<<30, func(h *core.HostResult) { h.Now.CPU = 50; h.Now.Rx = 7 })
	b := hpart("B", 4, 8<<30, func(h *core.HostResult) { h.Now = core.HostNow{} })
	r := MergeHost([]clusterPart[core.HostResult]{a, b}, infosOf("A", "B"))
	if r.Now.Cores != 4 || r.Now.CPU != 50 || r.Now.Rx != 7 {
		t.Fatalf("now: %+v", r.Now)
	}
}
