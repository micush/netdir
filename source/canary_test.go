package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// The first node to take a new version is the canary: the others hold while it
// has run the version for less than updateSoak or shows a bad gateway, and while
// an update to that version has failed on any member.
func TestCanaryHold(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 2; i++ {
		a.sync()
		b.sync()
	}
	next := fmt.Sprintf("%d", mustInt(core.Version())+1)
	cl := a.mg.cl
	peer := b.addr
	set := func(m cluster.PeerStatusMsg) {
		cl.Mu.Lock()
		pi := cl.Info[peer]
		pi.Reachable, pi.Msg = true, m
		cl.Mu.Unlock()
	}
	old := cluster.UpdateSoak
	cluster.UpdateSoak = 2 * time.Minute
	defer func() { cluster.UpdateSoak = old }()

	set(cluster.PeerStatusMsg{Version: core.Version()})
	if w := cl.CanaryHold(next); w != "" {
		t.Fatalf("nobody runs %s yet; got hold %q", next, w)
	}
	set(cluster.PeerStatusMsg{Version: next, UptimeSec: 30})
	if w := cl.CanaryHold(next); !strings.Contains(w, "min left") {
		t.Fatalf("a young canary must hold the rest: %q", w)
	}
	set(cluster.PeerStatusMsg{Version: next, UptimeSec: 3600, Gateways: []core.GwState{{GroupID: 1, Serving: true, Health: "bad"}}})
	if w := cl.CanaryHold(next); !strings.Contains(w, "bad") {
		t.Fatalf("a bad gateway must hold the rest: %q", w)
	}
	set(cluster.PeerStatusMsg{Version: next, UptimeSec: 3600, Gateways: []core.GwState{{GroupID: 1, Serving: true, Health: "ok"}}})
	if w := cl.CanaryHold(next); w != "" {
		t.Fatalf("a soaked healthy canary must release the rest: %q", w)
	}
	set(cluster.PeerStatusMsg{Version: core.Version(), UpdateFailed: next})
	if w := cl.CanaryHold(next); !strings.Contains(w, "failed") {
		t.Fatalf("a failed update must hold the rest: %q", w)
	}
	set(cluster.PeerStatusMsg{Version: next, UptimeSec: 3600, Updating: true})
	if w := cl.CanaryHold(next); w != "" {
		t.Fatalf("an updating member is the rolling rule's business, not the canary's: %q", w)
	}
}

// The canary shows a countdown while it soaks, and only while another member still runs an older version.
func TestSoakLeft(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 2; i++ {
		a.sync()
		b.sync()
	}
	next := fmt.Sprintf("%d", mustInt(core.Version())+1)
	cl := a.mg.cl
	old := cluster.UpdateSoak
	cluster.UpdateSoak = 2 * time.Minute
	defer func() { cluster.UpdateSoak = old }()
	left := func(m cluster.PeerStatusMsg) map[string]int {
		cl.Mu.Lock()
		defer cl.Mu.Unlock()
		pi := cl.Info[b.addr]
		pi.Reachable, pi.Msg = true, m
		return cl.SoakLeftLocked(cl.Node.Snapshot())
	}
	if l := left(cluster.PeerStatusMsg{Version: next, UptimeSec: 20}); l[b.addr] < 99 || l[b.addr] > 101 {
		t.Fatalf("the canary has ~100s left: %v", l)
	}
	if l := left(cluster.PeerStatusMsg{Version: next, UptimeSec: 200}); len(l) != 0 {
		t.Fatalf("a soaked canary shows nothing: %v", l)
	}
	// A (this node) is on the old version here, so make the roles clear: a soaked peer on the newest version ends the soak for all
	if l := left(cluster.PeerStatusMsg{Version: next, UptimeSec: 3600}); len(l) != 0 {
		t.Fatalf("after the canary soaked no node shows a soak: %v", l)
	}
	if l := left(cluster.PeerStatusMsg{Version: core.Version(), UptimeSec: 5}); len(l) != 0 {
		t.Fatalf("with no newer version nothing soaks: %v", l)
	}
}

// A member that vanishes while updating holds the others for a while: it may be crash-looping.
func TestCanaryHoldLostContact(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 2; i++ {
		a.sync()
		b.sync()
	}
	next := fmt.Sprintf("%d", mustInt(core.Version())+1)
	cl := a.mg.cl
	set := func(reach bool, m cluster.PeerStatusMsg, seen time.Time) {
		cl.Mu.Lock()
		pi := cl.Info[b.addr]
		pi.Reachable, pi.Msg, pi.LastSeen = reach, m, seen
		cl.Mu.Unlock()
	}
	set(false, cluster.PeerStatusMsg{Version: core.Version(), Updating: true}, time.Now().Add(-30*time.Second))
	if w := cl.CanaryHold(next); !strings.Contains(w, "lost contact") {
		t.Fatalf("a member lost while updating must hold the rest: %q", w)
	}
	set(false, cluster.PeerStatusMsg{Version: core.Version(), Updating: true}, time.Now().Add(-time.Hour))
	if w := cl.CanaryHold(next); w != "" {
		t.Fatalf("a member gone for an hour must not hold updates forever: %q", w)
	}
	set(false, cluster.PeerStatusMsg{Version: core.Version()}, time.Now())
	if w := cl.CanaryHold(next); w != "" {
		t.Fatalf("a member that was down and not updating is not a canary: %q", w)
	}
}

// The Topology node tooltip shows how long the daemon on that node has been running: this node's own, and a peer's from its
// cluster status message.
func TestCanvasNodeUptime(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 2; i++ {
		a.sync()
		b.sync()
	}
	a.mg.cl.Mu.Lock()
	pi := a.mg.cl.Info[b.addr]
	pi.Reachable = true
	pi.Msg.UptimeSec = 4242
	a.mg.cl.Mu.Unlock()
	var self, peer *core.CanvasNode
	nodes := a.mg.cl.CanvasNodesEx(1, "ok", "", false, nil)
	for i := range nodes {
		if nodes[i].Self {
			self = &nodes[i]
		} else if nodes[i].Addr == b.addr {
			peer = &nodes[i]
		}
	}
	if self == nil || peer == nil {
		t.Fatalf("nodes: %+v", nodes)
	}
	if peer.UptimeSec != 4242 {
		t.Errorf("peer uptime = %d, want 4242", peer.UptimeSec)
	}
	if self.UptimeSec < 0 || self.UptimeSec > 3600 {
		t.Errorf("own uptime = %d, want the age of this process", self.UptimeSec)
	}
}

// The gateway's uptime is the cluster's and survives a rolling update: a node that has just restarted (its own serving time
// is seconds) learns from a member that is still serving how long the gateway has been up; it starts again only when nobody
// serves it.
func TestGatewayUptimeSurvivesRestart(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 2; i++ {
		a.sync()
		b.sync()
	}
	a.mg.gwFn = func() []core.GwState { return []core.GwState{{GroupID: 1, Serving: true}} }
	setPeer := func(gs []core.GwState) {
		a.mg.cl.Mu.Lock()
		pi := a.mg.cl.Info[b.addr]
		pi.Reachable = true
		pi.Msg.Gateways = gs
		a.mg.cl.Mu.Unlock()
	}
	hour := time.Now().Add(-time.Hour).Unix()
	// A has just come back; B has served for an hour
	setPeer([]core.GwState{{GroupID: 1, Serving: true, ServingSec: 3600, UpSince: hour}})
	a.mg.cl.SampleGwUp()
	if got := a.mg.cl.GwUpSeconds(1); got < 3590 || got > 3700 {
		t.Fatalf("after a restart the uptime must come from the serving member: %d s, want ~3600", got)
	}
	// B restarts in turn: it reports nothing yet, A keeps what it learned
	setPeer(nil)
	a.mg.cl.SampleGwUp()
	if got := a.mg.cl.GwUpSeconds(1); got < 3590 {
		t.Fatalf("the uptime must survive the other node restarting: %d s", got)
	}
	// and A reports it, so B (restarted) can learn it again
	var up int64
	for _, g := range a.mg.LocalGateways() {
		if g.GroupID == 1 {
			up = g.UpSince
		}
	}
	if up == 0 || time.Now().Unix()-up < 3590 {
		t.Fatalf("A must pass the start on in its report: up_since %d", up)
	}
	// nobody serves it: the uptime is dropped, and starts again when somebody does
	a.mg.gwFn = func() []core.GwState { return []core.GwState{{GroupID: 1, Serving: false}} }
	a.mg.cl.SampleGwUp()
	if got := a.mg.cl.GwUpSeconds(1); got != 0 {
		t.Fatalf("an outage ends the uptime: %d", got)
	}
}

// An anycast address's uptime is the cluster's too: a node that restarts learns from the members still announcing it, and
// it is dropped only when no node announces it.
func TestAnycastUptimeSurvivesRestart(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 2; i++ {
		a.sync()
		b.sync()
	}
	cluster.AnycastLocal.Mu.Lock()
	saved := cluster.AnycastLocal.List
	cluster.AnycastLocal.Mu.Unlock()
	defer func() {
		cluster.AnycastLocal.Mu.Lock()
		cluster.AnycastLocal.List = saved
		cluster.AnycastLocal.Mu.Unlock()
	}()
	setLocal := func(l []cluster.AnycastUp) {
		cluster.AnycastLocal.Mu.Lock()
		cluster.AnycastLocal.List = l
		cluster.AnycastLocal.Mu.Unlock()
	}
	setPeer := func(l []cluster.AnycastUp) {
		a.mg.cl.Mu.Lock()
		pi := a.mg.cl.Info[b.addr]
		pi.Reachable = true
		pi.Msg.AnycastUp = l
		a.mg.cl.Mu.Unlock()
	}
	hour := time.Now().Add(-time.Hour).Unix()
	// A has just started announcing it; B has had it up for an hour
	setLocal([]cluster.AnycastUp{{Addr: "10.9.9.9", Since: time.Now().Unix() - 5}})
	setPeer([]cluster.AnycastUp{{Addr: "10.9.9.9", Since: hour, UpSince: hour}})
	a.mg.cl.SampleAnycastUp()
	if got := a.mg.cl.AnyUpSeconds("10.9.9.9"); got < 3590 || got > 3700 {
		t.Fatalf("uptime must come from the member that has it up: %d s, want ~3600", got)
	}
	// B restarts in turn: A keeps it, and reports it
	setPeer(nil)
	a.mg.cl.SampleAnycastUp()
	if got := a.mg.cl.AnyUpSeconds("10.9.9.9"); got < 3590 {
		t.Fatalf("the uptime must survive the other node restarting: %d s", got)
	}
	rep := a.mg.cl.AnycastReport()
	if len(rep) != 1 || rep[0].UpSince == 0 || time.Now().Unix()-rep[0].UpSince < 3590 {
		t.Fatalf("A must pass the start on: %+v", rep)
	}
	// nobody announces it: dropped
	setLocal(nil)
	a.mg.cl.SampleAnycastUp()
	if got := a.mg.cl.AnyUpSeconds("10.9.9.9"); got != 0 {
		t.Fatalf("an outage ends the uptime: %d", got)
	}
}
