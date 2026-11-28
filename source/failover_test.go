package main

import (
	"context"
	"testing"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// Three nodes, the primary goes silent: after the wait, and only with a majority agreeing, one replica (the same one every
// time) promotes itself.
func TestAutomaticFailover(t *testing.T) {
	defer func(d time.Duration) { cluster.FailoverAfter = d }(cluster.FailoverAfter)
	cluster.FailoverAfter = 50 * time.Millisecond
	a, b, c := newTNode(t, "A"), newTNode(t, "B"), newTNode(t, "C")
	b.join(a)
	c.join(a)
	for i := 0; i < 3; i++ {
		a.sync()
		b.sync()
		c.sync()
	}
	if got := len(a.mg.cl.Node.Snapshot().Peers) + 1; got != 3 {
		t.Fatalf("cluster has %d members", got)
	}
	a.mg.cl.Stop() // the primary stops answering (its process keeps running)
	round := func() {
		for _, n := range []*tnode{b, c} {
			n.mg.cl.SyncOnce(context.Background()) // fails while the primary is gone; that is the point
			n.mg.cl.FailoverTick()
		}
	}
	round()
	if b.mg.cl.Node.Snapshot().Role != cluster.RoleReplica || c.mg.cl.Node.Snapshot().Role != cluster.RoleReplica {
		t.Fatal("promoted before the wait")
	}
	for i := 0; i < 6; i++ {
		time.Sleep(80 * time.Millisecond)
		round()
	}
	rb, rc := b.mg.cl.Node.Snapshot(), c.mg.cl.Node.Snapshot()
	primaries := 0
	for _, s := range []core.ClusterSnapshot{rb, rc} {
		if s.Role == core.RolePrimary {
			primaries++
		}
	}
	if primaries != 1 || rb.Epoch != rc.Epoch || rb.PrimaryAddr != rc.PrimaryAddr || rb.Epoch < 2 {
		t.Fatalf("after failover: B %s epoch %d primary %s; C %s epoch %d primary %s", rb.Role, rb.Epoch, rb.PrimaryAddr, rc.Role, rc.Epoch, rc.PrimaryAddr)
	}
}

// With two members nothing promotes however long the primary is gone.
func TestFailoverStaysManual(t *testing.T) {
	defer func(d time.Duration) { cluster.FailoverAfter = d }(cluster.FailoverAfter)
	cluster.FailoverAfter = 20 * time.Millisecond
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	for i := 0; i < 3; i++ {
		a.sync()
		b.sync()
	}
	a.mg.cl.Stop()
	for i := 0; i < 5; i++ {
		time.Sleep(40 * time.Millisecond)
		b.mg.cl.SyncOnce(context.Background())
		b.mg.cl.FailoverTick()
	}
	if b.mg.cl.Node.Snapshot().Role != cluster.RoleReplica {
		t.Fatal("a two-node cluster promoted by itself")
	}
}

// A replica that is cut off from the others as well as the primary has no majority and never promotes.
func TestFailoverNeedsAMajority(t *testing.T) {
	defer func(d time.Duration) { cluster.FailoverAfter = d }(cluster.FailoverAfter)
	cluster.FailoverAfter = 20 * time.Millisecond
	a, b, c := newTNode(t, "A"), newTNode(t, "B"), newTNode(t, "C")
	b.join(a)
	c.join(a)
	for i := 0; i < 3; i++ {
		a.sync()
		b.sync()
		c.sync()
	}
	a.mg.cl.Stop()
	c.mg.cl.Stop()
	for i := 0; i < 6; i++ {
		time.Sleep(40 * time.Millisecond)
		b.mg.cl.SyncOnce(context.Background())
		b.mg.cl.FailoverTick()
	}
	if b.mg.cl.Node.Snapshot().Role != cluster.RoleReplica {
		t.Fatal("a replica on its own promoted without a majority")
	}
}
