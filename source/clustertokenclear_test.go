package main

import (
	"context"
	"strings"
	"testing"
)

// A node hands out at most maxPendingToks join codes that nobody used; clearing them withdraws every one (a code made
// before no longer joins) and makes room for new ones.
func TestClearJoinCodes(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	var first string
	for i := 0; i < maxPendingToks; i++ {
		code, _, err := a.mg.cl.MintJoinCode("t")
		if err != nil {
			t.Fatalf("code %d: %v", i+1, err)
		}
		if i == 0 {
			first = code
		}
	}
	if _, _, err := a.mg.cl.MintJoinCode("t"); err == nil || !strings.Contains(err.Error(), "--cluster-token-clear") {
		t.Fatalf("one too many must be refused and say how to clear them: %v", err)
	}
	if n := a.mg.cl.View().JoinCodes; n != maxPendingToks {
		t.Fatalf("the view counts %d unused codes, want %d", n, maxPendingToks)
	}
	// through the op the CLI and the GUI use
	res, err := a.mg.Op("cluster.token.clear", nil, "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["cleared"]; got != maxPendingToks {
		t.Fatalf("cleared %v, want %d", got, maxPendingToks)
	}
	if n := a.mg.cl.View().JoinCodes; n != 0 {
		t.Fatalf("%d codes left after clearing", n)
	}
	if err := b.mg.cl.Join(context.Background(), first, "t"); err == nil || !strings.Contains(err.Error(), "invalid or expired") {
		t.Fatalf("a cleared code must not join: %v", err)
	}
	// nothing to clear is not an error
	if n, err := a.mg.cl.ClearJoinCodes("t"); err != nil || n != 0 {
		t.Fatalf("clearing none: %d %v", n, err)
	}
	// and a new code works again
	code, _, err := a.mg.cl.MintJoinCode("t")
	if err != nil {
		t.Fatalf("a code after clearing: %v", err)
	}
	if err := b.mg.cl.Join(context.Background(), code, "t"); err != nil {
		t.Fatalf("join with the new code: %v", err)
	}
}
