package core

import (
	"fmt"
	"testing"
)

// After the boot guard rolls a version back, the node reports it failed (it survives the restart) until a newer one is staged.
func TestRolledBackVersionStaysFailed(t *testing.T) {
	u, err := NewUpdater(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	next := fmt.Sprintf("%d", mustInt(Version())+1)
	if u.FailedFor() != "" {
		t.Fatal("nothing failed yet")
	}
	u.writeGuard(bootGuard{State: "rolled-back", From: Version(), To: next})
	if got := u.FailedFor(); got != next {
		t.Fatalf("FailedFor = %q, want %q", got, next)
	}
	u.writeGuard(bootGuard{State: "applying", From: Version(), To: next})
	if got := u.FailedFor(); got != "" {
		t.Fatalf("a new attempt clears the failure: %q", got)
	}
}
