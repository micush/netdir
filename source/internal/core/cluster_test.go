package core

import (
	"testing"
)

func TestUpdaterHoldsSource(t *testing.T) {
	u := newTestUpdater(t)
	u.HoldSource() // nothing staged: nothing to hold
	if _, err := u.ExtractSource(makeTgz(t, good("9"))); err != nil {
		t.Fatal(err)
	}
	if u.OfferedSource() != "9" {
		t.Fatal("a staged source is offered")
	}
	u.HoldSource()
	if u.OfferedSource() != "" || u.SourceVersion() != "9" {
		t.Fatal("a held source is not offered but is still there")
	}
	if _, err := u.ExtractSource(makeTgz(t, good("10"))); err != nil || u.OfferedSource() != "10" {
		t.Fatal("something newer staged later is offered")
	}
	u.HoldSource()
	u.ReleaseSource()
	if u.OfferedSource() != "10" {
		t.Fatal("released")
	}
}
