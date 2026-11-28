package main

import (
	"testing"

	"netdir/internal/core"
)

func TestGuiGroupIsTheFirstLocalOne(t *testing.T) {
	m, _ := usersFixture(t, "root:x:0:\nsvc-local:x:1001:alice\n", fxPasswd, "")
	m.webPolicy.Store(&core.WebConfig{Group: "svc-ad, svc-local"})
	if g := m.guiGroup(); g != "svc-local" {
		t.Fatalf("a directory group first, then the local one: %q", g)
	}
	m.webPolicy.Store(&core.WebConfig{Group: "nothere,alsonot"})
	if g := m.guiGroup(); g != "nothere" {
		t.Fatalf("none is local: %q", g)
	}
}
