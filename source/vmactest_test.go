package main

import (
	"testing"

	"netdir/internal/core"
)

func TestCanvasSetRealMACs(t *testing.T) {
	dc := &core.DaemonConfig{Groups: []core.GroupConfig{{GroupID: 1, Interface: "eth0", VIP4: "10.0.0.1/24"}}}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 1, RealMACs: "on"}); err != nil || !dc.Groups[0].RealMACs {
		t.Fatalf("on: %v %v", err, dc.Groups[0].RealMACs)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 1, RealMACs: "off"}); err != nil || dc.Groups[0].RealMACs {
		t.Fatalf("off: %v", err)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 1, RealMACs: "maybe"}); err == nil {
		t.Fatal("bad value must be refused")
	}
}
