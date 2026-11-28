package main

import (
	"testing"

	"netdir/internal/core"
)

func TestCanvasSetAndClearName(t *testing.T) {
	dc := core.NewDaemonConfig()
	id := dc.Groups[0].GroupID
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: id, Label: "Office DNS"}); err != nil {
		t.Fatal(err)
	}
	if dc.Groups[0].Name != "Office DNS" {
		t.Fatalf("name = %q", dc.Groups[0].Name)
	}
	if cg := buildCanvas(dc, nil); cg[0].Name != "Office DNS" {
		t.Fatalf("canvas name = %q", cg[0].Name)
	}
	gs := []core.GatewayGroup{{GroupID: id}, {GroupID: 99}}
	core.NameGateways(gs, dc)
	if gs[0].Name != "Office DNS" || gs[1].Name != "" {
		t.Fatalf("nameGateways: %+v", gs)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: id, Label: "-"}); err != nil || dc.Groups[0].Name != "" {
		t.Fatalf("clear: %v %q", err, dc.Groups[0].Name)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "gateway", VIP: "10.9.9.1/24", Label: "Lab"}); err != nil {
		t.Fatal(err)
	}
	if dc.Groups[len(dc.Groups)-1].Name != "Lab" {
		t.Fatal("add did not set the name")
	}
}
