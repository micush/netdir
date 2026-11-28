package core

import (
	"strings"
	"testing"

	"netdir/device"
)

func TestBuildRemote(t *testing.T) {
	dir := device.Device{Name: "nd3", Platform: "netdir"}
	dir2 := device.Device{Name: "nd2", Platform: "netdir"}
	local := []device.Device{{Name: "sw1"}}
	parts := []downPart{
		{dir: dir, below: []device.Below{
			{Name: "a", Platform: "eos", Address: "10.0.0.1", Inst: "i1"},
			{Name: "sw1", Platform: "eos", Address: "10.0.0.2", Inst: "i1"},
			{Name: "deep", Platform: "eos", Address: "10.0.0.3", Inst: "i2", Via: []string{"n4", "n5", "n6", "n7", "n8"}}, // too long a chain
			{Name: "back", Platform: "eos", Address: "10.0.0.4", Inst: "me"},                                              // this installation's own
		}},
		{dir: dir2, below: []device.Below{
			{Name: "a-again", Platform: "eos", Address: "10.0.0.1", Inst: "i1", Via: []string{"x"}}, // the same device by a longer way
			{Name: "a", Platform: "eos", Address: "10.1.0.1", Inst: "i3"},                           // another device with the name taken
		}},
	}
	out := buildRemote(local, parts, "me")
	var names []string
	for _, r := range out {
		names = append(names, r.Name+"="+strings.Join(r.Via, ">"))
	}
	want := "a=nd2,a@nd3=nd3,sw1@nd3=nd3"
	if strings.Join(names, ",") != want {
		t.Errorf("index:\n got %v\nwant %s", names, want)
	}
	// the same address under another installation is another device; with no installation named, only the same name on the same director is the same
	again := buildRemote(nil, []downPart{{dir: dir, below: []device.Below{{Name: "a", Platform: "eos", Address: "10.0.0.1"}, {Name: "b", Platform: "eos", Address: "10.0.0.1"}}}}, "")
	if len(again) != 2 {
		t.Errorf("unnamed owner: %+v", again)
	}
}

// a list of a neighbor that is not up to date must not bring a device back through the installation that published it: netdir1 and netdir2
// have each other as devices, netdir3 (below netdir1) goes down, and netdir2 still lists its devices through netdir1
func TestStaleEntryDoesNotComeBack(t *testing.T) {
	dir2 := device.Device{Name: "netdir2", Platform: "netdir"}
	out := buildRemote([]device.Device{dir2}, []downPart{{dir: dir2, below: []device.Below{
		{Name: "technitium", Platform: "technitium", Address: "10.2.0.5", Inst: "i2", Path: []string{"i2"}},
		{Name: "observium", Platform: "observium", Address: "10.3.0.5", Inst: "i3", Via: []string{"netdir1"}, Path: []string{"i2", "i1", "i3"}}, // i2 got it from i1, which has lost it
	}}}, "i1")
	if len(out) != 1 || out[0].Name != "technitium" {
		t.Errorf("what netdir1 lists through netdir2: %+v", out)
	}
	// the same list for an installation that is not in the path keeps it
	if got := buildRemote([]device.Device{dir2}, []downPart{{dir: dir2, below: []device.Below{
		{Name: "observium", Platform: "observium", Address: "10.3.0.5", Inst: "i3", Via: []string{"netdir1"}, Path: []string{"i2", "i1", "i3"}}}}}, "i9"); len(got) != 1 {
		t.Errorf("an installation outside the path: %+v", got)
	}
}
