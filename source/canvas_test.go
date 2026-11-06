package main

import (
	"encoding/json"
	"strings"
	"testing"

	"netdir/device"
)

func TestGroupsKeyMeaning(t *testing.T) {
	load := func(js string) *DaemonConfig {
		t.Helper()
		dc := newDaemonConfig()
		if err := json.Unmarshal([]byte(js), dc); err != nil {
			t.Fatal(err)
		}
		return dc
	}
	if n := len(load(`{}`).Groups); n != 1 {
		t.Fatalf("absent groups = default group, got %d", n)
	}
	if n := len(load(`{"groups":null}`).Groups); n != 1 {
		t.Fatalf("null groups = default group, got %d", n)
	}
	dc := load(`{"groups":[]}`)
	if dc.Groups == nil || len(dc.Groups) != 0 {
		t.Fatalf("explicit empty groups must stay empty: %v", dc.Groups)
	}
	if err := dc.Validate(); err != nil {
		t.Fatalf("a config with no gateways is valid: %v", err)
	}
	// and it survives a save/load round trip as [] (not null, not the default)
	path := t.TempDir() + "/c.json"
	if err := dc.save(path); err != nil {
		t.Fatal(err)
	}
	back, err := loadConfig(path)
	if err != nil || len(back.Groups) != 0 {
		t.Fatalf("round trip: %v %v", back, err)
	}
}

func TestDuplicateSharedAddressRefused(t *testing.T) {
	dc := newDaemonConfig()
	g2 := defaultGroup()
	g2.GroupID = 2
	dc.Groups = append(dc.Groups, g2) // same 10.0.0.1/24 as group 1
	err := dc.Validate()
	if err == nil || !strings.Contains(err.Error(), "shared address") {
		t.Fatalf("two gateways on one address must be refused: %v", err)
	}
	dc.Groups[1].VIP4 = "10.0.1.1/24"
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWebCanvasEndpoint(t *testing.T) {
	e := newWebEnv(t)
	e.login("alice", "pw")
	r := e.do("GET", "/api/canvas", nil, withAuth(e, false))
	if r.code != 200 {
		t.Fatalf("canvas: %d %s", r.code, r.raw)
	}
	if _, ok := r.body["data"].([]any); !ok {
		t.Fatalf("data must be a list: %s", r.raw)
	}
	if r2 := e.do("GET", "/api/canvas", nil); r2.code != 401 {
		t.Fatalf("canvas needs a login: %d", r2.code)
	}
}

func TestCanvasMembers(t *testing.T) {
	rows := []SnapshotRow{
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.5", Local: true, AfnID: 1, Weight: 100, AGCIP: "10.0.0.5"},
		{GroupID: 1, AF: "v6", PeerIP: "10.0.0.5", Local: true, AfnID: 1, Weight: 100, AGCIP: "10.0.0.5"},
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.6", AfnID: 2, State: "active", AGCIP: "10.0.0.5"},
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.7", AfnID: 3, State: "expired"}, // gone quiet
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.8", AfnID: 0, State: "active"},  // no slot, not serving
		{GroupID: 2, AF: "v4", PeerIP: "10.0.0.9", AfnID: 1, State: "active"},  // another gateway
	}
	m := membersOf(rows, 1)
	if len(m) != 2 || m[0].IP != "10.0.0.5" || !m[0].Local || !m[0].AGC || m[0].AFs != "v4+v6" || m[1].IP != "10.0.0.6" || m[1].AGC {
		t.Fatalf("members: %+v", m)
	}
	if got := membersOf(nil, 1); got == nil || len(got) != 0 {
		t.Fatalf("empty must be a non-nil list for JSON: %#v", got)
	}
}

// A dual-stack gateway has two engines per node, and each speaks from its own address, so membersOf sees a node twice.
// The circle's tooltip counts nodes: 4 nodes with IPv4 and IPv6 running said "Serving nodes: 8".
func TestMergeFamilyMembersCountsNodes(t *testing.T) {
	var rows []SnapshotRow
	names := map[string]string{}
	for i := 1; i <= 4; i++ {
		v4, v6 := "192.168.5."+string(rune('0'+i)), "fe80::"+string(rune('0'+i))
		names[v4], names[v6] = "ntp"+string(rune('0'+i)), "ntp"+string(rune('0'+i))
		rows = append(rows,
			SnapshotRow{GroupID: 100, AF: "v6", PeerIP: v6, AfnID: i, Weight: 100, State: "active", Local: i == 1, AGCIP: "fe80::1"},
			SnapshotRow{GroupID: 100, AF: "v4", PeerIP: v4, AfnID: i, Weight: 100, State: "active", Local: i == 1, AGCIP: "192.168.5.1"})
	}
	rows = append(rows, SnapshotRow{GroupID: 100, AF: "v4", PeerIP: "192.168.5.99", AfnID: 9, State: "active"}) // an address no node owns
	gs := []CanvasGateway{{GroupID: 100, Members: membersOf(rows, 100)}}
	if len(gs[0].Members) != 9 {
		t.Fatalf("membersOf sees %d, want 9 (8 per-family entries and the stranger)", len(gs[0].Members))
	}
	mergeFamilyMembers(gs, names)
	ms := gs[0].Members
	if len(ms) != 5 {
		t.Fatalf("members after merging: %d, want 4 nodes and the unknown address: %+v", len(ms), ms)
	}
	for _, m := range ms {
		if m.IP == "192.168.5.99" {
			continue
		}
		if m.AFs != "v4+v6" || !strings.HasPrefix(m.IP, "192.168.5.") {
			t.Fatalf("a node is listed by its IPv4 address with both families: %+v", m)
		}
	}
	for _, m := range ms {
		if m.IP == "192.168.5.1" && (!m.Local || !m.AGC) {
			t.Fatalf("local and controller survive the merge: %+v", m)
		}
	}
}

// A dual-stack gateway elects its controllers per family: each node says which families it is the controller for, and
// the merge keeps that apart (the drawing shows the IPv6-only controller in blue).
func TestMergeFamilyMembersKeepsControllerFamilies(t *testing.T) {
	var rows []SnapshotRow
	names := map[string]string{}
	for i := 1; i <= 2; i++ {
		v4, v6 := "192.168.5."+string(rune('0'+i)), "fe80::"+string(rune('0'+i))
		names[v4], names[v6] = "ntp"+string(rune('0'+i)), "ntp"+string(rune('0'+i))
		rows = append(rows,
			SnapshotRow{GroupID: 1, AF: "v6", PeerIP: v6, AfnID: i, State: "active", Local: i == 1, AGCIP: "fe80::2"},
			SnapshotRow{GroupID: 1, AF: "v4", PeerIP: v4, AfnID: i, State: "active", Local: i == 1, AGCIP: "192.168.5.1"})
	}
	gs := []CanvasGateway{{GroupID: 1, Members: membersOf(rows, 1)}}
	mergeFamilyMembers(gs, names)
	ms := gs[0].Members
	if len(ms) != 2 || ms[0].IP != "192.168.5.1" || ms[0].AGCAFs != "v4" || ms[1].IP != "192.168.5.2" || ms[1].AGCAFs != "v6" || !ms[0].AGC || !ms[1].AGC {
		t.Fatalf("IPv4 controller on ntp1, IPv6 controller on ntp2: %+v", ms)
	}
	// both families on one node: one entry that says both
	for i := range rows {
		rows[i].AGCIP = map[string]string{"v4": "192.168.5.1", "v6": "fe80::1"}[rows[i].AF]
	}
	gs = []CanvasGateway{{GroupID: 1, Members: membersOf(rows, 1)}}
	mergeFamilyMembers(gs, names)
	if ms := gs[0].Members; ms[0].AGCAFs != "v4+v6" || ms[1].AGC || ms[1].AGCAFs != "" {
		t.Fatalf("both controllers on ntp1: %+v", ms)
	}
}

// Only the entries of nodes no longer in the cluster are dropped, from one gateway or all.
func TestCanvasPruneLeftNodes(t *testing.T) {
	dc := newDaemonConfig()
	a, b := defaultGroup(), defaultGroup()
	a.GroupID, a.ExcludedNodes = 100, []string{"member01", "gone0001", "gone0002"}
	b.GroupID, b.ExcludedNodes = 101, []string{"gone0001"}
	dc.Groups = []GroupConfig{a, b}
	msg, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", Group: 100, members: "member01,member02"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dc.Groups[0].ExcludedNodes, ",") != "member01" || len(dc.Groups[1].ExcludedNodes) != 1 {
		t.Fatalf("%s: %v %v", msg, dc.Groups[0].ExcludedNodes, dc.Groups[1].ExcludedNodes)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", members: "member01"}); err != nil || len(dc.Groups[1].ExcludedNodes) != 0 {
		t.Fatalf("every gateway: %v %v", err, dc.Groups[1].ExcludedNodes)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", members: "member01"}); err != errNoChange {
		t.Fatalf("nothing left: %v", err)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", Group: 999, members: "member01"}); err == nil {
		t.Fatal("an unknown gateway was accepted")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node"}); err == nil {
		t.Fatal("pruned without knowing the cluster")
	}
}

func TestApplyCanvasEdit(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{}
	do := func(e canvasEdit) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	fail := func(e canvasEdit, want string) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, e); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%+v: want error containing %q, got %v", e, want, err)
		}
	}
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "10.0.0.1/24", Interface: "eth0"})
	if err := dc.Validate(); err != nil {
		t.Fatalf("a bare gateway is valid: %v", err)
	}
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "2001:db8::1/64"})
	if len(dc.Groups) != 2 || dc.Groups[0].GroupID != firstGroupID || dc.Groups[1].GroupID != firstGroupID+1 || dc.Groups[1].VIP6 == "" || dc.Groups[1].Interface != "eth0" {
		t.Fatalf("gateways: %+v", dc.Groups)
	}
	fail(canvasEdit{Action: "add", Kind: "gateway", Group: firstGroupID, VIP: "10.9.9.9/24"}, "already exists")
	fail(canvasEdit{Action: "add", Kind: "gateway"}, "--vip")
	// a gateway can be added and deleted again
	do(canvasEdit{Action: "add", Kind: "gateway", Group: 7, VIP: "10.7.0.1/24"})
	if g := dc.Groups[2]; g.GroupID != 7 {
		t.Fatalf("gateway 7: %+v", g)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	do(canvasEdit{Action: "del", Kind: "gateway", Group: 7})
	// delete a circle: the whole gateway goes, the other one is untouched
	do(canvasEdit{Action: "del", Kind: "gateway", Group: firstGroupID})
	if len(dc.Groups) != 1 || dc.Groups[0].GroupID != firstGroupID+1 {
		t.Fatalf("after gateway delete: %+v", dc.Groups)
	}
	do(canvasEdit{Action: "del", Kind: "gateway", Group: firstGroupID + 1})
	if len(dc.Groups) != 0 {
		t.Fatal("deleting the last circle leaves no configuration")
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	fail(canvasEdit{Action: "del", Kind: "gateway", Group: 101}, "no gateway")
	fail(canvasEdit{Action: "zap", Kind: "gateway"}, "unknown canvas edit")
}

func TestBuildCanvasPerFamilyStatus(t *testing.T) {
	g := defaultGroup()
	g.VIP6 = "2001:db8::1/64"
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}

	v4ok := SnapshotRow{GroupID: 1, AF: "v4", Local: true, State: "active", ServiceUp: true}
	v6ok := SnapshotRow{GroupID: 1, AF: "v6", Local: true, State: "active", ServiceUp: true}
	v6wait := SnapshotRow{GroupID: 1, AF: "v6", Local: true, State: "listen"}

	both := buildCanvas(dc, []SnapshotRow{v4ok, v6ok})[0]
	if both.Status != "ok" || len(both.Families) != 2 {
		t.Fatalf("both families fine: %s %+v", both.Status, both.Families)
	}
	mixed := buildCanvas(dc, []SnapshotRow{v4ok, v6wait})[0]
	if mixed.Status != "warn" || mixed.Families[0].Status != "ok" || mixed.Families[1].Status != "warn" {
		t.Fatalf("IPv6 not serving must not hide behind a healthy IPv4: %s %+v", mixed.Status, mixed.Families)
	}
	if !strings.Contains(mixed.Detail, "IPv6") || !strings.Contains(mixed.Detail, "IPv4") {
		t.Fatalf("the detail must name both families: %q", mixed.Detail)
	}
	missing := buildCanvas(dc, []SnapshotRow{v4ok})[0]
	if missing.Status != "warn" || missing.Families[1].Status != "idle" {
		t.Fatalf("an IPv6 engine that is missing is a warning: %s %+v", missing.Status, missing.Families)
	}
	none := buildCanvas(dc, nil)[0]
	if none.Status != "idle" {
		t.Fatalf("nothing running: %s", none.Status)
	}
}

func TestBuildCanvasColours(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{defaultGroup()}
	// not running: grey circle
	if cv := buildCanvas(dc, nil); cv[0].Status != "idle" {
		t.Fatalf("not running: %+v", cv[0])
	}
	// running and the service answering: green
	rows := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "active", ServiceUp: true}}
	if cv := buildCanvas(dc, rows); cv[0].Status != "ok" {
		t.Fatalf("all fine => green, got %s (%s)", cv[0].Status, cv[0].Detail)
	}
	// running but the MCP and web listener is not serving: red
	rows[0].ServiceUp = false
	if cv := buildCanvas(dc, rows); cv[0].Status != "bad" || !strings.Contains(cv[0].Detail, "listener") {
		t.Fatalf("service down => red, got %s (%s)", cv[0].Status, cv[0].Detail)
	}
	// not serving yet: yellow
	standby := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "listen"}}
	if cv := buildCanvas(dc, standby); cv[0].Status != "warn" {
		t.Fatalf("not serving => yellow, got %s", cv[0].Status)
	}
}

// Dragging in the drawing (and --canvas-move) reorders the anycast addresses.
func TestCanvasMove(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups[0].GroupID = 1
	dc.Groups[0].ExtraVIPs = []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	must := func(e canvasEdit) {
		t.Helper()
		e.Group = 1
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	must(canvasEdit{Action: "move", Kind: "anycast", Address: "203.0.113.3", Pos: 1})
	if got := dc.Groups[0].ExtraVIPs; got[0] != "203.0.113.3" || got[1] != "203.0.113.1" || got[2] != "203.0.113.2" {
		t.Fatalf("anycast after move: %v", got)
	}
	must(canvasEdit{Action: "move", Kind: "anycast", Address: "203.0.113.3", Pos: 99}) // past the end: last
	if got := dc.Groups[0].ExtraVIPs; got[2] != "203.0.113.3" {
		t.Fatalf("clamped to the end: %v", got)
	}
	for _, e := range []canvasEdit{
		{Action: "move", Kind: "anycast", Group: 1, Address: "203.0.113.99", Pos: 1},
		{Action: "move", Kind: "anycast", Group: 1, Address: "203.0.113.1"},
	} {
		if _, err := applyCanvasEdit(dc, e); err == nil {
			t.Fatalf("%+v must be refused", e)
		}
	}
	if err := dc.Validate(); err != nil {
		t.Fatalf("a moved configuration must stay valid: %v", err)
	}
}

func TestCanvasDeviceDisable(t *testing.T) {
	dc := &DaemonConfig{}
	dc.Settings.Devices = []device.Device{{Name: "sw1", Platform: "iosxe", Address: "10.0.0.2", Credential: "c"}}
	if msg, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "device", Device: "sw1"}); err != nil || !dc.Settings.Devices[0].Disabled || !strings.Contains(msg, "disabled") {
		t.Fatalf("pause: %q %v", msg, err)
	}
	if msg, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "device", Device: "sw1"}); err != nil || !strings.Contains(msg, "already") {
		t.Errorf("pause twice: %q %v", msg, err)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "resume", Kind: "device", Device: "sw1"}); err != nil || dc.Settings.Devices[0].Disabled {
		t.Errorf("resume: %v", err)
	}
	for _, e := range []canvasEdit{{Action: "pause", Kind: "device"}, {Action: "pause", Kind: "device", Device: "nope"}} {
		if _, err := applyCanvasEdit(dc, e); err == nil {
			t.Errorf("%+v accepted", e)
		}
	}
}
