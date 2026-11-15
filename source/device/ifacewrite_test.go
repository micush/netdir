package device

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// fakeIfaceDev is a driver whose ports (name, description, admin state) change when a Raw is sent through it, the way each platform's
// request is read here: Junos and NX-OS lines, FortiOS PUT and BIG-IP PATCH bodies.
type fakeIfaceDev struct {
	Driver
	ports map[string]*Interface
	sent  []Raw
	fail  func(Raw) error
	mode  string // "junos", "nxos", "forti", "bigip"
}

func (f *fakeIfaceDev) Interfaces(context.Context) ([]Interface, error) {
	var out []Interface
	for _, p := range f.ports {
		out = append(out, *p)
	}
	return out, nil
}

func (f *fakeIfaceDev) RawChange(_ context.Context, r Raw, dry bool) (RawResult, error) {
	if f.fail != nil {
		if err := f.fail(r); err != nil {
			return RawResult{}, err
		}
	}
	f.sent = append(f.sent, r)
	up := func(b bool) *bool { return &b }
	switch f.mode {
	case "junos":
		for _, l := range r.Lines {
			w := strings.Fields(l)
			p := f.ports[w[2]]
			switch {
			case w[0] == "set" && w[3] == "disable":
				p.AdminUp = up(false)
			case w[0] == "delete" && w[3] == "disable":
				p.AdminUp = up(true)
			case w[0] == "set" && w[3] == "description":
				p.Description, _ = strconv.Unquote(strings.Join(w[4:], " "))
			case w[0] == "delete" && w[3] == "description":
				p.Description = ""
			}
		}
	case "nxos":
		var cur *Interface
		for _, l := range r.Lines {
			switch {
			case strings.HasPrefix(l, "interface "):
				cur = f.ports[strings.TrimPrefix(l, "interface ")]
			case l == "shutdown":
				cur.AdminUp = up(false)
			case l == "no shutdown":
				cur.AdminUp = up(true)
			case l == "no description":
				cur.Description = ""
			case strings.HasPrefix(l, "description "):
				cur.Description = strings.TrimPrefix(l, "description ")
			}
		}
	case "forti", "bigip":
		name := r.Path[strings.LastIndex(r.Path, "/")+1:]
		p := f.ports[name]
		if p == nil {
			return RawResult{}, errors.New("no such interface")
		}
		b := r.Body
		switch {
		case strings.Contains(b, `"status":"down"`), strings.Contains(b, `"disabled":true`):
			p.AdminUp = up(false)
		case strings.Contains(b, `"status":"up"`), strings.Contains(b, `"enabled":true`):
			p.AdminUp = up(true)
		}
		var m map[string]any
		if json.Unmarshal([]byte(b), &m) == nil {
			if d, ok := m["description"].(string); ok {
				p.Description = d
			}
		}
	}
	return RawResult{Applied: !dry}, nil
}

func newFakeIface(mode string, names ...string) *fakeIfaceDev {
	f := &fakeIfaceDev{ports: map[string]*Interface{}, mode: mode}
	for _, n := range names {
		up := true
		f.ports[n] = &Interface{Name: n, Description: "old " + n, AdminUp: &up}
	}
	return f
}

func TestIfaceChangeThroughRaw(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		mode  string
		ports []string
		store func(f *fakeIfaceDev) ifaceStore
		want  []string // what the first real request holds, parts
	}{
		{"junos", []string{"ge-0/0/1", "ge-0/0/2"}, func(f *fakeIfaceDev) ifaceStore { return ifaceStore{drv: f, rc: f, lines: junosLines} }, []string{"set interfaces ge-0/0/1 disable", "set interfaces ge-0/0/2 disable"}},
		{"nxos", []string{"Ethernet1/1", "Ethernet1/2"}, func(f *fakeIfaceDev) ifaceStore { return ifaceStore{drv: f, rc: f, lines: nxosLines} }, []string{"interface Ethernet1/1", "shutdown", "interface Ethernet1/2"}},
		{"forti", []string{"port1", "port2"}, func(f *fakeIfaceDev) ifaceStore { return ifaceStore{drv: f, rc: f, req: (&fortios{}).ifaceReq} }, []string{`PUT /api/v2/cmdb/system/interface/port1 {"status":"down"}`}},
		{"bigip", []string{"1.1", "1.2"}, func(f *fakeIfaceDev) ifaceStore { return ifaceStore{drv: f, rc: f, req: (&bigip{}).ifaceReq} }, []string{`PATCH /mgmt/tm/net/interface/1.1 {"disabled":true}`}},
	} {
		f := newFakeIface(tc.mode, tc.ports...)
		st := tc.store(f)
		down := Change{Action: ActShutdown, Ports: tc.ports}
		// a plan sends nothing
		r, err := runChange(ctx, st, down, true)
		if err != nil || len(r.Changes) != 2 || len(f.sent) != 0 {
			t.Fatalf("%s dry: %v %+v %v", tc.mode, err, r, f.sent)
		}
		// shutdown: sent, read back, held
		r, err = runChange(ctx, st, down, false)
		if err != nil || !r.Applied || r.RolledBack || *f.ports[tc.ports[0]].AdminUp {
			t.Fatalf("%s shutdown: %v %+v", tc.mode, err, r)
		}
		var all []string
		for _, s := range f.sent {
			if s.Method != "" {
				all = append(all, s.Method+" "+s.Path+" "+s.Body)
			}
			all = append(all, s.Lines...)
		}
		joined := strings.Join(all, "\n")
		for _, w := range tc.want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: %q not in the request:\n%s", tc.mode, w, joined)
			}
		}
		// already down: nothing to send
		f.sent = nil
		if r, err = runChange(ctx, st, down, false); err != nil || len(r.Changes) != 0 || len(r.Unchanged) != 2 || len(f.sent) != 0 {
			t.Fatalf("%s again: %v %+v %v", tc.mode, err, r, f.sent)
		}
		// no shutdown and a description
		if r, err = runChange(ctx, st, Change{Action: ActNoShutdown, Ports: tc.ports[:1]}, false); err != nil || !*f.ports[tc.ports[0]].AdminUp {
			t.Fatalf("%s no shutdown: %v %+v", tc.mode, err, r)
		}
		if r, err = runChange(ctx, st, Change{Action: ActDescription, Ports: tc.ports[:1], Value: `uplink "core"`}, false); err != nil || !r.Applied {
			t.Fatalf("%s description: %v %+v", tc.mode, err, r)
		}
		// a port the device lacks cancels the change
		f.sent = nil
		if _, err = runChange(ctx, st, Change{Action: ActShutdown, Ports: []string{tc.ports[0], "nosuch9"}}, false); err == nil || len(f.sent) != 0 {
			t.Errorf("%s missing port: %v %v", tc.mode, err, f.sent)
		}
		// a device that refuses the request: the error is passed up and nothing is claimed
		f.fail = func(Raw) error { return errors.New("refused") }
		if r, err = runChange(ctx, st, Change{Action: ActNoShutdown, Ports: tc.ports[1:]}, false); err == nil || r.Applied {
			t.Errorf("%s refused: %v %+v", tc.mode, err, r)
		}
	}
}

func TestIfaceNamesAndQuotes(t *testing.T) {
	if _, err := junosLines([]portPlan{{Port: "ge-0/0/1\nset system"}}); err == nil {
		t.Error("a line break in a port name was accepted")
	}
	if _, err := nxosLines([]portPlan{{Port: "Ethernet1/1; reload"}}); err == nil {
		t.Error("a ; in a port name was accepted")
	}
	if _, err := (&fortios{}).ifaceReq(portPlan{Port: "../admin"}); err == nil {
		t.Error("a path in a port name was accepted")
	}
	d := `a "b" \ c`
	ls, err := junosLines([]portPlan{{Port: "ge-0/0/1", Description: &d}})
	if err != nil || ls[0] != `set interfaces ge-0/0/1 description "a \"b\" \\ c"` {
		t.Errorf("junos quoting: %v %v", err, ls)
	}
	r, err := (&fortios{}).ifaceReq(portPlan{Port: "port1", Description: &d})
	if err != nil || r.Path != "/api/v2/cmdb/system/interface/port1" || !strings.Contains(r.Body, `a \"b\" \\ c`) {
		t.Errorf("forti body: %v %+v", err, r)
	}
}

func TestParsePortsOtherPlatforms(t *testing.T) {
	for in, want := range map[string]string{
		"ge-0/0/1-3": "ge-0/0/1 ge-0/0/2 ge-0/0/3", "xe-1/0/0": "xe-1/0/0", "port1, wan2": "port1 wan2", "dmz": "dmz", "1.1 1.2": "1.1 1.2", "ae0": "ae0",
	} {
		got, err := ParsePorts(in)
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	c, err := ParseChange("shut down port ge-0/0/4")
	if err != nil || c.Action != ActShutdown || c.Ports[0] != "ge-0/0/4" {
		t.Errorf("junos sentence: %+v %v", c, err)
	}
}
