package device

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("gi1/0/1-3, te1/1/1 and Gi1/0/2")
	want := []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3", "TenGigabitEthernet1/1/1"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%v %v", got, err)
	}
	if got, err := ParsePorts("et5-7 Ethernet10 po1"); err != nil || strings.Join(got, " ") != "Ethernet5 Ethernet6 Ethernet7 Ethernet10 Port-channel1" {
		t.Errorf("%v %v", got, err)
	}
	if got, _ := ParsePorts("gi1/0/24"); len(got) != 1 || got[0] != "GigabitEthernet1/0/24" {
		t.Errorf("%v", got)
	}
	if got, err := ParsePorts("1/1/1 1/1/3-1/1/4"); err != nil || strings.Join(got, " ") != "1/1/1 1/1/3 1/1/4" {
		t.Errorf("bare ports: %v %v", got, err)
	}
	if got, err := ParsePorts("1-3 7"); err != nil || strings.Join(got, " ") != "1 2 3 7" {
		t.Errorf("plain ports: %v %v", got, err)
	}
	for _, bad := range []string{"5-2", "", "gi", "gi1/0/5-2", "xx1/0/1", "gi1/0/1-9999", "gi1/0/1;reload", "gi 1/0/1", "gi1/0/1-", "1/", "gi1/0/a"} {
		if got, err := ParsePorts(bad); err == nil {
			t.Errorf("%q accepted: %v", bad, got)
		}
	}
	if got, err := ParsePorts("gi1/0/1-512"); err != nil || len(got) != 512 {
		t.Errorf("512 ports: %d %v", len(got), err)
	}
	if _, err := ParsePorts("gi1/0/1-512 gi1/1/1"); err == nil {
		t.Error("513 ports accepted")
	}
}

func TestParseChange(t *testing.T) {
	g24 := make([]string, 24)
	for i := range g24 {
		g24[i] = "GigabitEthernet1/0/" + itoa(i+1)
	}
	ok := []struct {
		in   string
		want Change
	}{
		{`change the description for ports gi1/0/1-24 to read "devices"`, Change{ActDescription, g24, "devices"}},
		{`Change the description for ports Gi1/0/1-24 to read “devices”`, Change{ActDescription, g24, "devices"}},
		{`set the description on interface gi1/0/1 to uplink to core`, Change{ActDescription, []string{"GigabitEthernet1/0/1"}, "uplink to core"}},
		{`set gi1/0/1 description to 'a to b'`, Change{ActDescription, []string{"GigabitEthernet1/0/1"}, "a to b"}},
		{`describe et3 as "web 01"`, Change{ActDescription, []string{"Ethernet3"}, "web 01"}},
		{`please update the description of ports gi1/0/1, gi1/0/2 as "x"`, Change{ActDescription, []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}, "x"}},
		{`clear the description on ports gi1/0/1-2`, Change{ActClearDescription, []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}, ""}},
		{`shut down gi1/0/5`, Change{ActShutdown, []string{"GigabitEthernet1/0/5"}, ""}},
		{`disable ports et1-2`, Change{ActShutdown, []string{"Ethernet1", "Ethernet2"}, ""}},
		{`no shutdown port-channel1`, Change{ActNoShutdown, []string{"Port-channel1"}, ""}},
		{`turn on interface te1/1/1`, Change{ActNoShutdown, []string{"TenGigabitEthernet1/1/1"}, ""}},
		{`change the description for port-channel1 to read "it's fine"`, Change{ActDescription, []string{"Port-channel1"}, "it's fine"}},
	}
	for _, c := range ok {
		got, err := ParseChange(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %+v %v, want %+v", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{
		"", "reload the switch", "delete everything", `change the description for ports gi1/0/1 to read "x" and then reload`,
		`change the description for ports gi1/0/1 to read ""`, "change the description for ports to read \"x\"", "shut down", "shut down all ports",
		"change the description for ports gi1/0/1 to read \"a\nb\"", `change the description for ports gi1/0/1 to read "` + strings.Repeat("x", 201) + `"`,
		"erase startup-config", "clear the description", `set gi1/0/1 description`,
	} {
		if c, err := ParseChange(bad); err == nil {
			t.Errorf("%q understood as %+v", bad, c)
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestChangeValidate(t *testing.T) {
	for _, bad := range []Change{
		{ActDescription, []string{"Ethernet1"}, ""}, {ActShutdown, []string{"Ethernet1"}, "x"}, {"reload", []string{"Ethernet1"}, ""},
		{ActShutdown, nil, ""}, {ActDescription, []string{"Ethernet1"}, "a\r\nreload"}, {ActDescription, []string{"Ethernet1"}, "a\x00b"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	c := Change{ActDescription, []string{"Ethernet1"}, "  café ☕  "}
	if err := c.Validate(); err != nil || c.Value != "café ☕" {
		t.Errorf("%+v %v", c, err)
	}
}

// fakeStore is a changeStore on a map, with the failures a test asks for.
type fakeStore struct {
	ports     map[string]portState
	writes    [][]portPlan
	failWrite map[int]bool // the n-th write (1-based) fails after applying half of its plan
	ignore    bool         // a write that does nothing and says nothing
}

func (f *fakeStore) read(context.Context) (map[string]portState, error) {
	m := map[string]portState{}
	for k, v := range f.ports {
		m[k] = v
	}
	return m, nil
}

func (f *fakeStore) write(_ context.Context, plan []portPlan) error {
	f.writes = append(f.writes, plan)
	n := len(f.writes)
	for i, p := range plan {
		if f.failWrite[n] && i >= len(plan)/2 {
			return errors.New("the device refused")
		}
		if f.ignore {
			continue
		}
		s := f.ports[p.Port]
		if p.Description != nil {
			s.Description = *p.Description
		}
		if p.Down != nil {
			s.Down = *p.Down
		}
		f.ports[p.Port] = s
	}
	return nil
}

func newFake() *fakeStore {
	return &fakeStore{ports: map[string]portState{
		"GigabitEthernet1/0/1": {Description: "old1"}, "GigabitEthernet1/0/2": {Description: "devices"},
		"GigabitEthernet1/0/3": {Down: true}, "GigabitEthernet1/0/4": {},
	}}
}

func TestRunChange(t *testing.T) {
	ctx := context.Background()
	ports := []string{"gigabitethernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3"}
	// dry run: the plan, no write
	f := newFake()
	r, err := runChange(ctx, f, Change{ActDescription, ports, "devices"}, true)
	if err != nil || !r.DryRun || r.Applied || len(f.writes) != 0 || len(r.Changes) != 2 || len(r.Unchanged) != 1 || r.Unchanged[0] != "GigabitEthernet1/0/2" {
		t.Fatalf("dry: %v %+v %d", err, r, len(f.writes))
	}
	if r.Changes[0] != (PortChange{"GigabitEthernet1/0/1", "description", "old1", "devices"}) {
		t.Errorf("change: %+v", r.Changes[0])
	}
	// the real thing: only the ports that differ are written
	r, err = runChange(ctx, f, Change{ActDescription, ports, "devices"}, false)
	if err != nil || !r.Applied || len(f.writes) != 1 || len(f.writes[0]) != 2 || f.ports["GigabitEthernet1/0/1"].Description != "devices" {
		t.Fatalf("apply: %v %+v %+v", err, r, f.writes)
	}
	// already as asked: nothing written
	f.writes = nil
	if r, err = runChange(ctx, f, Change{ActDescription, ports, "devices"}, false); err != nil || !r.Applied || len(f.writes) != 0 || len(r.Changes) != 0 {
		t.Errorf("again: %v %+v", err, r)
	}
	// shut down and back up
	if r, err = runChange(ctx, f, Change{ActShutdown, ports, ""}, false); err != nil || len(r.Changes) != 2 || !f.ports["GigabitEthernet1/0/1"].Down || r.Changes[0].Field != "admin" || r.Changes[0].After != "shutdown" {
		t.Errorf("shutdown: %v %+v", err, r)
	}
	if _, err = runChange(ctx, f, Change{ActNoShutdown, ports, ""}, false); err != nil || f.ports["GigabitEthernet1/0/3"].Down {
		t.Errorf("no shutdown: %v", err)
	}
	// clear
	if _, err = runChange(ctx, f, Change{ActClearDescription, ports, ""}, false); err != nil || f.ports["GigabitEthernet1/0/2"].Description != "" {
		t.Errorf("clear: %v", err)
	}
	// a port the device lacks: nothing is written
	f = newFake()
	_, err = runChange(ctx, f, Change{ActDescription, []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/99"}, "x"}, false)
	if err == nil || !strings.Contains(err.Error(), "GigabitEthernet1/0/99") || len(f.writes) != 0 || f.ports["GigabitEthernet1/0/1"].Description != "old1" {
		t.Errorf("missing port: %v", err)
	}
	// a write that fails half way: the old values are back
	f = newFake()
	f.failWrite = map[int]bool{1: true}
	all := []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3", "GigabitEthernet1/0/4"}
	r, err = runChange(ctx, f, Change{ActDescription, all, "new"}, false)
	if err == nil || !r.RolledBack || r.Applied || !strings.Contains(err.Error(), "the old values are back") {
		t.Fatalf("rollback: %v %+v", err, r)
	}
	if !reflect.DeepEqual(f.ports, newFake().ports) {
		t.Errorf("not as before: %+v", f.ports)
	}
	// a write that says yes and does nothing: caught by the read-back
	f = newFake()
	f.ignore = true
	r, err = runChange(ctx, f, Change{ActDescription, all, "new"}, false)
	if err == nil || r.Applied || !strings.Contains(err.Error(), "holds the description") {
		t.Errorf("silent: %v %+v", err, r)
	}
	// the rollback fails too: said plainly, with the ports
	f = newFake()
	f.failWrite = map[int]bool{1: true, 2: true}
	r, err = runChange(ctx, f, Change{ActDescription, all, "new"}, false)
	if err == nil || r.RolledBack || !strings.Contains(err.Error(), "putting the old values back failed") || !strings.Contains(err.Error(), "GigabitEthernet1/0/1") {
		t.Errorf("both fail: %v %+v", err, r)
	}
}
