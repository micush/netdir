package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"netdir/device"
)

// fedMesh runs four directors round by round the way the real ones exchange their lists (each builds its index from the lists its
// directors published in the round before, so a list can be a round old), with the links of the federation drawn in the design:
//
//	netdir1 ▸ netdir2, netdir3      netdir2 ▸ netdir1, netdir3, netdir4      netdir3 ▸ netdir4
//	technitium on netdir2, observium on netdir3, vcenter on netdir4
type fedMesh struct {
	links map[string][]string        // director → the directors it has as devices
	owns  map[string][]string        // director → the devices it holds the login of
	idx   map[string][]RemoteDevice  // director → its index
	inv   map[string][]device.Device // director → its inventory
}

func newFedMesh() *fedMesh {
	m := &fedMesh{
		links: map[string][]string{"n1": {"n2", "n3"}, "n2": {"n1", "n3", "n4"}, "n3": {"n4"}, "n4": {}},
		owns:  map[string][]string{"n2": {"technitium"}, "n3": {"observium"}, "n4": {"vcenter"}},
		idx:   map[string][]RemoteDevice{}, inv: map[string][]device.Device{},
	}
	m.rebuildInventory()
	return m
}

func (m *fedMesh) rebuildInventory() {
	for n, ls := range m.links {
		var inv []device.Device
		for _, d := range ls {
			inv = append(inv, device.Device{Name: "netdir" + d[1:], Platform: "netdir", Address: "10.0.0." + d[1:]})
		}
		for _, d := range m.owns[n] {
			inv = append(inv, device.Device{Name: d, Platform: "x", Address: "10.9.0." + d})
		}
		m.inv[n] = inv
	}
}

// published is what a director answers to list_devices: its own devices and its index, as Below gives them to the one that asked
func (m *fedMesh) published(n string, up map[string]bool) []device.Below {
	var out []device.Below
	for _, d := range m.inv[n] {
		out = append(out, device.Below{Name: d.Name, Platform: d.Platform, Address: d.Address, Inst: "i" + n[1:], Path: []string{"i" + n[1:]}})
	}
	for _, r := range m.idx[n] {
		out = append(out, device.Below{Name: r.Name, Platform: r.Platform, Address: r.Address, Via: r.Via, Inst: r.Inst, Path: append([]string{"i" + n[1:]}, r.Path...)})
	}
	return out
}

func (m *fedMesh) round(up map[string]bool) {
	prev := map[string][]device.Below{}
	for n := range m.links {
		prev[n] = m.published(n, up)
	}
	for n, ls := range m.links {
		if !up[n] {
			m.idx[n] = nil
			continue
		}
		var parts []downPart
		for _, d := range ls {
			if !up[d] {
				continue
			}
			parts = append(parts, downPart{dir: device.Device{Name: "netdir" + d[1:], Platform: "netdir"}, below: prev[d]})
		}
		m.idx[n] = buildRemote(m.inv[n], parts, "i"+n[1:])
	}
}

// route follows a request for name from director n down to the director that holds the login and gives the directors it went through
func (m *fedMesh) route(n, name string, seen []string) ([]string, error) {
	seen = append(seen, n)
	if len(seen) > 8 {
		return seen, fmt.Errorf("goes round: %v", seen)
	}
	for _, d := range m.owns[n] {
		if strings.EqualFold(d, name) {
			return seen, nil
		}
	}
	for _, r := range m.idx[n] {
		if strings.EqualFold(r.Name, name) {
			next := "n" + strings.TrimPrefix(r.Via[0], "netdir")
			if slices.Contains(seen, next) {
				return seen, fmt.Errorf("comes back to %s: %v", next, seen)
			}
			return m.route(next, r.Orig, seen)
		}
	}
	return seen, fmt.Errorf("%s has no %s", n, name)
}

func TestFederationMeshConverges(t *testing.T) {
	m := newFedMesh()
	up := map[string]bool{"n1": true, "n2": true, "n3": true, "n4": true}
	for i := 0; i < 8; i++ {
		m.round(up)
	}
	// the links are one way: what a director reaches is what is below it
	reach := map[string]map[string]string{
		"n1": {"technitium": "n2", "observium": "n3", "vcenter": "n4"}, "n2": {"observium": "n3", "vcenter": "n4"}, "n3": {"vcenter": "n4"}, "n4": {}}
	for _, n := range []string{"n1", "n2", "n3", "n4"} {
		for _, dev := range []string{"technitium", "observium", "vcenter"} {
			if slices.Contains(m.owns[n], dev) {
				continue
			}
			path, err := m.route(n, dev, nil)
			if owner, want := reach[n][dev]; want {
				if err != nil || path[len(path)-1] != owner || len(path) > 3 {
					t.Errorf("%s asks for %s: %v %v", n, dev, path, err)
				}
			} else if err == nil {
				t.Errorf("%s reaches %s, which is not below it: %v", n, dev, path)
			}
		}
		count := map[string]int{}
		for _, r := range m.idx[n] {
			count[r.Orig+"|"+r.Platform]++
			if slices.Contains(r.Path, "i"+n[1:]) || r.Inst == "i"+n[1:] {
				t.Errorf("%s lists %s, which goes through or belongs to itself: %+v", n, r.Name, r)
			}
		}
		for _, dev := range []string{"technitium|x", "observium|x", "vcenter|x"} {
			if count[dev] > 1 {
				t.Errorf("%s lists %s %d times", n, dev, count[dev])
			}
		}
	}
	// the state is steady: another round changes nothing
	before := map[string]string{}
	for n := range m.idx {
		before[n] = fmt.Sprint(m.idx[n])
	}
	m.round(up)
	for n := range m.idx {
		if fmt.Sprint(m.idx[n]) != before[n] {
			t.Errorf("%s changes after it has settled", n)
		}
	}

	// netdir4 goes down: vcenter must go from every director in a few rounds, with no director holding it up for another
	// (the lists of the neighbors are a round old, so for a round or two they still have it)
	up["n4"] = false
	m.owns["n4"] = nil
	m.rebuildInventory()
	gone := -1
	for i := 1; i <= 10; i++ {
		m.round(up)
		has := false
		for _, n := range []string{"n1", "n2", "n3"} {
			for _, r := range m.idx[n] {
				if r.Orig == "vcenter" {
					has = true
				}
			}
		}
		if !has {
			gone = i
			break
		}
	}
	if gone < 0 || gone > 4 {
		var left []string
		for n, l := range m.idx {
			for _, r := range l {
				if r.Orig == "vcenter" {
					left = append(left, n+" via "+strings.Join(r.Via, ">")+" path "+strings.Join(r.Path, ">"))
				}
			}
		}
		sort.Strings(left)
		t.Errorf("vcenter is still listed after %d rounds: %v", gone, left)
	}
}
