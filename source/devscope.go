package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"netdir/device"
)

// The devices an MCP key or an allowed source may use (Configure ▸ MCP ▸ Devices).  An entry is a device name, tag:TAG (every
// device that carries the tag, now and later), "all" or "none".  No entry is the same as "all", so what was saved before the
// field existed keeps working.  A caller that has both a key and a source entry may use only what both allow, as with the
// privacy level (the stricter wins), so a narrow key cannot be widened by the address it comes from.
//
// Devices outside the list are not shown (list_devices) and are refused as if they did not exist, so their names are not
// given away.  A target such as "all" or tag:dc1 reaches the devices the caller may use.  A change or a capture that picks
// even one device the caller may not use is refused whole, rather than done on a part.  A caller limited to some devices
// may not read or change the configuration, look at the signed-in users or restore a version, since those hold the whole
// inventory and the keys themselves.

const devScopeMax = 64 // entries in one list

func devEntryOK(e string) bool {
	if g, ok := strings.CutPrefix(e, "gateway:"); ok {
		n, err := strconv.Atoi(g)
		return err == nil && n > 0 && g == strconv.Itoa(n)
	}
	if t, ok := strings.CutPrefix(e, "tag:"); ok {
		return t != "" && len(t) <= 80 && !strings.ContainsAny(t, " ,\t\r\n\"")
	}
	return e != "" && len(e) <= 80 && strings.IndexFunc(e, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r))
	}) < 0
}

// normDevices checks a list of device entries and writes it the same way: nil for all, ["none"] for none, otherwise the names
// and tags without duplicates.  "none" wins over everything else in the list; "all" in a list with others means all.
func normDevices(list []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	none, all := false, false
	for _, e := range list {
		e = strings.TrimSpace(e)
		switch strings.ToLower(e) {
		case "":
			continue
		case "all":
			all = true
			continue
		case "none":
			none = true
			continue
		}
		if !devEntryOK(e) {
			return nil, fmt.Errorf("devices: %q: a device name, tag:TAG, all or none", e)
		}
		k := strings.ToLower(e)
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	switch {
	case none:
		return []string{"none"}, nil
	case all || len(out) == 0:
		return nil, nil
	case len(out) > devScopeMax:
		return nil, fmt.Errorf("devices: at most %d entries", devScopeMax)
	}
	return out, nil
}

// devScope is the lists of one caller (its key's and its source's); a nil scope allows every device.
type devScope struct {
	parts [][]string
	cfg   func() *DaemonConfig // the configuration now, to find the devices of a gateway:N entry (a device added to the gateway later is allowed too)
}

// bind gives the scope the way to read the gateways' devices.
func (sc *devScope) bind(cfg func() *DaemonConfig) {
	if sc != nil {
		sc.cfg = cfg
	}
}

// gatewayHas says whether device name is one of gateway id's devices.
func (sc *devScope) gatewayHas(id int, name string) bool {
	if sc.cfg == nil {
		return false
	}
	dc := sc.cfg()
	if dc == nil {
		return false
	}
	for _, g := range dc.Groups {
		if g.GroupID == id {
			for _, d := range g.Devices {
				if strings.EqualFold(d, name) {
					return true
				}
			}
		}
	}
	return false
}

// allowsGateway says whether the caller may see gateway id: every list it has must name it (gateway:ID).  A caller limited to
// devices only sees no gateway.
func (sc *devScope) allowsGateway(id int) bool {
	if !sc.limited() {
		return true
	}
	want := "gateway:" + strconv.Itoa(id)
	for _, part := range sc.parts {
		ok := false
		for _, e := range part {
			ok = ok || strings.EqualFold(e, want)
		}
		if !ok {
			return false
		}
	}
	return true
}

// alertSubjectGateway returns the gateway number of an alert subject written "group N ..." .
func alertSubjectGateway(subject string) (int, bool) {
	f := strings.Fields(subject)
	if len(f) >= 2 && f[0] == "group" {
		n, err := strconv.Atoi(f[1])
		return n, err == nil
	}
	return 0, false
}

// newDevScope makes the scope of lists, ignoring those that allow everything.
func newDevScope(lists ...[]string) *devScope {
	sc := &devScope{}
	for _, l := range lists {
		if len(l) > 0 {
			sc.parts = append(sc.parts, l)
		}
	}
	if len(sc.parts) == 0 {
		return nil
	}
	return sc
}

func (sc *devScope) limited() bool { return sc != nil && len(sc.parts) > 0 }

func hasTagEq(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

func (sc *devScope) allows(name string, tags []string) bool {
	if !sc.limited() {
		return true
	}
	for _, part := range sc.parts {
		ok := false
		for _, e := range part {
			if t, isTag := strings.CutPrefix(e, "tag:"); isTag {
				ok = ok || hasTagEq(tags, t)
			} else if g, isGW := strings.CutPrefix(e, "gateway:"); isGW {
				n, _ := strconv.Atoi(g)
				ok = ok || sc.gatewayHas(n, name)
			} else if !strings.EqualFold(e, "none") {
				ok = ok || strings.EqualFold(e, name)
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (sc *devScope) filter(devs []device.Device) []device.Device {
	if !sc.limited() {
		return devs
	}
	out := make([]device.Device, 0, len(devs))
	for _, d := range devs {
		if sc.allows(d.Name, d.Tags) {
			out = append(out, d)
		}
	}
	return out
}

func (sc *devScope) filterRemote(rem []RemoteDevice) []RemoteDevice {
	if !sc.limited() {
		return rem
	}
	out := make([]RemoteDevice, 0, len(rem))
	for _, d := range rem {
		if sc.allows(d.Name, d.Tags) {
			out = append(out, d)
		}
	}
	return out
}

// scopeOf is the scope of a session (nil for the GUI's own users, and for an MCP caller with no limit).
func scopeOf(s *session) *devScope {
	if s == nil {
		return nil
	}
	return s.devs
}

// scopedOffTools are the tools a caller limited to some devices is not offered: they read or change the whole configuration or any API route.
var scopedOffTools = map[string]bool{"get_config": true, "device_troubleshoot_user": true}

// scopeRefusedPrefixes are the API routes a limited caller may not use: they hold the whole inventory or the keys.
var scopeRefusedPrefixes = []string{"/api/config", "/api/versions", "/api/canvas/edit", "/api/devices/troubleshoot", "/api/devices/signin"}

// scopeGuard checks a request an MCP tool is about to make for a caller whose devices are limited.
func (c *mcpCtx) scopeGuard(method, path string, body []byte) error {
	sc := scopeOf(c.s)
	if !sc.limited() {
		return nil
	}
	p := path
	// a request relayed to another node names its path in the query: look at that one
	for i := 0; i < 3 && strings.HasPrefix(p, "/api/proxy"); i++ {
		u, err := url.Parse(p)
		if err != nil {
			return errors.New("not for a caller limited to some devices")
		}
		p = u.Query().Get("path")
	}
	if u, err := url.Parse(p); err == nil {
		p = u.Path
	}
	for _, x := range scopeRefusedPrefixes {
		if p == x || strings.HasPrefix(p, x+"/") {
			return errors.New("this key or address is limited to some devices: the configuration, its versions and sign-ins hold every device and every key, so they are not for it")
		}
	}
	switch p {
	case "/api/devices/change", "/api/devices/raw", "/api/devices/capture":
		var a struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(body, &a)
		return c.w.status.sup.scopeWrite(sc, a.Target)
	}
	return nil
}

// scopeWrite refuses a target that picks a device the scope does not allow (a name it may not use is "matches no device", as if there were none).
func (s *Supervisor) scopeWrite(sc *devScope, target string) error {
	if !sc.limited() || strings.TrimSpace(target) == "" {
		return nil
	}
	devs, _ := s.deviceInventory()
	rem, _ := s.remoteDevices(0, false)
	all := append(append([]device.Device(nil), devs...), remoteAsDevices(rem)...)
	target, err := s.expandGatewayTargets(target)
	if err != nil {
		return err
	}
	picked, err := device.Select(sc.filter(all), target)
	if err != nil {
		return err
	}
	full, err := device.Select(all, target)
	if err == nil && len(full) != len(picked) {
		return errors.New("the target picks devices this key or address may not use: name only the ones it may (list_devices)")
	}
	return nil
}
