package core

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// MCP: the Model Context Protocol (streamable HTTP, JSON answers only) at POST /mcp on the gateway addresses, so an assistant
// such as Claude can ask the gateway about its devices (and, from an address allowed to, change them).  The only things it can ask
// about netdir itself are the cluster status (list_nodes, get_topology) and the device list (list_devices); there is no tool for
// the configuration, the GUI's API, alerts, schedules, updates or the host, and none takes a node: the node serving the endpoint answers.  Like /metrics
// there is no login: the address of the connection is checked against settings.mcp_acl (Configure ▸ MCP), where
// an entry is read-only unless it says "rw", and "rw" is only for a single address.  Empty list: nobody.  A caller whose
// address changes sends a key instead (settings.mcp_keys, "Authorization: Bearer KEY", mcpkeys.go), from any address.
//
// A tool is a fixed request to the GUI's own API, made in-process as a user called "mcp@ADDRESS" (read-only unless the
// address is rw), so every rule of the GUI applies (a read-only caller cannot change anything, the last node serving a
// gateway cannot be paused, ...), every change is logged and kept in the configuration history under that name, and a
// request for another node goes through the cluster relay as the Node menu's do.  MCP cannot change netdir's own
// configuration, cluster, gateways, schedules or alerts, whatever the access: the only writes are device_change,
// device_raw and device_capture (mcpWriteGuard refuses every other non-GET request), and the rest is done in the GUI.
// No caller is shown a secret: keys and passwords answer "(hidden)".

const McpMaxBody = 1 << 20

const mcpMaxResult = McpMaxBody

const mcpMaxResultMB = 8

// normMCPACL checks the access list and writes each entry the same way: "10.1.0.0/24", "host.example.com", "10.1.1.50 rw",
// "10.1.0.0/24 strict", "10.1.1.50 rw none": an address or network, then ro or rw, then a privacy level (mcpprivacy.go).  The word
// "disabled" at the end ("10.1.1.50 rw disabled") keeps the entry in the list and gives it no access (right-click ▸ Disable); a
// disabled entry is not merged with the others of its address.
//
// An entry may end in a note, "# laptop of the network team" (up to mcpNoteMax characters, no control characters): it says what
// the entry is for and changes nothing; aclBody takes it off wherever an entry is read.  Entries of one address that are merged keep
// their notes, joined with "; ".
func NormMCPACL(list []string) ([]string, error) {
	if len(list) > 64 {
		return nil, errors.New("mcp: at most 64 entries in the access list")
	}
	notes := map[string][]string{} // the notes of the entries merged under an address
	type ent struct {
		t   string // the address (an enabled entry) or the whole text of the entry (a disabled one)
		off bool
	}
	mode, level := map[string]string{}, map[string]string{}
	devs, allDevs := map[string][]string{}, map[string]bool{} // the devices of an address (devscope.go); allDevs: one of its entries has no limit
	var order []ent
	seenOff := map[string]bool{}
	for _, s := range list {
		s, note, err := splitACLNote(s)
		if err != nil {
			return nil, err
		}
		f := strings.Fields(s)
		if len(f) == 0 {
			continue
		}
		off := false
		if last := strings.ToLower(f[len(f)-1]); len(f) > 1 && last == "disabled" {
			off, f = true, f[:len(f)-1]
		}
		var dl []string
		until := ""
		for i := 0; i < 2; i++ { // devices=… and until=…, in either order, after the address, ro or rw and the level
			n := len(f)
			if n < 2 {
				break
			}
			lw := strings.ToLower(f[n-1])
			if strings.HasPrefix(lw, "devices=") && dl == nil {
				var err error
				if dl, err = NormDevices(strings.Split(f[n-1][len("devices="):], ",")); err != nil {
					return nil, fmt.Errorf("mcp: access list: %q: %w", s, err)
				}
				f = f[:n-1]
			} else if strings.HasPrefix(lw, "until=") && until == "" {
				t, err := parseUntil(f[n-1][len("until="):])
				if err != nil {
					return nil, fmt.Errorf("mcp: access list: %q: %w", s, err)
				}
				until = "until=" + t.UTC().Format(untilLayout)
				f = f[:n-1]
			}
		}
		if len(f) > 3 {
			return nil, fmt.Errorf("mcp: access list: %q: an address or network, then ro or rw, then a privacy level, then devices=a,b,tag:x or none, then until=2026-12-31T17:00Z for an expiry (UTC), then disabled to switch it off", s)
		}
		rw, lvl := false, ""
		for _, w := range f[1:] {
			switch strings.ToLower(w) {
			case "rw", "read-write", "readwrite":
				rw = true
				continue
			case "ro", "read-only", "readonly":
				continue
			}
			l, ok := normLevel(w)
			if !ok || l == "" || lvl != "" {
				return nil, fmt.Errorf("mcp: access list: %q: after the address, ro or rw and a privacy level (none, standard, strict)", s)
			}
			lvl = l
		}
		n, err := normACL("mcp", f[:1])
		if err != nil {
			return nil, err
		}
		t := n[0]
		if rw {
			if _, err := netip.ParseAddr(t); err != nil {
				return nil, fmt.Errorf("mcp: access list: %q: read-write is for a single address, not a network or a host name", s)
			}
		}
		if off || until != "" { // an entry that is switched off or ends is kept as it is, not merged with the others of its address
			text := t
			if rw {
				text += " rw"
			}
			if lvl != "" {
				text += " " + lvl
			}
			if len(dl) > 0 {
				text += " devices=" + strings.Join(dl, ",")
			}
			if until != "" {
				text += " " + until
			}
			if off {
				text += " disabled"
			}
			if note != "" {
				text += " # " + note
			}
			if !seenOff[text] {
				seenOff[text] = true
				order = append(order, ent{t: text, off: true})
			}
			continue
		}
		if _, ok := mode[t]; !ok {
			order = append(order, ent{t: t})
		}
		if rw || mode[t] == "" {
			mode[t] = map[bool]string{true: "rw", false: "ro"}[rw || mode[t] == "rw"]
		}
		level[t] = StrictestLevel(level[t], lvl)
		if note != "" {
			dup := false
			for _, x := range notes[t] {
				dup = dup || x == note
			}
			if !dup {
				notes[t] = append(notes[t], note)
			}
		}
		if len(dl) == 0 {
			allDevs[t] = true
		} else if dl[0] != "none" {
			devs[t] = append(devs[t], dl...)
		} else if _, seen := devs[t]; !seen {
			devs[t] = nil
		}
	}
	out := make([]string, 0, len(order))
	for _, e := range order {
		if e.off {
			out = append(out, e.t)
			continue
		}
		t := e.t
		if mode[t] == "rw" {
			t += " rw"
		}
		if level[T0(t)] != "" {
			t += " " + level[T0(t)]
		}
		if !allDevs[T0(t)] {
			d, _ := NormDevices(devs[T0(t)])
			if len(d) == 0 {
				d = []string{"none"}
			}
			t += " devices=" + strings.Join(d, ",")
		}
		if n := strings.Join(notes[T0(e.t)], "; "); n != "" {
			t += " # " + n
		}
		out = append(out, t)
	}
	return out, nil
}

const mcpNoteMax = 200

// splitACLNote splits an entry into what it says and its note ("10.1.1.50 rw # laptop" is "10.1.1.50 rw" and "laptop").
func splitACLNote(e string) (body, note string, err error) {
	body, note, _ = strings.Cut(e, "#")
	note = strings.Join(strings.Fields(note), " ")
	if err := checkNote(note); err != nil {
		return "", "", fmt.Errorf("mcp: access list: %w", err)
	}
	return strings.TrimSpace(body), note, nil
}

// checkNote checks a note: short, one line, no control characters.
func checkNote(n string) error {
	if utf8.RuneCountInString(n) > mcpNoteMax {
		return fmt.Errorf("a note is at most %d characters", mcpNoteMax)
	}
	if strings.IndexFunc(n, unicode.IsControl) >= 0 {
		return errors.New("a note is one line of text, without control characters")
	}
	return nil
}

// aclBody is an entry of the access list without its note: what every reader of an entry must look at.
func AclBody(e string) string {
	b, _, _ := strings.Cut(e, "#")
	return strings.TrimSpace(b)
}

// aclOff says that an entry of the access list is disabled (it stays in the list and allows nothing).
func AclOff(e string) bool {
	f := strings.Fields(AclBody(e))
	return len(f) > 1 && strings.EqualFold(f[len(f)-1], "disabled")
}

const untilLayout = "2006-01-02T15:04Z"

// parseUntil reads an expiry in UTC: 2026-12-31 (the end of that day), 2026-12-31T17:00 or 2026-12-31T17:00Z (a space for the T is taken).
func parseUntil(s string) (time.Time, error) {
	s = strings.TrimSpace(strings.Replace(s, " ", "T", 1))
	for _, l := range []string{"2006-01-02T15:04Z", "2006-01-02T15:04", "2006-01-02T15:04:05Z"} {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			return t, nil
		}
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.UTC); err == nil {
		return t.Add(24*time.Hour - time.Minute), nil
	}
	return time.Time{}, fmt.Errorf("until=%s: write the time in UTC as 2026-12-31 or 2026-12-31T17:00Z", s)
}

// aclExpired says that an entry of the access list has an until= time that has passed.
func AclExpired(e string) bool {
	for _, w := range strings.Fields(AclBody(e))[1:] {
		if v, ok := strings.CutPrefix(strings.ToLower(w), "until="); ok {
			t, err := parseUntil(v)
			return err != nil || !McpNow().Before(t)
		}
	}
	return false
}

// t0 is the address of an entry written "ADDRESS [rw]".
func T0(e string) string { f := strings.Fields(AclBody(e)); return f[0] }

var mcpACLCache struct {
	sync.Mutex
	key    string
	at     time.Time
	ro, rw []netip.Prefix
	lvl    map[string][]netip.Prefix // the sources that have a privacy level of their own, by level
	devs   []aclDevs                 // every enabled entry and the devices it allows
}

// aclDevs is the devices of one entry of the access list: nil is all of them.
type aclDevs struct {
	nets []netip.Prefix
	devs []string
}

// mcpResultLimit is the most bytes one answer may be (Configure ▸ MCP ▸ Largest answer).
func (s *Supervisor) McpResultLimit() int {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dc != nil && s.Dc.Settings.MCPMaxResultMB > 1 {
		return min(s.Dc.Settings.MCPMaxResultMB, mcpMaxResultMB) << 20
	}
	return mcpMaxResult
}

// mcpKeys is the keys that may use the endpoint from any address (mcpkeys.go).
func (s *Supervisor) McpKeys() []MCPKey {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dc == nil {
		return nil
	}
	return s.Dc.Settings.MCPKeys
}

// mcpAccess says what a caller from this address may do: "rw", "ro" or "" (nothing).
func (s *Supervisor) mcpAccess(from netip.Addr) string {
	a, _ := s.McpAccessLevel(from)
	return a
}

// mcpSourceDevices is the devices the entries of the access list that match this address allow (nil: all of them, also when no entry
// matches, as then the address does not limit anything).  Entries that match are added up: one with no limit allows all.
func (s *Supervisor) McpSourceDevices(from netip.Addr) []string {
	s.McpAccessLevel(from) // brings the cache up to date
	c := &mcpACLCache
	c.Lock()
	ents := c.devs
	c.Unlock()
	from = from.Unmap()
	var out []string
	hit := false
	for _, e := range ents {
		if !inNets(e.nets, from) {
			continue
		}
		if len(e.devs) == 0 {
			return nil
		}
		hit = true
		for _, d := range e.devs {
			if d != "none" {
				out = append(out, d)
			}
		}
	}
	if hit && len(out) == 0 {
		return []string{"none"}
	}
	return out
}

// mcpAccessLevel says what a caller from this address may do ("rw", "ro" or "") and the privacy level the list gives it
// (the strictest of the entries that match it; "" when none of them has one).  Host names are looked up again after a
// minute, not for every request.
func (s *Supervisor) McpAccessLevel(from netip.Addr) (access, level string) {
	s.Mu.Lock()
	var acl []string
	if s.Dc != nil {
		acl = s.Dc.Settings.MCPACL
	}
	s.Mu.Unlock()
	if len(acl) == 0 {
		return "", ""
	}
	c := &mcpACLCache
	c.Lock()
	key := strings.Join(acl, ",")
	for _, e := range acl { // an entry that has just expired changes the list at once, not after the minute
		if AclExpired(e) {
			key += "|x"
		}
	}
	if c.key != key || time.Since(c.at) >= time.Minute {
		var ro, rw []string
		lv := map[string][]string{}
		for _, e := range acl {
			if AclOff(e) || AclExpired(e) {
				continue
			}
			f := strings.Fields(AclBody(e))
			if len(f) > 1 && f[1] == "rw" {
				rw = append(rw, f[0])
			} else {
				ro = append(ro, f[0])
			}
			for _, l := range f[1:] {
				if l == "none" || l == "standard" || l == "strict" {
					lv[l] = append(lv[l], f[0])
				}
			}
		}
		c.devs = nil
		for _, e := range acl {
			if AclOff(e) || AclExpired(e) {
				continue
			}
			var dl []string
			for _, w := range strings.Fields(AclBody(e))[1:] {
				if v, ok := strings.CutPrefix(w, "devices="); ok {
					dl = strings.Split(v, ",")
				}
			}
			c.devs = append(c.devs, aclDevs{nets: expandACL([]string{strings.Fields(AclBody(e))[0]}), devs: dl})
		}
		c.lvl = map[string][]netip.Prefix{}
		for l, nets := range lv {
			c.lvl[l] = expandACL(nets)
		}
		c.key, c.at, c.ro, c.rw = key, time.Now(), expandACL(ro), expandACL(rw)
	}
	ro, rw, lvl := c.ro, c.rw, c.lvl
	c.Unlock()
	from = from.Unmap()
	for l, nets := range lvl {
		if inNets(nets, from) {
			level = StrictestLevel(level, l)
		}
	}
	switch {
	case inNets(rw, from):
		return "rw", level
	case inNets(ro, from):
		return "ro", level
	}
	return "", ""
}
