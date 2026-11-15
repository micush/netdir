package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Changing a device.  This is the only way the gateway writes to one, and it is narrow on purpose:
//
//   - A change is a typed Change (an action, the ports, a value).  Nothing a caller types is ever sent to a device as it
//     is: each driver builds its own request from the validated fields (a port name checked against the device's own list,
//     a description checked for length and control characters), so a caller cannot reach a command or a path the
//     change does not name.  CheckShow and the read paths stay as they are; they never write.
//   - Plain English becomes a Change in ParseChange, a small fixed grammar (no model is involved), so what will happen is
//     what the typed Change says, and ParseChange refuses what it does not understand rather than guess.
//   - A change is planned first (what each port holds now and what it will hold), applied to the ports that differ, read back,
//     and put back as it was if anything fails or the read-back differs.  dry means plan only.
//
// What a change may do is listed in the actions below; a new one is a new action here and a case in each driver's
// store, not a free-form command.

// Change actions.
const (
	ActDescription      = "description"       // set the description of the ports to Value
	ActClearDescription = "clear_description" // remove the description
	ActShutdown         = "shutdown"          // administratively down
	ActNoShutdown       = "no_shutdown"       // administratively up
	ActClearCounters    = "clear_counters"    // zero the interface counters (the ports named, or all of them)
)

// Change is one typed change, the same for every platform: Action on Ports, with Value for a description.  Ports are
// interface names as the device spells them or the usual short forms (ParsePorts); every port must exist on the device.
type Change struct {
	Action string   `json:"action"`
	Ports  []string `json:"ports"`
	Value  string   `json:"value,omitempty"`
}

// AllPorts is the one "port" of a clear_counters change that clears every port of the device: Ports is []string{AllPorts}.  It
// is not an interface name any device has, so it cannot be mistaken for one.
const AllPorts = "all"

// AllPortsChange is the change that clears the counters of every port.
func AllPortsChange() Change { return Change{Action: ActClearCounters, Ports: []string{AllPorts}} }

// All says whether the change is for every port of the device (clear_counters only).
func (c Change) All() bool { return len(c.Ports) == 1 && c.Ports[0] == AllPorts }

// PortChange is one thing that changes (or would) on one port.
type PortChange struct {
	Port   string `json:"port"`
	Field  string `json:"field"` // "description" or "admin"
	Before string `json:"before"`
	After  string `json:"after"`
}

// ChangeResult is what a change did on one device.
type ChangeResult struct {
	DryRun     bool         `json:"dry_run,omitempty"`
	Applied    bool         `json:"applied"`               // the device holds the new values, read back
	Changes    []PortChange `json:"changes"`               // what differs (what changed, or would)
	Unchanged  []string     `json:"unchanged,omitempty"`   // ports that already held the values
	RolledBack bool         `json:"rolled_back,omitempty"` // the write failed or did not read back, and the old values are back
	Saved      bool         `json:"saved,omitempty"`       // the running configuration was saved over a reboot (save was asked for)
	Note       string       `json:"note,omitempty"`        // what a caller should know that is not an error (a save that needs no doing)
}

// ConfigSaver is a driver that can save the running configuration so that it survives a reboot (IOS-XE save-config, EOS write memory,
// AOS-CX copy running-config startup-config).  A platform that keeps what it is told on its own (Junos commits, FortiOS, Meraki,
// the Proxmox and vCenter platforms) has none, and a change there is already kept.
type ConfigSaver interface {
	SaveConfig(ctx context.Context) error
}

// Changer is a driver that can change what Change describes.  A driver that is not one answers ErrUnsupported to a
// change (the caller's type assertion fails).
type Changer interface {
	Change(ctx context.Context, c Change, dry bool) (ChangeResult, error)
}

const (
	maxChangePorts  = 512
	maxDescription  = 200
	rollbackTimeout = 60 * time.Second
)

// Validate checks a change before any device is asked about it.
func (c *Change) Validate() error {
	switch c.Action {
	case ActDescription:
		v, err := CheckDescription(c.Value)
		if err != nil {
			return err
		}
		if v == "" {
			return errors.New("a description to set is needed (to remove one, clear it)")
		}
		c.Value = v
	case ActClearDescription, ActShutdown, ActNoShutdown, ActClearCounters:
		if c.Value != "" {
			return fmt.Errorf("%s takes no value", c.Action)
		}
	default:
		return fmt.Errorf("action %q: description, clear_description, shutdown, no_shutdown or clear_counters", c.Action)
	}
	if c.All() && c.Action != ActClearCounters {
		return fmt.Errorf("%s needs the ports named; only clear_counters can take all of them", c.Action)
	}
	for _, p := range c.Ports {
		if strings.EqualFold(p, AllPorts) && !c.All() {
			return errors.New("name the ports or say all, not both")
		}
	}
	if len(c.Ports) == 0 {
		return errors.New("name the ports")
	}
	if len(c.Ports) > maxChangePorts {
		return fmt.Errorf("at most %d ports in one change", maxChangePorts)
	}
	return nil
}

// CheckDescription trims a description and refuses what could not be one: longer than 200 characters, or holding a
// control character (a line break would be a second command on a device that takes a command line).
func CheckDescription(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", errors.New("the description is not valid text")
	}
	if utf8.RuneCountInString(s) > maxDescription {
		return "", fmt.Errorf("a description is at most %d characters", maxDescription)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errors.New("a description is one line of text, with no control characters")
		}
	}
	return s, nil
}

// portTypes maps what people type to the interface type as Cisco and Arista spell it.  A device's own list decides which of
// them exist on it (Resolve matches without regard to case, so Port-channel and Port-Channel are one).
var portTypes = map[string]string{
	"gi": "GigabitEthernet", "gig": "GigabitEthernet", "gige": "GigabitEthernet", "gigabit": "GigabitEthernet", "gigabitethernet": "GigabitEthernet",
	"te": "TenGigabitEthernet", "ten": "TenGigabitEthernet", "tengig": "TenGigabitEthernet", "tengigabitethernet": "TenGigabitEthernet",
	"tw": "TwentyFiveGigE", "twe": "TwentyFiveGigE", "twentyfivegige": "TwentyFiveGigE",
	"fo": "FortyGigabitEthernet", "fortygigabitethernet": "FortyGigabitEthernet",
	"hu": "HundredGigE", "hundredgige": "HundredGigE",
	"fa": "FastEthernet", "fastethernet": "FastEthernet",
	"eth": "Ethernet", "et": "Ethernet", "ethernet": "Ethernet",
	"po": "Port-channel", "port-channel": "Port-channel", "portchannel": "Port-channel",
	"vl": "Vlan", "vlan": "Vlan",
	"lo": "Loopback", "loopback": "Loopback",
	"ma": "Management", "mgmt": "Management", "management": "Management",
	"lag": "lag",
	// Junos
	"ge-": "ge-", "xe-": "xe-", "et-": "et-", "ae": "ae", "irb": "irb",
	// FortiOS: port1, wan2, lan1
	"port": "port", "wan": "wan", "lan": "lan",
}

// literalPortRE is the few port names a device spells with no type and no number, or with no type this program has: FortiOS dmz, lan,
// wan, internal, ha and fortilink, and BIG-IP 1.1 and mgmt.  They are taken as written, and the device's own list says whether it has them.
var literalPortRE = regexp.MustCompile(`(?i)^(?:dmz|lan|wan|internal|ha|mgmt|fortilink|modem|\d+\.\d+|lo|ethernet|wi-fi|eth\d+\.\d+|(?:ens|eno|enp|enx|wlan|wlp|bond|br|docker|veth|virbr|vmbr|tun|tap|wg|ppp)[a-z0-9._-]*)$`)

var portTokenRE = regexp.MustCompile(`^([A-Za-z][A-Za-z-]*?)(\d+(?:/\d+)*)(?:-(\d+(?:/\d+)*))?$`)

// barePortRE is a port written with no type, as Aruba CX names them: 1/1/1, 1/1/1-48 or 1/1/1-1/1/48.
var plainPortRE = regexp.MustCompile(`^(\d+)(?:-(\d+))?$`) // Meraki switches number their ports 1, 2, 3 …

var barePortRE = regexp.MustCompile(`^(\d+(?:/\d+)+)(?:-(\d+(?:/\d+)*))?$`)

// expandRange lists the ports of a range that runs over the last number of the name.  The end is a number (48) or the whole
// path (1/1/48), which must be on the same module as the start.
func expandRange(tok, typ, path, end string) ([]string, error) {
	i := strings.LastIndex(path, "/")
	pre := path[:i+1]
	lo, _ := strconv.Atoi(path[i+1:])
	if j := strings.LastIndex(end, "/"); j >= 0 {
		if end[:j+1] != pre {
			return nil, fmt.Errorf("port %q: both ends of a range must be on the same module (%s…)", tok, pre)
		}
		end = end[j+1:]
	}
	hi, err := strconv.Atoi(end)
	if err != nil || hi < lo {
		return nil, fmt.Errorf("port %q: the end of a range is not below its start", tok)
	}
	if hi-lo >= maxChangePorts {
		return nil, fmt.Errorf("port %q: at most %d ports in one change", tok, maxChangePorts)
	}
	out := make([]string, 0, hi-lo+1)
	for n := lo; n <= hi; n++ {
		out = append(out, typ+pre+strconv.Itoa(n))
	}
	return out, nil
}

// ParsePorts turns "gi1/0/1-24, gi1/1/1 and te1/1/3-4" into interface names: GigabitEthernet1/0/1 … GigabitEthernet1/0/24,
// GigabitEthernet1/1/1, TenGigabitEthernet1/1/3, TenGigabitEthernet1/1/4.  A range runs over the last number of the
// name (gi1/0/1-24 is the ports 1 to 24 of module 1/0).  At most 512 ports; each only once.
func ParsePorts(s string) ([]string, error) {
	s = strings.NewReplacer(",", " ", ";", " ").Replace(s)
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Fields(s) {
		if strings.EqualFold(tok, "and") {
			continue
		}
		var names []string
		if p := plainPortRE.FindStringSubmatch(tok); p != nil {
			if p[2] == "" {
				names = []string{p[1]}
			} else {
				var err error
				if names, err = expandRange(tok, "", p[1], p[2]); err != nil {
					return nil, err
				}
			}
		} else if b := barePortRE.FindStringSubmatch(tok); b != nil {
			if b[2] == "" {
				names = []string{b[1]}
			} else {
				var err error
				if names, err = expandRange(tok, "", b[1], b[2]); err != nil {
					return nil, err
				}
			}
		} else {
			m := portTokenRE.FindStringSubmatch(tok)
			typ, ok := "", false
			if m != nil {
				typ, ok = portTypes[strings.ToLower(m[1])]
			}
			if !ok {
				if !literalPortRE.MatchString(tok) {
					return nil, fmt.Errorf("port %q: write it like gi1/0/1, gi1/0/1-24, te1/1/3, et5, on Aruba CX 1/1/1-1/1/48, on a Meraki switch 1-24, on Junos ge-0/0/1, on FortiOS port1, on BIG-IP 1.1", tok)
				}
				names = []string{tok} // the device's own list decides whether it has it
			} else if m[3] == "" {
				names = []string{typ + m[2]}
			} else {
				var err error
				if names, err = expandRange(tok, typ, m[2], m[3]); err != nil {
					return nil, err
				}
			}
		}
		for _, name := range names {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		if len(out) > maxChangePorts {
			return nil, fmt.Errorf("at most %d ports in one change", maxChangePorts)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("name the ports, e.g. gi1/0/1-24")
	}
	return out, nil
}

var (
	setDescRE  = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:change|set|update|make|put)\s+(?:the\s+)?descriptions?\s+(?:for|on|of|in)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s+(?:to|as)\s+(?:read\s+|say\s+|be\s+)?(.+?)\s*$`)
	setDesc2RE = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:change|set|update)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s+descriptions?\s+(?:to|as)\s+(?:read\s+|say\s+|be\s+)?(.+?)\s*$`)
	descRE     = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:describe|label|name)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s+as\s+(.+?)\s*$`)
	clearRE    = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:clear|remove|delete|erase|blank|reset)\s+(?:the\s+)?descriptions?\s+(?:for|on|of|from|in)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s*$`)
	downRE     = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:shut\s*down|disable|turn\s+off|admin(?:istratively)?\s+down|bring\s+down)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s*$`)
	downPostRE = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:shut|turn|take|bring|put)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s+(?:down|off)\s*$`)
	upPostRE   = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:turn|take|bring|put)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s+(?:up|on)\s*$`)
	// clear (all) (port|interface) counters|statistics (on|for|of ports)
	countersRE = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:clear|reset|zero)\s+(?:the\s+)?(?:all\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(?:counters?|statistics|stats)\s*(?:(?:for|on|of|from|in)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.*?))?\s*$`)
	allPortsRE = regexp.MustCompile(`(?i)^(?:all(?:\s+(?:the\s+)?(?:ports?|interfaces?))?|every\s+(?:port|interface))$`)
	upRE       = regexp.MustCompile(`(?is)^\s*(?:please\s+)?(?:no\s+shut(?:down)?|enable|turn\s+on|bring\s+up|admin(?:istratively)?\s+up)\s+(?:the\s+)?(?:(?:ports?|interfaces?|int|intf)\s+)?(.+?)\s*$`)
)

// unquote takes the text out of its quotation marks ("devices", 'devices', “devices”); text with no quotes is taken as it
// is.  Text after a closing quote is an error: it is a sentence the grammar does not know.
func unquote(s string) (string, error) {
	s = strings.TrimSpace(s)
	pairs := map[rune]rune{'"': '"', '\'': '\'', '“': '”', '‘': '’', '”': '”'}
	r, n := utf8.DecodeRuneInString(s)
	closeQ, ok := pairs[r]
	if !ok {
		return s, nil
	}
	rest := s[n:]
	end := strings.LastIndex(rest, string(closeQ))
	if end < 0 {
		return s, nil // an apostrophe at the start of a word, not a quotation
	}
	if strings.TrimSpace(rest[end+utf8.RuneLen(closeQ):]) != "" {
		return "", errors.New("there is text after the closing quotation mark")
	}
	return rest[:end], nil
}

// ParseChange turns an English request into a Change.  The grammar is small and fixed:
//
//	change the description for ports gi1/0/1-24 to read "devices"     (change|set|update|make|put; for|on|of|in; to|as; read|say|be)
//	set gi1/0/1-24 description to "devices"
//	describe gi1/0/1-24 as "devices"                                  (describe|label|name)
//	clear the description on gi1/0/1-24                               (clear|remove|delete|erase|blank|reset)
//	shut down | disable | turn off | admin down  gi1/0/1-24
//	no shutdown | enable | turn on | bring up | admin up  gi1/0/1-24
//	shut port 1/1/1 down | turn gi1/0/1-24 off | bring port 1/1/5 up      (the verb either side of the ports)
//	clear all port counters | clear counters on gi1/0/1-24             (clear|reset|zero; counters|statistics|stats)
//
// Ports are written with their type (gi1/0/1-24, te1/1/3, et1-48) or, as on Aruba CX, without (1/1/1-1/1/48).  A port with no type
// is matched to the device's own ports in resolve: exactly, or by the one port whose name ends with it.
//
// What it does not understand it refuses, saying so; it never guesses.
func ParseChange(text string) (Change, error) {
	t := strings.TrimSpace(text)
	if t == "" {
		return Change{}, errors.New("say what to change, e.g. change the description for ports gi1/0/1-24 to read \"devices\"")
	}
	if len(t) > 1000 {
		return Change{}, errors.New("the request is longer than 1000 characters")
	}
	finish := func(act, ports, val string) (Change, error) {
		ps, err := ParsePorts(ports)
		if err != nil {
			return Change{}, err
		}
		c := Change{Action: act, Ports: ps, Value: val}
		return c, c.Validate()
	}
	if m := countersRE.FindStringSubmatch(t); m != nil {
		ports := strings.TrimSpace(m[1])
		if ports == "" || allPortsRE.MatchString(ports) {
			c := AllPortsChange()
			return c, c.Validate()
		}
		return finish(ActClearCounters, ports, "")
	}
	for _, re := range []*regexp.Regexp{setDescRE, setDesc2RE, descRE} {
		if m := re.FindStringSubmatch(t); m != nil {
			v, err := unquote(m[2])
			if err != nil {
				return Change{}, err
			}
			return finish(ActDescription, m[1], v)
		}
	}
	for _, x := range []struct {
		re  *regexp.Regexp
		act string
	}{{clearRE, ActClearDescription}, {downPostRE, ActShutdown}, {upPostRE, ActNoShutdown}, {downRE, ActShutdown}, {upRE, ActNoShutdown}} {
		if m := x.re.FindStringSubmatch(t); m != nil {
			return finish(x.act, m[1], "")
		}
	}
	return Change{}, errors.New("I did not understand that. I know: change the description for ports gi1/0/1-24 to read \"text\"; clear the description on gi1/0/1-24; shut down gi1/0/1-24; no shutdown gi1/0/1-24; clear all port counters; clear counters on gi1/0/1-24")
}

// ── the common part of every driver's change ──

// portState is what the configuration of a port holds that a change can touch.
type portState struct {
	Description string
	Down        bool // administratively shut down
}

// portPlan is the state a port is to be put in: only the fields that are set.
type portPlan struct {
	Port        string
	Description *string
	Down        *bool
}

// changeStore is what a driver gives runChange: the configuration of the ports as it is, and a way to put ports in a state.
// write must put every plan in the state, and may stop at the first thing the device refuses.
type changeStore interface {
	read(ctx context.Context) (map[string]portState, error)
	write(ctx context.Context, plan []portPlan) error
}

func adminWord(down bool) string {
	if down {
		return "shutdown"
	}
	return "up"
}

var trailPathRE = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*(\d+(?:/\d+)+)$`)

// resolve matches the names asked for with the names the device has, without regard to case, and says which it lacks.
func resolve(have map[string]portState, want []string) ([]string, error) {
	byLower := make(map[string]string, len(have))
	for n := range have {
		byLower[strings.ToLower(n)] = n
	}
	var out, missing []string
	var ambiguous []string
	for _, w := range want {
		if n, ok := byLower[strings.ToLower(w)]; ok {
			out = append(out, n)
			continue
		}
		if barePortRE.MatchString(w) { // no type typed: the one port of the device that ends with it
			var hit []string
			for n := range have {
				if m := trailPathRE.FindStringSubmatch(n); m != nil && m[1] == w {
					hit = append(hit, n)
				}
			}
			sort.Strings(hit)
			if len(hit) == 1 {
				out = append(out, hit[0])
				continue
			}
			if len(hit) > 1 {
				ambiguous = append(ambiguous, fmt.Sprintf("%s is %s", w, strings.Join(hit, " and ")))
				continue
			}
		}
		missing = append(missing, w)
	}
	if len(ambiguous) > 0 {
		return nil, fmt.Errorf("say which port: %s; nothing was changed", strings.Join(ambiguous, "; "))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		if len(missing) > 8 {
			missing = append(missing[:8], fmt.Sprintf("… (%d in all)", len(missing)))
		}
		return nil, fmt.Errorf("the device has no port %s; nothing was changed", strings.Join(missing, ", "))
	}
	return out, nil
}

// runChange plans c against what the store reads, writes the ports that differ (unless dry), reads them back, and writes the old
// values back if the write failed or the read-back differs.
func runChange(ctx context.Context, st changeStore, c Change, dry bool) (ChangeResult, error) {
	res := ChangeResult{DryRun: dry, Changes: []PortChange{}}
	if err := c.Validate(); err != nil {
		return res, err
	}
	if c.Action == ActClearCounters {
		cl, ok := st.(counterClearer)
		if !ok {
			return res, errors.New("this platform's API has no way to clear interface counters")
		}
		return runClear(ctx, cl, c, dry)
	}
	before, err := st.read(ctx)
	if err != nil {
		return res, fmt.Errorf("reading the ports before the change: %w", err)
	}
	ports, err := resolve(before, c.Ports)
	if err != nil {
		return res, err
	}
	var plan, undo []portPlan
	for _, p := range ports {
		cur := before[p]
		switch c.Action {
		case ActDescription, ActClearDescription:
			want := c.Value
			if c.Action == ActClearDescription {
				want = ""
			}
			if cur.Description == want {
				res.Unchanged = append(res.Unchanged, p)
				continue
			}
			res.Changes = append(res.Changes, PortChange{Port: p, Field: "description", Before: cur.Description, After: want})
			d, o := want, cur.Description
			plan = append(plan, portPlan{Port: p, Description: &d})
			undo = append(undo, portPlan{Port: p, Description: &o})
		case ActShutdown, ActNoShutdown:
			want := c.Action == ActShutdown
			if cur.Down == want {
				res.Unchanged = append(res.Unchanged, p)
				continue
			}
			res.Changes = append(res.Changes, PortChange{Port: p, Field: "admin", Before: adminWord(cur.Down), After: adminWord(want)})
			d, o := want, cur.Down
			plan = append(plan, portPlan{Port: p, Down: &d})
			undo = append(undo, portPlan{Port: p, Down: &o})
		}
	}
	if dry {
		return res, nil
	}
	if len(plan) == 0 {
		res.Applied = true // already as asked
		return res, nil
	}
	werr := st.write(ctx, plan)
	if werr == nil {
		var after map[string]portState
		if after, werr = st.read(ctx); werr == nil {
			werr = verifyPlan(after, plan)
		} else {
			werr = fmt.Errorf("reading the ports back: %w", werr)
		}
	}
	if werr == nil {
		res.Applied = true
		return res, nil
	}
	// put the old values back, with a context of its own: the one the change ran under may be what ran out
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if uerr := st.write(rctx, undo); uerr != nil {
		return res, fmt.Errorf("%v; putting the old values back failed too (%v): check the ports %s", werr, uerr, portList(plan))
	}
	if after, rerr := st.read(rctx); rerr != nil || verifyPlan(after, undo) != nil {
		return res, fmt.Errorf("%v; the old values were sent back but could not be confirmed: check the ports %s", werr, portList(plan))
	}
	res.RolledBack = true
	return res, fmt.Errorf("%v; the old values are back", werr)
}

func portList(plan []portPlan) string {
	var n []string
	for _, p := range plan {
		n = append(n, p.Port)
	}
	if len(n) > 8 {
		n = append(n[:8], "…")
	}
	return strings.Join(n, ", ")
}

// verifyPlan says whether the ports hold what the plan put on them.
func verifyPlan(have map[string]portState, plan []portPlan) error {
	for _, p := range plan {
		cur, ok := have[p.Port]
		if !ok {
			return fmt.Errorf("port %s is not on the device any more", p.Port)
		}
		if p.Description != nil && cur.Description != *p.Description {
			return fmt.Errorf("port %s holds the description %q, not %q", p.Port, cur.Description, *p.Description)
		}
		if p.Down != nil && cur.Down != *p.Down {
			return fmt.Errorf("port %s is %s, not %s", p.Port, adminWord(cur.Down), adminWord(*p.Down))
		}
	}
	return nil
}

// keepManagement refuses to shut down a port that holds the address the gateway reaches the device on: the change would cut
// the gateway off, and with it the read-back and the way back.  Only a shutdown can do that; the other actions skip the check.
// When the device's address is a host name, what it resolves to is what counts.
func keepManagement(ctx context.Context, drv Driver, d Device, c Change) error {
	if c.Action != ActShutdown || !guardsOn {
		return nil
	}
	mgmt := map[netip.Addr]bool{}
	if a, err := netip.ParseAddr(d.Address); err == nil {
		mgmt[a.Unmap()] = true
	} else if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", d.Address); err == nil {
		for _, a := range ips {
			mgmt[a.Unmap()] = true
		}
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil {
		return fmt.Errorf("could not check which port the gateway reaches the device on, so nothing was shut down: %w", err)
	}
	asked := map[string]bool{}
	for _, p := range c.Ports {
		asked[strings.ToLower(p)] = true
	}
	for _, i := range ifs {
		hit := asked[strings.ToLower(i.Name)]
		if m := trailPathRE.FindStringSubmatch(i.Name); m != nil && asked[m[1]] {
			hit = true // a port written with no type: every port that ends with it is guarded
		}
		if !hit {
			continue
		}
		for _, ad := range i.Addresses {
			ip, _, _ := strings.Cut(ad, "/")
			if a, err := netip.ParseAddr(ip); err == nil && mgmt[a.Unmap()] {
				return fmt.Errorf("port %s holds %s, the address the gateway reaches the device on: shutting it down would cut the gateway off; nothing was changed", i.Name, ip)
			}
		}
	}
	return nil
}

// ── clearing counters ──

// counterClearer is what a driver gives to clear interface counters (a store that has it is asked by runChange; a driver with no
// typed port changes but this one calls runClear itself).  Counters are not configuration: there is nothing to read back and
// nothing to put back, so a clear is planned from the ports the device has and reported as sent.
type counterClearer interface {
	// ports lists the interface names the device has (what a named port is matched against).
	ports(ctx context.Context) ([]string, error)
	// clear zeroes the counters of the ports (every port when all is set).
	clear(ctx context.Context, ports []string, all bool) error
}

// runClear plans and makes a clear_counters change.
func runClear(ctx context.Context, cl counterClearer, c Change, dry bool) (ChangeResult, error) {
	res := ChangeResult{DryRun: dry, Changes: []PortChange{}}
	if err := c.Validate(); err != nil {
		return res, err
	}
	if c.Action != ActClearCounters {
		return res, fmt.Errorf("this platform's API only clears counters here, not %s", c.Action)
	}
	var ports []string
	if c.All() {
		res.Changes = append(res.Changes, PortChange{Port: "all ports", Field: "counters", Before: "counting", After: "cleared"})
	} else {
		names, err := cl.ports(ctx)
		if err != nil {
			return res, fmt.Errorf("reading the ports before the change: %w", err)
		}
		have := make(map[string]portState, len(names))
		for _, n := range names {
			have[n] = portState{}
		}
		if ports, err = resolve(have, c.Ports); err != nil {
			return res, err
		}
		for _, p := range ports {
			res.Changes = append(res.Changes, PortChange{Port: p, Field: "counters", Before: "counting", After: "cleared"})
		}
	}
	if dry {
		return res, nil
	}
	if err := cl.clear(ctx, ports, c.All()); err != nil {
		return res, err
	}
	res.Applied = true // sent and accepted; counters are not read back, and a clear cannot be undone
	return res, nil
}
