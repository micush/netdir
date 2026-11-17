package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// What net_scan (and the scan in the CLI and the API) may be asked to scan: one host, or a subnet (10.1.1.0/24), a range
// (10.1.1.10-10.1.1.50 or 10.1.1.10-50) or a list of these and host names, separated by commas; and which TCP ports (22,443 or
// 1-1024).  Everything is checked and turned into single addresses here, so what reaches nmap is a list of addresses (on its standard
// input) and a port list of digits, never text a caller wrote.
const (
	scanMaxHosts = 1024 // addresses in one scan (a /22)
	scanMaxPorts = 1024
	scanMaxNames = 20
)

var scanCommaRe = regexp.MustCompile(`\s*,\s*`)

// scanPlan is a checked scan request.
type scanPlan struct {
	key   string   // what the job is called: the address (or name) for one host asked for with no ports, else the request spelled out
	items []string // the addresses (and host names), one per host
	ports string   // "" for the 100 commonest, else nmap's -p list: 22,80,8000-8100
	v6    bool
}

func (p *scanPlan) multi() bool { return len(p.items) > 1 }

// timeout is how long the scan may run: two and a half minutes for one host, a little more for each host beyond that, 15 minutes at most.
func (p *scanPlan) timeout() time.Duration {
	if !p.multi() {
		return scanTimeout
	}
	return min(scanTimeout+time.Duration(len(p.items))*3*time.Second, 15*time.Minute)
}

func scanPlanOf(target, ports string) (*scanPlan, error) {
	target = scanCommaRe.ReplaceAllString(strings.TrimSpace(target), ",") // spaces may sit around the commas of a list, nowhere else
	if strings.ContainsAny(target, " \t\r\n") {
		return nil, fmt.Errorf("host: %q is not an IP address, a host name, a subnet or a range (separate several with commas)", target)
	}
	if target == "" {
		return nil, fmt.Errorf("host: an address or host name, a subnet (10.1.1.0/24), a range (10.1.1.10-50) or a list of these")
	}
	pl, err := scanPortList(ports)
	if err != nil {
		return nil, err
	}
	p := &scanPlan{ports: pl}
	seen := map[string]bool{}
	names, fam := 0, 0 // fam: the address family of the addresses so far (4 or 6)
	add := func(s string, v6 bool, isName bool) error {
		if seen[s] {
			return nil
		}
		if isName {
			if names++; names > scanMaxNames {
				return fmt.Errorf("host: at most %d host names in one scan", scanMaxNames)
			}
		} else {
			f := map[bool]int{false: 4, true: 6}[v6]
			if fam != 0 && fam != f {
				return fmt.Errorf("host: IPv4 and IPv6 addresses cannot be scanned together; scan them one family at a time")
			}
			fam, p.v6 = f, v6
		}
		seen[s] = true
		p.items = append(p.items, s)
		if len(p.items) > scanMaxHosts {
			return fmt.Errorf("host: more than %d addresses; scan a smaller subnet or range", scanMaxHosts)
		}
		return nil
	}
	for _, part := range strings.Split(target, ",") {
		if part == "" {
			continue
		}
		switch {
		case strings.Contains(part, "/"):
			pf, err := netip.ParsePrefix(part)
			if err != nil || pf.Addr().Zone() != "" {
				return nil, fmt.Errorf("host: %q is not a subnet like 10.1.1.0/24", part)
			}
			if pf.Addr().Is4In6() {
				return nil, fmt.Errorf("host: %q is not a subnet like 10.1.1.0/24", part)
			}
			pf = pf.Masked()
			first := pf.Addr()
			if first.IsMulticast() || first.IsUnspecified() || first.IsLoopback() && pf.Bits() < 8 {
				return nil, fmt.Errorf("host: %s is not a subnet of hosts", part)
			}
			host := first.BitLen() - pf.Bits() // bits of host part
			if host > 10 {
				return nil, fmt.Errorf("host: %s has more than %d addresses; scan a smaller subnet or range", part, scanMaxHosts)
			}
			n := 1 << host
			a := first
			for i := 0; i < n; i++ {
				if first.Is4() && host >= 2 && (i == 0 || i == n-1) { // a subnet's own and broadcast addresses are not hosts
					a = a.Next()
					continue
				}
				if err := add(a.String(), a.Is6(), false); err != nil {
					return nil, err
				}
				a = a.Next()
			}
		case strings.Contains(part, "-") && func() bool { _, e := netip.ParseAddr(part); return e != nil }() && scanLooksLikeRange(part):
			lo, hi, err := scanRange(part)
			if err != nil {
				return nil, err
			}
			for a, i := lo, 0; ; i++ {
				if i >= scanMaxHosts {
					return nil, fmt.Errorf("host: %s has more than %d addresses; scan a smaller range", part, scanMaxHosts)
				}
				if err := add(a.String(), a.Is6(), false); err != nil {
					return nil, err
				}
				if a == hi {
					break
				}
				a = a.Next()
			}
		default:
			if _, e := netip.ParseAddr(part); e == nil {
				a, err := scanAddr(part)
				if err != nil {
					return nil, fmt.Errorf("host: %w", err)
				}
				if err := add(a.String(), a.Is6(), false); err != nil {
					return nil, err
				}
				continue
			}
			key, _, name, err := netTarget(part)
			if err != nil || name == "" {
				return nil, fmt.Errorf("host: %q is not an IP address, a host name, a subnet or a range", part)
			}
			if err := add(key, false, true); err != nil {
				return nil, err
			}
		}
	}
	if len(p.items) == 0 {
		return nil, fmt.Errorf("host: nothing to scan")
	}
	switch {
	case len(p.items) == 1 && p.ports == "":
		p.key = p.items[0]
	case len(p.items) == 1:
		p.key = p.items[0] + " ports " + p.ports
	default:
		p.key = target
		if p.ports != "" {
			p.key += " ports " + p.ports
		}
		p.key = strings.ToLower(p.key)
	}
	return p, nil
}

// scanLooksLikeRange: something-dash-something that is not a host name (names have dashes too: my-host.example.com).
func scanLooksLikeRange(s string) bool {
	a, _, _ := strings.Cut(s, "-")
	_, err := netip.ParseAddr(a)
	return err == nil
}

// scanRange reads 10.1.1.10-10.1.1.50 or 10.1.1.10-50 (IPv6: both ends in full).
func scanRange(s string) (lo, hi netip.Addr, err error) {
	bad := fmt.Errorf("host: %q is not a range like 10.1.1.10-50 or 10.1.1.10-10.1.1.50", s)
	a, b, _ := strings.Cut(s, "-")
	lo, e1 := netip.ParseAddr(a)
	if e1 != nil || lo.Zone() != "" {
		return lo, hi, bad
	}
	lo = lo.Unmap()
	if hi, e2 := netip.ParseAddr(b); e2 == nil {
		hi = hi.Unmap()
		if hi.Is4() != lo.Is4() || hi.Compare(lo) < 0 {
			return lo, hi, bad
		}
		return lo, hi, scanRangeOK(lo, hi, s)
	}
	if !lo.Is4() {
		return lo, hi, bad
	}
	last, e := strconv.Atoi(b)
	o := lo.As4()
	if e != nil || last < int(o[3]) || last > 255 {
		return lo, hi, bad
	}
	o[3] = byte(last)
	hi = netip.AddrFrom4(o)
	return lo, hi, scanRangeOK(lo, hi, s)
}

func scanRangeOK(lo, hi netip.Addr, s string) error {
	if lo.IsMulticast() || lo.IsUnspecified() || hi.IsMulticast() {
		return fmt.Errorf("host: %s is not a range of hosts", s)
	}
	return nil
}

// scanPortList checks a port list: numbers and ranges, 1 to 65535, separated by commas, at most 1024 ports.  "" is the 100 commonest.
func scanPortList(s string) (string, error) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return "", nil
	}
	type span struct{ lo, hi int }
	var spans []span
	total := 0
	for _, part := range strings.Split(s, ",") {
		a, b, rng := strings.Cut(part, "-")
		lo, e1 := strconv.Atoi(a)
		hi := lo
		var e2 error
		if rng {
			hi, e2 = strconv.Atoi(b)
		}
		if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || hi < lo || strings.ContainsAny(part, "+ ") {
			return "", fmt.Errorf("ports: %q is not a port or a range of ports (1 to 65535, like 22,443 or 1-1024)", part)
		}
		spans = append(spans, span{lo, hi})
		total += hi - lo + 1
	}
	if total > scanMaxPorts {
		return "", fmt.Errorf("ports: %d ports; at most %d in one scan", total, scanMaxPorts)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	var out []string
	cur := spans[0]
	flush := func() {
		if cur.lo == cur.hi {
			out = append(out, strconv.Itoa(cur.lo))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", cur.lo, cur.hi))
		}
	}
	for _, sp := range spans[1:] {
		if sp.lo <= cur.hi+1 {
			cur.hi = max(cur.hi, sp.hi)
			continue
		}
		flush()
		cur = sp
	}
	flush()
	return strings.Join(out, ","), nil
}

// scanTidyPlan is scanTidy for a request: for several hosts, a line saying how many were scanned and answered and then a short report
// for each host that is up; for ports asked for, the "no open ports" line says which.
func scanTidyPlan(out string, p *scanPlan) string {
	if !p.multi() {
		t := scanTidy(out)
		if p.ports != "" {
			t = strings.Replace(t, "among the 100 commonest", "among the ports asked ("+p.ports+")", 1)
		}
		return t
	}
	const hostMark = "Nmap scan report for "
	var blocks []string
	var cur []string
	summary := ""
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, hostMark):
			if cur != nil {
				blocks = append(blocks, strings.Join(cur, "\n"))
			}
			cur = []string{l}
		case strings.HasPrefix(t, "Nmap done:"):
			summary = t
			if cur != nil {
				blocks = append(blocks, strings.Join(cur, "\n"))
				cur = nil
			}
		case cur != nil:
			cur = append(cur, l)
		}
	}
	if cur != nil {
		blocks = append(blocks, strings.Join(cur, "\n"))
	}
	scanned, up := len(p.items), len(blocks)
	if i := strings.Index(summary, "("); i > 0 && strings.Contains(summary, "hosts up") {
		fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(summary[:i], "Nmap done:")), "%d", &scanned)
		fmt.Sscanf(summary[i:], "(%d hosts up)", &up)
	} else if strings.Contains(summary, "(1 host up)") {
		up = 1
	}
	if len(blocks) == 0 {
		if strings.TrimSpace(out) == "" {
			return "nmap printed nothing"
		}
		return fmt.Sprintf("%d addresses scanned, none answered (a host that drops pings and probes is not found; scan it by itself to scan it regardless)", scanned)
	}
	lines := []string{fmt.Sprintf("%d addresses scanned, %d up", scanned, up)}
	for i, b := range blocks {
		if i == 100 {
			lines = append(lines, fmt.Sprintf("… and %d more hosts up", len(blocks)-100))
			break
		}
		head, rest, _ := strings.Cut(b, "\n")
		lines = append(lines, "", "▸ "+strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(head), hostMark)))
		t := scanTidy(rest)
		if p.ports != "" {
			t = strings.Replace(t, "among the 100 commonest", "among the ports asked", 1)
		}
		for _, l := range strings.Split(t, "\n") {
			lines = append(lines, "  "+l)
		}
	}
	return strings.Join(lines, "\n")
}
