package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// An nmap scan of a client, started from Statistics ▸ Top clients ▸ right-click ▸ Scan.  nmap runs on this node (the
// node picked in the Node menu), one scan per address at a time and a few at once, with fixed options: the address is
// the only thing a caller chooses, and it is checked to be an address before it gets near the command line.
const (
	scanTimeout  = 150 * time.Second
	scanParallel = 2
	scanKeep     = 200   // finished scans remembered (oldest dropped)
	scanTextMax  = 6000  // characters of the report kept
	scanReadMax  = 65536 // bytes of nmap's output read
)

// ScanJob is a scan, running or finished.
type ScanJob struct {
	Addr  string `json:"addr"`
	State string `json:"state"` // running, done, error, none
	Text  string `json:"text,omitempty"`
	At    int64  `json:"at,omitempty"` // when it started
	End   int64  `json:"end,omitempty"`
	By    string `json:"by,omitempty"`
}

var scans = struct {
	mu    sync.Mutex
	jobs  map[string]*ScanJob
	order []string
}{jobs: map[string]*ScanJob{}}

// scanAddr checks that s is one unicast address and returns it in its usual spelling.
func scanAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, fmt.Errorf("%s is not an address of one host", a)
	}
	return a, nil
}

// scanTarget checks what to scan: one unicast address, or a host name nmap looks up itself.
func scanTarget(s string) (key string, ip netip.Addr, name string, err error) {
	if _, e := netip.ParseAddr(strings.TrimSpace(s)); e == nil {
		a, e := scanAddr(s)
		if e != nil {
			return "", ip, "", e
		}
		return a.String(), a, "", nil
	}
	return netTarget(s)
}

// scanArgs are nmap's arguments for addr: no ping (hosts that drop it are scanned anyway), the 100 commonest ports,
// service and OS detection, and a cap on the time.
func scanArgs(a netip.Addr) []string { return scanArgsFor(a.String(), a.Is6()) }

// scanArgsFor is scanArgs for target, an address or a host name nmap looks up itself.
func scanArgsFor(target string, v6 bool) []string {
	return scanArgsPlan(&scanPlan{items: []string{target}, v6: v6})
}

// scanArgsPlan are the arguments for a checked request.  One host is scanned with no ping (hosts that drop it are scanned anyway) and
// its address comes last, after "--".  Several hosts are found first (nmap's own host discovery, so the dead addresses of a subnet are
// not scanned port by port) and their addresses are read from standard input (-iL -): scanStdin.
func scanArgsPlan(p *scanPlan) []string {
	args := []string{"-T4", "-sV", "--version-light", "-O", "--osscan-limit", "--max-retries", "1", "--host-timeout", "120s"}
	if p.ports != "" {
		args = append(args, "-p", p.ports)
	} else {
		args = append(args, "-F")
	}
	if p.v6 {
		args = append(args, "-6")
	}
	if p.multi() {
		return append(args, "-iL", "-")
	}
	return append(args, "-Pn", "--", p.items[0])
}

// scanStdin is the list of addresses nmap reads for a scan of several hosts.
func scanStdin(p *scanPlan) *strings.Reader {
	if !p.multi() {
		return nil
	}
	return strings.NewReader(strings.Join(p.items, "\n") + "\n")
}

var scanPortRe = regexp.MustCompile(`^(\d+)/(tcp|udp|sctp)\s+open\s+(\S+)\s*(.*)$`)

// scanTidy boils nmap's report down to what is worth reading in a tooltip: whether the host is up, its operating
// system, the MAC address with its maker, and the open ports with the service (and version) found on each.
// A report that has none of these in it (nmap said something else) is kept as it is, shortened.
func scanTidy(out string) string {
	var up, osName, osRun, osGuess, svcOS, mac string
	var ports []string
	down := false
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Host is up"):
			up = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(t, "Host is up"), "."))
			up = strings.Trim(up, "() ")
		case strings.Contains(t, "Host seems down"):
			down = true
		case strings.HasPrefix(t, "OS details:"):
			osName = strings.TrimSpace(strings.TrimPrefix(t, "OS details:"))
		case strings.HasPrefix(t, "Running:"):
			osRun = strings.TrimSpace(strings.TrimPrefix(t, "Running:"))
		case strings.HasPrefix(t, "Aggressive OS guesses:"):
			g := strings.TrimSpace(strings.TrimPrefix(t, "Aggressive OS guesses:"))
			if i := strings.Index(g, ", "); i > 0 {
				g = g[:i]
			}
			osGuess = g
		case strings.HasPrefix(t, "Service Info:"):
			for _, part := range strings.Split(strings.TrimPrefix(t, "Service Info:"), ";") {
				if p := strings.TrimSpace(part); strings.HasPrefix(p, "OS:") {
					svcOS = strings.TrimSpace(strings.TrimPrefix(p, "OS:"))
				}
			}
		case strings.HasPrefix(t, "MAC Address:"):
			mac = strings.TrimSpace(strings.TrimPrefix(t, "MAC Address:"))
		default:
			if m := scanPortRe.FindStringSubmatch(t); m != nil {
				e := m[1] + "/" + m[2] + "  " + m[3]
				if v := strings.TrimSpace(m[4]); v != "" {
					if len(v) > 60 {
						v = v[:60] + "…"
					}
					e += "  " + v
				}
				ports = append(ports, e)
			}
		}
	}
	for _, c := range []string{osName, osRun, osGuess, svcOS} {
		if c != "" {
			osName = c
			break
		}
	}
	if up == "" && !down && osName == "" && mac == "" && len(ports) == 0 {
		raw := scanTidyRaw(out)
		if len(raw) > 600 {
			raw = raw[:600] + "\n…"
		}
		return raw
	}
	var b []string
	switch {
	case down:
		b = append(b, "Host seems down (no answer to the probes)")
	case up != "":
		b = append(b, "Up, "+up)
	}
	if osName != "" {
		b = append(b, "OS: "+osName)
	}
	if mac != "" {
		b = append(b, "MAC: "+mac)
	}
	switch {
	case len(ports) == 0 && !down:
		b = append(b, "No open ports found among the 100 commonest")
	case len(ports) > 0:
		b = append(b, "Open ports:")
		for i, p := range ports {
			if i == 12 {
				b = append(b, fmt.Sprintf("… and %d more", len(ports)-12))
				break
			}
			b = append(b, "  "+p)
		}
	}
	return strings.Join(b, "\n")
}

// scanTidyRaw leaves out nmap's banner and footer lines and keeps the rest.
func scanTidyRaw(out string) string {
	var keep []string
	blank := false
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Starting Nmap"), strings.HasPrefix(t, "Nmap done"), strings.HasPrefix(t, "Read data files"),
			strings.HasPrefix(t, "Service detection performed"), strings.HasPrefix(t, "OS detection performed"),
			strings.HasPrefix(t, "OS and Service detection performed"), strings.HasPrefix(t, "Please report"):
			continue
		case t == "":
			if blank || len(keep) == 0 {
				continue
			}
			blank = true
		default:
			blank = false
		}
		keep = append(keep, strings.TrimRight(l, " \t"))
	}
	s := strings.TrimSpace(strings.Join(keep, "\n"))
	if len(s) > scanTextMax {
		s = s[:scanTextMax] + "\n…"
	}
	return s
}

// limitBuf keeps the first max bytes written and drops the rest.
type limitBuf struct {
	b   bytes.Buffer
	max int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// scanStart begins a scan of addr (an address or a host name) (or returns the one already running for it).
func scanStart(addr, actor string) (*ScanJob, error) { return scanStartPorts(addr, "", actor) }

// scanStartPorts is scanStart for a request that may name ports and several hosts (scantarget.go).
func scanStartPorts(addr, ports, actor string) (*ScanJob, error) {
	plan, err := scanPlanOf(addr, ports)
	if err != nil {
		return nil, err
	}
	key := plan.key
	path, err := exec.LookPath("nmap")
	if err != nil {
		return nil, errors.New("nmap is not installed on this node (install the nmap package)")
	}
	scans.mu.Lock()
	if j := scans.jobs[key]; j != nil && j.State == "running" {
		c := *j
		scans.mu.Unlock()
		return &c, nil
	}
	running := 0
	for _, j := range scans.jobs {
		if j.State == "running" {
			running++
		}
	}
	if running >= scanParallel {
		scans.mu.Unlock()
		return nil, fmt.Errorf("%d scans are running already; try again when one has finished", running)
	}
	j := &ScanJob{Addr: key, State: "running", At: time.Now().Unix(), By: actor}
	if _, had := scans.jobs[key]; !had {
		scans.order = append(scans.order, key)
		if len(scans.order) > scanKeep {
			delete(scans.jobs, scans.order[0])
			scans.order = scans.order[1:]
		}
	}
	scans.jobs[key] = j
	c := *j
	scans.mu.Unlock()
	infof("scan: %q started nmap of %s (%d hosts)", actor, key, len(plan.items))
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), plan.timeout())
		defer cancel()
		cmd := exec.CommandContext(ctx, path, scanArgsPlan(plan)...)
		if in := scanStdin(plan); in != nil {
			cmd.Stdin = in
		}
		out := &limitBuf{max: scanReadMax * max(1, min(len(plan.items), 16))}
		cmd.Stdout, cmd.Stderr = out, out
		err := cmd.Run()
		text := scanTidyPlan(out.b.String(), plan)
		state := "done"
		if err != nil {
			state = "error"
			switch {
			case ctx.Err() != nil:
				text = strings.TrimSpace("the scan took longer than " + plan.timeout().String() + " and was stopped\n" + text)
			case text == "":
				text = err.Error()
			}
		} else if text == "" {
			text = "nmap printed nothing"
		}
		scans.mu.Lock()
		j.State, j.Text, j.End = state, text, time.Now().Unix()
		scans.mu.Unlock()
		infof("scan: nmap of %s %s", key, state)
	}()
	return &c, nil
}

// scanGet is the state of the scan of addr: running, done, error, or none when there never was one.
func scanGet(addr string) (*ScanJob, error) { return scanGetPorts(addr, "") }

func scanGetPorts(addr, ports string) (*ScanJob, error) {
	plan, err := scanPlanOf(addr, ports)
	if err != nil {
		return nil, err
	}
	key := plan.key
	scans.mu.Lock()
	defer scans.mu.Unlock()
	if j := scans.jobs[key]; j != nil {
		c := *j
		return &c, nil
	}
	return &ScanJob{Addr: key, State: "none"}, nil
}
