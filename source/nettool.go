package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ping and traceroute of a client, from Statistics ▸ Top clients ▸ right-click ▸ Ping / Traceroute.  The command runs
// on this node (the node picked in the Node menu) with fixed options: the address is the only thing a caller chooses,
// and it is checked to be one host's address before it gets near the command line.  The output is kept while the
// command runs, so the popup can show it as it grows.
const (
	netToolParallel = 4
	netToolTextMax  = 16384
	pingTimeout     = 15 * time.Second
	traceTimeout    = 120 * time.Second
)

// NetJob is a ping or traceroute, running or finished.
type NetJob struct {
	Kind  string `json:"kind"` // ping, trace
	Addr  string `json:"addr"`
	State string `json:"state"` // running, done, error, none
	Text  string `json:"text,omitempty"`
	At    int64  `json:"at,omitempty"`
	End   int64  `json:"end,omitempty"`
	// Hops is the traceroute table as data, so the page can show the host names or the addresses without asking again.
	Hops []NetHop `json:"hops,omitempty"`
}

// NetHop is one row of a traceroute.  Name is the reverse-DNS name of Addr, when one was found.
type NetHop struct {
	Addr  string  `json:"addr"`
	Name  string  `json:"name,omitempty"`
	Loss  float64 `json:"loss"`
	Sent  int     `json:"sent"`
	Last  float64 `json:"last"`
	Avg   float64 `json:"avg"`
	Best  float64 `json:"best"`
	Worst float64 `json:"worst"`
}

var netJobs = struct {
	mu   sync.Mutex
	jobs map[string]*NetJob
}{jobs: map[string]*NetJob{}}

// netToolSpec is the program and arguments for kind and addr: four pings, or mtr with ten
// probes per hop, both without name lookups.  mtr runs in its raw mode, which reports every probe as it happens, so the
// table can grow on screen (its report mode prints only when it is done).
func netToolSpec(kind string, a netip.Addr) (string, []string, time.Duration, error) {
	return netToolSpecOpts(kind, a, NetOpts{})
}

// NetOpts are the choices a caller has beyond the host: for ping the number of pings (1 to 20, default 4), the payload size in
// bytes (8 to 65500; with Df the largest one that gets through is the path MTU less 28, or 48 for IPv6) and Df (do not fragment);
// for ping and mtr the family (4 or 6).  Zero is the default.
type NetOpts struct {
	Count, Size, Family int
	Df                  bool
}

func (o NetOpts) key() string {
	if o == (NetOpts{}) {
		return ""
	}
	return fmt.Sprintf("|%d|%d|%d|%t", o.Count, o.Size, o.Family, o.Df)
}

// netOptsParse reads the options as the API carries them (strings); kind says which apply.
func netOptsParse(kind, count, size, df, family string) (NetOpts, error) {
	var o NetOpts
	num := func(name, v string, lo, hi int) (int, error) {
		v = strings.TrimSpace(v)
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return 0, fmt.Errorf("%s: a whole number from %d to %d", name, lo, hi)
		}
		return n, nil
	}
	var err error
	if o.Family, err = num("family", family, 4, 6); err != nil || (o.Family != 0 && o.Family != 4 && o.Family != 6) {
		return o, errors.New("family: 4 or 6")
	}
	d := strings.ToLower(strings.TrimSpace(df))
	o.Df = d == "1" || d == "true"
	if kind != "ping" {
		if strings.TrimSpace(count) != "" || strings.TrimSpace(size) != "" || o.Df {
			return o, errors.New("count, size and df are for ping only")
		}
		return o, nil
	}
	if o.Count, err = num("count", count, 1, 20); err != nil {
		return o, err
	}
	if o.Size, err = num("size", size, 8, 65500); err != nil {
		return o, err
	}
	return o, nil
}

func netToolSpecOpts(kind string, a netip.Addr, o NetOpts) (string, []string, time.Duration, error) {
	switch kind {
	case "ping":
		n := o.Count
		if n == 0 {
			n = 4
		}
		args := []string{"-n", "-c", strconv.Itoa(n), "-W", "2"}
		if o.Size > 0 {
			args = append(args, "-s", strconv.Itoa(o.Size))
		}
		if o.Df {
			args = append(args, "-M", "do")
		}
		if a.Is6() {
			args = append(args, "-6")
		}
		return "ping", append(args, "--", a.String()), pingLimit(n), nil
	case "trace":
		args := []string{"-n", "--raw", "-c", "10"}
		if a.Is6() {
			args = append(args, "-6")
		}
		return "mtr", append(args, "--", a.String()), traceTimeout, nil
	}
	return "", nil, 0, fmt.Errorf("unknown tool %q", kind)
}

// pingLimit is how long n pings may take: one a second, and a reply that does not come is waited for two seconds.
func pingLimit(n int) time.Duration {
	if n <= 4 {
		return pingTimeout
	}
	return time.Duration(n+11) * time.Second
}

// netBuf is the output of a running job: every write goes straight into the job's text.
type netBuf struct {
	j *NetJob
}

func (b netBuf) Write(p []byte) (int, error) {
	netJobs.mu.Lock()
	if room := netToolTextMax - len(b.j.Text); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.j.Text += string(p)
	}
	netJobs.mu.Unlock()
	return len(p), nil
}

var netNameRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// netTarget checks what was asked about: one host's address, or a host name (looked up when the job runs).  key is how
// the job is remembered; ip is set for an address, name for a name.
func netTarget(s string) (key string, ip netip.Addr, name string, err error) {
	if a, e := scanAddr(s); e == nil {
		return a.String(), a, "", nil
	}
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(n) == 0 || len(n) > 253 {
		return "", ip, "", fmt.Errorf("%q is not an IP address or a host name", s)
	}
	labels := strings.Split(n, ".")
	for _, l := range labels {
		if !netNameRe.MatchString(l) {
			return "", ip, "", fmt.Errorf("%q is not an IP address or a host name", s)
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" { // 224.0.0.1 or 1.2.3 is a bad address, not a name
		return "", ip, "", fmt.Errorf("%q is not an IP address or a host name", s)
	}
	return n, ip, n, nil
}

// netToolStart begins ping or traceroute of addr, an address or a host name (or returns the one already running).  A
// finished one is replaced.
func netToolStart(kind, addr, actor string) (*NetJob, error) {
	return netToolStartOpts(kind, addr, actor, NetOpts{})
}

func netToolStartOpts(kind, addr, actor string, o NetOpts) (*NetJob, error) {
	key, ip, name, err := netTarget(addr)
	if err != nil {
		return nil, err
	}
	if ip.IsValid() && ((o.Family == 4 && !ip.Is4()) || (o.Family == 6 && !ip.Is6())) {
		return nil, fmt.Errorf("%s is not an IPv%d address", ip, o.Family)
	}
	prog, _, limit, err := netToolSpecOpts(kind, netip.MustParseAddr("127.0.0.1"), o)
	if err != nil {
		return nil, err
	}
	path, err := exec.LookPath(prog)
	if err != nil {
		pkg := map[string]string{"ping": "iputils-ping (iputils on the RHEL family)", "mtr": "mtr"}[prog]
		return nil, fmt.Errorf("%s is not installed on this node (install the %s package)", prog, pkg)
	}
	jk := kind + "|" + key + o.key()
	netJobs.mu.Lock()
	if j := netJobs.jobs[jk]; j != nil && j.State == "running" {
		c := *j
		netJobs.mu.Unlock()
		return &c, nil
	}
	running := 0
	for _, j := range netJobs.jobs {
		if j.State == "running" {
			running++
		}
	}
	if running >= netToolParallel {
		netJobs.mu.Unlock()
		return nil, errors.New("too many are running already; try again in a moment")
	}
	j := &NetJob{Kind: kind, Addr: key, State: "running", At: time.Now().Unix()}
	netJobs.jobs[jk] = j
	for k, o := range netJobs.jobs { // finished ones older than an hour are forgotten
		if o.State != "running" && time.Now().Unix()-o.End > 3600 {
			delete(netJobs.jobs, k)
		}
	}
	c := *j
	netJobs.mu.Unlock()
	infof("nettool: %q started %s of %s", actor, prog, key)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		defer cancel()
		finish := func(state, text string) {
			netJobs.mu.Lock()
			j.End, j.State = time.Now().Unix(), state
			if text != "" {
				j.Text = text
			}
			netJobs.mu.Unlock()
			infof("nettool: %s of %s %s", prog, key, state)
		}
		title := ""
		if name != "" { // a name: the first address it has (IPv4 first), looked up here
			rc, rcancel := context.WithTimeout(ctx, 5*time.Second)
			network := "ip"
			if o.Family == 4 || o.Family == 6 {
				network = "ip" + strconv.Itoa(o.Family)
			}
			ips, err := net.DefaultResolver.LookupNetIP(rc, network, name)
			rcancel()
			ip = netip.Addr{}
			for _, x := range ips {
				x = x.Unmap()
				if x.IsUnspecified() || x.IsMulticast() || x.Zone() != "" {
					continue
				}
				if !ip.IsValid() || (x.Is4() && ip.Is6()) {
					ip = x
				}
			}
			if !ip.IsValid() {
				msg := "no address found"
				if err != nil {
					msg = err.Error()
				}
				finish("error", name+": "+msg)
				return
			}
			title = name + " (" + ip.String() + ")"
			if kind == "ping" {
				netJobs.mu.Lock()
				fam := "IPv4"
				if ip.Is6() {
					fam = "IPv6"
				}
				j.Text = name + " → " + ip.String() + " (" + fam + ")\n\n"
				netJobs.mu.Unlock()
			}
		}
		_, args, _, _ := netToolSpecOpts(kind, ip, o)
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdout, cmd.Stderr = netBuf{j}, netBuf{j}
		var raw *mtrRaw
		if kind == "trace" {
			raw = &mtrRaw{j: j, hops: map[int]*mtrHop{}, target: ip.String(), title: title}
			cmd.Stdout = raw
		}
		err := cmd.Run()
		netJobs.mu.Lock()
		if raw != nil {
			raw.render() // the last partial line, and the table as it ended
		}
		state := "done"
		if err != nil {
			// ping exits 1 when nothing came back: its output already says so, and is not an error here
			var ee *exec.ExitError
			if ctx.Err() != nil {
				state = "error"
				j.Text = strings.TrimSpace(j.Text + "\n(stopped after " + limit.String() + ")")
			} else if !errors.As(err, &ee) || strings.TrimSpace(j.Text) == "" {
				state = "error"
				if strings.TrimSpace(j.Text) == "" {
					j.Text = err.Error()
				}
			}
		}
		if strings.TrimSpace(j.Text) == "" {
			j.Text = prog + " printed nothing"
		}
		netJobs.mu.Unlock()
		finish(state, "")
	}()
	return &c, nil
}

// netToolGet is the state of kind for addr: running, done, error, or none when there never was one.
func netToolGet(kind, addr string) (*NetJob, error) { return netToolGetOpts(kind, addr, NetOpts{}) }

func netToolGetOpts(kind, addr string, o NetOpts) (*NetJob, error) {
	key, _, _, err := netTarget(addr)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := netToolSpec(kind, netip.MustParseAddr("127.0.0.1")); err != nil {
		return nil, err
	}
	netJobs.mu.Lock()
	defer netJobs.mu.Unlock()
	if j := netJobs.jobs[kind+"|"+key+o.key()]; j != nil {
		c := *j
		return &c, nil
	}
	return &NetJob{Kind: kind, Addr: key, State: "none"}, nil
}

// mtrHop is what mtr's raw output has told so far about one hop.
type mtrHop struct {
	host                   string
	name                   string // reverse-DNS name of host, filled in by a background lookup
	asked                  bool
	sent, got              int
	last, sum, best, worst float64 // milliseconds
}

// mtrRaw turns mtr's --raw lines ("x HOP SEQ" probe sent, "h HOP ADDR" the hop's address, "p HOP USEC SEQ" a reply)
// into the usual table and keeps the job's text up to date after every line.  Hops are counted from 0 in the raw output.
type mtrRaw struct {
	j      *NetJob
	target string // the address probed
	title  string // what the table says it is to (the name and address, or the address)
	part   string
	hops   map[int]*mtrHop
}

func (m *mtrRaw) Write(p []byte) (int, error) {
	netJobs.mu.Lock()
	defer netJobs.mu.Unlock()
	m.part += string(p)
	if len(m.part) > 1<<20 {
		m.part = ""
	}
	for {
		i := strings.IndexByte(m.part, '\n')
		if i < 0 {
			break
		}
		m.line(m.part[:i])
		m.part = m.part[i+1:]
	}
	m.render()
	return len(p), nil
}

// resolve looks up the reverse name of a hop in the background; the table is rebuilt when it arrives.
func (m *mtrRaw) resolve(n int, addr string) {
	netToolRDNS <- struct{}{}
	defer func() { <-netToolRDNS }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	names, _ := net.DefaultResolver.LookupAddr(ctx, addr)
	cancel()
	if len(names) == 0 {
		return
	}
	netJobs.mu.Lock()
	defer netJobs.mu.Unlock()
	if h := m.hops[n]; h != nil {
		h.name = strings.TrimSuffix(names[0], ".")
		m.render()
	}
}

// netToolRDNS bounds the hop lookups running at once.
var netToolRDNS = make(chan struct{}, 8)

func (m *mtrRaw) titleOr() string {
	if m.title != "" {
		return m.title
	}
	return m.target
}

func (m *mtrRaw) line(l string) {
	f := strings.Fields(l)
	if len(f) < 3 {
		return
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 0 || n > 255 {
		return
	}
	h := m.hops[n]
	if h == nil {
		h = &mtrHop{}
		m.hops[n] = h
	}
	switch f[0] {
	case "x":
		h.sent++
	case "h":
		if a, err := netip.ParseAddr(f[2]); err == nil {
			h.host = a.String()
			if !h.asked {
				h.asked = true
				go m.resolve(n, h.host)
			}
		}
	case "p":
		us, err := strconv.ParseFloat(f[2], 64)
		if err != nil {
			return
		}
		ms := us / 1000
		if h.got == 0 || ms < h.best {
			h.best = ms
		}
		if ms > h.worst {
			h.worst = ms
		}
		h.got++
		h.last = ms
		h.sum += ms
	}
}

// render rebuilds the job's text from the table (the caller holds netJobs.mu, except after the command has ended
// and before the final state is set, when it is taken there as well).
func (m *mtrRaw) render() {
	if m.part != "" && !strings.Contains(m.part, "\n") && len(m.hops) > 0 {
		m.line(m.part)
		m.part = ""
	}
	keys := make([]int, 0, len(m.hops))
	for k, h := range m.hops {
		if h.sent > 0 || h.host != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	sort.Ints(keys)
	for i, k := range keys { // mtr probes a hop or two past the target before it knows it was reached: the table ends there
		if h := m.hops[k]; h.host == m.target && h.got > 0 {
			keys = keys[:i+1]
			break
		}
	}
	w := 0
	for _, k := range keys {
		if h := m.hops[k].host; len(h) > w {
			w = len(h)
		}
	}
	if w < 7 {
		w = 7
	}
	var b strings.Builder
	var hops []NetHop
	fmt.Fprintf(&b, "to %s\n%-*s  %6s %4s %7s %7s %7s %7s\n", m.titleOr(), w+4, "", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst")
	for i, k := range keys {
		h := m.hops[k]
		host := h.host
		if host == "" {
			host = "???"
		}
		loss, avg := 100.0, 0.0
		if h.sent > 0 {
			loss = 100 * float64(h.sent-h.got) / float64(h.sent)
		}
		if h.got > 0 {
			avg = h.sum / float64(h.got)
		}
		fmt.Fprintf(&b, "%2d. %-*s  %5.1f%% %4d %7.1f %7.1f %7.1f %7.1f\n", i+1, w, host, loss, h.sent, h.last, avg, h.best, h.worst)
		hops = append(hops, NetHop{Addr: h.host, Name: h.name, Loss: loss, Sent: h.sent, Last: h.last, Avg: avg, Best: h.best, Worst: h.worst})
	}
	m.j.Text = b.String()
	m.j.Hops = hops
}
