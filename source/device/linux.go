package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Linux host over SSH.  The driver runs the OpenSSH client (ssh) the way the SFTP backup does, because the program is stdlib-only:
// the login is a user name with a password (handed to ssh through SSH_ASKPASS, never on a command line) or an SSH private key (the
// credential's token, in PEM form); with neither, the daemon's own keys and agent are used.  The host key is learned the first time
// (StrictHostKeyChecking=accept-new) and checked after that; the device's "insecure" skips the check.
//
// Reads are plain commands of the login user (ip -j, /proc, /sys, df, free, lldpctl, systemctl, journalctl).  Writes and the few reads
// that need root go through sudo: "sudo -S" with the credential's password on its standard input, or "sudo -n" when there is none; a
// login as root runs them directly.  Option sudo=no runs everything as the login user.  The script is sent as base64 in the remote
// command, so no quoting of the host's shell matters, and the host needs a POSIX sh and base64 (coreutils or busybox).
//
// What the driver offers: facts, interfaces (ip -j addr), LLDP neighbors (lldpctl, when lldpd runs), ports with counters, routes,
// resources, a configuration made of the files and tables that describe the network, "show" commands from a fixed list, typed port
// changes (description through the interface alias, shutdown and no shutdown through ip link set) and raw lines of shell run as root.
// A Linux host keeps nothing to save: what ip changes lasts until the next reboot, and a line that writes a file keeps what it wrote.

func init() { Register("linux", newLinux) }

type linuxTarget struct {
	Host     string
	Port     int
	User     string
	Pass     string
	Key      string // PEM private key
	Insecure bool
	Sudo     bool // false: everything runs as the login user
	Win      bool // a Windows host: the script is PowerShell, fed to powershell on standard input
}

type linux struct {
	d Device
	t linuxTarget
}

func newLinux(d Device, c Credential) (Driver, error) {
	if c.Username == "" {
		return nil, fmt.Errorf("device %s: SSH needs a user name (and a password or a private key as the token; with neither the daemon's own keys are tried)", d.Name)
	}
	if strings.HasPrefix(d.Address, "-") || strings.ContainsAny(d.Address, " \t\r\n\x00'\"`$;&|<>\\") || d.Address == "" {
		return nil, fmt.Errorf("device %s: %q is not a host name or an address", d.Name, d.Address)
	}
	if strings.HasPrefix(c.Username, "-") || !regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}$`).MatchString(c.Username) {
		return nil, fmt.Errorf("device %s: %q is not a user name", d.Name, c.Username)
	}
	t := linuxTarget{Host: d.Address, Port: d.Port, User: c.Username, Pass: c.Password, Insecure: d.Insecure, Sudo: true}
	if t.Port == 0 {
		t.Port = 22
	}
	if strings.Contains(c.Token, "PRIVATE KEY") {
		t.Key = c.Token
	}
	switch strings.ToLower(d.Options["sudo"]) {
	case "", "yes", "auto", "true":
	case "no", "none", "false":
		t.Sudo = false
	default:
		return nil, fmt.Errorf("device %s: option sudo is yes or no", d.Name)
	}
	if c.Username == "root" {
		t.Sudo = false
	}
	return &linux{d: d, t: t}, nil
}

func (l *linux) Close(context.Context) {}

// linuxExec runs a script on the host and returns what it printed on standard output and on standard error.  priv runs it as root.
// Tests replace it.
var linuxExec = sshExec

const linuxMaxScript = 70 << 10

func sshBinary() string {
	if v := os.Getenv("NETDIR_SSH"); v != "" {
		return v
	}
	return "ssh"
}

func knownHostsFile() string {
	if v := os.Getenv("NETDIR_SSH_KNOWN_HOSTS"); v != "" {
		return v
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "netdir")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "ssh_known_hosts")
}

// remoteCommand is what ssh is told to run: the script is decoded on the host, and run by sh (as root with sudo, if priv).
func remoteCommand(t linuxTarget, script string, priv bool) string {
	b := base64.StdEncoding.EncodeToString([]byte(script))
	dec := "printf %s " + b + " | base64 -d"
	if !priv || !t.Sudo {
		return dec + " | sh"
	}
	if t.Pass != "" {
		return `sudo -S -p '' sh -c "$(` + dec + `)"`
	}
	return `sudo -n sh -c "$(` + dec + `)"`
}

// remoteInvocation is the command ssh is given and what it is fed on standard input: for Linux the sudo password (if any), for Windows
// the one-line wrapper around the script.
func remoteInvocation(t linuxTarget, script string, priv bool) (remote, stdin string) {
	if t.Win {
		return winInvocation(script)
	}
	if priv && t.Sudo && t.Pass != "" {
		stdin = t.Pass + "\n"
	}
	return remoteCommand(t, script, priv), stdin
}

func sshExec(ctx context.Context, t linuxTarget, script string, priv bool) (string, string, error) {
	if len(script) > linuxMaxScript {
		return "", "", fmt.Errorf("the commands are longer than %d KB", linuxMaxScript>>10)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
	}
	work, err := os.MkdirTemp("", "netdir-ssh-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(work)
	args := []string{"-T", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR"}
	if t.Insecure {
		args = append(args, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
	} else {
		args = append(args, "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile="+knownHostsFile())
	}
	env := os.Environ()
	switch {
	case t.Key != "":
		kf := filepath.Join(work, "id")
		if err := os.WriteFile(kf, []byte(strings.TrimSpace(t.Key)+"\n"), 0o600); err != nil {
			return "", "", err
		}
		args = append(args, "-o", "BatchMode=yes", "-o", "IdentityFile="+kf, "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no")
	case t.Pass != "":
		ap := filepath.Join(work, "askpass.sh")
		if err := os.WriteFile(ap, []byte("#!/bin/sh\nprintf '%s\\n' \"$NETDIR_SSH_ASKPASS_VALUE\"\n"), 0o700); err != nil {
			return "", "", err
		}
		args = append(args, "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1")
		env = append(env, "SSH_ASKPASS="+ap, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=none:0", "NETDIR_SSH_ASKPASS_VALUE="+t.Pass)
	default:
		args = append(args, "-o", "BatchMode=yes")
	}
	remote, in := remoteInvocation(t, script, priv)
	args = append(args, "-p", strconv.Itoa(t.Port), "-l", t.User, "--", t.Host, remote)
	cmd := exec.CommandContext(ctx, sshBinary(), args...)
	cmd.Env = env
	if in != "" {
		cmd.Stdin = strings.NewReader(in)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	so, se := out.String(), errb.String()
	if t.Pass != "" {
		so, se = strings.ReplaceAll(so, t.Pass, "***"), strings.ReplaceAll(se, t.Pass, "***")
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return "", "", errors.New("ssh is not installed on this node: install the OpenSSH client (openssh-client, or openssh-clients on RHEL/Fedora)")
	}
	return so, se, err
}

// linuxErr turns a failed run into the line that says why.
func linuxErr(op, stderr string, err error) error {
	msg := ""
	for _, l := range strings.Split(strings.ReplaceAll(stderr, "\r", ""), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "Warning: Permanently added") {
			msg = l
		}
	}
	low := strings.ToLower(stderr)
	var ee *exec.ExitError
	code := -1
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	switch {
	case strings.Contains(low, "permission denied (") || strings.Contains(low, "permission denied, please"):
		return fmt.Errorf("%s: SSH login refused (wrong user, password or key): %s", op, msg)
	case strings.Contains(low, "host key verification failed") || strings.Contains(low, "remote host identification has changed"):
		return fmt.Errorf("%s: the host key is not the one this node saw before (%s)", op, msg)
	case strings.Contains(low, "incorrect password") || strings.Contains(low, "sorry, try again") || strings.Contains(low, "a password is required") || strings.Contains(low, "no tty present"):
		return fmt.Errorf("%s: sudo did not accept it: the user needs sudo rights and the right password (or NOPASSWD without a password in the credential): %s", op, msg)
	case strings.Contains(low, "not in the sudoers") || strings.Contains(low, "may not run sudo"):
		return fmt.Errorf("%s: the user may not use sudo on this host: %s", op, msg)
	case code == 255 && msg != "":
		return fmt.Errorf("%s: %s", op, msg)
	case msg != "":
		return fmt.Errorf("%s: %s (exit %d)", op, msg, code)
	}
	return fmt.Errorf("%s: %v", op, err)
}

func (l *linux) run(ctx context.Context, op, script string, priv bool) (string, error) {
	so, se, err := linuxExec(ctx, l.t, script, priv)
	if err != nil {
		return so, linuxErr(op, se, err)
	}
	return so, nil
}

// section splits "@@name" separated output.
func linuxSections(s string) map[string]string {
	out := map[string]string{}
	cur := ""
	var b strings.Builder
	flush := func() {
		if cur != "" {
			out[cur] = strings.TrimSpace(b.String())
		}
		b.Reset()
	}
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(ln, "@@") {
			flush()
			cur = strings.TrimSpace(ln[2:])
			continue
		}
		b.WriteString(ln + "\n")
	}
	flush()
	return out
}

func kvLines(s string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func (l *linux) Facts(ctx context.Context) (Facts, error) {
	out, err := l.run(ctx, "facts", `echo "hostname=$(hostname 2>/dev/null)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "pretty=$PRETTY_NAME"; echo "osid=$ID"; fi
echo "kernel=$(uname -r)"
echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
echo "model=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "serial=$(cat /sys/class/dmi/id/product_serial 2>/dev/null)"
`, false)
	if err != nil {
		return Facts{}, err
	}
	m := kvLines(out)
	f := Facts{Hostname: m["hostname"], Vendor: "Linux", Model: m["model"], Serial: m["serial"]}
	f.OSVersion = strings.TrimSpace(firstOf(m["pretty"], m["osid"]) + " (kernel " + m["kernel"] + ")")
	if n, err := strconv.ParseInt(m["uptime"], 10, 64); err == nil {
		f.UptimeS = n
	}
	return f, nil
}

type ipAddr struct {
	Ifname    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	Operstate string   `json:"operstate"`
	Address   string   `json:"address"`
	MTU       int64    `json:"mtu"`
	Alias     string   `json:"ifalias"`
	LinkType  string   `json:"link_type"`
	AddrInfo  []struct {
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
	} `json:"addr_info"`
	Stats64 struct {
		Rx ipCounters `json:"rx"`
		Tx ipCounters `json:"tx"`
	} `json:"stats64"`
}

type ipCounters struct {
	Bytes     int64 `json:"bytes"`
	Packets   int64 `json:"packets"`
	Errors    int64 `json:"errors"`
	Dropped   int64 `json:"dropped"`
	Multicast int64 `json:"multicast"`
}

const linuxIfaceScript = `ip -j -s addr 2>/dev/null || ip -j addr
echo
echo "@@speed"
for i in /sys/class/net/*; do n=${i##*/}; printf '%s %s %s\n' "$n" "$(cat "$i/speed" 2>/dev/null)" "$(cat "$i/duplex" 2>/dev/null)"; done
`

func (l *linux) ifaceRead(ctx context.Context) ([]ipAddr, map[string][2]string, error) {
	out, err := l.run(ctx, "interfaces", linuxIfaceScript, false)
	if err != nil {
		return nil, nil, err
	}
	js, rest, _ := strings.Cut(out, "@@speed")
	var as []ipAddr
	if err := json.Unmarshal([]byte(strings.TrimSpace(js)), &as); err != nil {
		return nil, nil, fmt.Errorf("interfaces: the host's ip command did not answer JSON (iproute2 4.13 or later is needed): %v", err)
	}
	sp := map[string][2]string{}
	for _, ln := range strings.Split(rest, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			d := ""
			if len(f) >= 3 {
				d = f[2]
			}
			sp[f[0]] = [2]string{f[1], d}
		}
	}
	return as, sp, nil
}

func hasFlag(fl []string, f string) bool {
	for _, x := range fl {
		if x == f {
			return true
		}
	}
	return false
}

func (a ipAddr) iface(sp map[string][2]string) Interface {
	oper := a.Operstate == "UP" || (a.Operstate == "UNKNOWN" && hasFlag(a.Flags, "LOWER_UP"))
	i := Interface{Name: a.Ifname, Description: a.Alias, AdminUp: boolp(hasFlag(a.Flags, "UP")), OperUp: boolp(oper)}
	if a.Address != "" && a.Address != "00:00:00:00:00:00" {
		i.MAC = a.Address
	}
	for _, ai := range a.AddrInfo {
		i.Addresses = append(i.Addresses, fmt.Sprintf("%s/%d", ai.Local, ai.Prefixlen))
	}
	if n, err := strconv.ParseInt(sp[a.Ifname][0], 10, 64); err == nil && n > 0 {
		i.SpeedMbps = n
	}
	return i
}

func (l *linux) Interfaces(ctx context.Context) ([]Interface, error) {
	as, sp, err := l.ifaceRead(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(as))
	for _, a := range as {
		out = append(out, a.iface(sp))
	}
	return out, nil
}

// Ports implements Porter: the interfaces with the kernel's counters.
func (l *linux) Ports(ctx context.Context) ([]Port, error) {
	as, sp, err := l.ifaceRead(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Port, 0, len(as))
	for _, a := range as {
		p := Port{Interface: a.iface(sp), Type: a.LinkType, MTU: a.MTU, Duplex: sp[a.Ifname][1]}
		p.Counters = Counters{InOctets: a.Stats64.Rx.Bytes, InPackets: a.Stats64.Rx.Packets, InErrors: a.Stats64.Rx.Errors, InDiscards: a.Stats64.Rx.Dropped,
			InMulticast: a.Stats64.Rx.Multicast, OutOctets: a.Stats64.Tx.Bytes, OutPackets: a.Stats64.Tx.Packets, OutErrors: a.Stats64.Tx.Errors, OutDiscards: a.Stats64.Tx.Dropped}
		out = append(out, p)
	}
	return out, nil
}

// Neighbors are the LLDP neighbors lldpd reports; a host without lldpd has none to report.
func (l *linux) Neighbors(ctx context.Context) ([]Neighbor, error) {
	out, err := l.run(ctx, "neighbors", `if command -v lldpctl >/dev/null 2>&1; then lldpctl -f json 2>/dev/null || echo NOLLDPD; else echo NOLLDPCTL; fi`, false)
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if strings.HasSuffix(out, "NOLLDPCTL") || strings.HasSuffix(out, "NOLLDPD") {
		return nil, fmt.Errorf("neighbors: %w (lldpd is not installed or not running on this host)", ErrUnsupported)
	}
	return parseLldpctl(out)
}

func parseLldpctl(s string) ([]Neighbor, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(s), &root); err != nil {
		return nil, fmt.Errorf("neighbors: lldpctl did not answer JSON: %v", err)
	}
	lldp, _ := root["lldp"].(map[string]any)
	var ents []map[string]any
	switch t := lldp["interface"].(type) {
	case []any:
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				ents = append(ents, m)
			}
		}
	case map[string]any:
		ents = append(ents, t)
	}
	var out []Neighbor
	for _, e := range ents {
		names := make([]string, 0, len(e))
		for k := range e {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, ifn := range names {
			v, _ := e[ifn].(map[string]any)
			if v == nil {
				continue
			}
			n := Neighbor{LocalPort: ifn, Protocol: "lldp"}
			ch, _ := v["chassis"].(map[string]any)
			// the chassis is keyed by the neighbor's name, or holds the name itself
			if sub, ok := ch["id"]; !ok || sub == nil {
				for nm, cv := range ch {
					n.RemoteName = nm
					ch, _ = cv.(map[string]any)
					break
				}
			}
			if nm, ok := ch["name"].(map[string]any); ok {
				n.RemoteName = firstOf(str(nm["value"]), n.RemoteName)
			} else if s := str(ch["name"]); s != "" {
				n.RemoteName = s
			}
			n.RemoteDesc = str(ch["descr"])
			switch t := ch["mgmt-ip"].(type) {
			case string:
				n.RemoteAddr = t
			case []any:
				if len(t) > 0 {
					n.RemoteAddr = str(t[0])
				}
			}
			if p, ok := v["port"].(map[string]any); ok {
				if id, ok := p["id"].(map[string]any); ok {
					n.RemotePort = str(id["value"])
				}
				if n.RemotePort == "" {
					n.RemotePort = str(p["descr"])
				}
			}
			n.Detail = v
			out = append(out, n)
		}
	}
	return out, nil
}

// Routes implements Router.
func (l *linux) Routes(ctx context.Context) ([]Route, error) {
	out, err := l.run(ctx, "routes", `ip -j route 2>/dev/null; echo; echo "@@v6"; ip -j -6 route 2>/dev/null`, false)
	if err != nil {
		return nil, err
	}
	v4, v6, _ := strings.Cut(out, "@@v6")
	var rs []Route
	for _, js := range []string{v4, v6} {
		var rows []map[string]any
		if strings.TrimSpace(js) == "" || json.Unmarshal([]byte(strings.TrimSpace(js)), &rows) != nil {
			continue
		}
		for _, m := range rows {
			rs = append(rs, Route{Protocol: str(m["protocol"]), Prefix: str(m["dst"]), NextHop: str(m["gateway"]), Interface: str(m["dev"]), Metric: num(m["metric"]), Raw: m})
		}
	}
	return rs, nil
}

// Routing implements Router: the protocols a plain host does not run, so only what the kernel and the daemons that fill its table say.
func (l *linux) Routing(ctx context.Context) (Routing, error) {
	rs, err := l.Routes(ctx)
	if err != nil {
		return Routing{}, err
	}
	return Routing{Protocols: map[string]any{"kernel_routes": rs}, Unavailable: map[string]string{"bgp": "a Linux host has no routing protocols of its own; use its routing daemon (show routes lists what is in the table)"}}, nil
}

// Resources implements Resourcer.
func (l *linux) Resources(ctx context.Context) (Resources, error) {
	out, err := l.run(ctx, "resources", `echo "@@load"; cat /proc/loadavg; nproc 2>/dev/null
echo "@@mem"; free -b 2>/dev/null
echo "@@disk"; df -PT -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null
echo "@@temp"; for z in /sys/class/thermal/thermal_zone*; do [ -r "$z/temp" ] && echo "$(cat "$z/type" 2>/dev/null) $(cat "$z/temp")"; done 2>/dev/null
`, false)
	if err != nil {
		return Resources{}, err
	}
	sec := linuxSections(out)
	var r Resources
	lf := strings.Fields(strings.ReplaceAll(sec["load"], "\n", " "))
	if len(lf) >= 6 {
		cpus, _ := strconv.ParseFloat(lf[len(lf)-1], 64)
		if cpus < 1 {
			cpus = 1
		}
		a, _ := strconv.ParseFloat(lf[0], 64)
		b, _ := strconv.ParseFloat(lf[1], 64)
		r.CPU = &CPU{Now: a / cpus * 100, OneMin: a / cpus * 100, FiveMin: b / cpus * 100}
	}
	for _, ln := range strings.Split(sec["mem"], "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && (f[0] == "Mem:" || f[0] == "Swap:") {
			tot, _ := strconv.ParseInt(f[1], 10, 64)
			used, _ := strconv.ParseInt(f[2], 10, 64)
			m := Memory{Name: strings.TrimSuffix(f[0], ":"), Total: tot, Used: used, Free: tot - used}
			if tot > 0 {
				m.UsedPercent = float64(used) / float64(tot) * 100
			}
			r.Memory = append(r.Memory, m)
		}
	}
	for i, ln := range strings.Split(sec["disk"], "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 7 {
			continue
		}
		size, _ := strconv.ParseInt(f[2], 10, 64)
		used, _ := strconv.ParseInt(f[3], 10, 64)
		s := Storage{Name: f[6], Size: size, Free: size - used}
		if size > 0 {
			s.UsedPercent = float64(used) / float64(size) * 100
		}
		r.Storage = append(r.Storage, s)
	}
	for _, ln := range strings.Split(sec["temp"], "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			if t, err := strconv.ParseFloat(f[len(f)-1], 64); err == nil {
				c := t / 1000
				r.Sensors = append(r.Sensors, Sensor{Name: strings.Join(f[:len(f)-1], " "), Kind: "temperature", Reading: &c, Units: "C"})
			}
		}
	}
	r.Details = Routing{Protocols: map[string]any{}}
	return r, nil
}

// Config is what describes the host's network: names, addresses, routes, the resolver, netplan and ifupdown files, and the firewall
// rules when sudo allows them.  Files that may hold a secret (NetworkManager connections, wpa_supplicant) are not read.
func (l *linux) Config(ctx context.Context) (string, error) {
	out, err := l.run(ctx, "configuration", `echo "### hostname"; hostname
echo "### addresses"; ip addr 2>/dev/null
echo "### routes"; ip route 2>/dev/null; ip -6 route 2>/dev/null
echo "### rules"; ip rule 2>/dev/null
echo "### resolver"; cat /etc/resolv.conf 2>/dev/null
for f in /etc/netplan/*.yaml /etc/network/interfaces /etc/network/interfaces.d/* /etc/systemd/network/*.network /etc/systemd/network/*.netdev /etc/sysctl.conf /etc/hosts; do
  [ -f "$f" ] && [ -r "$f" ] && { echo "### $f"; cat "$f"; }
done
`, false)
	if err != nil {
		return "", err
	}
	if fw, ferr := l.run(ctx, "firewall", `if command -v nft >/dev/null 2>&1; then nft list ruleset; else iptables-save 2>/dev/null; fi`, true); ferr == nil && strings.TrimSpace(fw) != "" {
		out += "### firewall\n" + fw
	}
	const max = 1 << 20
	if len(out) > max {
		out = out[:max] + "\n… cut at 1 MB\n"
	}
	return out, nil
}

var linuxUnitRE = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,128}$`)

// linuxShow turns "show ..." into the command of a fixed list.
func linuxShow(f []string) (script string, priv bool, err error) {
	usage := errors.New("show ip | links | routes | neighbors | ports | services | service NAME | logs [N] | log UNIT [N] | disk | memory | cpu | processes | version | firewall | dns | time | users")
	if len(f) < 2 {
		return "", false, usage
	}
	n := func(i, def, max int) int {
		if len(f) > i {
			if v, err := strconv.Atoi(f[i]); err == nil && v > 0 {
				if v > max {
					return max
				}
				return v
			}
		}
		return def
	}
	switch strings.ToLower(f[1]) {
	case "ip", "addresses":
		return "ip -br addr", false, nil
	case "links":
		return "ip -s link", false, nil
	case "routes":
		return "ip route; echo; ip -6 route", false, nil
	case "neighbors", "arp":
		return "ip neigh", false, nil
	case "ports":
		return "ss -tuln", false, nil
	case "services":
		return "systemctl list-units --type=service --state=running --no-pager --no-legend", false, nil
	case "service":
		if len(f) < 3 || !linuxUnitRE.MatchString(f[2]) {
			return "", false, errors.New("show service NAME")
		}
		return "systemctl status --no-pager -- '" + f[2] + "'", false, nil
	case "logs":
		return "journalctl -n " + strconv.Itoa(n(2, 100, 500)) + " --no-pager", false, nil
	case "log":
		if len(f) < 3 || !linuxUnitRE.MatchString(f[2]) {
			return "", false, errors.New("show log UNIT [N]")
		}
		return "journalctl -u '" + f[2] + "' -n " + strconv.Itoa(n(3, 100, 500)) + " --no-pager", false, nil
	case "disk":
		return "df -hT -x tmpfs -x devtmpfs", false, nil
	case "memory":
		return "free -m", false, nil
	case "cpu":
		return "uptime; echo; ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -15", false, nil
	case "processes":
		return "ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pcpu | head -50", false, nil
	case "version":
		return "uname -a; echo; cat /etc/os-release 2>/dev/null", false, nil
	case "firewall":
		return "if command -v nft >/dev/null 2>&1; then nft list ruleset; else iptables-save; fi", true, nil
	case "dns":
		return "resolvectl status 2>/dev/null || cat /etc/resolv.conf", false, nil
	case "time":
		return "timedatectl 2>/dev/null || date", false, nil
	case "users":
		return "who; echo; last -n 20 2>/dev/null", false, nil
	}
	return "", false, usage
}

// Show runs one of the fixed read commands ("show routes", "show service sshd") and applies the output filters CheckShow allows.
func (l *linux) Show(ctx context.Context, cmd string) (string, error) {
	cmd, err := CheckShow(cmd)
	if err != nil {
		return "", err
	}
	head, filters, _ := strings.Cut(cmd, "|")
	script, priv, err := linuxShow(strings.Fields(head))
	if err != nil {
		return "", err
	}
	out, err := l.run(ctx, "show", script, priv)
	if err != nil && out == "" {
		return "", err
	}
	if filters != "" {
		out = linuxFilter(out, "|"+filters)
	}
	return RedactText(out), nil
}

// linuxFilter applies | include, exclude, grep, egrep, begin, head, last and count; other filters leave the text as it is.
func linuxFilter(s, filters string) string {
	for _, f := range strings.Split(filters, "|")[1:] {
		w := strings.Fields(f)
		if len(w) == 0 {
			continue
		}
		arg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(f), w[0]))
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		var out []string
		switch strings.ToLower(w[0]) {
		case "include", "grep", "egrep", "match", "find", "exclude", "except", "begin", "section":
			re, err := regexp.Compile("(?i)" + arg)
			if err != nil || len(arg) > 200 {
				re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(arg))
			}
			mode := strings.ToLower(w[0])
			started := false
			for _, ln := range lines {
				m := re.MatchString(ln)
				switch mode {
				case "exclude", "except":
					if !m {
						out = append(out, ln)
					}
				case "begin":
					started = started || m
					if started {
						out = append(out, ln)
					}
				default:
					if m {
						out = append(out, ln)
					}
				}
			}
		case "head":
			k := 10
			if v, err := strconv.Atoi(arg); err == nil && v > 0 {
				k = v
			}
			out = lines[:min(k, len(lines))]
		case "last":
			k := 10
			if v, err := strconv.Atoi(arg); err == nil && v > 0 {
				k = v
			}
			out = lines[max(0, len(lines)-k):]
		case "count":
			return strconv.Itoa(len(lines)) + "\n"
		default:
			continue
		}
		s = strings.Join(out, "\n") + "\n"
	}
	return s
}

// ── changes ──

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func linuxLines(plan []portPlan) ([]string, error) {
	var out []string
	for _, p := range plan {
		if err := ifaceNameOK(p.Port); err != nil {
			return nil, err
		}
		base := "ip link set dev " + shQuote(p.Port)
		if p.Description != nil {
			out = append(out, base+" alias "+shQuote(*p.Description))
		}
		if p.Down != nil {
			out = append(out, base+" "+map[bool]string{true: "down", false: "up"}[*p.Down])
		}
	}
	return out, nil
}

var (
	linuxRawDeny = regexp.MustCompile(`^(?:sudo\s+)?(?:reboot|shutdown|poweroff|halt|init\s+[06]|telinit|mkfs|wipefs|fdisk|parted|dd\s|passwd|chpasswd|usermod|useradd|userdel|visudo|rm\s+-\w*[rf]\w*\s+/(?:\s|$)|systemctl\s+(?:reboot|poweroff|halt|kexec)|ssh-keygen|iptables\s+-F|nft\s+flush)`)
	linuxPowerRE = regexp.MustCompile(`^(?:sudo\s+)?(?:reboot|shutdown|poweroff|halt|init\s+[06]|systemctl\s+(?:reboot|poweroff|halt))`)
)

// Change implements Changer: description (the interface alias), shutdown and no shutdown.  These are what ip changes in the running
// kernel; they last until the host restarts unless its own network configuration says the same.
func (l *linux) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if c.Action == ActClearCounters {
		return ChangeResult{}, errors.New("a Linux host's counters cannot be cleared (the kernel keeps them until the interface is removed)")
	}
	if as, _, err := l.ifaceRead(ctx); err == nil {
		have := map[string]bool{}
		for _, a := range as {
			have[a.Ifname] = true
		}
		// ParsePorts reads eth0 as Ethernet0, lo as Loopback and vlan10 as Vlan10: the host's own spelling is what it has
		for i, p := range c.Ports {
			if have[p] {
				continue
			}
			if m := regexp.MustCompile(`^(Ethernet|Loopback|Vlan|Port-channel)(\d*)$`).FindStringSubmatch(p); m != nil {
				alt := map[string]string{"Ethernet": "eth" + m[2], "Loopback": "lo" + m[2], "Vlan": "vlan" + m[2], "Port-channel": "bond" + m[2]}[m[1]]
				if have[alt] {
					c.Ports[i] = alt
				}
			}
		}
	}
	if err := keepManagement(ctx, l, l.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, ifaceStore{drv: l, rc: l, lines: linuxLines}, c, dry)
}

// RawChange implements RawChanger: lines of shell, run as root in order (a line that fails ends the run).  A Linux host has no
// transaction to undo them with: the result says which of them ran.
func (l *linux) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if r.Method != "" || r.Path != "" || r.Body != "" {
		return res, errors.New("method, path and body: this platform is changed with lines of shell")
	}
	lines, err := checkLines(r, linuxRawDeny)
	if err != nil {
		return res, err
	}
	if dry {
		res.Note = fmt.Sprintf("would run %d line(s) as root with sudo, in order, stopping at the first that fails; nothing was run. A Linux host has no undo.", len(lines))
		return res, nil
	}
	script := "set -e\n" + strings.Join(lines, "\n") + "\n"
	so, se, err := linuxExec(ctx, l.t, script, true)
	res.Answer = rawTrunc([]byte(strings.TrimSpace(so + "\n" + se)))
	if err != nil {
		if power := func() bool {
			for _, ln := range lines {
				if linuxPowerRE.MatchString(strings.ToLower(ln)) {
					return true
				}
			}
			return false
		}(); power && sshEnded(err) {
			res.Applied, res.Note = true, "the connection ended, as it does when the host restarts or powers off"
			return res, nil
		}
		return res, fmt.Errorf("%w; lines before the failing one have run and are not undone", linuxErr("change", se, err))
	}
	res.Applied = true
	if r.Save {
		res.Note = "nothing to save: a Linux host keeps what a line wrote to a file; what ip changes in the running kernel is lost at the next restart unless a line also wrote it to the network configuration"
	}
	return res, nil
}

// sshEnded says whether err is ssh losing its connection (exit status 255), as when the host goes down under a command.
func sshEnded(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 255
}
