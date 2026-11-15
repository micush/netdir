package device

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const ipJSON = `[{"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN","address":"00:00:00:00:00:00","mtu":65536,"link_type":"loopback","addr_info":[{"local":"127.0.0.1","prefixlen":8}],"stats64":{"rx":{"bytes":10,"packets":1},"tx":{"bytes":10,"packets":1}}},
{"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","address":"52:54:00:aa:bb:cc","mtu":1500,"ifalias":"uplink","link_type":"ether","addr_info":[{"local":"192.0.2.10","prefixlen":24}],"stats64":{"rx":{"bytes":1000,"packets":10,"errors":1,"dropped":2},"tx":{"bytes":2000,"packets":20}}},
{"ifname":"eth1","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN","address":"52:54:00:aa:bb:cd","mtu":1500,"link_type":"ether","addr_info":[]}]`

// fakeLinux answers the scripts the driver sends and applies "ip link set" lines to its state.
type fakeLinux struct {
	down  map[string]bool
	alias map[string]string
	privs []string
	fail  string
}

func newFakeLinux() *fakeLinux {
	return &fakeLinux{down: map[string]bool{"eth1": true}, alias: map[string]string{"eth0": "uplink"}}
}

var ipLinkRE = regexp.MustCompile(`^ip link set dev '([^']+)' (down|up|alias '((?:[^']|'\\'')*)')$`)

func (f *fakeLinux) exec(_ context.Context, _ linuxTarget, script string, priv bool) (string, string, error) {
	if priv {
		f.privs = append(f.privs, script)
		if f.fail != "" && strings.Contains(script, f.fail) {
			return "partial\n", "RTNETLINK answers: Operation not permitted\n", errors.New("exit status 2")
		}
		for _, ln := range strings.Split(script, "\n") {
			if m := ipLinkRE.FindStringSubmatch(ln); m != nil {
				switch {
				case m[2] == "down":
					f.down[m[1]] = true
				case m[2] == "up":
					f.down[m[1]] = false
				default:
					f.alias[m[1]] = strings.ReplaceAll(m[3], `'\''`, "'")
				}
			}
		}
		return "", "", nil
	}
	switch {
	case strings.Contains(script, "ip -j -s addr"):
		js := ipJSON
		for n, d := range f.down {
			if !d {
				js = strings.Replace(js, `{"ifname":"`+n+`","flags":["BROADCAST","MULTICAST"]`, `{"ifname":"`+n+`","flags":["BROADCAST","MULTICAST","UP"]`, 1)
			}
		}
		if a := f.alias["eth1"]; a != "" {
			js = strings.Replace(js, `{"ifname":"eth1",`, `{"ifname":"eth1","ifalias":"`+strings.ReplaceAll(a, `"`, `\"`)+`",`, 1)
		}
		if a := f.alias["eth0"]; a != "uplink" {
			js = strings.Replace(js, `"ifalias":"uplink"`, `"ifalias":"`+a+`"`, 1)
		}
		return js + "\n@@speed\nlo 0 \neth0 1000 full\neth1 -1 \n", "", nil
	case strings.Contains(script, "hostname="):
		return "hostname=web1\npretty=Debian GNU/Linux 12\nosid=debian\nkernel=6.1.0\nuptime=3600\nmodel=KVM\nserial=\n", "", nil
	case strings.Contains(script, "lldpctl"):
		return `{"lldp":{"interface":[{"eth0":{"chassis":{"sw1":{"id":{"type":"mac","value":"aa:bb"},"descr":"Switch","mgmt-ip":"192.0.2.1"}},"port":{"id":{"type":"ifname","value":"Gi1/0/1"},"descr":"to web1"}}}]}}`, "", nil
	case strings.Contains(script, "ip -j route"):
		return `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"static","metric":100}]` + "\n@@v6\n[]", "", nil
	case strings.Contains(script, "/proc/loadavg"):
		return "@@load\n2.00 1.00 0.50 1/100 123\n4\n@@mem\n total used free\nMem: 1000 250 750\nSwap: 0 0 0\n@@disk\nFilesystem Type 1B-blocks Used Available Capacity Mounted\n/dev/vda1 ext4 1000 400 600 40% /\n@@temp\nx86_pkg_temp 45000\n", "", nil
	case strings.Contains(script, "### hostname"):
		return "### hostname\nweb1\n### routes\ndefault via 192.0.2.1\n", "", nil
	case strings.Contains(script, "ip -br addr"):
		return "lo UNKNOWN 127.0.0.1/8\neth0 UP 192.0.2.10/24\n", "", nil
	}
	return "", "", errors.New("unexpected script: " + script)
}

func useFake(t *testing.T) (*fakeLinux, *linux) {
	t.Helper()
	f := newFakeLinux()
	old := linuxExec
	linuxExec = f.exec
	t.Cleanup(func() { linuxExec = old })
	d, err := newLinux(Device{Name: "web1", Platform: "linux", Address: "192.0.2.10"}, Credential{Username: "ops", Password: "pw-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return f, d.(*linux)
}

func TestLinuxReads(t *testing.T) {
	_, l := useFake(t)
	ctx := context.Background()
	f, err := l.Facts(ctx)
	if err != nil || f.Hostname != "web1" || f.UptimeS != 3600 || !strings.Contains(f.OSVersion, "Debian") || f.Vendor != "Linux" {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := l.Interfaces(ctx)
	if err != nil || len(ifs) != 3 {
		t.Fatalf("interfaces %v %v", ifs, err)
	}
	by := map[string]Interface{}
	for _, i := range ifs {
		by[i.Name] = i
	}
	if e := by["eth0"]; e.Description != "uplink" || !*e.AdminUp || !*e.OperUp || e.SpeedMbps != 1000 || e.Addresses[0] != "192.0.2.10/24" || e.MAC == "" {
		t.Errorf("eth0 %+v", e)
	}
	if e := by["eth1"]; *e.AdminUp || *e.OperUp || e.SpeedMbps != 0 {
		t.Errorf("eth1 %+v", e)
	}
	if e := by["lo"]; !*e.OperUp || e.MAC != "" {
		t.Errorf("lo %+v", e)
	}
	ps, err := l.Ports(ctx)
	if err != nil || ps[1].Counters.InOctets != 1000 || ps[1].Counters.InErrors != 1 || ps[1].Duplex != "full" || ps[1].MTU != 1500 {
		t.Fatalf("ports %+v %v", ps, err)
	}
	ns, err := l.Neighbors(ctx)
	if err != nil || len(ns) != 1 || ns[0].LocalPort != "eth0" || ns[0].RemoteName != "sw1" || ns[0].RemotePort != "Gi1/0/1" || ns[0].RemoteAddr != "192.0.2.1" {
		t.Fatalf("neighbors %+v %v", ns, err)
	}
	rs, err := l.Routes(ctx)
	if err != nil || len(rs) != 1 || rs[0].NextHop != "192.0.2.1" || rs[0].Prefix != "default" {
		t.Fatalf("routes %+v %v", rs, err)
	}
	r, err := l.Resources(ctx)
	if err != nil || r.CPU == nil || r.CPU.OneMin != 50 || r.Memory[0].UsedPercent != 25 || r.Storage[0].Name != "/" || r.Storage[0].UsedPercent != 40 || *r.Sensors[0].Reading != 45 {
		t.Fatalf("resources %+v %v", r, err)
	}
}

func TestLinuxNeighborsWithoutLLDP(t *testing.T) {
	old := linuxExec
	defer func() { linuxExec = old }()
	linuxExec = func(context.Context, linuxTarget, string, bool) (string, string, error) {
		return "NOLLDPCTL\n", "", nil
	}
	l := &linux{t: linuxTarget{}}
	if _, err := l.Neighbors(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestLinuxShow(t *testing.T) {
	_, l := useFake(t)
	ctx := context.Background()
	out, err := l.Show(ctx, "show ip | include eth0")
	if err != nil || strings.TrimSpace(out) != "eth0 UP 192.0.2.10/24" {
		t.Fatalf("%q %v", out, err)
	}
	if out, _ := l.Show(ctx, "show ip | count"); strings.TrimSpace(out) != "2" {
		t.Errorf("count %q", out)
	}
	for _, bad := range []string{"ls /", "show", "show service foo;reboot", "show service a$(b)", "show log 'x' 5", "show nothing", "show ip > /tmp/x"} {
		if _, err := l.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, c := range [][]string{{"show", "service", "sshd.service"}, {"show", "log", "ssh@x.service", "50"}, {"show", "logs", "9999"}} {
		s, _, err := linuxShow(c)
		if err != nil {
			t.Errorf("%v: %v", c, err)
		}
		if c[1] == "logs" && !strings.Contains(s, "-n 500") {
			t.Errorf("logs not capped: %s", s)
		}
	}
}

func TestLinuxTypedChange(t *testing.T) {
	f, l := useFake(t)
	ctx := context.Background()
	ports, err := ParsePorts("eth1, lo")
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Change(ctx, Change{Action: ActNoShutdown, Ports: ports[:1]}, false)
	if err != nil || f.down["eth1"] {
		t.Fatalf("no shutdown: %+v %v down=%v", res, err, f.down)
	}
	if len(f.privs) == 0 || !strings.Contains(f.privs[0], "ip link set dev 'eth1' up") {
		t.Fatalf("script %v", f.privs)
	}
	res, err = l.Change(ctx, Change{Action: ActDescription, Ports: []string{"eth1"}, Value: "it's a test"}, false)
	if err != nil || f.alias["eth1"] != "it's a test" {
		t.Fatalf("description: %+v %v %q", res, err, f.alias["eth1"])
	}
	before := len(f.privs)
	if _, err := l.Change(ctx, Change{Action: ActShutdown, Ports: []string{"eth9"}}, false); err == nil || len(f.privs) != before {
		t.Errorf("a port the host lacks was changed: %v", err)
	}
	before = len(f.privs)
	if _, err := l.Change(ctx, Change{Action: ActShutdown, Ports: []string{"eth1"}}, true); err != nil || len(f.privs) != before {
		t.Errorf("dry run sent something: %v", err)
	}
	if _, err := l.Change(ctx, Change{Action: ActClearCounters, Ports: []string{AllPorts}}, false); err == nil {
		t.Error("clear counters accepted")
	}
}

func TestLinuxPortNames(t *testing.T) {
	got, err := ParsePorts("ens3 enp1s0 br0 eth0.100 lo bond0 wlan0 docker0 veth1a2b")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ens3", "enp1s0", "br0", "eth0.100", "lo", "bond0", "wlan0", "docker0", "veth1a2b"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v", got)
	}
}

func TestLinuxRawChange(t *testing.T) {
	f, l := useFake(t)
	ctx := context.Background()
	res, err := l.RawChange(ctx, Raw{Lines: []string{"ip route add 10.9.0.0/16 via 192.0.2.1", "sysctl -w net.ipv4.ip_forward=1"}}, true)
	if err != nil || !res.DryRun || res.Applied || len(f.privs) != 0 {
		t.Fatalf("dry %+v %v", res, err)
	}
	res, err = l.RawChange(ctx, Raw{Lines: []string{"ip route add 10.9.0.0/16 via 192.0.2.1", "sysctl -w net.ipv4.ip_forward=1"}}, false)
	if err != nil || !res.Applied || len(f.privs) != 1 || !strings.HasPrefix(f.privs[0], "set -e\n") {
		t.Fatalf("run %+v %v %v", res, err, f.privs)
	}
	f.fail = "badcmd"
	res, err = l.RawChange(ctx, Raw{Lines: []string{"badcmd x"}}, false)
	if err == nil || res.Applied || !strings.Contains(err.Error(), "not undone") || !strings.Contains(res.Answer, "partial") {
		t.Errorf("failure %+v %v", res, err)
	}
	if _, err := l.RawChange(ctx, Raw{Method: "POST", Path: "/x"}, false); err == nil {
		t.Error("a REST request was accepted")
	}
	// the lists: refused with them on (the tests' default), sent with them off
	if _, err := l.RawChange(ctx, Raw{Lines: []string{"reboot"}}, false); err == nil {
		t.Error("reboot sent with the lists on")
	}
	SetGuards(false)
	defer SetGuards(true)
	f.fail = ""
	if res, err := l.RawChange(ctx, Raw{Lines: []string{"useradd bob"}}, false); err != nil || !res.Applied {
		t.Errorf("useradd with the lists off: %+v %v", res, err)
	}
}

func TestLinuxRemoteCommand(t *testing.T) {
	script := "echo $HOME 'q'\n"
	b := base64.StdEncoding.EncodeToString([]byte(script))
	user := linuxTarget{User: "ops", Pass: "pw", Sudo: true}
	if c := remoteCommand(user, script, false); strings.Contains(c, "sudo") || !strings.Contains(c, b) || strings.Contains(c, "pw") {
		t.Errorf("unprivileged: %s", c)
	}
	if c := remoteCommand(user, script, true); !strings.HasPrefix(c, "sudo -S -p '' sh -c") {
		t.Errorf("sudo with a password: %s", c)
	}
	if c := remoteCommand(linuxTarget{User: "ops", Sudo: true}, script, true); !strings.HasPrefix(c, "sudo -n ") {
		t.Errorf("sudo without a password: %s", c)
	}
	if c := remoteCommand(linuxTarget{User: "root"}, script, true); strings.Contains(c, "sudo") {
		t.Errorf("root: %s", c)
	}
}

func TestNewLinuxChecks(t *testing.T) {
	ok := Credential{Username: "ops", Password: "x"}
	for _, d := range []Device{{Address: "-oProxyCommand=x"}, {Address: ""}, {Address: "a b"}, {Address: "h;x"}} {
		if _, err := newLinux(d, ok); err == nil {
			t.Errorf("address %q accepted", d.Address)
		}
	}
	for _, u := range []string{"", "-oX", "a b", "a;b"} {
		if _, err := newLinux(Device{Address: "h"}, Credential{Username: u}); err == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	d, err := newLinux(Device{Address: "h", Options: map[string]string{"sudo": "no"}}, ok)
	if err != nil || d.(*linux).t.Sudo || d.(*linux).t.Port != 22 {
		t.Errorf("%v %+v", err, d)
	}
	if _, err := newLinux(Device{Address: "h", Options: map[string]string{"sudo": "maybe"}}, ok); err == nil {
		t.Error("bad sudo option accepted")
	}
}

// A stand-in ssh that records how it was called and what it was given on standard input.
func TestSSHExecArguments(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "rec")
	fake := filepath.Join(dir, "ssh")
	os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+rec+".args\ncat > "+rec+".stdin\nenv | grep -E '^(SSH_ASKPASS|NETDIR_SSH_ASKPASS_VALUE)=' > "+rec+".env\nfor a in \"$@\"; do case $a in IdentityFile=*) cat \"${a#IdentityFile=}\" > "+rec+".key; stat -c %a \"${a#IdentityFile=}\" > "+rec+".mode;; esac; done\necho out; echo err >&2\n"), 0o755)
	t.Setenv("NETDIR_SSH", fake)
	t.Setenv("NETDIR_SSH_KNOWN_HOSTS", filepath.Join(dir, "kh"))
	read := func(n string) string { b, _ := os.ReadFile(rec + n); return string(b) }

	so, se, err := sshExec(context.Background(), linuxTarget{Host: "h1", Port: 2222, User: "ops", Pass: "s3cret", Sudo: true}, "id", true)
	if err != nil || so != "out\n" || se != "err\n" {
		t.Fatalf("%q %q %v", so, se, err)
	}
	args := read(".args")
	if strings.Contains(args, "s3cret") || !strings.Contains(args, "-p\n2222\n") || !strings.Contains(args, "-l\nops\n") || !strings.Contains(args, "StrictHostKeyChecking=accept-new") || !strings.Contains(args, "sudo -S -p ''") {
		t.Errorf("args:\n%s", args)
	}
	if read(".stdin") != "s3cret\n" || !strings.Contains(read(".env"), "NETDIR_SSH_ASKPASS_VALUE=s3cret") || !strings.Contains(read(".env"), "SSH_ASKPASS=") {
		t.Errorf("stdin %q env %q", read(".stdin"), read(".env"))
	}

	_, _, err = sshExec(context.Background(), linuxTarget{Host: "h1", Port: 22, User: "ops", Key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", Insecure: true}, "id", false)
	if err != nil {
		t.Fatal(err)
	}
	args = read(".args")
	if !strings.Contains(args, "BatchMode=yes") || !strings.Contains(args, "StrictHostKeyChecking=no") || !strings.Contains(read(".key"), "abc") || strings.TrimSpace(read(".mode")) != "600" {
		t.Errorf("key run:\n%s key=%q mode=%q", args, read(".key"), read(".mode"))
	}
	if _, err := os.Stat(strings.TrimSpace(strings.SplitN(strings.SplitAfter(args, "IdentityFile=")[1], "\n", 2)[0])); err == nil {
		t.Error("the key file was left behind")
	}
}

func TestLinuxErrors(t *testing.T) {
	cases := map[string]string{
		"ops@h: Permission denied (publickey,password).": "login refused",
		"Host key verification failed.":                  "host key",
		"Sorry, try again.":                              "sudo",
		"ops is not in the sudoers file.":                "sudo",
	}
	for se, want := range cases {
		if e := linuxErr("x", se, errors.New("exit status 255")); !strings.Contains(e.Error(), want) {
			t.Errorf("%q -> %v", se, e)
		}
	}
	_ = exec.ErrNotFound
}

func TestParseLldpctlShapes(t *testing.T) {
	// one neighbor written as an object, the chassis holding its name directly
	ns, err := parseLldpctl(`{"lldp":{"interface":{"eth2":{"chassis":{"id":{"type":"mac","value":"aa"},"name":"core1","descr":"Core"},"port":{"id":{"value":"Eth1/2"}}}}}}`)
	if err != nil || len(ns) != 1 || ns[0].LocalPort != "eth2" || ns[0].RemoteName != "core1" || ns[0].RemotePort != "Eth1/2" {
		t.Fatalf("%+v %v", ns, err)
	}
	if ns, err := parseLldpctl(`{"lldp":{}}`); err != nil || len(ns) != 0 {
		t.Errorf("%+v %v", ns, err)
	}
}

var (
	_ Changer    = (*linux)(nil)
	_ Porter     = (*linux)(nil)
	_ Router     = (*linux)(nil)
	_ Resourcer  = (*linux)(nil)
	_ RawChanger = (*linux)(nil)
)
