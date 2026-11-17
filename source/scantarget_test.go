package main

import (
	"strings"
	"testing"
)

func TestScanPortList(t *testing.T) {
	for in, want := range map[string]string{"": "", "22": "22", " 443, 22 ,80 ": "22,80,443", "1-5,3-9,20": "1-9,20", "80,80,81": "80-81", "8000-8100": "8000-8100"} {
		got, err := scanPortList(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "65536", "a", "22-", "-5", "9-3", "1-2000", "22;ls", "T:22", "22,,x", "1e3"} {
		if _, err := scanPortList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestScanPlanOf(t *testing.T) {
	type c struct {
		in, ports string
		n         int
		key       string
		first     string
	}
	for _, x := range []c{
		{"10.1.1.5", "", 1, "10.1.1.5", "10.1.1.5"},
		{"NS1.cush.local.", "", 1, "ns1.cush.local", "ns1.cush.local"},
		{"10.1.1.5", "443,22", 1, "10.1.1.5 ports 22,443", "10.1.1.5"},
		{"10.1.1.0/24", "", 254, "10.1.1.0/24", "10.1.1.1"},
		{"10.1.1.0/30", "", 2, "10.1.1.0/30", "10.1.1.1"},
		{"10.1.1.0/31", "", 2, "10.1.1.0/31", "10.1.1.0"},
		{"10.1.1.9/32", "", 1, "10.1.1.9", "10.1.1.9"},
		{"10.1.1.10-13", "", 4, "10.1.1.10-13", "10.1.1.10"},
		{"10.1.1.10-10.1.2.9", "", 256, "10.1.1.10-10.1.2.9", "10.1.1.10"},
		{"10.1.1.1, 10.1.1.1-3, host-a.example.com", "22", 4, "10.1.1.1,10.1.1.1-3,host-a.example.com ports 22", "10.1.1.1"},
		{"2001:db8::/126", "", 4, "2001:db8::/126", "2001:db8::"},
		{"2001:db8::1-2001:db8::3", "", 3, "2001:db8::1-2001:db8::3", "2001:db8::1"},
		{"10.0.0.0/22", "", 1022, "10.0.0.0/22", "10.0.0.1"},
	} {
		p, err := scanPlanOf(x.in, x.ports)
		if err != nil {
			t.Errorf("%q: %v", x.in, err)
			continue
		}
		if len(p.items) != x.n || p.key != strings.ToLower(x.key) || p.items[0] != x.first {
			t.Errorf("%q: %d items key %q first %q; want %d %q %q", x.in, len(p.items), p.key, p.items[0], x.n, x.key, x.first)
		}
	}
	for _, bad := range []string{"", ",", "10.1.0.0/21", "10.1.1.0/24x", "10.1.1.50-10.1.1.10", "10.1.1.10-300", "10.1.1.1-2001:db8::1", "224.0.0.0/24", "0.0.0.0/8", "10.1.1.1,2001:db8::1", "10.0.0.1-10.0.9.1", "a_b.example.com/24", "10.1.1.1;ls", "-oN/tmp/x", "10.1.1.1 -p-", "::ffff:10.1.1.0/120"} {
		if p, err := scanPlanOf(bad, ""); err == nil {
			t.Errorf("%q accepted: %d items", bad, len(p.items))
		}
	}
	if _, err := scanPlanOf("10.1.1.1", "99999"); err == nil {
		t.Error("a bad port list was accepted")
	}
	var names []string
	for i := 0; i < scanMaxNames+1; i++ {
		names = append(names, "h"+strings.Repeat("a", i)+".example.com")
	}
	if _, err := scanPlanOf(strings.Join(names, ","), ""); err == nil {
		t.Error("too many host names accepted")
	}
}

func TestScanArgsPlan(t *testing.T) {
	one, _ := scanPlanOf("10.1.1.5", "")
	a := strings.Join(scanArgsPlan(one), " ")
	if !strings.Contains(a, "-Pn") || !strings.Contains(a, "-F") || !strings.HasSuffix(a, "-- 10.1.1.5") || strings.Contains(a, "-iL") || scanStdin(one) != nil {
		t.Errorf("one host: %s", a)
	}
	ports, _ := scanPlanOf("10.1.1.5", "22,443")
	a = strings.Join(scanArgsPlan(ports), " ")
	if strings.Contains(a, "-F") || !strings.Contains(a, "-p 22,443") || !strings.HasSuffix(a, "-- 10.1.1.5") {
		t.Errorf("ports: %s", a)
	}
	many, _ := scanPlanOf("10.1.1.0/30,10.1.1.9", "80")
	a = strings.Join(scanArgsPlan(many), " ")
	if strings.Contains(a, "-Pn") || !strings.HasSuffix(a, "-iL -") || !strings.Contains(a, "-p 80") || strings.Contains(a, "10.1.1.9") {
		t.Errorf("several hosts: %s", a) // the addresses go on standard input, not the command line
	}
	b := new(strings.Builder)
	in := scanStdin(many)
	buf := make([]byte, 100)
	n, _ := in.Read(buf)
	b.Write(buf[:n])
	if b.String() != "10.1.1.1\n10.1.1.2\n10.1.1.9\n" {
		t.Errorf("stdin %q", b.String())
	}
	v6, _ := scanPlanOf("2001:db8::/126", "")
	if !strings.Contains(strings.Join(scanArgsPlan(v6), " "), "-6") {
		t.Error("no -6 for IPv6")
	}
	if many.timeout() <= one.timeout() {
		t.Errorf("timeouts %s %s", many.timeout(), one.timeout())
	}
	big, _ := scanPlanOf("10.0.0.0/22", "")
	if big.timeout().Minutes() > 15 {
		t.Errorf("timeout %s", big.timeout())
	}
}

func TestScanTidyPlanSeveralHosts(t *testing.T) {
	p, _ := scanPlanOf("10.1.1.0/24", "22,80")
	out := `Starting Nmap 7.94
Nmap scan report for gw.example.com (10.1.1.1)
Host is up (0.0010s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2
Device type: general purpose
OS details: Linux 5.15

Nmap scan report for 10.1.1.7
Host is up (0.0020s latency).
All 2 scanned ports on 10.1.1.7 are closed

Nmap done: 254 IP addresses (2 hosts up) scanned in 12.3 seconds
`
	got := scanTidyPlan(out, p)
	for _, w := range []string{"254 addresses scanned, 2 up", "▸ gw.example.com (10.1.1.1)", "22/tcp  ssh  OpenSSH 9.2", "▸ 10.1.1.7", "OS: Linux 5.15"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
	if got := scanTidyPlan("Nmap done: 254 IP addresses (0 hosts up) scanned in 3 seconds\n", p); !strings.Contains(got, "254 addresses scanned, none answered") {
		t.Errorf("none up: %q", got)
	}
	one, _ := scanPlanOf("10.1.1.5", "22,443")
	if got := scanTidyPlan("Nmap scan report for 10.1.1.5\nHost is up (0.01s latency).\nAll 2 scanned ports are closed\n", one); !strings.Contains(got, "among the ports asked (22,443)") {
		t.Errorf("one host with ports: %q", got)
	}
}
