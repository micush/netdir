package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// ── frames to test with ──────────────────────────────────────────────────────

var (
	macA = []byte{0x00, 0x1a, 0x7c, 0x01, 0x02, 0x00}
	macB = []byte{0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc}
)

func eth(dst, src []byte, etype uint16, payload []byte) []byte {
	b := append(append(append([]byte{}, dst...), src...), byte(etype>>8), byte(etype))
	return append(b, payload...)
}

func ip4(src, dst string, proto byte, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	h[8], h[9] = 64, proto
	copy(h[12:], net.ParseIP(src).To4())
	copy(h[16:], net.ParseIP(dst).To4())
	return append(h, l4...)
}

func ip6(src, dst string, next byte, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	h[6], h[7] = next, 64
	copy(h[8:], net.ParseIP(src).To16())
	copy(h[24:], net.ParseIP(dst).To16())
	return append(h, l4...)
}

func udp(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func tcp(sport, dport uint16, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12], h[13] = 5<<4, flags
	return append(h, payload...)
}

func arpPkt(op uint16, sha []byte, spa string, tha []byte, tpa string) []byte {
	p := []byte{0, 1, 8, 0, 6, 4, byte(op >> 8), byte(op)}
	p = append(p, sha...)
	p = append(p, net.ParseIP(spa).To4()...)
	p = append(p, tha...)
	return append(p, net.ParseIP(tpa).To4()...)
}

func TestCaptureStateRingAndEpoch(t *testing.T) {
	cs := &CaptureState{maxPkts: 5}
	ep := cs.begin("eth0", "", linktypeEthernet)
	now := time.Now()
	for i := 0; i < 8; i++ {
		cs.add(ep, nil, now, eth(macA, macB, 0x88cc, []byte{byte(i)}))
	}
	st := cs.Since(0, 100)
	if st.Count != 5 || len(st.Packets) != 5 || st.Packets[0].Seq != 4 || st.Cursor != 8 || !st.Running || st.Iface != "eth0" {
		t.Fatalf("ring: %+v", st)
	}
	if st := cs.Since(6, 100); len(st.Packets) != 2 || st.Packets[0].Seq != 7 {
		t.Fatalf("since a cursor: %+v", st.Packets)
	}
	if st := cs.Since(0, 2); len(st.Packets) != 2 || st.Packets[1].Seq != 8 {
		t.Fatalf("the newest max: %+v", st.Packets)
	}
	// a packet from an earlier socket is dropped once a new capture has begun, or this one was stopped
	ep2 := cs.begin("eth1", "", linktypeEthernet)
	cs.add(ep, nil, now, []byte{1})
	if st := cs.Since(0, 10); st.Count != 0 || st.Iface != "eth1" {
		t.Fatalf("after a new begin: %+v", st)
	}
	cs.Stop()
	cs.add(ep2, nil, now, []byte{1})
	if st := cs.Since(0, 10); st.Count != 0 || st.Running {
		t.Fatalf("after stop: %+v", st)
	}
	// the byte cap
	b := &CaptureState{maxBytes: 100}
	ep = b.begin("x", "", linktypeRaw)
	for i := 0; i < 10; i++ {
		b.add(ep, nil, now, make([]byte, 30))
	}
	if st := b.Since(0, 100); st.Bytes > 100 || st.Count != 3 {
		t.Fatalf("byte cap: %d bytes %d packets", st.Bytes, st.Count)
	}
	// the filter counts what it turned away
	f, _ := CompileCapFilter("udp")
	c := &CaptureState{}
	ep = c.begin("x", "udp", linktypeEthernet)
	c.add(ep, f, now, eth(macA, macB, 0x0800, ip4("1.1.1.1", "2.2.2.2", 17, udp(1, 2, nil))))
	c.add(ep, f, now, eth(macA, macB, 0x0800, ip4("1.1.1.1", "2.2.2.2", 6, tcp(1, 2, 2, nil))))
	if st := c.Since(0, 10); st.Count != 1 || st.Matched != 1 || st.Seen != 2 {
		t.Fatalf("filter counts: %+v", st)
	}
}

// ── a real capture (needs the socket; skipped where the sandbox does not allow it) ──

func canCapture(t *testing.T) {
	t.Helper()
	cs := &CaptureState{}
	if err := cs.StartOn("lo", ""); err != nil {
		t.Skipf("no raw sockets here: %v", err)
	}
	cs.Stop()
}

func sendUDP(t *testing.T, port int, n int) {
	t.Helper()
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < n; i++ {
		c.Write([]byte("netdir capture test"))
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCaptureOnTheLoopback(t *testing.T) {
	canCapture(t)
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer l.Close()
	port := l.LocalAddr().(*net.UDPAddr).Port
	l2, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer l2.Close()
	other := l2.LocalAddr().(*net.UDPAddr).Port

	cs := &CaptureState{}
	if err := cs.StartOn("lo", "udp and port "+Itoa(port)); err != nil {
		t.Fatal(err)
	}
	sendUDP(t, port, 3)
	sendUDP(t, other, 3) // the filter turns these away
	time.Sleep(300 * time.Millisecond)
	st := cs.Since(0, 100)
	cs.Stop()
	if st.Count != 3 || st.Seen < 6 {
		t.Fatalf("kept %d, seen %d", st.Count, st.Seen)
	}
	if !strings.Contains(st.Packets[0].Summary, "UDP 127.0.0.1.") || !strings.Contains(st.Packets[0].Summary, "> 127.0.0.1."+Itoa(port)) {
		t.Fatalf("summary %q", st.Packets[0].Summary)
	}

	// a timed capture into a private buffer
	go func() { time.Sleep(300 * time.Millisecond); sendUDP(t, port, 4) }()
	pcap, kept, seen, err := CaptureRun(context.Background(), "lo", "udp and dst port "+Itoa(port), 1200*time.Millisecond, CapRelayBytes)
	if err != nil || kept != 4 || seen < 4 {
		t.Fatalf("run: %v kept %d seen %d", err, kept, seen)
	}
	if _, pk, err := ReadPcap(pcap); err != nil || len(pk) != 4 {
		t.Fatalf("the file: %v %d", err, len(pk))
	}
}

func TestCaptureRefusals(t *testing.T) {
	cs := &CaptureState{}
	if err := cs.StartOn("no-such-if0", ""); err == nil || !strings.Contains(err.Error(), "no interface named") {
		t.Errorf("unknown interface: %v", err)
	}
	if err := cs.StartOn("lo", "port nine"); err == nil || !strings.Contains(err.Error(), "filter") {
		t.Errorf("bad filter: %v", err)
	}
	if err := cs.StartOn("lo", strings.Repeat("tcp or ", 100)); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long filter: %v", err)
	}
	if cs.Since(0, 1).Running {
		t.Error("a refused start left a capture running")
	}
}

func TestCapFilter(t *testing.T) {
	q := udpPayload()
	dq := eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.20.0.205", 17, udp(53124, 123, q))) // client > VIP, DNS
	dr := eth(macB, macA, 0x0800, ip4("10.20.0.205", "192.0.2.1", 17, udp(123, 53124, q))) // VIP > client
	web := eth(macA, macB, 0x0800, ip4("192.0.2.9", "10.0.0.2", 6, tcp(40000, 443, 0x02, nil)))
	v6 := eth(macA, macB, 0x86dd, ip6("2001:db8::1", "2001:db8::2", 6, tcp(40000, 123, 0x02, nil)))
	arpq := eth([]byte{255, 255, 255, 255, 255, 255}, macB, 0x0806, arpPkt(1, macB, "10.20.0.1", make([]byte, 6), "10.20.0.205"))
	ping := eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.0.0.2", 1, []byte{8, 0, 0, 0}))
	frames := map[string][]byte{"dq": dq, "dr": dr, "web": web, "v6": v6, "arp": arpq, "ping": ping}
	for filter, want := range map[string]string{
		"":                                      "dq dr web v6 arp ping",
		"host 10.20.0.205":                      "dq dr arp", // the ARP's target address counts, as in tcpdump
		"src host 10.20.0.205":                  "dr",
		"dst host 10.20.0.205":                  "dq arp",
		"net 192.0.2.0/24":                      "dq dr web ping",
		"src net 192.0.2.0/24 and not port 123": "web ping",
		"port 123":                              "dq dr v6",
		"dst port 123":                          "dq v6",
		"src port 123":                          "dr",
		"portrange 100-130":                     "dq dr v6",
		"ntp":                                   "dq dr v6",
		"udp":                                   "dq dr",
		"tcp":                                   "web v6",
		"tcp port 123":                          "v6",
		"udp port 123 and host 192.0.2.1":       "dq dr",
		"ip6":                                   "v6",
		"ip6 host 2001:db8::1":                  "v6",
		"ip host 2001:db8::1":                   "",
		"arp":                                   "arp",
		"icmp":                                  "ping",
		"host 10.20.0.205 and not arp":          "dq dr",
		"(tcp or icmp) and host 192.0.2.9":      "web",
		"tcp || icmp":                           "web v6 ping",
		"! udp && ! arp":                        "web v6 ping",
		"ether host 00:1a:7c:01:02:00":          "dq dr web v6 ping",
		"ether src 00:1a:7c:01:02:00":           "dr",
		"ether dst 02:00:00:aa:bb:cc":           "dr",
		"UDP PORT NTP":                          "dq dr",
		"port https":                            "web",
	} {
		f, err := CompileCapFilter(filter)
		if err != nil {
			t.Errorf("%q: %v", filter, err)
			continue
		}
		var got []string
		for _, n := range []string{"dq", "dr", "web", "v6", "arp", "ping"} {
			if f.match(linktypeEthernet, frames[n]) {
				got = append(got, n)
			}
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q matches %q, want %q", filter, strings.Join(got, " "), want)
		}
	}
	for _, bad := range []string{"host", "host notanip", "port abc", "port 70000", "net 10.0.0.0", "foo", "(tcp", "tcp)", "tcp and", "not", "ether host zz", "src", "portrange 5", "tcp udp"} {
		if _, err := CompileCapFilter(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// a fragment other than the first carries no ports
	frag := ip4("192.0.2.1", "10.0.0.2", 17, udp(1000, 123, nil))
	binary.BigEndian.PutUint16(frag[6:], 0x00b9) // fragment offset 185
	if f, _ := CompileCapFilter("port 123"); f.match(linktypeEthernet, eth(macA, macB, 0x0800, frag)) {
		t.Error("a later fragment matched on a port")
	}
	// a truncated frame never panics
	f, _ := CompileCapFilter("tcp port 123 or host 1.2.3.4 or ether host 00:00:00:00:00:00")
	for n := 0; n <= len(v6); n++ {
		f.match(linktypeEthernet, v6[:n])
		summarizePacket(linktypeEthernet, v6[:n])
		summarizePacket(linktypeEthernet, dq[:min(n, len(dq))])
	}
}

func TestCapSummaries(t *testing.T) {
	q := udpPayload()
	for name, c := range map[string]struct {
		frame []byte
		want  string
	}{
		"udp datagram":    {eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.20.0.205", 17, udp(53124, 123, q))), "UDP 192.0.2.1.53124 > 10.20.0.205.123, length"},
		"tcp syn":         {eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.0.0.2", 6, tcp(1234, 443, 0x02, nil))), "TCP 192.0.2.1.1234 > 10.0.0.2.443 [S]"},
		"tcp synack":      {eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.0.0.2", 6, tcp(1234, 443, 0x12, nil))), "[S.]"},
		"icmp echo":       {eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.0.0.2", 1, []byte{8, 0, 0, 0})), "ICMP 192.0.2.1 > 10.0.0.2: echo request"},
		"arp request":     {eth([]byte{255, 255, 255, 255, 255, 255}, macB, 0x0806, arpPkt(1, macB, "10.20.0.1", make([]byte, 6), "10.20.0.205")), "ARP, who-has 10.20.0.205 tell 10.20.0.1 (eth 02:00:00:aa:bb:cc > ff:ff:ff:ff:ff:ff)"},
		"arp reply":       {eth(macB, []byte{0x02, 9, 9, 9, 9, 9}, 0x0806, arpPkt(2, macA, "10.20.0.205", macB, "10.20.0.1")), "ARP, 10.20.0.205 is-at 00:1a:7c:01:02:00 (eth 02:09:09:09:09:09 > 02:00:00:aa:bb:cc)"},
		"ipv6 udp":        {eth(macA, macB, 0x86dd, ip6("2001:db8::1", "2001:db8::2", 17, udp(1000, 123, q))), "UDP 2001:db8::1.1000 > 2001:db8::2.123"},
		"vlan":            {eth(macA, macB, 0x8100, append([]byte{0, 5, 8, 0}, ip4("192.0.2.1", "10.0.0.2", 17, udp(1, 2, nil))...)), "UDP 192.0.2.1.1 > 10.0.0.2.2"},
		"other ethertype": {eth(macA, macB, 0x88cc, []byte{1, 2, 3}), "ethertype 0x88cc"},
		"short":           {[]byte{1, 2, 3}, "short frame (3 bytes)"},
	} {
		if got := summarizePacket(linktypeEthernet, c.frame); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not contain %q", name, got, c.want)
		}
	}
	// neighbour discovery, with the target's MAC
	ns := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, net.ParseIP("2001:db8::205").To16()...)
	if got := summarizePacket(linktypeEthernet, eth(macA, macB, 0x86dd, ip6("fe80::1", "ff02::1:ff00:205", 58, ns))); !strings.Contains(got, "neighbor solicitation, who has 2001:db8::205 (eth 02:00:00:aa:bb:cc > 00:1a:7c:01:02:00)") {
		t.Errorf("NS: %q", got)
	}
	na := append(append([]byte{136, 0, 0, 0, 0x60, 0, 0, 0}, net.ParseIP("2001:db8::205").To16()...), 2, 1, 0x00, 0x1a, 0x7c, 0x01, 0x02, 0x00)
	if got := summarizePacket(linktypeEthernet, eth(macB, macA, 0x86dd, ip6("2001:db8::205", "fe80::1", 58, na))); !strings.Contains(got, "neighbor advertisement, 2001:db8::205 is at 00:1a:7c:01:02:00") {
		t.Errorf("NA: %q", got)
	}
	// a bare IP packet (an interface without a hardware address)
	if got := summarizePacket(linktypeRaw, ip4("192.0.2.1", "10.0.0.2", 17, udp(5, 6, nil))); !strings.Contains(got, "UDP 192.0.2.1.5 > 10.0.0.2.6") {
		t.Errorf("raw: %q", got)
	}
}

func TestPcapRoundTripAndLimit(t *testing.T) {
	cs := &CaptureState{}
	ep := cs.begin("eth0", "", linktypeEthernet)
	t0 := time.Unix(1700000000, 123456000)
	var frames [][]byte
	for i := 0; i < 20; i++ {
		f := eth(macA, macB, 0x0800, ip4("192.0.2.1", "10.0.0.2", 17, udp(uint16(1000+i), 123, udpPayload())))
		frames = append(frames, f)
		cs.add(ep, nil, t0.Add(time.Duration(i)*time.Millisecond), f)
	}
	var buf bytes.Buffer
	cs.WritePcap(&buf, 0)
	lt, pkts, err := ReadPcap(buf.Bytes())
	if err != nil || lt != linktypeEthernet || len(pkts) != 20 {
		t.Fatalf("round trip: %v %d %d", err, lt, len(pkts))
	}
	for i, p := range pkts {
		if !bytes.Equal(p.data, frames[i]) || !p.T.Equal(t0.Add(time.Duration(i)*time.Millisecond)) || p.origlen != len(frames[i]) {
			t.Fatalf("packet %d differs", i)
		}
	}
	// a limit keeps the newest that fit, and the file is still a whole .pcap
	per := 16 + len(frames[0])
	buf.Reset()
	cs.WritePcap(&buf, 24+3*per+5)
	_, pkts, err = ReadPcap(buf.Bytes())
	if err != nil || len(pkts) != 3 || !bytes.Equal(pkts[2].data, frames[19]) || !bytes.Equal(pkts[0].data, frames[17]) {
		t.Fatalf("limit: %v %d", err, len(pkts))
	}
	if buf.Len() > 24+3*per+5 {
		t.Fatalf("the limit was passed: %d", buf.Len())
	}
	// a file that is not a .pcap, and one cut in the middle of a record
	if _, _, err := ReadPcap([]byte("nope")); err == nil {
		t.Error("garbage read as a .pcap")
	}
	var full bytes.Buffer
	cs.WritePcap(&full, 0)
	if _, p, err := ReadPcap(full.Bytes()[:full.Len()-10]); err != nil || len(p) != 19 {
		t.Errorf("cut file: %v %d", err, len(p))
	}
	// the header is what tcpdump expects
	h := pcapGlobalHeader(capSnaplen, linktypeEthernet)
	if binary.LittleEndian.Uint32(h[0:]) != 0xa1b2c3d4 || binary.LittleEndian.Uint16(h[4:]) != 2 || binary.LittleEndian.Uint16(h[6:]) != 4 || binary.LittleEndian.Uint32(h[20:]) != 1 {
		t.Errorf("header %x", h)
	}
}

// udpPayload is 48 bytes of UDP payload for the packet tests.
func udpPayload() []byte {
	b := make([]byte, 48)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
