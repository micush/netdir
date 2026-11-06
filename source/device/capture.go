package device

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Packet capture on a device (Capturer).  A capture runs on the device for a few seconds into a file of its own, is fetched,
// decoded here and removed from the device again.  What comes back is a summary: the first packets one line each (time, protocol,
// addresses, ports, TCP flags, length: headers only, never payload), the protocols and the busiest address pairs counted.  The
// raw .pcap is not returned.
//
// Every capture is bounded: at most capMaxSeconds, capMaxPackets packets, the first capSnap bytes of each packet.  A filter is
// the platform's own (tcpdump syntax on EOS and BIG-IP; the director's own filter) and is limited to words, numbers and
// ".:/()_-" so nothing can leave the filter and run as a shell command.

const (
	capMaxSeconds     = 30
	capDefaultSeconds = 5
	capMaxPackets     = 2000
	capDefaultPackets = 500
	capSnap           = 96
	capListLines      = 100
	capMaxFile        = 2 << 20
)

var (
	capFilterRE = regexp.MustCompile(`^[A-Za-z0-9 .:/()_-]{0,200}$`)
	capIfaceRE  = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,40}$`)
)

// CaptureReq asks for a capture.  Interface and Filter are in the platform's terms; Seconds and Packets default and are capped.
type CaptureReq struct {
	Interface string `json:"interface,omitempty"`
	Filter    string `json:"filter,omitempty"`
	Seconds   int    `json:"seconds,omitempty"`
	Packets   int    `json:"packets,omitempty"`
}

// CapCount is a count for the protocol or address-pair lists.
type CapCount struct {
	Name    string `json:"name"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
}

// CaptureResult is what a capture holds.
type CaptureResult struct {
	Interface string     `json:"interface"`
	Filter    string     `json:"filter,omitempty"`
	Seconds   int        `json:"seconds"`
	Count     int        `json:"packets"` // packets in the capture
	Bytes     int        `json:"bytes"`   // their length on the wire
	Protocols []CapCount `json:"protocols"`
	Talkers   []CapCount `json:"talkers"`
	Listed    []string   `json:"first"` // the first packets, one line each
	Note      string     `json:"note,omitempty"`
}

// Capturer is implemented by a driver that can capture packets.
type Capturer interface {
	Capture(ctx context.Context, r CaptureReq) (CaptureResult, error)
}

// check applies the defaults and the limits.
func (r CaptureReq) check() (CaptureReq, error) {
	r.Interface, r.Filter = strings.TrimSpace(r.Interface), strings.TrimSpace(r.Filter)
	if r.Seconds == 0 {
		r.Seconds = capDefaultSeconds
	}
	if r.Seconds < 1 || r.Seconds > capMaxSeconds {
		return r, fmt.Errorf("seconds: 1 to %d", capMaxSeconds)
	}
	if r.Packets == 0 {
		r.Packets = capDefaultPackets
	}
	if r.Packets < 1 || r.Packets > capMaxPackets {
		return r, fmt.Errorf("packets: 1 to %d", capMaxPackets)
	}
	if r.Interface != "" && !capIfaceRE.MatchString(r.Interface) {
		return r, errors.New("interface: letters, digits and _ . : / - only")
	}
	if !capFilterRE.MatchString(r.Filter) {
		return r, errors.New("filter: words, numbers and . : / ( ) _ - only, up to 200 characters (e.g. \"host 10.0.0.5 and port 53\")")
	}
	return r, nil
}

// tcpdumpCmd is the command that writes the capture to file (the arguments were checked by check, and file is made here).
func tcpdumpCmd(iface, filter string, secs, pkts int, file string) string {
	f := ""
	if filter != "" {
		f = " '" + filter + "'"
	}
	return fmt.Sprintf("timeout %d tcpdump -n -s %d -i %s -c %d -w %s%s 2>&1", secs, capSnap, iface, pkts, file, f)
}

// unB64 decodes the text a `base64` command printed (it may have line breaks and a trailing newline).
func unB64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > capMaxFile*4/3+16 {
		return nil, errors.New("the capture file is larger than 2 MB: ask for fewer packets or a narrower filter")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the capture file did not come back intact (%v): the capture may have failed, or the device's shell answered something else", err)
	}
	return b, nil
}

// ---- the .pcap file ----

func portName(proto string, a, b uint16) string {
	for _, p := range []uint16{a, b} {
		switch p {
		case 53:
			return "DNS"
		case 123:
			if proto == "UDP" {
				return "NTP"
			}
		case 67, 68:
			if proto == "UDP" {
				return "DHCP"
			}
		case 443:
			if proto == "TCP" {
				return "TLS"
			}
		}
	}
	return proto
}

func tcpFlags(f byte) string {
	var s []byte
	for _, x := range []struct {
		bit byte
		c   byte
	}{{0x02, 'S'}, {0x10, 'A'}, {0x01, 'F'}, {0x04, 'R'}, {0x08, 'P'}, {0x20, 'U'}} {
		if f&x.bit != 0 {
			s = append(s, x.c)
		}
	}
	if len(s) == 0 {
		return "."
	}
	return string(s)
}

// decodePacket describes one packet from its link layer: the protocol name, a source and a destination (for the pair count) and
// the line's text.
func decodePacket(link int, d []byte) (proto, src, dst, text string) {
	ip := d
	et := uint16(0)
	vlan := ""
	switch link {
	case 1: // Ethernet
		if len(d) < 14 {
			return "other", "", "", "short frame"
		}
		et = binary.BigEndian.Uint16(d[12:])
		ip = d[14:]
		if et == 0x8100 && len(ip) >= 4 {
			vlan = fmt.Sprintf("vlan %d ", binary.BigEndian.Uint16(ip)&0x0fff)
			et = binary.BigEndian.Uint16(ip[2:])
			ip = ip[4:]
		}
	case 113: // Linux cooked
		if len(d) < 16 {
			return "other", "", "", "short frame"
		}
		et = binary.BigEndian.Uint16(d[14:])
		ip = d[16:]
	case 101, 228: // raw IP
		if len(d) > 0 && d[0]>>4 == 6 {
			et = 0x86dd
		} else {
			et = 0x0800
		}
	default:
		return "other", "", "", fmt.Sprintf("link type %d", link)
	}
	var l4 []byte
	var pn byte
	switch et {
	case 0x0800:
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return "IPv4", "", "", vlan + "IPv4 (cut)"
		}
		ihl := int(ip[0]&15) * 4
		a, _ := netip.AddrFromSlice(ip[12:16])
		b, _ := netip.AddrFromSlice(ip[16:20])
		src, dst, pn = a.String(), b.String(), ip[9]
		if ihl >= 20 && ihl <= len(ip) && binary.BigEndian.Uint16(ip[6:])&0x1fff == 0 {
			l4 = ip[ihl:]
		}
	case 0x86dd:
		if len(ip) < 40 || ip[0]>>4 != 6 {
			return "IPv6", "", "", vlan + "IPv6 (cut)"
		}
		a, _ := netip.AddrFromSlice(ip[8:24])
		b, _ := netip.AddrFromSlice(ip[24:40])
		src, dst, pn = a.String(), b.String(), ip[6]
		l4 = ip[40:]
	case 0x0806:
		if len(ip) >= 28 {
			a, _ := netip.AddrFromSlice(ip[14:18])
			b, _ := netip.AddrFromSlice(ip[24:28])
			if binary.BigEndian.Uint16(ip[6:]) == 1 {
				return "ARP", a.String(), b.String(), fmt.Sprintf("%sARP who-has %s tell %s", vlan, b, a)
			}
			return "ARP", a.String(), b.String(), fmt.Sprintf("%sARP reply %s is-at", vlan, a)
		}
		return "ARP", "", "", vlan + "ARP"
	case 0x88cc:
		return "LLDP", "", "", vlan + "LLDP"
	default:
		return fmt.Sprintf("0x%04x", et), "", "", fmt.Sprintf("%sethertype 0x%04x", vlan, et)
	}
	switch pn {
	case 6:
		if len(l4) >= 14 {
			sp, dp := binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
			return portName("TCP", sp, dp), src, dst, fmt.Sprintf("%sTCP %s.%d > %s.%d [%s]", vlan, src, sp, dst, dp, tcpFlags(l4[13]))
		}
		return "TCP", src, dst, fmt.Sprintf("%sTCP %s > %s", vlan, src, dst)
	case 17:
		if len(l4) >= 8 {
			sp, dp := binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
			return portName("UDP", sp, dp), src, dst, fmt.Sprintf("%sUDP %s.%d > %s.%d", vlan, src, sp, dst, dp)
		}
		return "UDP", src, dst, fmt.Sprintf("%sUDP %s > %s", vlan, src, dst)
	case 1, 58:
		n := "ICMP"
		if pn == 58 {
			n = "ICMPv6"
		}
		if len(l4) >= 2 {
			return n, src, dst, fmt.Sprintf("%s%s %s > %s type %d code %d", vlan, n, src, dst, l4[0], l4[1])
		}
		return n, src, dst, fmt.Sprintf("%s%s %s > %s", vlan, n, src, dst)
	}
	return fmt.Sprintf("IP %d", pn), src, dst, fmt.Sprintf("%sIP protocol %d %s > %s", vlan, pn, src, dst)
}

// summarizePcap reads a .pcap and counts it.
func summarizePcap(b []byte) (CaptureResult, error) {
	var res CaptureResult
	if len(b) < 24 {
		return res, errors.New("the capture file is empty or not a .pcap: the capture may have failed to start (an interface or filter the device refused)")
	}
	var bo binary.ByteOrder
	nano := false
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nano = binary.LittleEndian, true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nano = binary.BigEndian, true
	default:
		return res, errors.New("not a .pcap file: the capture may have failed to start (an interface or filter the device refused)")
	}
	link := int(bo.Uint32(b[20:]))
	protos, talk := map[string]*CapCount{}, map[string]*CapCount{}
	var t0 time.Time
	for off := 24; off+16 <= len(b); {
		caplen, orig := int(bo.Uint32(b[off+8:])), int(bo.Uint32(b[off+12:]))
		if caplen < 0 || off+16+caplen > len(b) {
			break
		}
		frac := int64(bo.Uint32(b[off+4:]))
		if !nano {
			frac *= 1000
		}
		t := time.Unix(int64(bo.Uint32(b[off:])), frac)
		proto, src, dst, text := decodePacket(link, b[off+16:off+16+caplen])
		off += 16 + caplen
		res.Count++
		res.Bytes += orig
		if t0.IsZero() {
			t0 = t
		}
		count(protos, proto, orig)
		if src != "" {
			count(talk, src+" > "+dst, orig)
		}
		if len(res.Listed) < capListLines {
			res.Listed = append(res.Listed, fmt.Sprintf("+%.6f %s, %d bytes", t.Sub(t0).Seconds(), text, orig))
		}
	}
	res.Protocols = top(protos, 12)
	res.Talkers = top(talk, 10)
	if res.Count > capListLines {
		res.Note = fmt.Sprintf("the first %d of %d packets are listed", capListLines, res.Count)
	}
	return res, nil
}

func count(m map[string]*CapCount, k string, n int) {
	c := m[k]
	if c == nil {
		if len(m) >= 5000 {
			return
		}
		c = &CapCount{Name: k}
		m[k] = c
	}
	c.Packets++
	c.Bytes += n
}

func top(m map[string]*CapCount, n int) []CapCount {
	out := make([]CapCount, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// sleepCtx waits, and returns early with the context's error.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
