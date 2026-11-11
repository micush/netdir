package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Small network probes run by this node (MCP: net_port, net_tls, net_arp, net_wake; mcpnettools.go).  All are written in Go (no
// program is needed) and each checks its arguments before it opens a socket.

// probeHost resolves host (an address or a name) to the address to use for family 0, 4 or 6.
func probeHost(host, family string) (netip.Addr, string, error) {
	_, ip, name, err := scanTarget(host)
	if err != nil {
		return netip.Addr{}, "", err
	}
	fam := strings.TrimSpace(family)
	if fam != "" && fam != "4" && fam != "6" {
		return netip.Addr{}, "", errors.New("family: 4 or 6")
	}
	if name == "" {
		if (fam == "4" && !ip.Is4()) || (fam == "6" && !ip.Is6()) {
			return netip.Addr{}, "", fmt.Errorf("%s is not an IPv%s address", ip, fam)
		}
		return ip, "", nil
	}
	network := "ip"
	if fam != "" {
		network = "ip" + fam
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, name)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("%s: %v", name, err)
	}
	var pick netip.Addr
	for _, x := range ips {
		x = x.Unmap()
		if x.IsUnspecified() || x.IsMulticast() || x.Zone() != "" {
			continue
		}
		if !pick.IsValid() || (x.Is4() && pick.Is6()) {
			pick = x
		}
	}
	if !pick.IsValid() {
		return netip.Addr{}, "", fmt.Errorf("%s: no address found", name)
	}
	return pick, name, nil
}

func probeNetwork(ip netip.Addr) string {
	if ip.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

// portCheck connects to each of ports (at most 10, a list such as "22,443") on host and says open, closed (refused) or filtered
// (no answer in 4 s): a quick test of one port where an nmap scan would sweep a hundred.
func portCheck(host, ports, family string) (any, error) {
	var list []int
	seen := map[int]bool{}
	for _, f := range strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("ports: %q is not a port from 1 to 65535", f)
		}
		if !seen[n] {
			seen[n] = true
			list = append(list, n)
		}
	}
	if len(list) == 0 || len(list) > 10 {
		return nil, errors.New("ports: one to ten ports, such as 443 or 22,443")
	}
	ip, name, err := probeHost(host, family)
	if err != nil {
		return nil, err
	}
	type res struct {
		Port  int    `json:"port"`
		State string `json:"state"`
		Ms    int64  `json:"ms,omitempty"`
		Error string `json:"error,omitempty"`
	}
	out := make([]res, len(list))
	var wg sync.WaitGroup
	for i, p := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			c, err := (&net.Dialer{Timeout: 4 * time.Second}).Dial(probeNetwork(ip), net.JoinHostPort(ip.String(), strconv.Itoa(p)))
			r := res{Port: p, Ms: time.Since(t0).Milliseconds()}
			var ne net.Error
			switch {
			case err == nil:
				c.Close()
				r.State = "open"
			case errors.Is(err, syscall.ECONNREFUSED):
				r.State = "closed"
			case errors.As(err, &ne) && ne.Timeout():
				r.State, r.Ms = "filtered", 0
			default:
				r.State, r.Error, r.Ms = "error", err.Error(), 0
			}
			out[i] = r
		}()
	}
	wg.Wait()
	m := map[string]any{"host": strings.TrimSpace(host), "address": ip.String(), "results": out}
	if name != "" {
		m["host"] = name
	}
	return m, nil
}

var tlsVersions = map[uint16]string{tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1", tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3"}

// tlsCheck does a TLS handshake with host:port and reports the protocol, the cipher, the certificate chain with its dates and whether it
// would be trusted by this node (the system roots, for the name asked).  The handshake accepts any certificate so that an expired or
// self-signed one is shown rather than refused; nothing is sent after it.
func tlsCheck(host, port, sni, family string) (any, error) {
	p := 443
	if strings.TrimSpace(port) != "" {
		var err error
		if p, err = strconv.Atoi(strings.TrimSpace(port)); err != nil || p < 1 || p > 65535 {
			return nil, errors.New("port: from 1 to 65535")
		}
	}
	ip, name, err := probeHost(host, family)
	if err != nil {
		return nil, err
	}
	sn := strings.TrimSpace(sni)
	if sn == "" {
		sn = name
	} else if _, _, _, err := netTarget(sn); err != nil {
		return nil, errors.New("sni: a host name")
	}
	if a, err := netip.ParseAddr(sn); err == nil && a.IsValid() {
		sn = "" // no server name for an address
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := d.DialContext(ctx, probeNetwork(ip), net.JoinHostPort(ip.String(), strconv.Itoa(p)))
	if err != nil {
		return nil, fmt.Errorf("connect to %s port %d: %v", ip, p, err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: sn, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint: a diagnostic: the chain is verified below
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with %s port %d: %v", ip, p, err)
	}
	st := c.ConnectionState()
	now := time.Now()
	type cert struct {
		Subject   string   `json:"subject"`
		Issuer    string   `json:"issuer"`
		NotBefore string   `json:"not_before"`
		NotAfter  string   `json:"not_after"`
		DaysLeft  int      `json:"days_left"`
		Names     []string `json:"names,omitempty"`
		Key       string   `json:"key"`
		Sig       string   `json:"signature"`
		CA        bool     `json:"ca,omitempty"`
	}
	var chain []cert
	for _, x := range st.PeerCertificates {
		cc := cert{Subject: x.Subject.String(), Issuer: x.Issuer.String(), NotBefore: x.NotBefore.UTC().Format("2006-01-02"), NotAfter: x.NotAfter.UTC().Format("2006-01-02"),
			DaysLeft: int(x.NotAfter.Sub(now).Hours() / 24), Sig: x.SignatureAlgorithm.String(), CA: x.IsCA}
		cc.Names = append(cc.Names, x.DNSNames...)
		for _, a := range x.IPAddresses {
			cc.Names = append(cc.Names, a.String())
		}
		if len(cc.Names) > 20 {
			cc.Names = cc.Names[:20]
		}
		switch k := x.PublicKey.(type) {
		case *rsa.PublicKey:
			cc.Key = "RSA " + strconv.Itoa(k.N.BitLen())
		case *ecdsa.PublicKey:
			cc.Key = "ECDSA " + k.Curve.Params().Name
		case ed25519.PublicKey:
			cc.Key = "Ed25519"
		default:
			cc.Key = "other"
		}
		chain = append(chain, cc)
	}
	m := map[string]any{"address": ip.String(), "port": p, "protocol": tlsVersions[st.Version], "cipher": tls.CipherSuiteName(st.CipherSuite), "chain": chain}
	if st.NegotiatedProtocol != "" {
		m["alpn"] = st.NegotiatedProtocol
	}
	if sn != "" {
		m["server_name"] = sn
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, x := range st.PeerCertificates[1:] {
			inter.AddCert(x)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sn, Intermediates: inter, CurrentTime: now}); err != nil {
			m["trusted"] = false
			m["verify_error"] = err.Error()
		} else {
			m["trusted"] = true
		}
		switch d := chain[0].DaysLeft; {
		case d < 0:
			m["warning"] = fmt.Sprintf("the certificate expired %d days ago", -d)
		case d < 30:
			m["warning"] = fmt.Sprintf("the certificate expires in %d days", d)
		}
	}
	return m, nil
}

// arpLookup says which MAC address this node has for ip and on which interface: from the ARP table (IPv4) or the neighbour table
// (IPv6, with the ip program).  An address that is not in the table yet but is on a subnet of this node is asked for once (one UDP
// datagram to its discard port makes the kernel ARP for it) and the table read again.
func arpLookup(ip string) (any, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || a.Zone() != "" {
		return nil, errors.New("ip: an IP address")
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return nil, fmt.Errorf("%s is not an address of one host on the network", a)
	}
	iface, subnet := onLinkOf(a)
	m := map[string]any{"ip": a.String()}
	if iface != "" {
		m["interface"], m["subnet"] = iface, subnet
	} else {
		m["note"] = "not on a subnet this node is attached to: the neighbour table only has hosts on the same segment"
	}
	find := func() (string, string, string) { return neighbourOf(a) }
	mac, dev, state := find()
	if mac == "" && iface != "" {
		if c, err := net.DialTimeout("udp", net.JoinHostPort(a.String(), "9"), time.Second); err == nil {
			_, _ = c.Write([]byte{0})
			c.Close()
			time.Sleep(700 * time.Millisecond)
			mac, dev, state = find()
		}
	}
	if mac == "" {
		m["found"] = false
		return m, nil
	}
	m["found"], m["mac"], m["interface"] = true, mac, dev
	if state != "" {
		m["state"] = state
	}
	return m, nil
}

// onLinkOf finds the interface of this node whose subnet holds a.
func onLinkOf(a netip.Addr) (string, string) {
	ifs, _ := net.Interfaces()
	for _, in := range ifs {
		addrs, _ := in.Addrs()
		for _, ad := range addrs {
			if pf, err := netip.ParsePrefix(ad.String()); err == nil && pf.Contains(a) && !a.IsLoopback() {
				return in.Name, pf.Masked().String()
			}
		}
	}
	return "", ""
}

// neighbourOf reads the MAC address of a from the kernel's tables: mac, interface, state.
func neighbourOf(a netip.Addr) (string, string, string) {
	if a.Is4() {
		b, err := os.ReadFile("/proc/net/arp")
		if err != nil {
			return "", "", ""
		}
		for _, l := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) >= 6 && f[0] == a.String() && f[3] != "00:00:00:00:00:00" && f[2] != "0x0" {
				return f[3], f[5], "reachable"
			}
		}
		return "", "", ""
	}
	path, err := exec.LookPath("ip")
	if err != nil {
		return "", "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-6", "neigh", "show", "to", a.String())
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, _ := cmd.Output()
	for _, l := range strings.Split(string(out), "\n") { // fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
		f := strings.Fields(l)
		var dev, mac, state string
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				dev = f[i+1]
			case "lladdr":
				mac = f[i+1]
			}
		}
		if len(f) > 0 {
			state = strings.ToLower(f[len(f)-1])
		}
		if mac != "" {
			return mac, dev, state
		}
	}
	return "", "", ""
}

// wakeSend sends a Wake-on-LAN magic packet for mac: six 0xFF bytes and the MAC sixteen times, as a UDP datagram to port 9 of the
// broadcast address (255.255.255.255 unless broadcast, an IPv4 address, is given, e.g. the subnet's directed broadcast).
func wakeSend(mac, broadcast, actor string) (any, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return nil, errors.New("mac: a MAC address such as aa:bb:cc:dd:ee:ff")
	}
	dst := "255.255.255.255"
	if b := strings.TrimSpace(broadcast); b != "" {
		a, err := netip.ParseAddr(b)
		if err != nil || !a.Is4() || a.IsMulticast() || a.IsLoopback() || a.IsUnspecified() {
			return nil, errors.New("broadcast: an IPv4 broadcast address such as 10.1.5.255")
		}
		dst = a.String()
	}
	pkt := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xFF)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	c, err := net.DialTimeout("udp4", net.JoinHostPort(dst, "9"), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if uc, ok := c.(*net.UDPConn); ok { // sending to a broadcast address needs SO_BROADCAST
		rc, err := uc.SyscallConn()
		if err == nil {
			_ = rc.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1) })
		}
	}
	if _, err := c.Write(pkt); err != nil {
		return nil, err
	}
	infof("wake: %q sent a magic packet for %s to %s", actor, hw, dst)
	return map[string]any{"mac": hw.String(), "sent_to": dst + ":9", "note": "a magic packet was sent; the machine must have Wake-on-LAN enabled and be on the same segment"}, nil
}
