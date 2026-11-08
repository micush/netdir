package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// What an MCP caller is never told: the public addresses and AS numbers of the network, e-mail addresses and serial
// numbers.  The caller is a public LLM service; a list of a firewall's public addresses and its upstreams' AS numbers is
// what someone looking for a weakness would ask for first.  Private addresses (RFC 1918, ULA, link-local, CGNAT,
// documentation ranges) and private AS numbers are shown, because the work needs them.
//
// Each hidden value is replaced by a token that is the same for the same value (PUBLIC-IP-3fa91c), so that "the same
// next hop in the route table and in the firewall rule" can still be seen.  The token is a keyed hash with a salt made
// when the daemon starts: it cannot be reversed or looked up, and it changes at a restart and between nodes.
//
// This is done to everything a tool answers (mcp.go) by walking the answer, so a new tool is covered without anyone
// remembering to.  What it cannot find (a public address written as a host name, an address split across fields, a
// serial number under a name it does not know) is not hidden.  A serial number (under a name that says so) is shown by its last
// four characters, ****1234.
//
// How much is hidden is set by a privacy level (mcpprivacy.go): "none", "standard" (what is described above, the default)
// or "strict" (private addresses and AS numbers, MAC addresses and the serial numbers too), each with rules that
// Configure ▸ Privacy can change: how many leading digits of an address stay, whether MAC addresses are hidden,
// words of the owner's own that are always hidden.  The level of a caller is set per key and per allowed source.

var maskSalt = func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }()

func maskTag(prefix, v string) string {
	m := hmac.New(sha256.New, maskSalt)
	m.Write([]byte(v))
	return prefix + "-" + hex.EncodeToString(m.Sum(nil))[:6]
}

var (
	reV4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// an address written as one decimal number, 3232236805: only where a word before it says it is an address (a count of bytes is not)
	reDecIP  = regexp.MustCompile(`(?i)((?:^|[^a-z0-9])(?:[a-z0-9]+[_-])*(?:ip|ipv4|addr|address|gateway|gw|host|src|dst|hop|nexthop|via|peer|neighbor)(?:[_-][a-z0-9]+)*\s*[:=]?\s*"?)(\d{8,10})\b`)
	reAddrKy = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:ip|ipv4|addr|address|gateway|gw|host|src|dst|hop|nexthop|via|peer|neighbor)(?:$|[^a-z])|ipaddr|ipaddress|nexthop`)
	reHexIP  = regexp.MustCompile(`(?i)\b0x[0-9a-f]{8}\b`)
	reV6     = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`)
	reAS     = regexp.MustCompile(`\bAS ?(\d{1,10})\b`)
	reASKw   = regexp.MustCompile(`(?i)\b((?:remote|local|peer|neighbor|origin)-as|router bgp|bgp-as|as-number|autonomous-system)(\s*[:=]?\s*"?)(\d{1,10})\b`)
	reMail   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	reNum    = regexp.MustCompile(`\d{1,10}`)
	reMAC    = regexp.MustCompile(`(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{6}\.[0-9a-f]{6}|[0-9a-f]{12}`)
	reArpa4  = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.){1,4}in-addr\.arpa\b`)
	reArpa6  = regexp.MustCompile(`(?i)\b(?:[0-9a-f]\.){1,32}ip6\.arpa\b`)
	reDash   = regexp.MustCompile(`\b\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b`)
	reB64    = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	reToken  = regexp.MustCompile(`(?:(?:PUBLIC|PRIVATE)-(?:IP|IP6|AS)|MASKED-[A-Z]+)-[0-9a-f]{6}`)
)

var nonPublic4 = mustPrefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3") // multicast, reserved and netmasks too
var nonPublic6 = mustPrefixes("::/8", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "100::/64")

// private4/private6 are the addresses of a private network (what "private addresses" hides at the strict level); loopback,
// documentation ranges, multicast and netmasks are not among them.
var private4 = mustPrefixes("10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")
var private6 = mustPrefixes("fc00::/7", "fe80::/10")

func mustPrefixes(l ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range l {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// publicAddr says whether a is an address of the public Internet.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	set := nonPublic6
	if a.Is4() {
		set = nonPublic4
	}
	for _, p := range set {
		if p.Contains(a) {
			return false
		}
	}
	return a.IsValid()
}

func privateAddr(a netip.Addr) bool {
	a = a.Unmap()
	set := private6
	if a.Is4() {
		set = private4
	}
	return inNets(set, a)
}

// publicASN: 16- and 32-bit private, documentation and reserved AS numbers are not public.
func publicASN(n uint64) bool {
	switch {
	case n == 0 || n == 23456 || n == 65535 || n >= 4294967295:
		return false
	case n >= 64496 && n <= 65551: // documentation (64496-64511), private (64512-65534), reserved
		return false
	case n >= 4200000000:
		return false
	}
	return true
}

// privateASN: the private-use AS numbers (RFC 6996).
func privateASN(n uint64) bool {
	return n >= 64512 && n <= 65534 || n >= 4200000000 && n <= 4294967294
}

// maskRules is a PrivacyRules ready to use (the word list compiled).  A nil *maskRules, and the level "none", hide nothing.
type maskRules struct {
	r     PrivacyRules
	words *regexp.Regexp
	none  bool
	noEnc bool // do not look for encoded pieces (set on the copy used to test a decoded piece)
}

func newMaskRules(r PrivacyRules) *maskRules {
	m := &maskRules{r: r}
	if len(r.Words) > 0 {
		w := append([]string(nil), r.Words...)
		sort.Slice(w, func(i, j int) bool { return len(w[i]) > len(w[j]) }) // the longest first, so "corp-edge" wins over "corp"
		for i := range w {
			w[i] = regexp.QuoteMeta(w[i])
		}
		m.words = regexp.MustCompile(`(?i)` + strings.Join(w, "|"))
	}
	return m
}

var maskNone = &maskRules{none: true}

// the rules of the standard level as shipped: what the daemon hid before levels existed
var stdMask = newMaskRules(standardRules())

func (m *maskRules) asn(digits string) (string, bool) {
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return "", false
	}
	switch {
	case publicASN(n) && m.r.PublicASNs, privateASN(n) && m.r.PrivateASNs:
		return xDigits(digits), true
	}
	return "", false
}

// xDigits is a number with all but its last three digits (a short one: its last digit or two) written as x: 15169 reads xx169.
// A route distinguisher's parts and a number of an AS are written so.
func xDigits(d string) string {
	n := len(d)
	if n <= 1 {
		return "x"
	}
	keep := min(3, n-1)
	return strings.Repeat("x", n-keep) + d[n-keep:]
}

func maskASNText(digits string) (string, bool) { return stdMask.asn(digits) }

// ip4Keep is an address with the octets that are hidden written as x: x.x.x.x, or with the first keep octets readable
// 203.0.x.x, or with a negative keep the last ones x.x.114.7.  The same address always reads the same, but two addresses
// that differ only in the hidden octets read alike, which is what the owner chose to see in place of a long token.  The
// tag a caller made for the address is not used.
func ip4Keep(a netip.Addr, _ string, keep int) string {
	o := a.As4()
	show := [4]bool{}
	switch {
	case keep > 0:
		for i := 0; i < keep && i < 3; i++ {
			show[i] = true
		}
	case keep < 0:
		for i := 4 + max(keep, -3); i < 4; i++ {
			show[i] = true
		}
	}
	parts := make([]string, 4)
	for i := range parts {
		parts[i] = "x"
		if show[i] {
			parts[i] = strconv.Itoa(int(o[i]))
		}
	}
	return strings.Join(parts, ".")
}

// ip6Keep is ip4Keep for the eight groups of an IPv6 address: x:x:123::456.  The groups that are shown are written as they
// are and the longest run of shown groups that are zero is written ::, as the address itself would be.
func ip6Keep(a netip.Addr, _ string, keep int) string {
	o := a.As16()
	show := [8]bool{}
	switch {
	case keep > 0:
		for i := 0; i < keep && i < 3; i++ {
			show[i] = true
		}
	case keep < 0:
		for i := 8 + max(keep, -3); i < 8; i++ {
			show[i] = true
		}
	}
	var g [8]string
	zero := [8]bool{}
	for i := range g {
		v := uint64(o[2*i])<<8 | uint64(o[2*i+1])
		g[i] = "x"
		if show[i] {
			g[i] = strconv.FormatUint(v, 16)
			zero[i] = v == 0
		}
	}
	best, bestLen := -1, 1 // a lone zero group is not shortened
	for i := 0; i < 8; {
		if !zero[i] {
			i++
			continue
		}
		j := i
		for j < 8 && zero[j] {
			j++
		}
		if j-i > bestLen {
			best, bestLen = i, j-i
		}
		i = j
	}
	if best < 0 {
		return strings.Join(g[:], ":")
	}
	return strings.Join(g[:best], ":") + "::" + strings.Join(g[best+bestLen:], ":")
}

// xMAC writes a MAC address as it was written (aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff, aabbccddeeff) with the digits of
// the bytes the rules hide as x: nic shows the last three bytes (xx:xx:xx:dd:ee:ff), oui the first three, anything else none.
func xMAC(x, mode string) string {
	var digits []byte
	for i := 0; i < len(x); i++ {
		if c := x[i]; c != ':' && c != '-' && c != '.' {
			digits = append(digits, c)
		}
	}
	out := make([]byte, 0, len(x))
	n := 0
	for i := 0; i < len(x); i++ {
		c := x[i]
		if c == ':' || c == '-' || c == '.' {
			out = append(out, c)
			continue
		}
		hide := true
		switch mode {
		case "nic":
			hide = n < 6
		case "oui":
			hide = n >= 6
		}
		if hide {
			c = 'x'
		}
		out = append(out, c)
		n++
	}
	return string(out)
}

// text hides what a piece of text says, as the rules ask.
// decIP is the stand-in for a number that is an IPv4 address, if the rules hide that address.
func (m *maskRules) decIP(digits string) (string, bool) {
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || n > 0xffffffff || n < 1<<24 {
		return "", false
	}
	a := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	switch {
	case m.r.PublicIPs && publicAddr(a):
		return ip4Keep(a, maskTag("PUBLIC-IP", a.String()), m.r.IPKeep), true
	case m.r.PrivateIPs && privateAddr(a):
		return ip4Keep(a, maskTag("PRIVATE-IP", a.String()), m.r.IPKeep), true
	}
	return "", false
}

// unpad4 takes the leading zeros out of the parts of a dotted address, which netip refuses.
func unpad4(x string) string {
	p := strings.Split(x, ".")
	for i, d := range p {
		if len(d) > 1 && d[0] == '0' {
			p[i] = strings.TrimLeft(d, "0")
			if p[i] == "" {
				p[i] = "0"
			}
		}
	}
	return strings.Join(p, ".")
}

func (m *maskRules) text(s string) string {
	if s == "" || m == nil || m.none {
		return s
	}
	r := m.r
	if !m.noEnc {
		s = m.hideEncoded(s)
	}
	if r.Emails {
		s = reMail.ReplaceAllStringFunc(s, func(x string) string { return maskTag("MASKED-EMAIL", strings.ToLower(x)) })
	}
	if r.PublicASNs || r.PrivateASNs || r.PublicIPs || r.PrivateIPs {
		s = reRDText.ReplaceAllStringFunc(s, func(x string) string {
			g := reRDText.FindStringSubmatch(x)
			if t, ok := m.rd(g[2], g[3]); ok {
				return g[1] + t
			}
			return x
		})
	}
	if r.MACs != "" && r.MACs != "show" {
		s = replaceMAC(s, func(x string) string { return xMAC(x, r.MACs) })
	}
	if r.PublicIPs || r.PrivateIPs {
		hide := func(a netip.Addr) bool { return r.PublicIPs && publicAddr(a) || r.PrivateIPs && privateAddr(a) }
		// reverse names (3.2.1.10.in-addr.arpa, the nibbles of an IPv6 address under ip6.arpa) and host names made of the address (ip-10-1-2-3)
		s = reArpa4.ReplaceAllStringFunc(s, func(x string) string {
			p := strings.Split(strings.TrimSuffix(strings.ToLower(x), ".in-addr.arpa"), ".")
			var o [4]byte
			for i, d := range p {
				n, err := strconv.Atoi(d)
				if err != nil || n > 255 {
					return x
				}
				o[len(p)-1-i] = byte(n)
			}
			if hide(netip.AddrFrom4(o)) {
				return maskTag("MASKED-PTR", strings.ToLower(x))
			}
			return x
		})
		s = reArpa6.ReplaceAllStringFunc(s, func(x string) string {
			p := strings.Split(strings.TrimSuffix(strings.ToLower(x), ".ip6.arpa"), ".")
			var o [16]byte
			for i, d := range p {
				n, _ := strconv.ParseUint(d, 16, 8)
				k := len(p) - 1 - i // the nibble's place, counted from the front
				if k%2 == 0 {
					o[k/2] |= byte(n) << 4
				} else {
					o[k/2] |= byte(n)
				}
			}
			if hide(netip.AddrFrom16(o)) {
				return maskTag("MASKED-PTR", strings.ToLower(x))
			}
			return x
		})
		s = reDash.ReplaceAllStringFunc(s, func(x string) string {
			a, err := netip.ParseAddr(strings.ReplaceAll(x, "-", "."))
			if err != nil || !hide(a) {
				return x
			}
			if publicAddr(a) {
				return ip4Keep(a, maskTag("PUBLIC-IP", a.String()), r.IPKeep)
			}
			return ip4Keep(a, maskTag("PRIVATE-IP", a.String()), r.IPKeep)
		})
		s = reV4.ReplaceAllStringFunc(s, func(x string) string {
			a, err := netip.ParseAddr(unpad4(x)) // 192.168.005.005 is the same address
			if err != nil {
				return x
			}
			switch {
			case r.PublicIPs && publicAddr(a):
				return ip4Keep(a, maskTag("PUBLIC-IP", a.String()), r.IPKeep)
			case r.PrivateIPs && privateAddr(a):
				return ip4Keep(a, maskTag("PRIVATE-IP", a.String()), r.IPKeep)
			}
			return x
		})
		s = reDecIP.ReplaceAllStringFunc(s, func(x string) string {
			sub := reDecIP.FindStringSubmatch(x)
			if t, ok := m.decIP(sub[2]); ok {
				return sub[1] + t
			}
			return x
		})
		s = reHexIP.ReplaceAllStringFunc(s, func(x string) string { // 0xc0a80505
			n, err := strconv.ParseUint(x[2:], 16, 32)
			if err != nil {
				return x
			}
			a := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
			switch {
			case r.PublicIPs && publicAddr(a):
				return ip4Keep(a, maskTag("PUBLIC-IP", a.String()), r.IPKeep)
			case r.PrivateIPs && privateAddr(a):
				return ip4Keep(a, maskTag("PRIVATE-IP", a.String()), r.IPKeep)
			}
			return x
		})
		s = reV6.ReplaceAllStringFunc(s, func(x string) string {
			a, err := netip.ParseAddr(x)
			if err != nil || !a.Is6() {
				return x
			}
			switch {
			case r.PublicIPs && publicAddr(a):
				return ip6Keep(a, maskTag("PUBLIC-IP6", a.String()), r.IPKeep)
			case r.PrivateIPs && privateAddr(a):
				return ip6Keep(a, maskTag("PRIVATE-IP6", a.String()), r.IPKeep)
			}
			return x
		})
	}
	if r.PublicASNs || r.PrivateASNs {
		s = reAS.ReplaceAllStringFunc(s, func(x string) string {
			d := reNum.FindString(x)
			if t, ok := m.asn(d); ok {
				return x[:len(x)-len(d)] + t // "AS" stays
			}
			return x
		})
		s = reASKw.ReplaceAllStringFunc(s, func(x string) string {
			sub := reASKw.FindStringSubmatch(x)
			if t, ok := m.asn(sub[3]); ok {
				return sub[1] + sub[2] + t
			}
			return x
		})
	}
	return m.hideWords(s)
}

// hideEncoded replaces a base64 piece that decodes to readable text the rules would hide something in.  Opaque identifiers carry
// what is hidden around them: an Infoblox _ref is "record:host/<base64 of dns.host_address$._default.net.example.10.1.2.3>:name",
// and masking only the readable name would leave the address in the base64.
func (m *maskRules) hideEncoded(s string) string {
	if len(s) < 16 {
		return s
	}
	return reB64.ReplaceAllStringFunc(s, func(run string) string {
		cands := []string{run}
		for i, n := 0, 0; i < len(run) && n < 3; i++ { // a "/" may be the end of a prefix ("host/ZG5z…") rather than part of the encoding
			if run[i] == '/' {
				cands = append(cands, run[i+1:])
				n++
			}
		}
		for _, c := range cands {
			if len(c) < 16 {
				continue
			}
			if d, ok := decodeText(c); ok && m.plain(d) != d {
				return run[:len(run)-len(c)] + maskTag("MASKED-REF", c)
			}
		}
		return run
	})
}

// plain hides as text does, but looks for no encoded pieces (it is used on what a piece decodes to).
func (m *maskRules) plain(s string) string {
	c := *m
	c.noEnc = true
	return c.text(s)
}

// decodeText decodes a base64 string (standard or URL alphabet, padded or not) that is printable ASCII.
func decodeText(c string) (string, bool) {
	c = strings.TrimRight(c, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(c)
		if err != nil || len(b) < 8 {
			continue
		}
		ok := true
		for _, x := range b {
			if x < 0x20 || x > 0x7e {
				ok = false
				break
			}
		}
		if ok {
			return string(b), true
		}
	}
	return "", false
}

// hideWords replaces the owner's own words, leaving the tokens already made alone (a word such as "public" must not break them).
func (m *maskRules) hideWords(s string) string {
	if m.words == nil {
		return s
	}
	rep := func(x string) string {
		return m.words.ReplaceAllStringFunc(x, func(w string) string { return maskTag("MASKED-WORD", strings.ToLower(w)) })
	}
	spans := reToken.FindAllStringIndex(s, -1)
	if len(spans) == 0 {
		return rep(s)
	}
	var b strings.Builder
	at := 0
	for _, sp := range spans {
		b.WriteString(rep(s[at:sp[0]]))
		b.WriteString(s[sp[0]:sp[1]])
		at = sp[1]
	}
	b.WriteString(rep(s[at:]))
	return b.String()
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// replaceMAC replaces the MAC addresses of s that stand alone (not a piece of a longer colon- or dot-separated run, such as an IPv6 address).
func replaceMAC(s string, f func(string) string) string {
	if !reMAC.MatchString(s) {
		return s
	}
	// a word before or after the separator ("mac:", "hwaddr-") ends the address; a run of up to four hex digits ("dead:") is a piece of a longer one
	word := func(i, d int) bool {
		n, hex := 0, true
		for ; i >= 0 && i < len(s) && isAlnum(s[i]); i += d {
			n++
			hex = hex && (s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f' || s[i] >= 'A' && s[i] <= 'F')
		}
		return n > 0 && !(hex && n <= 4)
	}
	var b strings.Builder
	at, from := 0, 0
	for from < len(s) {
		loc := reMAC.FindStringIndex(s[from:])
		if loc == nil {
			break
		}
		sp := [2]int{from + loc[0], from + loc[1]}
		edge := func(i int) bool {
			if i < 0 || i >= len(s) {
				return true
			}
			c := s[i]
			if (c == ':' || c == '-') && (i == sp[0]-1 && word(i-1, -1) || i == sp[1] && word(i+1, 1)) {
				return true
			}
			if c == '.' && i == sp[1] && (i+1 >= len(s) || !isAlnum(s[i+1])) {
				return true // the full stop at the end of a sentence
			}
			return !(c == ':' || c == '-' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
		}
		if edge(sp[0]-1) && edge(sp[1]) && !digitsOnly12(s[sp[0]:sp[1]]) {
			b.WriteString(s[at:sp[0]])
			b.WriteString(f(s[sp[0]:sp[1]]))
			at, from = sp[1], sp[1]
		} else {
			from = sp[0] + 1 // not an address standing alone: look again from the next character
		}
	}
	b.WriteString(s[at:])
	return b.String()
}

// digitsOnly12 is a twelve-digit number, which is far more likely to be a counter or a time than an address written without separators.
func digitsOnly12(x string) bool {
	if len(x) != 12 {
		return false
	}
	for i := 0; i < len(x); i++ {
		if x[i] < '0' || x[i] > '9' {
			return false
		}
	}
	return true
}

// maskText hides what a piece of text says about the public network, as the standard level does.
func maskText(s string) string { return stdMask.text(s) }

func normKey(k string) string { return strings.ReplaceAll(strings.ToLower(k), "_", "-") }

func asnKey(k string) bool {
	k = normKey(k)
	switch k {
	case "as", "asn", "as-number", "as-num", "as-id", "autonomous-system", "local-asn", "remote-asn":
		return true
	}
	return strings.HasSuffix(k, "-as") || strings.HasSuffix(k, "-asn") || strings.HasSuffix(k, "-as-number")
}

// rdKey says whether a key holds a route distinguisher (ASN:number or address:number).
func rdKey(k string) bool {
	k = normKey(k)
	return k == "rd" || strings.HasSuffix(k, "-rd") || strings.Contains(k, "route-distinguisher") || strings.Contains(k, "routedistinguisher")
}

var (
	reRDText = regexp.MustCompile(`(?i)(\b(?:rd|route-distinguisher)(?:\s+|\s*=\s*"?))((?:\d{1,3}\.){3}\d{1,3}|\d{1,10}(?:\.\d{1,5})?):(\d{1,10})\b`)
	reRDVal  = regexp.MustCompile(`^\s*((?:\d{1,3}\.){3}\d{1,3}|\d{1,10}(?:\.\d{1,5})?):(\d{1,10})\s*$`)
)

// rd hides a route distinguisher as far as the rules hide its first part: the AS number (or the address) as they would
// anywhere, and then the number after it, which shows its last digits like an AS number does.  Nothing hidden: unchanged.
func (m *maskRules) rd(admin, num string) (string, bool) {
	if a, err := netip.ParseAddr(admin); err == nil {
		if m.r.PublicIPs && publicAddr(a) || m.r.PrivateIPs && privateAddr(a) {
			return ip4Keep(a, "", m.r.IPKeep) + ":" + xDigits(num), true
		}
		return "", false
	}
	if n, err := strconv.ParseUint(strings.SplitN(admin, ".", 2)[0], 10, 64); err == nil && !strings.Contains(admin, ".") && (publicASN(n) && m.r.PublicASNs || privateASN(n) && m.r.PrivateASNs) {
		return xDigits(admin) + ":" + xDigits(num), true
	}
	return "", false
}

func asPathKey(k string) bool {
	k = normKey(k)
	return k == "as-path" || k == "aspath" || k == "as-paths" || strings.HasSuffix(k, "-as-path")
}

var idKeys = map[string]bool{"snmp-contact": true, "snmp-location": true, "sys-contact": true, "sys-location": true, "syscontact": true, "syslocation": true}

// serialKey says whether a key names a serial number.  Its value is shown by its last four characters (****1234), which is enough
// to tell two units apart or to read one out to the vendor, and not enough to register or claim a device.
func serialKey(k string) bool {
	n := normKey(k)
	switch n {
	case "sn", "snhw", "serial", "entphysicalserialnum":
		return true
	}
	for _, suf := range []string{"serial", "serial-number", "serial-num", "serial-no", "serialnumber", "serialno", "serialnum"} {
		if strings.HasSuffix(n, suf) {
			return !strings.HasSuffix(n, "-port")
		}
	}
	return false
}

// serialTail is a serial number with all but its last four characters hidden.
func serialTail(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= 4 {
		return "****"
	}
	return "****" + string(r[len(r)-4:])
}

// reSerialTail is what serialTail makes; sent back in a change it keeps the real value, like a token.
// reMaskedIP is an address as ip4Keep and ip6Keep write it: at least one x among the parts, the others numbers.
var reMaskedIP = regexp.MustCompile(`^(?:(?:x|\d{1,3})(?:\.(?:x|\d{1,3})){3}|(?:x|[0-9a-f]{1,4})(?::(?:x|[0-9a-f]{1,4})){7})$`)

// reMaskedMAC and reMaskedNum are a MAC address, an AS number or a route distinguisher with digits written as x.
var (
	reMaskedMAC = regexp.MustCompile(`(?i)^(?:(?:[0-9a-fx]{2}[:-]){5}[0-9a-fx]{2}|[0-9a-fx]{4}(?:\.[0-9a-fx]{4}){2}|[0-9a-fx]{12})$`)
	reMaskedNum = regexp.MustCompile(`^(?:x+\d{1,3}|(?:x\.x\.x\.x|[\dx.]+):x+\d{0,3}|x+\d{1,3}:x+\d{0,3})$`)
)

// maskedWithX says whether a text is an address, MAC address, AS number or route distinguisher with digits written as x.
// One without an x is a real value.
func maskedWithX(t string) bool {
	return strings.Contains(strings.ToLower(t), "x") && (reMaskedIP.MatchString(t) || reMaskedMAC.MatchString(t) || reMaskedNum.MatchString(t))
}

var reSerialTail = regexp.MustCompile(`^\*{4}[A-Za-z0-9 ._/-]{0,4}$`)

// maskValue walks a decoded JSON value (numbers kept as json.Number).
func (m *maskRules) value(v any, key string) any {
	if m == nil || m.none {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			nk := m.text(k)
			for i := 2; ; i++ { // two addresses that read alike (x.x.x.x) as keys must not swallow each other
				if _, dup := out[nk]; !dup {
					break
				}
				nk = m.text(k) + "#" + strconv.Itoa(i)
			}
			out[nk] = m.value(t[k], k)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = m.value(x, key)
		}
		return t
	case json.Number:
		if reAddrKy.MatchString(key) && !m.none {
			if tag, ok := m.decIP(t.String()); ok { // "ip": 3232236805
				return tag
			}
		}
		if asnKey(key) {
			if tag, ok := m.asn(t.String()); ok {
				return tag
			}
		}
		return t
	case string:
		if tt := strings.TrimSpace(t); len(tt) > 1 && (tt[0] == '{' || tt[0] == '[') {
			// text that is itself a JSON document (a show command answers so): masked by its key names, and kept indented
			d := json.NewDecoder(strings.NewReader(tt))
			d.UseNumber()
			var inner any
			if d.Decode(&inner) == nil && !d.More() {
				if b, err := json.MarshalIndent(m.value(inner, ""), "", "  "); err == nil {
					return string(b)
				}
			}
		}
		switch {
		case reAddrKy.MatchString(key) && len(strings.TrimSpace(t)) >= 8 && strings.Trim(strings.TrimSpace(t), "0123456789") == "" && func() bool { _, ok := m.decIP(strings.TrimSpace(t)); return ok }():
			tag, _ := m.decIP(strings.TrimSpace(t))
			return tag
		case serialKey(key) && t != "" && m.r.Serials == "tail":
			return serialTail(t)
		case serialKey(key) && t != "" && m.r.Serials == "hide":
			return maskTag("MASKED-SERIAL", strings.TrimSpace(t))
		case idKeys[normKey(key)] && t != "" && m.r.Contacts:
			return maskTag("MASKED-ID", t)
		case rdKey(key) && reRDVal.MatchString(t):
			g := reRDVal.FindStringSubmatch(t)
			if v, ok := m.rd(g[1], g[2]); ok {
				return v
			}
		case asnKey(key):
			if tag, ok := m.asn(strings.TrimSpace(t)); ok {
				return tag
			}
		case asPathKey(key):
			t = reNum.ReplaceAllStringFunc(t, func(x string) string {
				if tag, ok := m.asn(x); ok {
					return tag
				}
				return x
			})
		}
		return m.text(t)
	}
	return v
}

// json hides in a JSON answer what the rules ask to hide.
func (m *maskRules) json(b []byte) []byte {
	if m == nil || m.none {
		return b
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return []byte(m.text(string(b))) // not JSON: as text
	}
	out, err := json.Marshal(m.value(v, ""))
	if err != nil {
		return []byte(m.text(string(b)))
	}
	return out
}

func mcpMaskJSON(b []byte) []byte { return stdMask.json(b) }

// mcpUnmask turns a caller's hidden-value tokens back into "(hidden)" in a body it sends, so that what the caller read
// (a configuration with PUBLIC-IP-3fa91c in it) can be sent back in a change and the real value is restored from the
// current configuration, like a secret.  A token that matches nothing there is refused like any other "(hidden)".
func mcpUnmask(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = mcpUnmask(x)
		}
	case []any:
		for i, x := range t {
			t[i] = mcpUnmask(x)
		}
	case string:
		if reToken.MatchString(t) || reSerialTail.MatchString(t) || maskedWithX(t) {
			return mcpHidden
		}
	}
	return v
}
