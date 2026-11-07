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
	reV4    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reV6    = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`)
	reAS    = regexp.MustCompile(`\bAS ?(\d{1,10})\b`)
	reASKw  = regexp.MustCompile(`(?i)\b((?:remote|local|peer|neighbor|origin)-as|router bgp|bgp-as|as-number|autonomous-system)(\s*[:=]?\s*"?)(\d{1,10})\b`)
	reMail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	reNum   = regexp.MustCompile(`\d{1,10}`)
	reMAC   = regexp.MustCompile(`(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}`)
	reB64   = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	reToken = regexp.MustCompile(`(?:(?:PUBLIC|PRIVATE)-(?:IP|IP6|AS)|MASKED-[A-Z]+)-[0-9a-f]{6}`)
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
	case publicASN(n) && m.r.PublicASNs:
		return maskTag("PUBLIC-AS", digits), true
	case privateASN(n) && m.r.PrivateASNs:
		return maskTag("PRIVATE-AS", digits), true
	}
	return "", false
}

func maskASNText(digits string) (string, bool) { return stdMask.asn(digits) }

// ip4Keep is an address with the first keep octets left readable: 203.0.PUBLIC-IP-3fa91c; with a negative keep, the last ones:
// PUBLIC-IP-3fa91c.114.7.
func ip4Keep(a netip.Addr, tag string, keep int) string {
	o := a.As4()
	var b strings.Builder
	switch {
	case keep > 0:
		for i := 0; i < keep && i < 3; i++ {
			b.WriteString(strconv.Itoa(int(o[i])))
			b.WriteByte('.')
		}
		return b.String() + tag
	case keep < 0:
		for i := 4 + max(keep, -3); i < 4; i++ {
			b.WriteByte('.')
			b.WriteString(strconv.Itoa(int(o[i])))
		}
	}
	return tag + b.String()
}

func ip6Keep(a netip.Addr, tag string, keep int) string {
	o := a.As16()
	grp := func(i int) string { return strconv.FormatUint(uint64(o[2*i])<<8|uint64(o[2*i+1]), 16) }
	var b strings.Builder
	switch {
	case keep > 0:
		for i := 0; i < keep && i < 3; i++ {
			b.WriteString(grp(i))
			b.WriteByte(':')
		}
		return b.String() + tag
	case keep < 0:
		for i := 8 + max(keep, -3); i < 8; i++ {
			b.WriteByte(':')
			b.WriteString(grp(i))
		}
	}
	return tag + b.String()
}

// text hides what a piece of text says, as the rules ask.
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
	if r.MACs != "" && r.MACs != "show" {
		s = replaceMAC(s, func(x string) string {
			low := strings.ToLower(x)
			tag := maskTag("MASKED-MAC", strings.NewReplacer("-", ":", ".", "").Replace(low))
			if r.MACs == "nic" { // the last three bytes, the part that is the card's own
				if strings.Contains(x, ".") {
					return tag + "." + x[len(x)-7:]
				}
				return tag + x[8:9] + x[9:]
			}
			if r.MACs == "oui" {
				if strings.Contains(x, ".") {
					return x[:4] + "." + tag // the first two bytes of the vendor part
				}
				return x[:8] + x[2:3] + tag
			}
			return tag
		})
	}
	if r.PublicIPs || r.PrivateIPs {
		s = reV4.ReplaceAllStringFunc(s, func(x string) string {
			a, err := netip.ParseAddr(x)
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
			if t, ok := m.asn(reNum.FindString(x)); ok {
				return t
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
	idx := reMAC.FindAllStringIndex(s, -1)
	if len(idx) == 0 {
		return s
	}
	var b strings.Builder
	at := 0
	for _, sp := range idx {
		edge := func(i int) bool {
			if i < 0 || i >= len(s) {
				return true
			}
			c := s[i]
			if c == '.' && i == sp[1] && (i+1 >= len(s) || !isAlnum(s[i+1])) {
				return true // the full stop at the end of a sentence
			}
			return !(c == ':' || c == '-' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
		}
		b.WriteString(s[at:sp[0]])
		if edge(sp[0]-1) && edge(sp[1]) {
			b.WriteString(f(s[sp[0]:sp[1]]))
		} else {
			b.WriteString(s[sp[0]:sp[1]])
		}
		at = sp[1]
	}
	b.WriteString(s[at:])
	return b.String()
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
var reSerialTail = regexp.MustCompile(`^\*{4}[A-Za-z0-9 ._/-]{0,4}$`)

// maskValue walks a decoded JSON value (numbers kept as json.Number).
func (m *maskRules) value(v any, key string) any {
	if m == nil || m.none {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[m.text(k)] = m.value(x, k)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = m.value(x, key)
		}
		return t
	case json.Number:
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
		case serialKey(key) && t != "" && m.r.Serials == "tail":
			return serialTail(t)
		case serialKey(key) && t != "" && m.r.Serials == "hide":
			return maskTag("MASKED-SERIAL", strings.TrimSpace(t))
		case idKeys[normKey(key)] && t != "" && m.r.Contacts:
			return maskTag("MASKED-ID", t)
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
		if reToken.MatchString(t) || reSerialTail.MatchString(t) {
			return mcpHidden
		}
	}
	return v
}
