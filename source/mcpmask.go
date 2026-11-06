package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
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
// serial number under a name it does not know) is not hidden.

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
	reToken = regexp.MustCompile(`(?:PUBLIC-(?:IP|IP6|AS)|MASKED-[A-Z]+)-[0-9a-f]{6}`)
)

var nonPublic4 = mustPrefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3") // multicast, reserved and netmasks too
var nonPublic6 = mustPrefixes("::/8", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "100::/64")

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

func maskASNText(digits string) (string, bool) {
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || !publicASN(n) {
		return "", false
	}
	return maskTag("PUBLIC-AS", digits), true
}

// maskText hides what a piece of text says about the public network.
func maskText(s string) string {
	if s == "" {
		return s
	}
	s = reMail.ReplaceAllStringFunc(s, func(m string) string { return maskTag("MASKED-EMAIL", strings.ToLower(m)) })
	s = reV4.ReplaceAllStringFunc(s, func(m string) string {
		if a, err := netip.ParseAddr(m); err == nil && publicAddr(a) {
			return maskTag("PUBLIC-IP", a.String())
		}
		return m
	})
	s = reV6.ReplaceAllStringFunc(s, func(m string) string {
		if a, err := netip.ParseAddr(m); err == nil && a.Is6() && publicAddr(a) {
			return maskTag("PUBLIC-IP6", a.String())
		}
		return m
	})
	s = reAS.ReplaceAllStringFunc(s, func(m string) string {
		if t, ok := maskASNText(reNum.FindString(m)); ok {
			return t
		}
		return m
	})
	s = reASKw.ReplaceAllStringFunc(s, func(m string) string {
		sub := reASKw.FindStringSubmatch(m)
		if t, ok := maskASNText(sub[3]); ok {
			return sub[1] + sub[2] + t
		}
		return m
	})
	return s
}

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

var idKeys = map[string]bool{"serial": true, "serial-number": true, "serial-num": true, "serialnumber": true, "chassis-serial": true,
	"snmp-contact": true, "snmp-location": true, "sys-contact": true, "sys-location": true, "syscontact": true, "syslocation": true}

// maskValue walks a decoded JSON value (numbers kept as json.Number).
func maskValue(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[maskText(k)] = maskValue(x, k)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = maskValue(x, key)
		}
		return t
	case json.Number:
		if asnKey(key) {
			if tag, ok := maskASNText(t.String()); ok {
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
				if b, err := json.MarshalIndent(maskValue(inner, ""), "", "  "); err == nil {
					return string(b)
				}
			}
		}
		switch {
		case idKeys[normKey(key)] && t != "":
			return maskTag("MASKED-ID", t)
		case asnKey(key):
			if tag, ok := maskASNText(strings.TrimSpace(t)); ok {
				return tag
			}
		case asPathKey(key):
			t = reNum.ReplaceAllStringFunc(t, func(m string) string {
				if tag, ok := maskASNText(m); ok {
					return tag
				}
				return m
			})
		}
		return maskText(t)
	}
	return v
}

// mcpMaskJSON hides the public addresses, AS numbers, e-mail addresses and serial numbers in a JSON answer.
func mcpMaskJSON(b []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return []byte(maskText(string(b))) // not JSON: as text
	}
	out, err := json.Marshal(maskValue(v, ""))
	if err != nil {
		return []byte(maskText(string(b)))
	}
	return out
}

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
		if reToken.MatchString(t) {
			return mcpHidden
		}
	}
	return v
}
