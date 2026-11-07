package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The leak test.  tools/leaktest.sh records everything every driver returns while the driver tests run (device/leakcapture_test.go)
// and runs this test on it: what an MCP caller gets at the strict level, from the driver's answer through the same redaction
// and masking the daemon uses, must hold none of the addresses, MAC addresses, e-mail addresses, AS numbers, serial numbers or secrets
// of the test data.  The test data uses documentation addresses; they are counted as real here.  The checks are written
// apart from the masking code (other patterns), so a form the masking does not know is found by them.

var (
	leakV4   = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	leakV6   = regexp.MustCompile(`(?i)[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*`)
	leakMAC  = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}`)
	leakMail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}`)
	leakB64  = regexp.MustCompile(`[A-Za-z0-9+/_-]{12,}={0,2}`)
	leakDash = regexp.MustCompile(`\b\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b`)
	leakArpa = regexp.MustCompile(`(?i)(?:\d{1,3}\.){1,4}in-addr\.arpa`)
	leakMask = regexp.MustCompile(`^(?:255|254|252|248|240|224|192|128|0)(?:\.(?:255|254|252|248|240|224|192|128|0)){3}$`)
)

// leakTiny: ::ffff and the like, what is left of an IPv4-mapped address once its IPv4 part is a stand-in
func leakTiny(a netip.Addr) bool {
	b := a.As16()
	for _, x := range b[:12] {
		if x != 0 && x != 0xff {
			return false
		}
	}
	return true
}

func leakAllowedV4(x string) bool {
	a, err := netip.ParseAddr(x)
	if err != nil {
		return true // 999.1.1.1: not an address
	}
	return a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || leakMask.MatchString(x) || strings.HasPrefix(x, "0.")
}

type leakFinding struct{ kind, plat, op, ctx string }

func leakCtx(s string, i, j int) string {
	a, b := max(0, i-30), min(len(s), j+30)
	return strings.ReplaceAll(s[a:b], "\n", " ")
}

func leakScan(plat, op, s string, secrets []string) []leakFinding {
	var out []leakFinding
	add := func(k string, i, j int) { out = append(out, leakFinding{k, plat, op, leakCtx(s, i, j)}) }
	for _, m := range leakV4.FindAllStringIndex(s, -1) {
		if x := s[m[0]:m[1]]; !leakAllowedV4(x) {
			add("ipv4", m[0], m[1])
		}
	}
	for _, m := range leakV6.FindAllStringIndex(s, -1) {
		x := strings.Trim(s[m[0]:m[1]], ":")
		if a, err := netip.ParseAddr(strings.TrimSuffix(s[m[0]:m[1]], ":")); err == nil && a.Is6() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast() && !leakTiny(a) {
			add("ipv6", m[0], m[1])
		} else if a, err := netip.ParseAddr(x); err == nil && a.Is6() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast() && len(x) > 3 {
			add("ipv6", m[0], m[1])
		}
	}
	for _, m := range leakMAC.FindAllStringIndex(s, -1) {
		if !strings.Contains(s[max(0, m[0]-12):m[0]], "MASKED-MAC") {
			add("mac", m[0], m[1])
		}
	}
	for _, m := range leakMail.FindAllStringIndex(s, -1) {
		add("email", m[0], m[1])
	}
	for _, m := range leakArpa.FindAllStringIndex(s, -1) {
		add("in-addr.arpa", m[0], m[1])
	}
	for _, m := range leakDash.FindAllStringIndex(s, -1) {
		add("dashed-ip", m[0], m[1])
	}
	for _, m := range leakB64.FindAllStringIndex(s, -1) {
		x := strings.TrimRight(s[m[0]:m[1]], "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(x); err == nil && len(b) >= 8 {
				d := string(b)
				if f := leakV4.FindString(d); f != "" && !leakAllowedV4(f) || leakMail.MatchString(d) || leakMAC.MatchString(d) {
					add("base64", m[0], m[1])
				}
			}
		}
	}
	for _, sec := range secrets {
		if i := strings.Index(s, sec); i >= 0 {
			add("secret", i, i+len(sec))
		}
	}
	return out
}

// leakWalk checks the keys that name a serial number or an AS number: their values must be stand-ins.
func leakWalk(plat, op string, v any, key string, out *[]leakFinding) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			leakWalk(plat, op, x, k, out)
		}
	case []any:
		for _, x := range t {
			leakWalk(plat, op, x, key, out)
		}
	case string:
		switch {
		case serialKey(key) && t != "" && !strings.Contains(t, "MASKED-SERIAL") && t != mcpHidden:
			*out = append(*out, leakFinding{"serial", plat, op, key + "=" + t})
		case asnKey(key) && regexp.MustCompile(`^\d+$`).MatchString(strings.TrimSpace(t)):
			if x, err := parseUint(strings.TrimSpace(t)); err == nil && !(x >= 64496 && x <= 64511) { // the documentation numbers are not real ones
				*out = append(*out, leakFinding{"asn", plat, op, key + "=" + t})
			}
		case idKeys[normKey(key)] && t != "" && !strings.Contains(t, "MASKED-ID") && t != mcpHidden:
			*out = append(*out, leakFinding{"contact", plat, op, key + "=" + t})
		}
	case json.Number:
		if asnKey(key) {
			n := t.String()
			if x, err := parseUint(n); err == nil && (publicASN(x) || privateASN(x)) && !(x >= 64496 && x <= 64511) {
				*out = append(*out, leakFinding{"asn", plat, op, key + "=" + n})
			}
		}
	}
}

func parseUint(s string) (uint64, error) {
	var n uint64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func TestLeakEveryDriver(t *testing.T) {
	path := os.Getenv("NETDIR_LEAKFILE")
	if path == "" {
		t.Skip("set NETDIR_LEAKFILE (tools/leaktest.sh does)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Records []struct {
			Platform string `json:"platform"`
			Op       string `json:"op"`
			Value    any    `json:"value"`
			Err      string `json:"err"`
		} `json:"records"`
		Secrets []string `json:"secrets"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	// the documentation ranges of the test data are real addresses here
	o4, o6 := nonPublic4, nonPublic6
	nonPublic4 = mustPrefixes("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3")
	nonPublic6 = mustPrefixes("::/8", "ff00::/8")
	t.Cleanup(func() { nonPublic4, nonPublic6 = o4, o6 })

	// credentials of the tests of a failed login ("wrong", "nope") are ordinary words in an error text, not secrets that got out
	var secrets []string
	for _, x := range in.Secrets {
		if l := strings.ToLower(x); !strings.HasPrefix(l, "wrong") && l != "nope" {
			secrets = append(secrets, x)
		}
	}
	in.Secrets = secrets
	m := newMaskRules(strictRules())
	var found []leakFinding
	rawSeen := map[string]int{} // the same checks on the answers before masking: proof that they find what they look for
	plats := map[string]int{}
	for _, r := range in.Records {
		plats[r.Platform]++
		var vals []any
		if r.Value != nil {
			vals = append(vals, r.Value)
		}
		if r.Err != "" {
			vals = append(vals, r.Err)
		}
		for _, v := range vals {
			// the path of a result: redaction of secrets, then the level's masking
			b, _ := json.Marshal(mcpRedact(v))
			for _, f := range leakScan(r.Platform, r.Op, string(b), nil) {
				rawSeen[f.kind]++
			}
			var rv any
			if json.Unmarshal(b, &rv) == nil {
				var rf []leakFinding
				leakWalk(r.Platform, r.Op, rv, "", &rf)
				for _, f := range rf {
					rawSeen[f.kind]++
				}
			}
			for _, sec := range in.Secrets {
				if strings.Contains(string(b), sec) {
					rawSeen["secret"]++
				}
			}
			masked := m.json(b)
			if s, ok := v.(string); ok && r.Value == nil {
				masked = []byte(m.text(s)) // an error text
			}
			found = append(found, leakScan(r.Platform, r.Op, string(masked), in.Secrets)...)
			dec := json.NewDecoder(strings.NewReader(string(masked)))
			dec.UseNumber()
			var mv any
			if dec.Decode(&mv) == nil {
				leakWalk(r.Platform, r.Op, mv, "", &found)
			}
		}
	}
	if len(plats) < 15 {
		t.Fatalf("only %d platforms were recorded: %v", len(plats), plats)
	}
	byKind := map[string][]leakFinding{}
	for _, f := range found {
		byKind[f.kind] = append(byKind[f.kind], f)
	}
	var kinds []string
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		seen := map[string]bool{}
		t.Logf("LEAK %s: %d", k, len(byKind[k]))
		n := 0
		for _, f := range byKind[k] {
			key := f.plat + f.op + f.ctx
			if seen[key] || n >= 12 {
				continue
			}
			seen[key] = true
			n++
			t.Logf("   %s/%s: …%s…", f.plat, f.op, f.ctx)
		}
	}
	if len(found) > 0 {
		t.Errorf("%d leaks in %d recorded answers of %d platforms", len(found), len(in.Records), len(plats))
	}
	t.Logf("%d recorded answers, %d platforms, %d secrets looked for; before masking the checks find %v", len(in.Records), len(plats), len(in.Secrets), rawSeen)
	if rawSeen["ipv4"] < 20 || rawSeen["mac"] < 3 {
		t.Errorf("the checks found too little in the unmasked answers (%v): they are not looking properly", rawSeen)
	}
}

// Unusual ways of writing what must be hidden: each case holds one real value, and none of it may survive the strict level.
func TestLeakAdversarialForms(t *testing.T) {
	o4, o6 := nonPublic4, nonPublic6
	nonPublic4 = mustPrefixes("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3")
	nonPublic6 = mustPrefixes("::/8", "ff00::/8")
	t.Cleanup(func() { nonPublic4, nonPublic6 = o4, o6 })
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := map[string]string{
		"port":          "connect to 203.0.113.9:443 failed",
		"port-brackets": "listening on [2001:db8:1::9]:8443",
		"cidr":          "route 198.51.100.0/24 via 10.1.2.3",
		"slash-in-key":  `{"198.51.100.7/32": "x"}`,
		"url":           "https://203.0.113.10/api/v1?host=198.51.100.4&x=1",
		"user-at-ip":    "ssh://admin@203.0.113.11:22",
		"upper-v6":      "peer 2001:DB8:ABCD::1 up",
		"full-v6":       "peer 2001:0db8:0000:0000:0000:0000:0000:0001 up",
		"mapped":        "peer ::ffff:203.0.113.12 up",
		"zone":          "link fe80::1%eth0 up",
		"mac-dash":      "mac 00-1A-2B-3C-4D-5E",
		"mac-dots":      "mac 001a.2b3c.4d5e",
		"mac-in-word":   "iface-001a2b3c4d5e",
		"mac-upper":     "MAC 00:1A:2B:3C:4D:5E",
		"mac-in-json":   `{"mac":"00:1a:2b:3c:4d:5e"}`,
		"json-in-str":   `{"body":"{\"ip\":\"203.0.113.13\",\"mac\":\"00:1a:2b:3c:4d:5f\"}"}`,
		"b64-ref":       "record:a/" + b64("dns.a$._default.example.net.host.203.0.113.14") + ":host",
		"b64-url":       "ref=" + strings.NewReplacer("+", "-", "/", "_").Replace(b64("net$10.20.30.40/24/default")),
		"email":         "contact noc@example.net",
		"email-plus":    "contact first.last+tag@sub.example.co.uk",
		"as-text":       "peer AS64500 is up",
		"as-kw":         "router bgp 65001",
		"ip-leading0":   "host 010.001.002.003",
		"ip-in-text":    "address:203.0.113.15,gateway:203.0.113.1",
		"ip-in-key":     `{"host-203.0.113.16": 1}`,
		"v4-after-eq":   "ip=203.0.113.17;next=203.0.113.18",
		"two-in-one":    "203.0.113.19-203.0.113.20",
		"range":         "pool 203.0.113.21 - 203.0.113.30",
		"ptr":           "17.113.0.203.in-addr.arpa",
		"ptr6":          "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
		"dashed":        "ip-203-0-113-22.example.net",
		"xml":           "<address>203.0.113.23</address><mac>00:1a:2b:3c:4d:60</mac>",
		"snmp-hex":      "00 1a 2b 3c 4d 61",
	}
	m := newMaskRules(strictRules())
	var bad []string
	for name, in := range cases {
		out := m.text(in)
		if json.Valid([]byte(in)) {
			out = string(m.json([]byte(in)))
		}
		if f := leakScan("adv", name, out, nil); len(f) > 0 {
			bad = append(bad, fmt.Sprintf("%s: %q -> %q (%s)", name, in, out, f[0].kind))
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Log(b)
	}
	if len(bad) > 0 {
		t.Errorf("%d forms leak", len(bad))
	}
}
