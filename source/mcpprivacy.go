package main

import (
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// Privacy levels for what an MCP caller is told (mcpmask.go does the hiding).  Three levels:
//
//	none      nothing is hidden (secrets still are: mcpsecrets.go, always)
//	standard  public addresses and AS numbers, e-mail addresses, contacts and locations, serial numbers by their last four
//	          characters: what netdir hid before levels existed, so an upgrade changes nothing (the default)
//	strict    all of that, and private addresses, private AS numbers, MAC addresses and serial numbers, completely
//
// Settings ▸ Privacy sets the level for callers that have none of their own, and what each of the two levels hides.  A key
// (mcp_keys[].privacy) and an allowed source (mcp_acl, "10.1.0.0/24 strict") may have a level of their own; a caller who has
// several (a key and an address) gets the strictest of them, and one with none gets the default.

type PrivacyRules struct {
	PublicIPs   bool     `json:"public_ips"`        // public IPv4/IPv6 addresses
	PrivateIPs  bool     `json:"private_ips"`       // addresses of private networks (RFC 1918, CGNAT, link-local, ULA)
	IPKeep      int      `json:"ip_keep,omitempty"` // 0-3: how many leading octets (IPv6: groups) of a hidden address stay readable
	PublicASNs  bool     `json:"public_asns"`       // public AS numbers
	PrivateASNs bool     `json:"private_asns"`      // private-use AS numbers
	Serials     string   `json:"serials"`           // show | tail (last four characters) | hide
	MACs        string   `json:"macs"`              // show | oui (the vendor part stays) | hide
	Emails      bool     `json:"emails"`            // e-mail addresses
	Contacts    bool     `json:"contacts"`          // SNMP contact and location
	Words       []string `json:"words,omitempty"`   // words of your own that are always hidden (host names, company, sites)
}

// PrivacyConfig is settings.privacy.
type PrivacyConfig struct {
	Default  string        `json:"default,omitempty"`  // the level of a caller that has none: none | standard (the default) | strict
	Standard *PrivacyRules `json:"standard,omitempty"` // what "standard" hides; unset: the built-in rules
	Strict   *PrivacyRules `json:"strict,omitempty"`
}

const (
	privWordsMax = 100
	privWordMin  = 3
	privWordMax  = 64
)

func standardRules() PrivacyRules {
	return PrivacyRules{PublicIPs: true, PublicASNs: true, Serials: "tail", MACs: "show", Emails: true, Contacts: true}
}

func strictRules() PrivacyRules {
	return PrivacyRules{PublicIPs: true, PrivateIPs: true, PublicASNs: true, PrivateASNs: true, Serials: "hide", MACs: "hide", Emails: true, Contacts: true}
}

// normLevel writes a level the same way; ok is false for a word that is none of them ("" is allowed: no level of its own).
func normLevel(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", true
	case "none", "off":
		return "none", true
	case "standard", "std":
		return "standard", true
	case "strict":
		return "strict", true
	}
	return "", false
}

func privRank(l string) int {
	switch l {
	case "none":
		return 0
	case "strict":
		return 2
	}
	return 1
}

// strictestLevel is the strictest of the levels that are set ("" when none is).
func strictestLevel(l ...string) string {
	best := ""
	for _, x := range l {
		if x != "" && (best == "" || privRank(x) > privRank(best)) {
			best = x
		}
	}
	return best
}

func (r *PrivacyRules) clone() *PrivacyRules {
	if r == nil {
		return nil
	}
	c := *r
	c.Words = append([]string(nil), r.Words...)
	if len(c.Words) == 0 {
		c.Words = nil
	}
	return &c
}

func (c *PrivacyConfig) clone() *PrivacyConfig {
	if c == nil {
		return nil
	}
	return &PrivacyConfig{Default: c.Default, Standard: c.Standard.clone(), Strict: c.Strict.clone()}
}

func normRules(name string, r *PrivacyRules) (*PrivacyRules, error) {
	if r == nil {
		return nil, nil
	}
	c := *r
	if c.IPKeep < 0 || c.IPKeep > 3 {
		return nil, fmt.Errorf("privacy: %s: the digits of an address to keep are 0 to 3", name)
	}
	switch strings.ToLower(strings.TrimSpace(c.Serials)) {
	case "", "show", "tail", "hide":
		c.Serials = strings.ToLower(strings.TrimSpace(c.Serials))
	default:
		return nil, fmt.Errorf("privacy: %s: serial numbers are shown, tail (last four) or hidden: show, tail, hide", name)
	}
	switch strings.ToLower(strings.TrimSpace(c.MACs)) {
	case "", "show", "oui", "hide":
		c.MACs = strings.ToLower(strings.TrimSpace(c.MACs))
	default:
		return nil, fmt.Errorf("privacy: %s: MAC addresses are show, oui (vendor part stays) or hide", name)
	}
	if c.Serials == "" {
		c.Serials = "show"
	}
	if c.MACs == "" {
		c.MACs = "show"
	}
	if len(c.Words) > privWordsMax {
		return nil, fmt.Errorf("privacy: %s: at most %d words", name, privWordsMax)
	}
	seen := map[string]bool{}
	var words []string
	for _, w := range c.Words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if n := len([]rune(w)); n < privWordMin || n > privWordMax {
			return nil, fmt.Errorf("privacy: %s: the word %q must be %d to %d characters (a shorter one would hide parts of everything)", name, w, privWordMin, privWordMax)
		}
		if strings.IndexFunc(w, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("privacy: %s: the word %q has a control character", name, w)
		}
		if k := strings.ToLower(w); !seen[k] {
			seen[k] = true
			words = append(words, w)
		}
	}
	c.Words = words
	return &c, nil
}

// normPrivacy checks settings.privacy; nothing set (or only the defaults) leaves no key in the file.
func normPrivacy(c *PrivacyConfig) (*PrivacyConfig, error) {
	if c == nil {
		return nil, nil
	}
	out := &PrivacyConfig{}
	var ok bool
	if out.Default, ok = normLevel(c.Default); !ok {
		return nil, fmt.Errorf("privacy: the default level is none, standard or strict")
	}
	var err error
	if out.Standard, err = normRules("standard", c.Standard); err != nil {
		return nil, err
	}
	if out.Strict, err = normRules("strict", c.Strict); err != nil {
		return nil, err
	}
	if out.Default == "standard" {
		out.Default = ""
	}
	if out.Default == "" && out.Standard == nil && out.Strict == nil {
		return nil, nil
	}
	return out, nil
}

// level is the level that applies to callers that have none of their own.
func (c *PrivacyConfig) level() string {
	if c == nil || c.Default == "" {
		return "standard"
	}
	return c.Default
}

func (c *PrivacyConfig) rules(level string) *maskRules {
	var std, strict PrivacyRules = standardRules(), strictRules()
	if c != nil {
		if c.Standard != nil {
			std = *c.Standard
		}
		if c.Strict != nil {
			strict = *c.Strict
		}
	}
	switch level {
	case "none":
		return maskNone
	case "strict":
		return cachedRules(strict)
	}
	return cachedRules(std)
}

var maskCache struct {
	sync.Mutex
	m map[string]*maskRules
}

func cachedRules(r PrivacyRules) *maskRules {
	key := fmt.Sprintf("%v|%v|%d|%v|%v|%s|%s|%v|%v|%q", r.PublicIPs, r.PrivateIPs, r.IPKeep, r.PublicASNs, r.PrivateASNs, r.Serials, r.MACs, r.Emails, r.Contacts, r.Words)
	maskCache.Lock()
	defer maskCache.Unlock()
	if m, ok := maskCache.m[key]; ok {
		return m
	}
	if maskCache.m == nil || len(maskCache.m) > 64 {
		maskCache.m = map[string]*maskRules{}
	}
	m := newMaskRules(r)
	maskCache.m[key] = m
	return m
}

// mcpPrivacy is the rules for a caller whose key and source have these levels (either may be "").
func (s *Supervisor) mcpPrivacy(levels ...string) *maskRules {
	s.mu.Lock()
	var c *PrivacyConfig
	if s.dc != nil {
		c = s.dc.Settings.Privacy
	}
	s.mu.Unlock()
	l := strictestLevel(levels...)
	if l == "" {
		l = c.level()
	}
	return c.rules(l)
}
