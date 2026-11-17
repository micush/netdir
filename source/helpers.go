package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// unmapPrefix turns ::ffff:a.b.c.d/N into a.b.c.d/(N-96) so it matches unmapped addresses.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}

// parseClientNets turns "10.0.0.0/8", "192.168.1.5" or "2001:db8::/32" into canonical prefixes.
func parseClientNets(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, unmapPrefix(p.Masked()))
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network like 10.0.0.0/8", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// matchExpr is a search as the log filter reads it: groups separated by "or", each a list of terms that must all be
// found ("and", or plain words next to each other in one term).  A word with a "!" before it (!dns), or after "not" (not dns), is a
// term that must NOT be found.
type matchExpr [][]string

func parseMatch(text string) matchExpr {
	var expr matchExpr
	var group, term []string
	endTerm := func() {
		if len(term) > 0 {
			group = append(group, strings.Join(term, " "))
			term = nil
		}
	}
	endGroup := func() {
		endTerm()
		if len(group) > 0 {
			expr = append(expr, group)
			group = nil
		}
	}
	pend := false // a "not" waits for the word it applies to
	for _, w := range strings.Fields(strings.ToLower(text)) {
		switch w {
		case "and":
			endTerm()
			pend = false
		case "or":
			endGroup()
			pend = false
		case "not":
			pend = !pend
		default:
			bare := strings.TrimLeft(w, "!")
			if bang := len(w) - len(bare); bang > 0 || pend {
				endTerm()
				if bare != "" {
					if (bang%2 == 1) != pend {
						bare = "!" + bare
					}
					group = append(group, bare)
				}
				pend = false
				continue
			}
			term = append(term, w)
		}
	}
	endGroup()
	return expr
}

// matches says whether the expression holds for something known by these (lower-case) texts: each term must be found in at
// least one of them.
func (e matchExpr) matches(texts ...string) bool {
	for _, group := range e {
		all := true
		for _, term := range group {
			neg := strings.HasPrefix(term, "!")
			found := false
			for _, t := range texts {
				if strings.Contains(t, strings.TrimPrefix(term, "!")) {
					found = true
					break
				}
			}
			if found == neg {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
