package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// dig from this node (the node a caller names, over MCP: net_dig): one query with fixed options, the name, the record type and
// optionally the server to ask (an address) being the only things a caller chooses, each checked before it gets near the command
// line.  Run through exec with no shell.
const (
	digTimeout = 15 * time.Second
	digTextMax = 8192
)

var digTypes = map[string]bool{"A": true, "AAAA": true, "MX": true, "NS": true, "TXT": true, "CNAME": true, "SOA": true, "PTR": true, "SRV": true, "CAA": true,
	"DS": true, "DNSKEY": true, "NAPTR": true, "TLSA": true, "SPF": true}

var digLabelRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

func digRun(name, qtype, server string) (map[string]any, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	qtype = strings.ToUpper(strings.TrimSpace(qtype))
	server = strings.TrimSpace(server)
	if qtype == "" {
		qtype = "A"
	}
	if !digTypes[qtype] {
		return nil, errors.New("type: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, DS, DNSKEY, NAPTR, TLSA or SPF")
	}
	args := []string{"+time=3", "+tries=1"}
	if server != "" {
		a, err := netip.ParseAddr(server)
		if err != nil || a.Zone() != "" {
			return nil, errors.New("server: an IP address")
		}
		args = append(args, "@"+a.String())
	}
	if a, err := netip.ParseAddr(name); err == nil && a.Zone() == "" { // an address is asked for its name
		args = append(args, "-x", a.String())
		qtype = "PTR"
	} else {
		if name == "" || len(name) > 253 {
			return nil, errors.New("name: a host or domain name, or an IP address")
		}
		for _, l := range strings.Split(name, ".") {
			if !digLabelRe.MatchString(l) {
				return nil, fmt.Errorf("name: %q is not a host or domain name or an IP address", name)
			}
		}
		args = append(args, "--", name, qtype)
	}
	path, err := exec.LookPath("dig")
	if err != nil {
		return nil, errors.New("dig is not installed on this node (install the bind9-dnsutils package; bind-utils on the RHEL family)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), digTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	b, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(b))
	if len(text) > digTextMax {
		text = text[:digTextMax] + "\n…"
	}
	if err != nil && text == "" {
		if ctx.Err() != nil {
			return nil, errors.New("dig did not finish in " + digTimeout.String())
		}
		return nil, fmt.Errorf("dig failed: %v", err)
	}
	out := map[string]any{"name": name, "type": qtype, "text": text}
	if server != "" {
		out["server"] = server
	}
	return out, nil
}
