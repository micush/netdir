package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
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
		if out, e := digGo(name, qtype, server); e == nil || !errors.Is(e, errDigNoFallback) {
			return out, e
		}
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

var errDigNoFallback = errors.New("no fallback for this type")

// digGo answers the common queries (an address's name, A, AAAA, MX, NS, TXT, CNAME, SRV) with Go's resolver when dig is not installed,
// so a reverse lookup works on any node.  The server, when given, is asked on port 53.
func digGo(name, qtype, server string) (map[string]any, error) {
	r := net.DefaultResolver
	if server != "" {
		a, _ := netip.ParseAddr(server)
		addr := net.JoinHostPort(a.String(), "53")
		r = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), digTimeout)
	defer cancel()
	var lines []string
	var err error
	if a, e := netip.ParseAddr(name); e == nil && a.Zone() == "" {
		qtype = "PTR"
		var names []string
		names, err = r.LookupAddr(ctx, a.String())
		for _, n := range names {
			lines = append(lines, a.String()+"\tPTR\t"+n)
		}
	} else {
		switch qtype {
		case "A", "AAAA":
			var ips []netip.Addr
			ips, err = r.LookupNetIP(ctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[qtype], name)
			for _, ip := range ips {
				lines = append(lines, name+"\t"+qtype+"\t"+ip.String())
			}
		case "MX":
			var mx []*net.MX
			mx, err = r.LookupMX(ctx, name)
			for _, m := range mx {
				lines = append(lines, fmt.Sprintf("%s\tMX\t%d %s", name, m.Pref, m.Host))
			}
		case "NS":
			var ns []*net.NS
			ns, err = r.LookupNS(ctx, name)
			for _, n := range ns {
				lines = append(lines, name+"\tNS\t"+n.Host)
			}
		case "TXT":
			var t []string
			t, err = r.LookupTXT(ctx, name)
			for _, x := range t {
				lines = append(lines, name+"\tTXT\t"+strconv.Quote(x))
			}
		case "CNAME":
			var c string
			c, err = r.LookupCNAME(ctx, name)
			if err == nil && c != "" {
				lines = append(lines, name+"\tCNAME\t"+c)
			}
		case "PTR":
			var names []string
			names, err = r.LookupAddr(ctx, name)
			for _, n := range names {
				lines = append(lines, name+"\tPTR\t"+n)
			}
		default:
			return nil, errDigNoFallback
		}
	}
	text := strings.Join(lines, "\n")
	if err != nil && text == "" {
		return nil, fmt.Errorf("%s %s: %v", name, qtype, err)
	}
	if len(text) > digTextMax {
		text = text[:digTextMax] + "\n…"
	}
	out := map[string]any{"name": name, "type": qtype, "text": text, "note": "dig is not installed on this node: answered by its resolver, answers only"}
	if server != "" {
		out["server"] = server
	}
	return out, nil
}
