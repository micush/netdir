package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The network tools for an assistant: net_ping, net_mtr, net_dig, net_curl, net_whois and net_scan (nmap).  They are the Network tools
// of the GUI (nettool.go, scan.go, whois.go, dig.go, curl.go) run by the netdir process of a node that serves a gateway, so the answer is
// how the network looks from there: "scan 10.1.1.1 from paris" is net_scan with gateway "paris".
//
// A gateway has the tools when the device of platform "tools" (one device, any name; device/tools.go) is among its devices: add it to
// the gateway to enable them there.  The gateway is named by its label or its number; left out, it is the only gateway that has the
// tools, if there is exactly one.  The job runs on a node that serves the gateway (this node when it does, or when there is no cluster).
// Fixed options only and every argument is checked before it reaches a program.  All of them may be used by a read-only key (they change
// nothing); a key limited to some devices is not offered any.
func init() {
	mcpTools = append(mcpTools, mcpNetTools()...)
	for _, n := range []string{"net_ping", "net_mtr", "net_whois", "net_dig", "net_curl", "net_scan"} {
		scopedOffTools[n] = true
	}
}

// toolsGateways are the gateways that have a tools device: number and label.
func (c *mcpCtx) toolsGateways() []CanvasGateway {
	var out []CanvasGateway
	for _, g := range c.w.status.canvasGroups() {
		for _, d := range g.Devices {
			if d.Platform == "tools" {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func gwLabel(g CanvasGateway) string {
	if g.Name != "" {
		return g.Name + " (" + strconv.Itoa(g.GroupID) + ")"
	}
	return strconv.Itoa(g.GroupID)
}

// toolsNode finds where the tools of a gateway run: "" for this node, else the cluster address of a node that serves it.
func (c *mcpCtx) toolsNode(gateway string) (string, error) {
	have := c.toolsGateways()
	if len(have) == 0 {
		return "", errors.New("no gateway has the network tools: add a device of platform tools to a gateway (Devices ▸ Add)")
	}
	var names []string
	for _, g := range have {
		names = append(names, gwLabel(g))
	}
	sort.Strings(names)
	var gw *CanvasGateway
	gateway = strings.TrimSpace(gateway)
	switch {
	case gateway == "" && len(have) == 1:
		gw = &have[0]
	case gateway == "":
		return "", fmt.Errorf("from which gateway? The tools are enabled on: %s", strings.Join(names, ", "))
	default:
		for i, g := range have {
			if strings.EqualFold(g.Name, gateway) || strconv.Itoa(g.GroupID) == gateway {
				gw = &have[i]
			}
		}
		if gw == nil {
			return "", fmt.Errorf("the network tools are not enabled on gateway %q; they are on: %s", gateway, strings.Join(names, ", "))
		}
	}
	peers := c.peers()
	if len(peers) <= 1 { // no cluster: this node is the only one
		return "", nil
	}
	if !gw.Excluded && gw.Status != "idle" && gw.Status != "bad" && len(gw.Members) > 0 { // this node serves it
		for _, m := range gw.Members {
			if m.Local {
				return "", nil
			}
		}
	}
	// another node: the gateway's members are known by the address they use in the gateway protocol
	for _, m := range gw.Members {
		if m.Local {
			continue
		}
		for _, p := range peers {
			if !p.Reachable {
				continue
			}
			for _, ip := range append(append([]string{}, p.GwIPs...), p.IPs...) {
				if ip == m.IP {
					if p.Self {
						return "", nil
					}
					return p.Addr, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no node that serves gateway %s can be reached", gwLabel(*gw))
}

// mcpNetRun starts a job on the node and waits for it: poll is the GET that reads it.
func (c *mcpCtx) mcpNetRun(node, startPath string, body map[string]any, pollPath string, limit time.Duration) (any, error) {
	if _, err := c.call("POST", startPath, body, node); err != nil {
		return nil, err
	}
	end := time.Now().Add(limit + 15*time.Second)
	for {
		select {
		case <-c.ctx.Done():
			return nil, errors.New("cancelled")
		case <-time.After(time.Second):
		}
		b, err := c.call("GET", pollPath, nil, node)
		if err != nil {
			return nil, err
		}
		var j map[string]any
		if json.Unmarshal(b, &j) != nil {
			return nil, errors.New("the node answered something unreadable")
		}
		if st, _ := j["state"].(string); st != "running" || time.Now().After(end) {
			if st == "running" {
				j["note"] = "still running after " + limit.String() + "; ask again to read the result"
			}
			delete(j, "at")
			delete(j, "end")
			return j, nil
		}
	}
}

func mcpNetTools() []mcpTool {
	gw := mcpProp{name: "gateway", typ: "string", desc: "The gateway to run from: its label (paris) or number. The tools run on a node that serves it, and only on a gateway that has the network tools device. Left out: the only gateway that has them."}
	note := " Runs from a node that serves the gateway named in gateway, so it shows the network as seen from there."
	host := mcpProp{name: "host", typ: "string", required: true, desc: "An IP address or a host name."}
	netTool := func(name, title, kind, desc string, limit time.Duration) mcpTool {
		return mcpTool{name: name, title: title, idempotent: true, noNode: true, desc: desc + note, props: []mcpProp{gw, host},
			run: func(c *mcpCtx) (any, error) {
				h := c.str("host")
				if _, _, _, err := netTarget(h); err != nil {
					return nil, err
				}
				n, err := c.toolsNode(c.str("gateway"))
				if err != nil {
					return nil, err
				}
				return c.mcpNetRun(n, "/api/nettool", map[string]any{"kind": kind, "client": h}, "/api/nettool?kind="+kind+"&client="+url.QueryEscape(h), limit)
			}}
	}
	// the tools that answer at once: asked of the node with a GET
	get := func(c *mcpCtx, path string) (any, error) {
		n, err := c.toolsNode(c.str("gateway"))
		if err != nil {
			return nil, err
		}
		b, err := c.call("GET", path, nil, n)
		return asAny(b), err
	}
	return []mcpTool{
		netTool("net_ping", "Ping from a gateway", "ping", "Four pings of a host: replies, loss and times.", pingTimeout),
		netTool("net_mtr", "Traceroute (mtr) from a gateway", "trace", "mtr of a host, ten probes per hop: each hop's address, name, loss and times. This is the traceroute.", traceTimeout),
		{name: "net_whois", title: "Whois from a gateway", idempotent: true, noNode: true,
			desc:  "Whois of a domain or an IP address (registrar, dates, name servers; owner and network for an address)." + note,
			props: []mcpProp{gw, {name: "lookup", typ: "string", required: true, desc: "A domain name or an IP address."}},
			run: func(c *mcpCtx) (any, error) {
				return get(c, "/api/whois?lookup="+url.QueryEscape(strings.TrimSpace(c.str("lookup"))))
			}},
		{name: "net_dig", title: "dig from a gateway", idempotent: true, noNode: true,
			desc: "dig of a name: one query with the usual output (status, answer, authority, query time, the server that answered). For an IP address it asks for the name (dig -x)." + note,
			props: []mcpProp{gw, {name: "name", typ: "string", required: true, desc: "A host or domain name, or an IP address."},
				{name: "type", typ: "string", desc: "The record type: A (default), AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, DS, DNSKEY, NAPTR, TLSA or SPF."},
				{name: "server", typ: "string", desc: "The DNS server to ask, an IP address; the node's resolver when it is left out."}},
			run: func(c *mcpCtx) (any, error) {
				return get(c, "/api/dig?name="+url.QueryEscape(c.str("name"))+"&type="+url.QueryEscape(c.str("type"))+"&server="+url.QueryEscape(c.str("server")))
			}},
		{name: "net_curl", title: "curl from a gateway", idempotent: true, noNode: true,
			desc: "curl of an http or https address: the response headers (HEAD, the default) or the page too (GET; the first 16 KB), and the timings (connect, TLS, first byte, total), the address reached and the status code. Redirects are followed only when follow is true." + note,
			props: []mcpProp{gw, {name: "url", typ: "string", required: true, desc: "An http or https address, e.g. https://example.com/."},
				{name: "method", typ: "string", desc: "HEAD (default) or GET."},
				{name: "follow", typ: "boolean", desc: "Follow up to three redirects."},
				{name: "insecure", typ: "boolean", desc: "Do not check the server's certificate."}},
			run: func(c *mcpCtx) (any, error) {
				if _, err := curlCheckURL(c.str("url")); err != nil {
					return nil, err
				}
				q := "/api/curl?lookup=" + url.QueryEscape(c.str("url")) + "&method=" + url.QueryEscape(c.str("method"))
				if f, _ := c.flag("follow"); f {
					q += "&follow=1"
				}
				if f, _ := c.flag("insecure"); f {
					q += "&insecure=1"
				}
				return get(c, q)
			}},
		{name: "net_scan", title: "nmap scan from a gateway", idempotent: true, noNode: true,
			desc:  "An nmap scan of one host: the 100 commonest TCP ports, service and OS detection, no ping, at most two minutes. It sends probe traffic to the host, so scan only hosts you may." + note,
			props: []mcpProp{gw, {name: "host", typ: "string", required: true, desc: "One IP address (not a name or a range)."}},
			run: func(c *mcpCtx) (any, error) {
				h := strings.TrimSpace(c.str("host"))
				if _, err := scanAddr(h); err != nil {
					return nil, fmt.Errorf("host: %w", err)
				}
				n, err := c.toolsNode(c.str("gateway"))
				if err != nil {
					return nil, err
				}
				return c.mcpNetRun(n, "/api/scan", map[string]any{"client": h}, "/api/scan?client="+url.QueryEscape(h), scanTimeout)
			}},
	}
}
