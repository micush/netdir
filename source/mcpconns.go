package main

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// Who is connected to the MCP listeners right now: the open connections on each gateway address, counted by the address they come
// from (one assistant may hold several connections).  The gateway's tooltip shows the number as "Clients".  The node's own checks
// (an address of the listener itself, or loopback) are not clients.

type mcpConnTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]mcpConnKey
	n     map[mcpConnKey]int
}

type mcpConnKey struct{ local, remote string }

var mcpConns = &mcpConnTracker{conns: map[net.Conn]mcpConnKey{}, n: map[mcpConnKey]int{}}

func bareAddr(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		h = a.String()
	}
	if p, err := netip.ParseAddr(h); err == nil {
		return p.Unmap().String()
	}
	return h
}

// hook is the ConnState of a listener's server.
func (t *mcpConnTracker) hook(c net.Conn, st http.ConnState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch st {
	case http.StateNew:
		if _, ok := t.conns[c]; ok {
			return
		}
		k := mcpConnKey{bareAddr(c.LocalAddr()), bareAddr(c.RemoteAddr())}
		t.conns[c] = k
		t.n[k]++
	case http.StateClosed, http.StateHijacked:
		if k, ok := t.conns[c]; ok {
			delete(t.conns, c)
			if t.n[k]--; t.n[k] <= 0 {
				delete(t.n, k)
			}
		}
	}
}

// clients is how many different addresses have a connection open to any of the gateway addresses.
func (t *mcpConnTracker) clients(addrs ...string) int {
	want := map[string]bool{}
	for _, a := range addrs {
		a = strings.TrimSpace(strings.SplitN(a, "/", 2)[0])
		if a != "" {
			want[a] = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := map[string]bool{}
	for k := range t.n {
		if !want[k.local] || k.remote == k.local {
			continue
		}
		if ip, err := netip.ParseAddr(k.remote); err == nil && ip.IsLoopback() {
			continue
		}
		seen[k.remote] = true
	}
	return len(seen)
}
