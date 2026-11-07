package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Who is using the MCP endpoint: a client is a caller (the key's name, or the address when there is no key) that sent any request
// (the handshake and the tool list included) in the last mcpClientWindow.  The endpoint keeps no session and no connection state of
// its own (POST only, an idle connection is closed after a minute), so "recently asked" is what "connected" can mean.  The gateway's
// tooltip shows the number as "Clients", added up over the nodes that serve the gateway.  Callers are kept as short hashes, so the
// nodes can count each caller once without sending names or addresses around.

const mcpClientWindow = 5 * time.Minute

type mcpSeenKey struct{ local, caller string }

type mcpSeenSet struct {
	mu  sync.Mutex
	at  map[mcpSeenKey]time.Time
	now func() time.Time
}

var mcpSeen = &mcpSeenSet{at: map[mcpSeenKey]time.Time{}, now: time.Now}

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

func callerHash(caller string) string {
	s := sha256.Sum256([]byte(caller))
	return hex.EncodeToString(s[:6])
}

// record notes that caller sent a request to the address local (the address the request came in on).
func (t *mcpSeenSet) record(local, caller string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.at[mcpSeenKey{local, callerHash(caller)}] = now
	if len(t.at) > 256 { // forget the old ones now and then
		for k, v := range t.at {
			if now.Sub(v) > mcpClientWindow {
				delete(t.at, k)
			}
		}
	}
}

// callers lists, as hashes, the callers that used any of the addresses in the window.
func (t *mcpSeenSet) callers(addrs ...string) []string {
	want := map[string]bool{}
	for _, a := range addrs {
		a = strings.TrimSpace(strings.SplitN(a, "/", 2)[0])
		if a != "" {
			want[a] = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	set := map[string]bool{}
	for k, v := range t.at {
		if now.Sub(v) > mcpClientWindow {
			delete(t.at, k)
			continue
		}
		if want[k.local] {
			set[k.caller] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
