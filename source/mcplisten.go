package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The MCP endpoint on the gateways' addresses.  /mcp is not served by the web GUI's listener to a caller who came in on a
// gateway address; it has a listener of its own on every address a gateway carries (the VIPs, the further addresses and the
// anycast addresses), on settings.mcp_port (443 by default), and that listener serves /mcp and nothing else.  The GUI
// keeps its own port and refuses a connection that arrived on a gateway address (noGatewayListener), so the page and the
// API are reached on the node's own address only.
//
// Each listener is bound with IP_FREEBIND, so it exists before the address does (an address that moves to this node with
// the election, or is added by BGP) and keeps working while it comes and goes.  The set follows the configuration every few
// seconds.  A gateway that is paused here, or that this node does not serve, has no listener.
//
// A node is fit to carry the gateways' traffic while these listeners serve (mcpServing, health.go).

const (
	defaultMCPPort = 443
	// IP_FREEBIND and IPV6_FREEBIND are missing from package syscall; the same on every Linux architecture.
	soIPFreebind   = 15
	soIPv6Freebind = 78
)

// mcpPort is the port of the MCP listeners.
func (s Settings) mcpPort() int {
	if s.MCPPort == 0 {
		return defaultMCPPort
	}
	return s.MCPPort
}

// gatewayAddrs is every address the gateways of dc carry, as plain addresses.  serving limits it to the gateways this node
// serves now (not paused here or everywhere, not excluded).
func gatewayAddrs(dc *DaemonConfig, serving bool) []netip.Addr {
	if dc == nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(s string) {
		if s == "" {
			return
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			s = p.Addr().String()
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	self := localNodeID()
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if serving {
			if g.Paused || g.PausedAll {
				continue
			}
			out2 := false
			for _, id := range g.ExcludedNodes {
				if id == self {
					out2 = true
				}
			}
			if out2 {
				continue
			}
		}
		add(g.VIP4)
		add(g.VIP6)
		for _, a := range g.MoreVIP4 {
			add(a)
		}
		for _, a := range g.MoreVIP6 {
			add(a)
		}
		for _, a := range g.ExtraVIPs {
			add(a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// noGatewayListener hands the GUI no connection that came in on a gateway address.
type noGatewayListener struct {
	net.Listener
	blocked func(netip.Addr) bool
}

func (l noGatewayListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
			if a, ok := netip.AddrFromSlice(ta.IP); ok && l.blocked(a.Unmap()) {
				c.Close()
				continue
			}
		}
		return c, nil
	}
}

// isGatewayAddr says whether a is an address of any gateway in the running configuration.
func (w *WebServer) isGatewayAddr(a netip.Addr) bool {
	for _, g := range gatewayAddrs(w.status.sup.config(), false) {
		if g == a {
			return true
		}
	}
	return false
}

type mcpListener struct {
	srv *http.Server
	ln  net.Listener
}

// mcpListeners keeps one listener per gateway address.
type mcpListeners struct {
	w      *WebServer
	mu     sync.Mutex
	port   int
	ls     map[netip.Addr]*mcpListener
	failed map[netip.Addr]string // an address that could not be bound, with the reason (logged once)
	cancel context.CancelFunc
}

func newMCPListeners(w *WebServer) *mcpListeners {
	return &mcpListeners{w: w, ls: map[netip.Addr]*mcpListener{}, failed: map[netip.Addr]string{}}
}

func (m *mcpListeners) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	m.reconcile()
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.reconcile()
			}
		}
	}()
}

func (m *mcpListeners) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.closeAllLocked()
	m.mu.Unlock()
	mcpServing.Store(false)
}

func (m *mcpListeners) closeAllLocked() {
	for a, l := range m.ls {
		l.srv.Close()
		delete(m.ls, a)
	}
}

func (m *mcpListeners) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", m.w.handleMCP)
	return mux
}

func freebindControl(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if network == "tcp6" {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, soIPv6Freebind, 1)
		} else {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, soIPFreebind, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// reconcile makes the listeners match the configuration.
func (m *mcpListeners) reconcile() {
	dc := m.w.status.sup.config()
	if dc == nil {
		return
	}
	port := dc.Settings.mcpPort()
	want := gatewayAddrs(dc, true)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel == nil {
		return // stopped
	}
	if port != m.port {
		m.closeAllLocked()
		m.failed = map[netip.Addr]string{}
		m.port = port
	}
	if err := m.w.certs.Ensure(); err != nil {
		if m.failed[netip.Addr{}] != err.Error() {
			errorf("mcp: not serving — TLS certificate: %v", err)
		}
		m.failed[netip.Addr{}] = err.Error()
		mcpServing.Store(false)
		return
	}
	delete(m.failed, netip.Addr{})
	wanted := map[netip.Addr]bool{}
	for _, a := range want {
		wanted[a] = true
	}
	for a, l := range m.ls {
		if !wanted[a] {
			l.srv.Close()
			delete(m.ls, a)
			infof("mcp: stopped listening on %s", net.JoinHostPort(a.String(), strconv.Itoa(m.port)))
		}
	}
	for a := range m.failed {
		if a.IsValid() && !wanted[a] {
			delete(m.failed, a)
		}
	}
	for _, a := range want {
		if m.ls[a] != nil {
			continue
		}
		l, err := m.listen(a)
		if err != nil {
			if m.failed[a] != err.Error() {
				errorf("mcp: cannot listen on %s: %v", net.JoinHostPort(a.String(), strconv.Itoa(m.port)), err)
			}
			m.failed[a] = err.Error()
			continue
		}
		delete(m.failed, a)
		m.ls[a] = l
		infof("mcp: listening on https://%s/mcp", net.JoinHostPort(a.String(), strconv.Itoa(m.port)))
	}
	mcpServing.Store(len(m.failed) == 0)
}

func (m *mcpListeners) listen(a netip.Addr) (*mcpListener, error) {
	network := "tcp4"
	if a.Is6() {
		network = "tcp6"
	}
	lc := net.ListenConfig{Control: freebindControl}
	ln, err := lc.Listen(context.Background(), network, net.JoinHostPort(a.String(), strconv.Itoa(m.port)))
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler: m.handler(),
		TLSConfig: &tls.Config{
			GetCertificate: m.w.certs.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorf("mcp: listener on %s stopped: %v", ln.Addr(), err)
			m.mu.Lock()
			if m.ls[a] != nil && m.ls[a].srv == srv {
				delete(m.ls, a) // the next round binds it again
			}
			m.mu.Unlock()
		}
	}()
	return &mcpListener{srv: srv, ln: ln}, nil
}
