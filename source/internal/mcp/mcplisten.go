package mcp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"netdir/internal/core"
	"netdir/internal/web"
)

const // IP_FREEBIND and IPV6_FREEBIND are missing from package syscall; the same on every Linux architecture.
soIPFreebind = 15

const soIPv6Freebind = 78

type mcpListener struct {
	srv *http.Server
	ln  net.Listener
}

// mcpListeners keeps one listener per gateway address.
type McpListeners struct {
	w      *web.WebServer
	mu     sync.Mutex
	port   int
	ls     map[netip.Addr]*mcpListener
	failed map[netip.Addr]string // an address that could not be bound, with the reason (logged once)
	cancel context.CancelFunc
}

// newMCPListeners makes the MCP endpoint of a web server: /mcp on its own addresses, and listeners on the gateways' addresses.
func NewMCPListeners(w *web.WebServer) *McpListeners {
	m := &McpListeners{w: w, ls: map[netip.Addr]*mcpListener{}, failed: map[netip.Addr]string{}}
	w.SetMCP(m.handleMCP)
	return m
}

func (m *McpListeners) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	m.Reconcile()
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Reconcile()
			}
		}
	}()
}

func (m *McpListeners) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.closeAllLocked()
	m.mu.Unlock()
	core.McpServing.Store(false)
}

func (m *McpListeners) closeAllLocked() {
	for a, l := range m.ls {
		l.srv.Close()
		delete(m.ls, a)
	}
}

func (m *McpListeners) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", m.handleMCP)
	m.w.RegisterOAuth(mux, true)
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
func (m *McpListeners) Reconcile() {
	dc := m.w.Status.Sup().Config()
	if dc == nil {
		return
	}
	port := dc.Settings.McpPort()
	want := core.GatewayAddrs(dc, true)
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
	if err := m.w.Certs.Ensure(); err != nil {
		if m.failed[netip.Addr{}] != err.Error() {
			core.Errorf("mcp: not serving — TLS certificate: %v", err)
		}
		m.failed[netip.Addr{}] = err.Error()
		core.McpServing.Store(false)
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
			core.Infof("mcp: stopped listening on %s", net.JoinHostPort(a.String(), strconv.Itoa(m.port)))
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
				core.Errorf("mcp: cannot listen on %s: %v", net.JoinHostPort(a.String(), strconv.Itoa(m.port)), err)
			}
			m.failed[a] = err.Error()
			continue
		}
		delete(m.failed, a)
		m.ls[a] = l
		core.Infof("mcp: listening on https://%s/mcp", net.JoinHostPort(a.String(), strconv.Itoa(m.port)))
	}
	core.McpServing.Store(len(m.failed) == 0)
}

func (m *McpListeners) listen(a netip.Addr) (*mcpListener, error) {
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
			GetCertificate: m.w.Certs.GetCertificate,
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
			core.Errorf("mcp: listener on %s stopped: %v", ln.Addr(), err)
			m.mu.Lock()
			if m.ls[a] != nil && m.ls[a].srv == srv {
				delete(m.ls, a) // the next round binds it again
			}
			m.mu.Unlock()
		}
	}()
	return &mcpListener{srv: srv, ln: ln}, nil
}
