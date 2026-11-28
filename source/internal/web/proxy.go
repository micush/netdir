package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// Node picker: the GUI on any cluster node can configure and monitor any other
// node.  The browser keeps talking to the node it logged in to; that node
// relays the request over the existing pinned-TLS, HMAC-signed cluster channel
// (POST /cluster/proxy), and the target node runs it through its own web
// handlers as though the user had made it there, attributed "user via node".
// The user is authenticated and authorised (PAM, group netdir) on the node they
// logged in to only; peers trust each other with the cluster secret already.
// Everything but login, logout and the session can be relayed — the Cluster and
// Upgrade pages included, so "Leave cluster", "Promote" or "Update now" act on
// the node picked in the top bar.

type ProxyCtxKey struct{}

// proxyPrefixes are the API areas that can be driven on another node: all of
// them except login, logout and the session, which belong to the node the
// operator logged in to.
var proxyPrefixes = []string{
	"/api/gateways", "/api/neighbors", "/api/devices", "/api/canvas", "/api/assert-agc",
	"/api/config", "/api/versions", "/api/tls", "/api/cluster", "/api/update", "/api/power", "/api/users", "/api/nodepause", "/api/noderename", "/api/bgp", "/api/ospf", "/api/dnsreg", "/api/snmp", "/api/lldp", "/api/log", "/api/mcpusage", "/api/scan", "/api/nettool", "/api/whois", "/api/dig", "/api/curl", "/api/portcheck", "/api/tlscheck", "/api/arp", "/api/wake", "/api/host", "/api/hostlookup", "/api/dnslookup", "/api/schedule", "/api/alerts", "/api/backup", "/api/capture", "/api/vmactest", "/api/tshoot/node",
}

// proxyAllowed reports why method+rawPath may not be relayed, or nil.
func ProxyAllowed(method, rawPath string) error {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut:
	default:
		return fmt.Errorf("method %s cannot be relayed", method)
	}
	if len(rawPath) < 6 || !strings.HasPrefix(rawPath, "/api/") {
		return errors.New("only /api/ paths can be relayed")
	}
	lower := strings.ToLower(rawPath)
	if strings.Contains(rawPath, "..") || strings.Contains(rawPath, "\\") || strings.Contains(lower, "%2e") ||
		strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.ContainsAny(rawPath, "\r\n\x00") {
		return errors.New("path not allowed")
	}
	u, err := url.Parse(rawPath)
	if err != nil || u.Host != "" || u.Scheme != "" || !strings.HasPrefix(u.Path, "/api/") {
		return errors.New("path not allowed")
	}
	for _, p := range proxyPrefixes {
		if u.Path == p || strings.HasPrefix(u.Path, p+"/") {
			return nil
		}
	}
	return errors.New("this part of the GUI always acts on the node you are logged in to")
}

// maxRelayBody keeps a relayed request, base64-encoded in its envelope, inside
// the peer channel's body limit.
const maxRelayBody = 5 << 20

// handleProxy is the browser-facing side: /api/proxy?node=ADDR&path=/api/...
func (w *WebServer) handleProxy(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	node, path := r.URL.Query().Get("node"), r.URL.Query().Get("path")
	if node == "" || path == "" {
		core.JsonError(rw, http.StatusBadRequest, "node and path are required")
		return
	}
	if err := ProxyAllowed(r.Method, path); err != nil {
		core.JsonError(rw, http.StatusForbidden, err.Error())
		return
	}
	if w.Mg.Cluster() == nil {
		core.JsonError(rw, http.StatusBadRequest, "this node is not in a cluster")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, maxRelayBody))
	if err != nil {
		core.JsonError(rw, http.StatusRequestEntityTooLarge, "too large to send through another node (limit 5 MB) — use that node's own GUI for this upload")
		return
	}
	if r.Method != http.MethodGet {
		core.Warnf("web: %q relaying %s %s to %s (from %s)", s.User, r.Method, strings.SplitN(path, "?", 2)[0], node, core.ClientIP(r))
	}
	resp, err := w.Mg.Cluster().Relay(r.Context(), node, core.ProxyReq{
		User: s.User, Method: r.Method, Path: path, CT: r.Header.Get("Content-Type"), Body: body, RO: w.ro(s),
	})
	if err != nil {
		code := http.StatusBadGateway
		var pe *cluster.PeerError
		if errors.As(err, &pe) && pe.Status == http.StatusForbidden {
			code = http.StatusForbidden
		}
		core.JsonError(rw, code, "node "+node+": "+err.Error())
		return
	}
	if resp.CT != "" {
		rw.Header().Set("Content-Type", resp.CT)
	}
	if resp.Disp != "" {
		rw.Header().Set("Content-Disposition", resp.Disp)
	}
	rw.WriteHeader(resp.Status)
	rw.Write(resp.Body)
}
