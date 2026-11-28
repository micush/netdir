package cluster

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netdir/internal/core"
)

// The cluster network layer.  Peers talk to each other on a dedicated TLS
// listener (default :22162).  Each node has its own long-lived identity
// certificate whose SHA-256 fingerprint the other members pin (learned from
// the join code and then gossiped), so the channel does not depend on the GUI
// certificate, which admins may replace at will.  On top of that every request
// carries an HMAC over the cluster secret (handed out at join), a timestamp
// and a nonce.  Nothing here uses the PAM/GUI login.

const (
	JoinCodePrefix  = "netdir-join-v1:"
	clockSkew       = 90 * time.Second
	nonceTTL        = 5 * time.Minute
	nonceSweepEvery = time.Second
	maxNonces       = 50000 // sweep at once above this many remembered nonces
	MaxPeerBody     = 8 << 20
	peerTimeout     = 6 * time.Second
	sourceTimeout   = 60 * time.Second
)

// PeerStatusMsg is what a node tells others about itself.
type PeerStatusMsg struct {
	Peer          core.ClusterPeer   `json:"peer"`
	Epoch         uint64             `json:"epoch"`
	Role          core.Role          `json:"role"`
	PrimaryAddr   string             `json:"primary_addr"`
	Peers         []core.ClusterPeer `json:"peers"`
	Removed       []string           `json:"removed"`
	Version       string             `json:"version"`
	Hostname      string             `json:"hostname,omitempty"`
	SourceVersion string             `json:"source_version"`
	Updating      bool               `json:"updating"`
	UpdateFailed  string             `json:"update_failed,omitempty"`
	// UptimeSec is how long this process has been running (the canary soak reads it); absent on older nodes
	UptimeSec int64 `json:"uptime_sec,omitempty"`
	// AnycastUp lists the anycast addresses this node announces now, with how long (see AnycastUp); absent on older nodes
	AnycastUp []AnycastUp       `json:"anycast_up,omitempty"`
	SharedRev uint64            `json:"shared_rev"`
	Intent    core.UpdateIntent `json:"intent"`
	// PrimaryDownSec is how long this node has gone without reaching the primary (its vote for automatic failover); 0 when it
	// can reach it, or on the primary itself.  Absent on older nodes.
	PrimaryDownSec int64 `json:"primary_down_sec,omitempty"`
	// Which gateways this node is serving; GwKnown is false for nodes that
	// predate the field (their health is then assumed).
	GwKnown  bool           `json:"gw_known,omitempty"`
	Gateways []core.GwState `json:"gateways,omitempty"`
	// NodePaused: the whole node is paused (Operate ▸ Node); shown on the Topology drawing.
	NodePaused bool `json:"node_paused,omitempty"`
	// Host is this node's CPU, memory and disk use, for the Topology drawing (absent on older nodes).
	Host *core.HostLoad `json:"host,omitempty"`
	// Addrs are this node's Ethernet interfaces with their IPv4 and IPv6 GUA addresses, for the node's tooltip on the
	// Topology drawing (absent on older nodes).
	Addrs []core.NodeIface `json:"addrs,omitempty"`
	// GwIPs are the addresses this node uses in the gateway protocol (one per address family of each group): what the
	// Gateways page shows as a member's IP, so another node can say which node that is.
	GwIPs []string `json:"gw_ips,omitempty"`
}

type clusterStateMsg struct {
	Epoch       uint64             `json:"epoch"`
	PrimaryAddr string             `json:"primary_addr"`
	Peers       []core.ClusterPeer `json:"peers"`
	SharedRev   uint64             `json:"shared_rev"`
	Shared      core.SharedConfig  `json:"shared"`
	Seeds       []GroupSeed        `json:"seeds"`
	Cert        *core.AdminCert    `json:"cert,omitempty"`
	Intent      core.UpdateIntent  `json:"intent"`
}

type joinRequest struct {
	Token        string           `json:"token"`
	Peer         core.ClusterPeer `json:"peer"`
	ExplicitSelf bool             `json:"explicit_self"`
	MTLS         bool             `json:"mtls,omitempty"` // the joiner presents its identity certificate on calls
}

type joinResponse struct {
	Secret      string             `json:"secret"`
	Epoch       uint64             `json:"epoch"`
	PrimaryAddr string             `json:"primary_addr"`
	Server      core.ClusterPeer   `json:"server"`
	Peers       []core.ClusterPeer `json:"peers"`
}

type JoinCode struct {
	Token string   `json:"t"`
	Fp    string   `json:"f"`
	Addrs []string `json:"a"`
}

type announceMsg struct {
	Epoch       uint64 `json:"epoch"`
	PrimaryAddr string `json:"primary_addr"`
	// Home, set when the role is handed over for an update, is the node the new primary gives it back to once the update is over.
	Home string `json:"home,omitempty"`
}

type adminMsg struct {
	Op      string          `json:"op"`
	By      string          `json:"by"`
	Payload json.RawMessage `json:"payload"`
}

// peerInfo is what we last learned about a peer.
type peerInfo struct {
	Reachable bool
	Msg       PeerStatusMsg
	LastSeen  time.Time
	Err       string
}

// Cluster runs the listener, the sync loop and the client side.
type Cluster struct {
	upMu  sync.Mutex
	gwUp  map[int]time.Time    // since when somebody in the cluster has served each gateway without a break (see sampleGwUp)
	anyUp map[string]time.Time // the same for each anycast address (see sampleAnycastUp)

	routes map[string]PeerHandler // what the layers above answer on the cluster port (pattern -> handler; SetRoutes)

	Mg   ClusterHost  `json:"-"`
	Node *ClusterNode `json:"-"`

	strain strainLog // host-load over/under log lines (strainlog.go)

	Mu         sync.Mutex `json:"-"`
	cfg        core.ClusterConfig
	listen     string
	srv        *http.Server
	cancelSrv  context.CancelFunc
	Info       map[string]*peerInfo `json:"-"`
	nonces     map[string]time.Time
	nonceSweep time.Time // when the nonces were last swept for expired ones
	joinFails  map[string]*core.FailRec
	goodAddr   map[string]string // peer's main address -> the address that last worked
	lastSync   time.Time
	lastErr    string
	conflict   string
	// primaryDownSince is when this replica last began failing to reach the primary without a break (zero: it can)
	primaryDownSince time.Time
	ReturnSince      time.Time `json:"-"` // since when the update has looked over, so the primary may go back home (handover.go)
	kick             chan struct{}
	syncMu           sync.Mutex
}

func clusterSelfAddr(cfg core.ClusterConfig) string {
	if cfg.Self != "" {
		return cfg.Self
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		port = strconv.Itoa(core.DefaultClusterPort)
	}
	return net.JoinHostPort(host, port)
}

// ClusterHost is what the cluster needs from the management layer of its node (Mgmt): the configuration, the gateways and the
// updates of this node.
type ClusterHost interface {
	LiveConfig() (*core.DaemonConfig, []byte, error)
	ApplyClusterShared(sh core.SharedConfig, seeds []GroupSeed, rev uint64, from string)
	ExcludeNewNode(id string)
	ExecAdminOp(op, by string, payload json.RawMessage) (json.RawMessage, error)
	LocalGateways() []core.GwState
	LocalGwIPs() []string
	KnowsGateways() bool // whether this node runs gateways at all (LocalGateways says nothing otherwise)
	NodePaused() bool
	PowerHandoverTick()
	UpdateTick(ctx context.Context)
	UsersExport() []core.UsersMsg
	UsersPeer(msg core.UsersMsg, by string) error
	UsersPull(ctx context.Context, from core.ClusterPeer)
	Updater() *core.Updater
	Certs() *core.CertManager
	Versions() *VersionStore
	StateDir() string
	ConfPath() string
}

func NewCluster(mg ClusterHost, cfg core.ClusterConfig) (*Cluster, error) {
	node, err := LoadOrCreateClusterNode(mg.StateDir()+"/cluster", clusterSelfAddr(cfg))
	if err != nil {
		return nil, err
	}
	c := &Cluster{
		Mg: mg, Node: node, cfg: cfg, Info: map[string]*peerInfo{}, nonces: map[string]time.Time{},
		joinFails: map[string]*core.FailRec{}, goodAddr: map[string]string{}, kick: make(chan struct{}, 1),
	}
	c.refreshAlts()
	core.SetLocalNodeID(node.Self().NodeID)
	return c, nil
}

func (c *Cluster) Enabled() bool {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.cfg.Enabled
}

func (c *Cluster) Snapshot() core.ClusterSnapshot { return c.Node.Snapshot() }

func (c *Cluster) SelfAddrForEvents() string { return c.Node.Self().Addr }

// OnConfig applies a (re)loaded config: self address, listener, shared revision.
func (c *Cluster) OnConfig(dc *core.DaemonConfig) {
	c.Mu.Lock()
	c.cfg = dc.Cluster
	c.Mu.Unlock()
	c.Node.SetSelf(clusterSelfAddr(dc.Cluster))
	c.refreshAlts()
	if snap := c.Node.Snapshot(); snap.Role == core.RolePrimary || !dc.Cluster.Enabled {
		if c.Node.BumpShared(core.SharedOf(dc).Hash()) {
			core.Infof("cluster: shared settings changed (revision %d)", c.Node.Snapshot().SharedRev)
		}
	}
	go c.applyListener()
}

// ── listener ─────────────────────────────────────────────────────────────────

func (c *Cluster) applyListener() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if !c.cfg.Enabled || c.cfg.Listen != c.listen {
		if c.srv != nil {
			c.cancelSrv()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			c.srv.Shutdown(ctx)
			cancel()
			c.srv = nil
			c.listen = ""
			core.Infof("cluster: listener stopped")
		}
	}
	if !c.cfg.Enabled || c.srv != nil {
		return
	}
	ln, err := net.Listen("tcp", c.cfg.Listen)
	if err != nil {
		core.Errorf("cluster: cannot listen on %s: %v", c.cfg.Listen, err)
		return
	}
	cert, _ := c.Node.Identity()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /cluster/join", c.handleJoin)
	mux.HandleFunc("GET /cluster/status", c.peerAuth(c.handleStatus))
	mux.HandleFunc("GET /cluster/state", c.peerAuth(c.handleState))
	mux.HandleFunc("POST /cluster/announce", c.peerAuth(c.handleAnnounce))
	mux.HandleFunc("POST /cluster/peers/add", c.peerAuth(c.handlePeerAdd))
	mux.HandleFunc("POST /cluster/peers/remove", c.peerAuth(c.handlePeerRemove))
	mux.HandleFunc("POST /cluster/peers/unremove", c.peerAuth(c.handlePeerUnremove))
	mux.HandleFunc("POST /cluster/admin", c.peerAuth(c.handleAdmin))
	mux.HandleFunc("GET /cluster/source", c.peerAuth(c.handleSource))
	mux.HandleFunc("POST /cluster/users", c.peerAuth(c.handleUsers))
	for pattern, h := range c.routes {
		mux.HandleFunc(pattern, c.peerAuth(h))
	}
	srv := &http.Server{
		ErrorLog: log.New(io.Discard, "", 0), Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		// the client certificate is asked for but not chain-checked (there is no CA): peerAuth compares its
		// fingerprint with the identity the signed request claims
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert},
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.srv, c.cancelSrv, c.listen = srv, cancel, c.cfg.Listen
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			core.Errorf("cluster: listener stopped: %v", err)
		}
	}()
	_ = ctx
	core.Infof("cluster: listening on %s as %s (node %s, %s, epoch %d, identity sha256 %s)",
		c.cfg.Listen, c.Node.Self().Addr, c.Node.Snapshot().NodeID, c.Node.Snapshot().Role,
		c.Node.Snapshot().Epoch, core.ShortFP(c.Node.Fingerprint()))
}

func (c *Cluster) Stop() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.srv != nil {
		c.cancelSrv()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c.srv.Shutdown(ctx)
		cancel()
		c.srv = nil
		c.listen = ""
	}
}

// ── request authentication ───────────────────────────────────────────────────

func SignMessage(secret []byte, peerHdr, ts, nonce, method, path string, body []byte) string {
	bh := sha256.Sum256(body)
	return SignMessageHash(secret, peerHdr, ts, nonce, method, path, hex.EncodeToString(bh[:]))
}

// signMessageHash is signMessage with the hex SHA-256 of the body already known.  A request carries that hash in
// X-Netdir-Body, so the signature can be checked before the body is read; the body is then held to the hash.
func SignMessageHash(secret []byte, peerHdr, ts, nonce, method, path, bodyHash string) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "netdir-cluster-v1\n%s\n%s\n%s\n%s\n%s\n%s", ts, nonce, method, path, peerHdr, bodyHash)
	return hex.EncodeToString(mac.Sum(nil))
}

// legacyPreAuthBody is how much of a request body is read from a caller that cannot be told apart from a stranger
// before its signature is checked: a peer older than v194 does not send X-Netdir-Body, so its signature covers a
// body that has to be read first.  A member known by its certificate may send up to maxPeerBody.
const LegacyPreAuthBody = 64 << 10

func isHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (c *Cluster) peerAuth(h func(http.ResponseWriter, *http.Request, core.ClusterPeer, []byte)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ts, nonce, sig, peerHdr := r.Header.Get("X-Netdir-Ts"), r.Header.Get("X-Netdir-Nonce"), r.Header.Get("X-Netdir-Sig"), r.Header.Get("X-Netdir-Peer")
		t, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || nonce == "" || len(nonce) > 64 || sig == "" {
			core.JsonError(rw, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if d := time.Since(time.Unix(t, 0)); d > clockSkew || d < -clockSkew {
			core.JsonError(rw, http.StatusUnauthorized, "clock skew too large (check NTP on both nodes)")
			return
		}
		// Nothing is read from a stranger before the signature is checked.  A request carries the hash of its
		// body, which the signature covers: the signature is checked first, then the body is read and held to
		// the hash.  A request from a peer that predates that header can only be checked after its body is
		// read, so that is limited to a small size unless the TLS client certificate is a known member's.
		var body []byte
		if bodyHash := r.Header.Get("X-Netdir-Body"); isHexHash(bodyHash) {
			want := SignMessageHash(c.Node.Secret(), peerHdr, ts, nonce, r.Method, r.URL.Path, bodyHash)
			if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
				core.JsonError(rw, http.StatusUnauthorized, "unauthenticated")
				return
			}
			if r.ContentLength > MaxPeerBody {
				core.JsonError(rw, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			body, err = io.ReadAll(http.MaxBytesReader(rw, r.Body, MaxPeerBody))
			if err != nil {
				core.JsonError(rw, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			if sum := sha256.Sum256(body); subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(bodyHash)) != 1 {
				core.JsonError(rw, http.StatusUnauthorized, "the body is not the one that was signed")
				return
			}
		} else {
			limit := int64(LegacyPreAuthBody)
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if _, known := c.Node.PeerByFp(certFingerprint(r.TLS.PeerCertificates[0])); known {
					limit = MaxPeerBody
				}
			}
			if r.ContentLength > limit {
				core.JsonError(rw, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			body, err = io.ReadAll(http.MaxBytesReader(rw, r.Body, limit))
			if err != nil {
				core.JsonError(rw, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			want := SignMessage(c.Node.Secret(), peerHdr, ts, nonce, r.Method, r.URL.Path, body)
			if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
				core.JsonError(rw, http.StatusUnauthorized, "unauthenticated")
				return
			}
		}
		c.Mu.Lock()
		now := time.Now()
		// Expired nonces are swept at most once a second (or at once when the table is large), not on every
		// request: the sweep visits every entry, and every peer call used to pay for it.  An entry that has
		// expired but not yet been swept is no replay: the timestamp check already refuses anything that old.
		if now.After(c.nonceSweep) || len(c.nonces) > maxNonces {
			for k, exp := range c.nonces {
				if now.After(exp) {
					delete(c.nonces, k)
				}
			}
			c.nonceSweep = now.Add(nonceSweepEvery)
		}
		if exp, dup := c.nonces[sig]; dup && now.Before(exp) {
			c.Mu.Unlock()
			core.JsonError(rw, http.StatusUnauthorized, "replayed request")
			return
		}
		c.nonces[sig] = now.Add(nonceTTL)
		c.Mu.Unlock()

		var caller core.ClusterPeer
		if raw, err := base64.StdEncoding.DecodeString(peerHdr); err == nil {
			json.Unmarshal(raw, &caller)
		}
		// The signature proves the caller holds the cluster secret, which every member (and every member that was
		// ever removed) has.  The identity certificate it presented on the TLS connection proves which member it
		// is: it must be the one the request claims, and that member must be on the list and not removed.
		certFp := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certFp = certFingerprint(r.TLS.PeerCertificates[0])
			if caller.Fp != certFp {
				core.JsonError(rw, http.StatusUnauthorized, "the client certificate is not the identity this request claims")
				return
			}
		}
		if c.Node.IsRemovedFp(caller.Fp) || certFp != "" && c.Node.IsRemovedFp(certFp) {
			core.WriteJSON(rw, http.StatusForbidden, map[string]any{"ok": false, "error": "removed from the cluster", "removed": true})
			return
		}
		strict := c.Node.Strict()
		switch {
		case certFp == "" && (strict || c.Node.IsMTLS(caller.Fp)):
			core.JsonError(rw, http.StatusUnauthorized, "a client certificate is required")
			return
		case certFp != "":
			if known, ok := c.Node.PeerByFp(certFp); ok && known.NodeID == caller.NodeID {
				c.Node.NoteMTLS(certFp)
			} else if strict {
				core.JsonError(rw, http.StatusForbidden, "not a member of this cluster")
				return
			}
		}
		if caller.Addr != "" {
			if core.ContainsStr(c.Node.Snapshot().Removed, caller.Addr) {
				core.WriteJSON(rw, http.StatusForbidden, map[string]any{"ok": false, "error": "removed from the cluster", "removed": true})
				return
			}
			if validPeer(caller) && c.Node.AddPeer(caller) {
				core.Infof("cluster: learned peer %s (node %s)", caller.Addr, caller.NodeID)
				if certFp != "" {
					c.Node.NoteMTLS(certFp)
				}
			}
		}
		h(rw, r, caller, body)
	}
}

func validPeer(p core.ClusterPeer) bool {
	if p.Addr == "" || len(p.Fp) != 64 || p.NodeID == "" || len(p.NodeID) > 64 {
		return false
	}
	if _, err := hex.DecodeString(p.Fp); err != nil {
		return false
	}
	if len(p.Alts) > 16 {
		return false
	}
	for _, a := range p.Alts {
		if !validHostPort(a) {
			return false
		}
	}
	return validHostPort(p.Addr)
}

// validHostPort accepts only "host:port" where the host is an IP address or a
// plain host name and the port is 1-65535.  Peer addresses end up in a URL, so
// anything that could change where the request goes ("@", "/", "?", "#",
// spaces, a zone) is refused.
func validHostPort(a string) bool {
	if a == "" || len(a) > 255 {
		return false
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil || host == "" {
		return false
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return !strings.Contains(host, "%")
	}
	if len(host) > 253 {
		return false
	}
	for _, c := range host {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// ── client ───────────────────────────────────────────────────────────────────

type PeerError struct {
	Status  int
	Msg     string
	Removed bool
}

func (e *PeerError) Error() string { return e.Msg }

// call performs an authenticated request to peer.
func (c *Cluster) Call(ctx context.Context, peer core.ClusterPeer, method, path string, in, out any, timeout time.Duration) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	return c.callRaw(ctx, peer, method, path, body, func(rd io.Reader) error {
		if out == nil {
			return nil
		}
		return json.NewDecoder(rd).Decode(out)
	}, timeout, nil)
}

// callRaw talks to a peer, trying every address it is known by (the preferred
// one first: the last that worked, then its main address, then its alternatives
// — host name, IPv4, IPv6). Only connection-level failures move on to the next
// address; an answer from the peer, even a refusal, is final.
func (c *Cluster) callRaw(ctx context.Context, peer core.ClusterPeer, method, path string, body []byte, onBody func(io.Reader) error, timeout time.Duration, hdr http.Header) error {
	addrs := c.AddrsFor(peer)
	var errs []string
	for _, a := range addrs {
		// A dead address is given up on when the connection cannot be made (peerConnectTimeout, in the dial), not by cutting
		// the whole call short: a call that takes a while (a troubleshooting bundle, an upload) must not be abandoned at the
		// first address and started again on the next.
		err := c.callAddr(ctx, a, peer, method, path, body, onBody, timeout, hdr)
		if err == nil {
			c.noteGoodAddr(peer, a)
			return nil
		}
		var pe *PeerError
		if errors.As(err, &pe) || ctx.Err() != nil || len(addrs) == 1 {
			return err
		}
		errs = append(errs, a+": "+err.Error())
	}
	return errors.New(strings.Join(errs, "; "))
}

func (c *Cluster) AddrsFor(peer core.ClusterPeer) []string {
	all := append([]string{peer.Addr}, peer.Alts...)
	c.Mu.Lock()
	good := c.goodAddr[peer.Addr]
	c.Mu.Unlock()
	// Addresses first, names last: a name needs DNS, which may be this very cluster's gateway (paused or
	// restarting), while an address needs nothing. Within each group the last one that worked comes first.
	var ips, names []string
	seen := map[string]bool{}
	for _, a := range append([]string{good}, all...) {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		if h, _, err := net.SplitHostPort(a); err == nil && net.ParseIP(h) != nil {
			ips = append(ips, a)
		} else {
			names = append(names, a)
		}
	}
	return append(ips, names...)
}

func (c *Cluster) noteGoodAddr(peer core.ClusterPeer, addr string) {
	c.Mu.Lock()
	c.goodAddr[peer.Addr] = addr
	c.Mu.Unlock()
}

func (c *Cluster) callAddr(ctx context.Context, addr string, peer core.ClusterPeer, method, path string, body []byte, onBody func(io.Reader) error, timeout time.Duration, hdr http.Header) error {
	if !validHostPort(addr) || !strings.HasPrefix(path, "/") {
		return errors.New("refusing to call " + strconv.Quote(addr) + path)
	}
	self := c.Node.Self()
	pj, _ := json.Marshal(self)
	peerHdr := base64.StdEncoding.EncodeToString(pj)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := core.RandHex(12)
	req, err := http.NewRequestWithContext(ctx, method, PeerURL(path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Netdir-Peer", peerHdr)
	req.Header.Set("X-Netdir-Ts", ts)
	req.Header.Set("X-Netdir-Nonce", nonce)
	bsum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(bsum[:])
	req.Header.Set("X-Netdir-Body", bodyHash)
	req.Header.Set("X-Netdir-Sig", SignMessageHash(c.Node.Secret(), peerHdr, ts, nonce, method, path, bodyHash))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	me, _ := c.Node.Identity()
	resp, err := PinnedClientAs(addr, peer.Fp, timeout, &me).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if hdr != nil {
		for k, v := range resp.Header {
			hdr[k] = v
		}
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error   string `json:"error"`
			Removed bool   `json:"removed"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &PeerError{Status: resp.StatusCode, Msg: e.Error, Removed: e.Removed}
	}
	return onBody(io.LimitReader(resp.Body, core.MaxUploadBytes+1<<20))
}

// ── server handlers ──────────────────────────────────────────────────────────

func (c *Cluster) statusMsg() PeerStatusMsg {
	snap := c.Node.Snapshot()
	host, _ := os.Hostname()
	return PeerStatusMsg{
		Hostname: host,
		Peer:     c.Node.Self(), Epoch: snap.Epoch, Role: snap.Role, PrimaryAddr: snap.PrimaryAddr,
		Peers: append(c.knownPeers(snap), c.Node.Self()), Removed: snap.Removed,
		Version: core.Version(), SourceVersion: c.Mg.Updater().OfferedSource(), Updating: c.Mg.Updater().Busy(),
		UpdateFailed: c.Mg.Updater().FailedFor(), UptimeSec: int64(time.Since(processStart) / time.Second), AnycastUp: c.AnycastReport(), SharedRev: snap.SharedRev, Intent: c.Mg.Updater().Intent(), PrimaryDownSec: c.primaryDownSec(),
		GwKnown: c.Mg.KnowsGateways(), Gateways: c.Mg.LocalGateways(), NodePaused: c.Mg.NodePaused(), Host: hostLoadPtr(), Addrs: core.EthernetAddrs(), GwIPs: c.Mg.LocalGwIPs(),
	}
}

func (c *Cluster) knownPeers(snap core.ClusterSnapshot) []core.ClusterPeer { return snap.Peers }

func (c *Cluster) handleStatus(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, _ []byte) {
	core.WriteJSON(rw, http.StatusOK, c.statusMsg())
}

func (c *Cluster) handleState(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, _ []byte) {
	snap := c.Node.Snapshot()
	if snap.Role != core.RolePrimary {
		core.JsonError(rw, http.StatusConflict, "this node is not the primary")
		return
	}
	dc, _, err := c.Mg.LiveConfig()
	if err != nil {
		core.JsonError(rw, http.StatusInternalServerError, err.Error())
		return
	}
	msg := clusterStateMsg{
		Epoch: snap.Epoch, PrimaryAddr: snap.PrimaryAddr, Peers: append(snap.Peers, c.Node.Self()),
		SharedRev: snap.SharedRev, Shared: core.SharedOf(dc), Seeds: SeedsOf(dc), Intent: c.Mg.Updater().Intent(),
	}
	if dc.Cluster.ShareCert {
		if cp, kp, meta, ok := c.Mg.Certs().Managed(); ok && meta.Source != "" {
			msg.Cert = &core.AdminCert{CertPEM: string(cp), KeyPEM: string(kp)}
		}
	}
	core.WriteJSON(rw, http.StatusOK, msg)
}

func (c *Cluster) handleAnnounce(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var m announceMsg
	if json.Unmarshal(body, &m) != nil || m.PrimaryAddr == "" {
		core.JsonError(rw, http.StatusBadRequest, "bad announce")
		return
	}
	before := c.Node.Snapshot()
	snap, err := c.Node.AdoptAnnounce(m.Epoch, m.PrimaryAddr)
	switch {
	case errors.Is(err, ErrStaleEpoch):
		core.JsonError(rw, http.StatusConflict, fmt.Sprintf("stale epoch %d (this node is at %d)", m.Epoch, snap.Epoch))
		return
	case errors.Is(err, ErrEpochConflict):
		c.setConflict(fmt.Sprintf("%s claimed to be primary at epoch %d, but this node already follows %s at that epoch", m.PrimaryAddr, m.Epoch, snap.PrimaryAddr))
		core.JsonError(rw, http.StatusConflict, err.Error())
		return
	}
	if snap.Epoch != before.Epoch {
		core.Infof("cluster: epoch %d — %s is primary (this node is now %s)", snap.Epoch, snap.PrimaryAddr, snap.Role)
		if snap.Role == core.RolePrimary {
			c.SetPrimaryHome(m.Home) // a handover for an update says where the role goes back to; any other change of primary says nothing
		} else {
			c.SetPrimaryHome("")
		}
		c.syncSoon()
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "epoch": snap.Epoch, "role": snap.Role})
}

func (c *Cluster) setConflict(s string) {
	c.Mu.Lock()
	c.conflict = s
	c.Mu.Unlock()
	core.Warnf("cluster: %s", s)
}

// handlePeerAdd tells this node about a member that just joined through another node, so it does not have to wait
// for the next sync to serve it (a strict cluster refuses callers it has not been told about).
func (c *Cluster) handlePeerAdd(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var m struct {
		Peer core.ClusterPeer `json:"peer"`
		MTLS bool             `json:"mtls,omitempty"`
	}
	if json.Unmarshal(body, &m) != nil || !validPeer(m.Peer) {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	newcomer := m.Peer.NodeID != "" && !c.knowsNode(m.Peer.NodeID)
	if c.Node.AddPeer(m.Peer) {
		core.Infof("cluster: %s (node %s) joined through %s", m.Peer.Addr, m.Peer.NodeID, caller.Addr)
	}
	if newcomer && c.Mg != nil && c.Node.Snapshot().Role == core.RolePrimary {
		// the primary leaves a node that joined through another member out of the gateways too (the member that took the
		// join asks for the same; the second is a no-op)
		go c.Mg.ExcludeNewNode(m.Peer.NodeID)
	}
	if m.MTLS {
		c.Node.NoteMTLS(m.Peer.Fp)
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (c *Cluster) handlePeerRemove(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var m struct {
		Addr string `json:"addr"`
	}
	if json.Unmarshal(body, &m) != nil || m.Addr == "" {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	if m.Addr == c.Node.Self().Addr {
		c.LeaveLocal("removed by an administrator of " + caller.Addr)
	} else {
		c.Node.RemovePeer(m.Addr)
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (c *Cluster) handlePeerUnremove(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var m struct {
		Addr string `json:"addr"`
	}
	if json.Unmarshal(body, &m) != nil || m.Addr == "" {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	c.Node.UnremovePeer(m.Addr)
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (c *Cluster) handleAdmin(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var m adminMsg
	if json.Unmarshal(body, &m) != nil || m.Op == "" {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	if c.Node.Snapshot().Role != core.RolePrimary {
		core.JsonError(rw, http.StatusConflict, "this node is not the primary")
		return
	}
	res, err := c.Mg.ExecAdminOp(m.Op, m.By+" (via "+caller.Addr+")", m.Payload)
	if err != nil {
		core.JsonError(rw, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if res == nil {
		res = json.RawMessage(`{}`)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(res)
}

func (c *Cluster) handleSource(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, _ []byte) {
	if c.Mg.Updater().OfferedSource() == "" {
		core.JsonError(rw, http.StatusNotFound, "no source tree is offered by this node")
		return
	}
	data, ver, err := c.Mg.Updater().SourceTarball()
	if err != nil {
		core.JsonError(rw, http.StatusNotFound, err.Error())
		return
	}
	rw.Header().Set("Content-Type", "application/gzip")
	rw.Header().Set("X-Netdir-Version", ver)
	rw.Write(data)
}

func (c *Cluster) handleJoin(rw http.ResponseWriter, r *http.Request) {
	ip := core.ClientIP(r)
	if _, locked := c.joinThrottled(ip); locked {
		core.JsonError(rw, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	var req joinRequest
	if !core.ReadJSON(rw, r, 16<<10, &req) {
		return
	}
	if req.Token == "" || !c.Node.RedeemToken(req.Token) {
		c.joinFail(ip)
		time.Sleep(300 * time.Millisecond)
		core.JsonError(rw, http.StatusUnauthorized, "invalid or expired join token")
		return
	}
	peer := req.Peer
	if !req.ExplicitSelf { // trust the address we actually saw, with the joiner's port
		if _, port, err := net.SplitHostPort(peer.Addr); err == nil {
			peer.Addr = net.JoinHostPort(ip, port)
		}
	}
	if !validPeer(peer) {
		core.JsonError(rw, http.StatusBadRequest, "invalid peer description")
		return
	}
	if peer.Addr == c.Node.Self().Addr {
		core.JsonError(rw, http.StatusConflict, "the joining node has the same address as this one ("+peer.Addr+"): set its own cluster.self")
		return
	}
	c.Node.UnremovePeer(peer.Addr)
	c.Node.UnremoveFp(peer.Fp) // a token is an administrator's decision to let this identity in
	newcomer := peer.NodeID != "" && !c.knowsNode(peer.NodeID)
	c.Node.AddPeer(peer)
	if newcomer && c.Mg != nil {
		// A node that joins does not start serving every gateway: it is left out of each until an administrator adds it
		// (right-click the gateway ▸ Add node).  Done before the answer, so the joiner's first sync already carries it.
		// Whichever member took the join does it: a replica's change reaches the primary like any shared edit.
		c.Mg.ExcludeNewNode(peer.NodeID)
	}
	if req.MTLS {
		c.Node.NoteMTLS(peer.Fp)
	}
	snap := c.Node.Snapshot()
	// tell the other members now: the joiner calls them (the primary above all) as soon as it has our answer
	c.broadcast(snap.Peers, "/cluster/peers/add", map[string]any{"peer": peer, "mtls": req.MTLS})
	core.Infof("cluster: %s (node %s) joined", peer.Addr, peer.NodeID)
	core.WriteJSON(rw, http.StatusOK, joinResponse{
		Secret: base64.RawStdEncoding.EncodeToString(c.Node.Secret()), Epoch: snap.Epoch, PrimaryAddr: snap.PrimaryAddr,
		Server: c.Node.Self(), Peers: append(snap.Peers, c.Node.Self()),
	})
}

func (c *Cluster) joinThrottled(ip string) (time.Duration, bool) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if f := c.joinFails[ip]; f != nil && time.Now().Before(f.Locked) {
		return time.Until(f.Locked), true
	}
	return 0, false
}

func (c *Cluster) joinFail(ip string) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	f := c.joinFails[ip]
	if f == nil || time.Since(f.First) > core.FailWindow {
		f = &core.FailRec{First: time.Now()}
		c.joinFails[ip] = f
	}
	if f.Count++; f.Count >= 8 {
		f.Locked = time.Now().Add(core.LockDuration)
		f.Count = 0
	}
}

// ── admin API (also used by CLI/GUI) ─────────────────────────────────────────

func (c *Cluster) requireEnabled() error {
	if !c.Enabled() {
		return errors.New("clustering is disabled on this node (cluster.enabled is false)")
	}
	return nil
}

// sharedAddrs are the addresses that belong to the gateways and not to this node: every gateway's VIPs and its anycast
// addresses.  Every node answers on them, so one of them can never be a way to reach one particular node.
func (c *Cluster) SharedAddrs() map[string]bool {
	out := map[string]bool{}
	if c.Mg == nil {
		return out
	}
	dc, _, err := c.Mg.LiveConfig()
	if err != nil || dc == nil {
		return out
	}
	for _, g := range dc.Groups {
		for _, v := range append(g.VipsFor(core.AfIPv4), g.VipsFor(core.AfIPv6)...) {
			if a, err := core.VipAddr(v); err == nil {
				out[a.String()] = true
			}
		}
		for _, x := range g.ExtraVIPs {
			if a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimSuffix(x, "/32"), "/128")); err == nil {
				out[a.String()] = true
			}
		}
	}
	return out
}

func (c *Cluster) candidateAddrs() []string {
	var ifs []ifaceAddrs
	if all, err := net.Interfaces(); err == nil {
		for _, i := range all {
			if as, err := i.Addrs(); err == nil {
				ifs = append(ifs, ifaceAddrs{Name: i.Name, Loopback: i.Flags&net.FlagLoopback != 0, Addrs: as})
			}
		}
	}
	host, _ := os.Hostname()
	return nodeAddrCandidates(c.Node.Self().Addr, host, ifs, c.SharedAddrs())
}

type ifaceAddrs struct {
	Name     string
	Loopback bool
	Addrs    []net.Addr
}

// nodeAddrCandidates is the addresses this node tells the others it can be reached on: its cluster address, its host name
// and the addresses of its interfaces, each with the cluster port.  Left out: the loopback and its addresses (the anycast
// addresses live there), the virtual-MAC interfaces netdirN.M (the VIP lives there), link-local addresses, and any address
// in shared (the VIPs and anycast addresses of the gateways, which every node answers on).  A peer that dialled one of
// those would reach whichever node holds it at the moment, and be refused there for the certificate.
func nodeAddrCandidates(self, host string, ifs []ifaceAddrs, shared map[string]bool) []string {
	_, port, _ := net.SplitHostPort(self)
	addrs := []string{self}
	if host != "" {
		addrs = append(addrs, net.JoinHostPort(host, port))
	}
	for _, i := range ifs {
		if i.Loopback || strings.HasPrefix(i.Name, "netdir") {
			continue
		}
		for _, a := range i.Addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() && !shared[n.IP.String()] {
				addrs = append(addrs, net.JoinHostPort(n.IP.String(), port))
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// refreshAlts re-reads this node's host name and interface addresses (IPv4 and
// IPv6) so peers can reach it by any of them; they are shared with every
// request and in the join code.
func (c *Cluster) refreshAlts() {
	all := c.candidateAddrs()
	self := c.Node.Self().Addr
	var alts []string
	for _, a := range all {
		if a != self {
			alts = append(alts, a)
		}
	}
	if len(alts) > 12 {
		alts = alts[:12]
	}
	sort.Strings(alts)
	c.Node.SetAlts(alts)
}

// MintJoinCode creates a single-use code that lets another node join.
func (c *Cluster) MintJoinCode(by string) (string, time.Time, error) {
	if err := c.requireEnabled(); err != nil {
		return "", time.Time{}, err
	}
	tok, exp, err := c.Node.MintToken(by)
	if err != nil {
		return "", time.Time{}, err
	}
	b, _ := json.Marshal(JoinCode{Token: tok, Fp: c.Node.Fingerprint(), Addrs: c.candidateAddrs()})
	core.Infof("cluster: join code minted by %s (valid until %s)", by, exp.Format(time.RFC3339))
	return JoinCodePrefix + base64.RawURLEncoding.EncodeToString(b), exp, nil
}

// ClearJoinCodes withdraws every join code this node has handed out that was not used yet; it reports how many.
func (c *Cluster) ClearJoinCodes(by string) (int, error) {
	if err := c.requireEnabled(); err != nil {
		return 0, err
	}
	n, err := c.Node.ClearTokens()
	if err == nil {
		core.Infof("cluster: %d unused join code(s) cleared by %s", n, by)
	}
	return n, err
}

func DecodeJoinCode(code string) (JoinCode, error) {
	var jc JoinCode
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, JoinCodePrefix) {
		return jc, errors.New("not a netdir join code (expected it to start with \"" + JoinCodePrefix + "\")")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, JoinCodePrefix))
	if err != nil || json.Unmarshal(raw, &jc) != nil || jc.Token == "" || len(jc.Fp) != 64 || len(jc.Addrs) == 0 || len(jc.Addrs) > 32 {
		return jc, errors.New("the join code is damaged — copy it again in full")
	}
	for _, a := range jc.Addrs {
		if !validHostPort(a) {
			return jc, errors.New("the join code is damaged — copy it again in full")
		}
	}
	return jc, nil
}

// Join makes this node a member of the cluster the code came from.  Its shared
// settings are then replaced by the cluster's.
func (c *Cluster) Join(ctx context.Context, code, by string) error {
	if err := c.requireEnabled(); err != nil {
		return err
	}
	jc, err := DecodeJoinCode(code)
	if err != nil {
		return err
	}
	if !c.Node.Joinable() {
		return ErrNotJoinable
	}
	c.Mu.Lock()
	explicit := c.cfg.Self != ""
	c.Mu.Unlock()
	req := joinRequest{Token: jc.Token, Peer: c.Node.Self(), ExplicitSelf: explicit, MTLS: true}
	var errs []string
	for _, addr := range jc.Addrs {
		if !validHostPort(addr) {
			errs = append(errs, "skipped an invalid address in the join code")
			continue
		}
		var res joinResponse
		body, _ := json.Marshal(req)
		hreq, err := http.NewRequestWithContext(ctx, "POST", PeerURL("/cluster/join"), bytes.NewReader(body))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		hreq.Header.Set("Content-Type", "application/json")
		resp, err := pinnedClient(addr, jc.Fp, 8*time.Second).Do(hreq)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var e struct {
				Error string `json:"error"`
			}
			json.Unmarshal(data, &e)
			if e.Error == "" {
				e.Error = resp.Status
			}
			return fmt.Errorf("%s refused the join: %s", addr, e.Error)
		}
		if err := json.Unmarshal(data, &res); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		// The server keeps the address it calls itself (peers are identified by
		// it, including as primary); the address that worked is remembered and
		// listed among its alternatives.
		if addr != res.Server.Addr && !core.ContainsStr(res.Server.Alts, addr) {
			res.Server.Alts = append([]string{addr}, res.Server.Alts...)
		}
		if res.Server.Addr == c.Node.Self().Addr || res.PrimaryAddr == c.Node.Self().Addr {
			return fmt.Errorf("this node and the cluster both call themselves %s: give this node its own address (cluster.self) and try again", c.Node.Self().Addr)
		}
		c.noteGoodAddr(res.Server, addr)
		res.Server.Fp = jc.Fp
		// safety net: a way back to the configuration this node had
		if _, raw, err := c.Mg.LiveConfig(); err == nil {
			if _, err := os.Stat(c.Mg.ConfPath()); err == nil {
				c.Mg.Versions().Record(raw, by, "before joining the cluster of "+addr, true)
			}
		}
		peers := append([]core.ClusterPeer{res.Server}, res.Peers...)
		primary := res.PrimaryAddr
		if err := c.Node.JoinAs(res.Secret, res.Epoch, primary, peers); err != nil {
			return err
		}
		c.Mg.Updater().HoldSource() // before the first status message: what this node had staged is not offered to the cluster
		core.Infof("cluster: joined the cluster via %s (primary %s, epoch %d) — requested by %s", addr, primary, res.Epoch, by)
		if err := c.SyncOnce(ctx); err != nil {
			core.Warnf("cluster: joined, but the first sync failed: %v", err)
		}
		c.Mg.UsersPull(ctx, res.Server)
		return nil
	}
	return fmt.Errorf("could not reach the cluster: %s", strings.Join(errs, "; "))
}

// Promote makes this node the primary at the next epoch and tells the others.
func (c *Cluster) Promote(by string) (core.ClusterSnapshot, error) {
	if err := c.requireEnabled(); err != nil {
		return core.ClusterSnapshot{}, err
	}
	snap := c.Node.Promote()
	c.SetPrimaryHome("") // a promotion is the administrator's (or the failover's) choice: nothing takes the role back
	core.Warnf("cluster: this node was promoted to primary (epoch %d) by %s", snap.Epoch, by)
	c.announce(snap)
	return snap, nil
}

func (c *Cluster) announce(snap core.ClusterSnapshot) {
	var wg sync.WaitGroup
	for _, p := range snap.Peers {
		wg.Add(1)
		go func(p core.ClusterPeer) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), peerTimeout)
			defer cancel()
			if err := c.Call(ctx, p, "POST", "/cluster/announce", announceMsg{Epoch: snap.Epoch, PrimaryAddr: snap.PrimaryAddr}, nil, peerTimeout); err != nil {
				core.Warnf("cluster: could not announce epoch %d to %s: %v (it will learn on its next sync)", snap.Epoch, p.Addr, err)
			}
		}(p)
	}
	wg.Wait()
}

// RemovePeer removes a member cluster-wide.
func (c *Cluster) RemovePeer(addr, by string) error {
	if err := c.requireEnabled(); err != nil {
		return err
	}
	snap := c.Node.Snapshot()
	if addr == snap.SelfAddr {
		return errors.New("use \"leave\" to remove this node itself")
	}
	if addr == snap.PrimaryAddr && snap.Role != core.RolePrimary {
		return errors.New("that node is the primary; promote this node first")
	}
	var target *core.ClusterPeer
	for i := range snap.Peers {
		if snap.Peers[i].Addr == addr {
			target = &snap.Peers[i]
		}
	}
	if target == nil {
		return fmt.Errorf("%s is not a member", addr)
	}
	c.Node.RemovePeer(addr)
	core.Warnf("cluster: %s removed by %s", addr, by)
	c.broadcast(snap.Peers, "/cluster/peers/remove", map[string]string{"addr": addr})
	return nil
}

// DeletePeer removes a member for good and keeps nothing about it: the member is dropped cluster-wide (a copy of it that is
// still running resets itself to a cluster of one) and its address is then taken off the removed list on every node, so no
// block is left behind. An address that is only on the removed list is cleared from it.
func (c *Cluster) DeletePeer(addr, by string) error {
	if err := c.requireEnabled(); err != nil {
		return err
	}
	snap := c.Node.Snapshot()
	member := false
	var others []core.ClusterPeer
	for _, p := range snap.Peers {
		if p.Addr == addr {
			member = true
		} else {
			others = append(others, p)
		}
	}
	if !member {
		if !c.Node.UnremovePeer(addr) {
			return fmt.Errorf("%s is not a member", addr)
		}
		c.broadcast(snap.Peers, "/cluster/peers/unremove", map[string]string{"addr": addr})
		core.Warnf("cluster: %s forgotten by %s", addr, by)
		return nil
	}
	if err := c.RemovePeer(addr, by); err != nil {
		return err
	}
	c.Node.UnremovePeer(addr)
	c.broadcast(others, "/cluster/peers/unremove", map[string]string{"addr": addr})
	core.Warnf("cluster: %s deleted by %s", addr, by)
	return nil
}

func (c *Cluster) UnremovePeer(addr, by string) error {
	if err := c.requireEnabled(); err != nil {
		return err
	}
	if !c.Node.UnremovePeer(addr) {
		return fmt.Errorf("%s is not on the removed list", addr)
	}
	c.broadcast(c.Node.Snapshot().Peers, "/cluster/peers/unremove", map[string]string{"addr": addr})
	return nil
}

func (c *Cluster) broadcast(peers []core.ClusterPeer, path string, body any) {
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p core.ClusterPeer) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), peerTimeout)
			defer cancel()
			if err := c.Call(ctx, p, "POST", path, body, nil, peerTimeout); err != nil {
				core.Debugf("cluster: %s to %s: %v", path, p.Addr, err)
			}
		}(p)
	}
	wg.Wait()
}

// Leave tells the other members and becomes a single-node cluster again.
func (c *Cluster) Leave(by string) error {
	if err := c.requireEnabled(); err != nil {
		return err
	}
	snap := c.Node.Snapshot()
	if len(snap.Peers) == 0 {
		return errors.New("this node is not part of a multi-node cluster")
	}
	if snap.Role == core.RolePrimary && len(snap.Peers) > 0 {
		core.Warnf("cluster: leaving while primary — promote another member first if the others should keep a primary")
	}
	c.broadcast(snap.Peers, "/cluster/peers/remove", map[string]string{"addr": snap.SelfAddr})
	c.LeaveLocal("left by " + by)
	return nil
}

func (c *Cluster) LeaveLocal(why string) {
	c.Node.Reset()
	c.Mu.Lock()
	c.Info = map[string]*peerInfo{}
	c.conflict = ""
	c.Mu.Unlock()
	core.Warnf("cluster: this node is no longer in the cluster (%s) — it is now its own single-node cluster", why)
}

// forwardAdmin sends an admin write to the primary and returns its reply.
func (c *Cluster) ForwardAdmin(op, by string, payload any) (json.RawMessage, error) {
	snap := c.Node.Snapshot()
	var primary *core.ClusterPeer
	for i := range snap.Peers {
		if snap.Peers[i].Addr == snap.PrimaryAddr {
			primary = &snap.Peers[i]
		}
	}
	if primary == nil {
		return nil, fmt.Errorf("the primary %s is not a known peer", snap.PrimaryAddr)
	}
	pb, _ := json.Marshal(payload)
	if payload == nil {
		pb = []byte("null")
	}
	var out json.RawMessage
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := c.Call(ctx, *primary, "POST", "/cluster/admin", adminMsg{Op: op, By: by, Payload: pb}, &out, 30*time.Second)
	return out, err
}

// ── sync loop ────────────────────────────────────────────────────────────────

func (c *Cluster) syncSoon() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *Cluster) SyncNow() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c.SyncOnce(ctx)
}

// Run is the background loop: poll peers, pull the primary's state, and
// consider a software update.  It also drives updates on unclustered nodes.
func (c *Cluster) Run(ctx context.Context) {
	for {
		c.Mu.Lock()
		iv := time.Duration(c.cfg.SyncIntervalSec) * time.Second
		c.Mu.Unlock()
		if iv < time.Second {
			iv = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		case <-c.kick:
		}
		sctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		if c.Enabled() {
			c.SyncOnce(sctx)
		}
		c.SampleGwUp()
		c.SampleAnycastUp()
		c.FailoverTick()
		c.Mg.PowerHandoverTick()
		c.Mg.UpdateTick(sctx)
		cancel()
		c.LogStrain()
	}
}

// SyncOnce polls every peer (epoch discovery, gossip), pulls state if this
// node is a replica, and records the outcome.
func (c *Cluster) SyncOnce(ctx context.Context) error {
	if !c.Enabled() {
		return nil
	}
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	c.refreshAlts()
	snap := c.Node.Snapshot()

	type result struct {
		peer core.ClusterPeer
		msg  PeerStatusMsg
		err  error
	}
	results := make(chan result, len(snap.Peers))
	for _, p := range snap.Peers {
		go func(p core.ClusterPeer) {
			var m PeerStatusMsg
			cctx, cancel := context.WithTimeout(ctx, peerTimeout)
			defer cancel()
			err := c.Call(cctx, p, "GET", "/cluster/status", nil, &m, peerTimeout)
			results <- result{p, m, err}
		}(p)
	}
	infos := map[string]*peerInfo{}
	for range snap.Peers {
		r := <-results
		pi := &peerInfo{Msg: r.msg, Reachable: r.err == nil}
		if r.err == nil {
			pi.LastSeen = time.Now()
		} else {
			pi.Err = r.err.Error()
			var pe *PeerError
			if errors.As(r.err, &pe) && pe.Removed {
				c.LeaveLocal("the cluster removed this node (" + r.peer.Addr + ")")
				return nil
			}
		}
		infos[r.peer.Addr] = pi
	}
	var firstErr error
	c.Mu.Lock()
	for addr, pi := range infos {
		if old := c.Info[addr]; old != nil && !pi.Reachable {
			pi.LastSeen = old.LastSeen
			pi.Msg = old.Msg
		}
		c.Info[addr] = pi
	}
	for addr := range c.Info {
		if _, ok := infos[addr]; !ok {
			delete(c.Info, addr)
		}
	}
	c.Mu.Unlock()

	// epoch discovery and gossip
	for addr, pi := range infos {
		if !pi.Reachable {
			continue
		}
		m := pi.Msg
		// Remember the peer's own addresses (saved with the member list), so that after a restart the cluster
		// can reach it without asking DNS, which may be the very service that is down.
		for _, p := range snap.Peers {
			if p.Addr == addr {
				if np, ok := learnPeerAddrs(p, core.AddrList(m.Addrs)); ok {
					c.Node.AddPeer(np)
				}
			}
		}
		if m.Epoch > c.Node.Snapshot().Epoch {
			if s, err := c.Node.AdoptAnnounce(m.Epoch, m.PrimaryAddr); err == nil {
				core.Infof("cluster: learned from %s that %s is primary at epoch %d (this node is now %s)", addr, s.PrimaryAddr, s.Epoch, s.Role)
			}
		} else if m.Epoch == c.Node.Snapshot().Epoch && m.PrimaryAddr != c.Node.Snapshot().PrimaryAddr && m.PrimaryAddr != "" {
			c.setConflict(fmt.Sprintf("%s reports primary %s at epoch %d, this node follows %s — promote exactly one node to resolve", addr, m.PrimaryAddr, m.Epoch, c.Node.Snapshot().PrimaryAddr))
		}
		for _, rem := range m.Removed {
			if rem == c.Node.Self().Addr {
				c.LeaveLocal("another member removed this node")
				return nil
			}
			if !core.ContainsStr(c.Node.Snapshot().Removed, rem) {
				c.Node.RemovePeer(rem)
			}
		}
		for _, p := range m.Peers {
			if validPeer(p) && c.Node.AddPeer(p) {
				core.Infof("cluster: learned peer %s from %s", p.Addr, addr)
			}
		}
	}

	snap = c.Node.Snapshot()
	if snap.Role == RoleReplica {
		if err := c.pullState(ctx, snap); err != nil {
			firstErr = err
		}
	} else {
		c.Mu.Lock()
		c.conflict = pickConflict(c.conflict, snap, infos)
		c.Mu.Unlock()
	}
	c.Mu.Lock()
	c.lastSync = time.Now()
	if firstErr != nil {
		c.lastErr = firstErr.Error()
	} else {
		c.lastErr = ""
	}
	c.Mu.Unlock()
	return firstErr
}

// pickConflict clears a stale conflict message once everyone agrees again.
func pickConflict(cur string, snap core.ClusterSnapshot, infos map[string]*peerInfo) string {
	for _, pi := range infos {
		if pi.Reachable && pi.Msg.Epoch == snap.Epoch && pi.Msg.PrimaryAddr != snap.PrimaryAddr && pi.Msg.PrimaryAddr != "" {
			return cur
		}
	}
	return ""
}

func (c *Cluster) pullState(ctx context.Context, snap core.ClusterSnapshot) error {
	var primary *core.ClusterPeer
	for i := range snap.Peers {
		if snap.Peers[i].Addr == snap.PrimaryAddr {
			primary = &snap.Peers[i]
		}
	}
	if primary == nil {
		return fmt.Errorf("the primary %s is not a known peer", snap.PrimaryAddr)
	}
	var st clusterStateMsg
	cctx, cancel := context.WithTimeout(ctx, peerTimeout*2)
	defer cancel()
	if err := c.Call(cctx, *primary, "GET", "/cluster/state", nil, &st, peerTimeout*2); err != nil {
		return fmt.Errorf("pulling state from the primary %s: %w", primary.Addr, err)
	}
	if st.Epoch != snap.Epoch {
		if st.Epoch > snap.Epoch {
			c.Node.AdoptAnnounce(st.Epoch, st.PrimaryAddr)
		}
		return fmt.Errorf("the primary answered with epoch %d, this node is at %d", st.Epoch, snap.Epoch)
	}
	for _, p := range st.Peers {
		if validPeer(p) {
			c.Node.AddPeer(p)
		}
	}
	c.Mg.ApplyClusterShared(st.Shared, st.Seeds, st.SharedRev, primary.Addr)
	c.Mg.Updater().SetIntent(st.Intent)
	dc, _, err := c.Mg.LiveConfig()
	if err == nil && dc.Cluster.ShareCert {
		var cp, kp []byte
		if st.Cert != nil {
			cp, kp = []byte(st.Cert.CertPEM), []byte(st.Cert.KeyPEM)
		}
		if err := c.Mg.Certs().ApplyCluster(cp, kp); err != nil {
			core.Warnf("cluster: could not apply the shared certificate: %v", err)
		}
	}
	return nil
}

type ClusterView struct {
	Enabled       bool            `json:"enabled"`
	NodeID        string          `json:"node_id"`
	Self          string          `json:"self"`
	Role          core.Role       `json:"role"`
	Epoch         uint64          `json:"epoch"`
	PrimaryAddr   string          `json:"primary_addr"`
	Fingerprint   string          `json:"fingerprint"`
	Listen        string          `json:"listen"`
	Joinable      bool            `json:"joinable"`
	SharedRev     uint64          `json:"shared_rev"`
	Peers         []core.PeerView `json:"peers"`
	Removed       []string        `json:"removed"`
	LastSync      time.Time       `json:"last_sync,omitempty"`
	LastSyncError string          `json:"last_sync_error,omitempty"`
	Conflict      string          `json:"conflict,omitempty"`
	Warnings      []string        `json:"warnings"`
	// FailoverOn says whether automatic failover is in force with this many members (from three)
	FailoverOn bool `json:"failover_on"`
	// JoinCodes is how many join codes this node has handed out that are unused and still valid
	JoinCodes int `json:"join_codes"`
}

// PeerList is the nodes of View, for the device checks (HealthCluster).
func (c *Cluster) PeerList() []core.PeerView { return c.View().Peers }

// NodeSecret is the cluster secret, nil when the node has none (HealthCluster).
func (c *Cluster) NodeSecret() []byte {
	if c.Node == nil {
		return nil
	}
	return c.Node.Secret()
}

func (c *Cluster) View() ClusterView {
	snap := c.Node.Snapshot()
	joinCodes := c.Node.PendingTokens()
	selfIPs, selfGw := core.AddrList(core.EthernetAddrs()), c.Mg.LocalGwIPs() // before c.mu: they ask the engines
	c.Mu.Lock()
	defer c.Mu.Unlock()
	v := ClusterView{
		Enabled: c.cfg.Enabled, NodeID: snap.NodeID, Self: snap.SelfAddr, Role: snap.Role, Epoch: snap.Epoch,
		PrimaryAddr: snap.PrimaryAddr, Fingerprint: c.Node.Fingerprint(), Listen: c.cfg.Listen,
		SharedRev: snap.SharedRev, Removed: snap.Removed, LastSync: c.lastSync, LastSyncError: c.lastErr,
		Conflict: c.conflict, Peers: []core.PeerView{}, Warnings: []string{},
	}
	v.Joinable = snap.Role == core.RolePrimary && len(snap.Peers) == 0 && snap.Epoch == 1
	v.FailoverOn = failoverEnabled(len(snap.Peers) + 1)
	v.JoinCodes = joinCodes
	v.Peers = append(v.Peers, core.PeerView{
		Addr: snap.SelfAddr, NodeID: snap.NodeID, Fingerprint: c.Node.Fingerprint(), Self: true, Reachable: true,
		Role: snap.Role, Epoch: snap.Epoch, IsPrimary: snap.Role == core.RolePrimary, NodePaused: c.Mg.NodePaused(), Version: core.Version(),
		SourceVersion: c.Mg.Updater().SourceVersion(), Updating: c.Mg.Updater().Busy(), UpdateFailed: c.Mg.Updater().FailedFor(),
		SharedRev: snap.SharedRev, LastSeen: time.Now(), Hostname: core.SelfHost(), IPs: selfIPs, GwIPs: selfGw,
	})
	for _, p := range snap.Peers {
		pv := core.PeerView{Addr: p.Addr, NodeID: p.NodeID, Fingerprint: p.Fp, IsPrimary: p.Addr == snap.PrimaryAddr}
		if pi := c.Info[p.Addr]; pi != nil {
			pv.Reachable, pv.LastSeen, pv.Error = pi.Reachable, pi.LastSeen, pi.Err
			pv.Restarting = restartingInfo(pi)
			m := pi.Msg
			pv.Role, pv.Epoch, pv.Version, pv.SourceVersion = m.Role, m.Epoch, m.Version, m.SourceVersion
			pv.Updating, pv.UpdateFailed, pv.SharedRev = m.Updating, m.UpdateFailed, m.SharedRev
			pv.Hostname = m.Hostname
			pv.NodePaused = m.NodePaused
			pv.IPs, pv.GwIPs = core.AddrList(m.Addrs), m.GwIPs
		}
		v.Peers = append(v.Peers, pv)
	}
	sort.SliceStable(v.Peers[1:], func(i, j int) bool { return v.Peers[1+i].Addr < v.Peers[1+j].Addr })
	soak := c.SoakLeftLocked(snap)
	for i := range v.Peers {
		v.Peers[i].SoakSec = soak[v.Peers[i].Addr]
	}
	if !c.cfg.Enabled {
		v.Warnings = append(v.Warnings, "clustering is disabled on this node (cluster.enabled is false)")
	}
	if snap.Role == RoleReplica && snap.PrimaryAddr != snap.SelfAddr {
		pri := false
		for _, p := range v.Peers {
			if p.Addr == snap.PrimaryAddr && p.Reachable {
				pri = true
			}
		}
		if !pri {
			v.Warnings = append(v.Warnings, "the primary "+snap.PrimaryAddr+" is not reachable — settings changes will fail until it is back; promote this node if it is gone for good")
		}
	}
	return v
}

// updateNodes feeds the update status table.
func (c *Cluster) UpdateNodes() []core.UpdateNode {
	intent := c.Mg.Updater().Intent()
	snap := c.Node.Snapshot()
	self := core.UpdateNode{
		Addr: snap.SelfAddr, Self: true, Reachable: true, Running: core.Version(), Source: c.Mg.Updater().SourceVersion(),
		Queued: intent.Wants(snap.SelfAddr), Updating: c.Mg.Updater().Busy(), Failed: c.Mg.Updater().FailedFor(),
	}
	self.Behind = core.VersionGreater(self.Source, self.Running)
	out := []core.UpdateNode{self}
	if !c.Enabled() {
		return out
	}
	c.Mu.Lock()
	defer c.Mu.Unlock()
	soak := c.SoakLeftLocked(snap)
	out[0].SoakSec = soak[snap.SelfAddr]
	for _, p := range snap.Peers {
		n := core.UpdateNode{Addr: p.Addr, Queued: intent.Wants(p.Addr), SoakSec: soak[p.Addr]}
		if pi := c.Info[p.Addr]; pi != nil {
			n.Restarting = restartingInfo(pi)
			n.Reachable, n.Running, n.Source, n.Updating, n.Failed = pi.Reachable, pi.Msg.Version, pi.Msg.SourceVersion, pi.Msg.Updating, pi.Msg.UpdateFailed
		}
		out = append(out, n)
	}
	return out
}

// bestSourcePeer returns the reachable peer offering the highest source version.
func (c *Cluster) BestSourcePeer(above string) (core.ClusterPeer, string, bool) {
	snap := c.Node.Snapshot()
	c.Mu.Lock()
	defer c.Mu.Unlock()
	best, bestVer := core.ClusterPeer{}, above
	for _, p := range snap.Peers {
		if pi := c.Info[p.Addr]; pi != nil && pi.Reachable && core.VersionGreater(pi.Msg.SourceVersion, bestVer) {
			best, bestVer = p, pi.Msg.SourceVersion
		}
	}
	return best, bestVer, best.Addr != ""
}

// pullSource downloads and stages a peer's source tree.
func (c *Cluster) PullSource(ctx context.Context, peer core.ClusterPeer) (string, error) {
	var buf bytes.Buffer
	err := c.callRaw(ctx, peer, "GET", "/cluster/source", nil, func(r io.Reader) error {
		_, err := io.Copy(&buf, r)
		return err
	}, sourceTimeout, nil)
	if err != nil {
		return "", err
	}
	return c.Mg.Updater().ExtractSource(buf.Bytes())
}

// shouldWaitForOthers staggers a rolling update: wait while another reachable
// member is updating, or while an earlier-sorted one that also wants and needs
// the update (and hasn't failed on it) is still to go.
//
// An earlier-sorted member that cannot go yet because it is the only one serving
// a gateway (the others are paused or down) is not waited for: it would hold
// everyone behind it forever, including the paused members that serve nothing and
// are the very ones that can update safely.
func (c *Cluster) ShouldWaitForOthers(target string, intent core.UpdateIntent) bool {
	snap := c.Node.Snapshot()
	var mine []core.GwState
	var groups []core.GroupConfig
	if c.Mg != nil {
		mine = c.Mg.LocalGateways() // before c.mu: it takes its own lock
		if dc, _, err := c.Mg.LiveConfig(); err == nil {
			groups = dc.Groups
		}
	}
	c.Mu.Lock()
	defer c.Mu.Unlock()
	// what every reachable member (self included) says it serves
	members := []core.PeerGateways{selfGateways(snap.SelfAddr, c.Mg != nil && c.Mg.KnowsGateways(), mine)}
	members[0].NodeID = snap.NodeID
	for _, p := range snap.Peers {
		if pi := c.Info[p.Addr]; pi != nil && pi.Reachable {
			pg := gatewaysOf(p.Addr, pi)
			pg.NodeID = p.NodeID
			members = append(members, pg)
		}
	}
	MarkGatewayExcluded(members, groups)
	for _, p := range snap.Peers {
		pi := c.Info[p.Addr]
		if pi == nil || !pi.Reachable {
			continue
		}
		if pi.Msg.Updating {
			return true
		}
		if p.Addr < snap.SelfAddr && intent.Wants(p.Addr) && core.VersionGreater(target, pi.Msg.Version) && pi.Msg.UpdateFailed != target {
			if heldBySafety(p.Addr, pi.Msg.Gateways, members) {
				continue
			}
			return true
		}
	}
	return false
}

// processStart is when this daemon started; peers read it as uptime.
var processStart = time.Now()

// updateSoak is how long the first node to take a new version must run it, with
// no gateway marked bad, before the other nodes follow (the canary).  A var so
// tests can shorten it.
var UpdateSoak = 2 * time.Minute

// restartingInfo reports whether a member that does not answer was last seen installing an update (or about to), recently enough that it
// is most likely restarting into the new version (the Topology, Cluster and Upgrade pages say "updating", not "down").
func restartingInfo(pi *peerInfo) bool {
	if pi == nil || pi.Reachable || pi.LastSeen.IsZero() || time.Since(pi.LastSeen) >= canaryLostWindow {
		return false
	}
	// it said it was installing, or it had a newer source staged than it runs (the poll can miss the short installing phase)
	return pi.Msg.Updating || core.VersionGreater(pi.Msg.SourceVersion, pi.Msg.Version)
}

// canaryLostWindow is how long after the last contact a member that was updating (or running the target) holds the others.
const canaryLostWindow = 5 * time.Minute

// canaryHold says why this node must not update yet, or "".  The first node
// to update is the canary: the rest hold while any reachable member that runs
// the target version has been up less than updateSoak or reports a bad
// gateway, and while any member's update to the target has failed.  Once one
// member has soaked, the others go on in turn without waiting for each other's
// soak.
func (c *Cluster) CanaryHold(target string) string {
	snap := c.Node.Snapshot()
	c.Mu.Lock()
	defer c.Mu.Unlock()
	var young string
	for _, p := range snap.Peers {
		pi := c.Info[p.Addr]
		if pi == nil {
			continue
		}
		m := pi.Msg
		if !pi.Reachable {
			// a member that vanished while updating, or right after taking the target, may be crash-looping: hold for a while
			if (m.Updating || m.Version == target) && !pi.LastSeen.IsZero() && time.Since(pi.LastSeen) < canaryLostWindow {
				return "lost contact with " + p.Addr + " while it was updating to v" + target + "; the others wait"
			}
			continue
		}
		if m.UpdateFailed == target {
			return "update to v" + target + " failed on " + p.Addr + "; the others wait"
		}
		if m.Version != target || m.Updating {
			continue
		}
		bad := false
		for _, g := range m.Gateways {
			if g.Health == "bad" {
				bad = true
			}
		}
		up := time.Duration(m.UptimeSec) * time.Second
		if bad {
			return p.Addr + " runs v" + target + " but a gateway there is bad; the others wait"
		}
		if up >= UpdateSoak {
			return "" // this member has soaked: the canary passed
		}
		if young == "" {
			young = p.Addr + " runs v" + target + " (" + strconv.Itoa(int((UpdateSoak-up)/time.Minute)+1) + " min left to settle); the others wait"
		}
	}
	return young
}

// soakLeftLocked maps each member that is soaking to the seconds it has left: a
// member on the newest version, up for less than updateSoak, while some member
// still runs an older one (the others are waiting on it).  c.mu is held.
func (c *Cluster) SoakLeftLocked(snap core.ClusterSnapshot) map[string]int {
	type mem struct {
		addr string
		ver  string
		up   time.Duration
		busy bool
	}
	ms := []mem{{snap.SelfAddr, core.Version(), time.Since(processStart), c.Mg.Updater().Busy()}}
	for _, p := range snap.Peers {
		if pi := c.Info[p.Addr]; pi != nil && pi.Reachable {
			ms = append(ms, mem{p.Addr, pi.Msg.Version, time.Duration(pi.Msg.UptimeSec) * time.Second, pi.Msg.Updating})
		}
	}
	newest := ms[0].ver
	for _, m := range ms {
		if core.VersionGreater(m.ver, newest) {
			newest = m.ver
		}
	}
	older := false
	for _, m := range ms {
		if m.ver != newest {
			older = true
		}
	}
	out := map[string]int{}
	if !older {
		return out
	}
	for _, m := range ms {
		if m.ver == newest && !m.busy && m.up >= UpdateSoak {
			return out // the canary has soaked: later nodes update without a soak of their own
		}
	}
	for _, m := range ms {
		if m.ver == newest && !m.busy && m.up < UpdateSoak {
			out[m.addr] = int((UpdateSoak-m.up)/time.Second) + 1
		}
	}
	return out
}

// selfGateways and gatewaysOf express one member's gateway report as a peerGateways.
func selfGateways(addr string, known bool, gs []core.GwState) core.PeerGateways {
	pg := core.PeerGateways{Addr: addr, Known: known, Serving: map[int]bool{}, Fresh: map[int]bool{}, Offnet: map[int]bool{}}
	for _, g := range gs {
		pg.Serving[g.GroupID], pg.Fresh[g.GroupID], pg.Offnet[g.GroupID] = g.Serving, g.Fresh, g.Offnet
	}
	return pg
}

func gatewaysOf(addr string, pi *peerInfo) core.PeerGateways {
	return selfGateways(addr, pi.Msg.GwKnown, pi.Msg.Gateways)
}

// heldBySafety reports whether member addr, which reports gws, is currently
// stopped by the "keep every gateway served" rule: it serves a gateway that no
// other reachable member serves.  members includes addr itself, which is left out.
func heldBySafety(addr string, gws []core.GwState, members []core.PeerGateways) bool {
	others := make([]core.PeerGateways, 0, len(members))
	for _, m := range members {
		if m.Addr != addr {
			others = append(others, m)
		}
	}
	ok, _ := SafeToTakeDown(gws, others)
	return !ok
}

func Max2(a, b string) string {
	if core.VersionGreater(a, b) {
		return a
	}
	return b
}

// servingSettle is how long a gateway must have been served continuously before
// another member may restart on the strength of it.
var ServingSettle = 15 * time.Second

// gatewayStates computes what this node serves.  Paused gateways are left out:
// this node is not expected to serve them.
func GatewayStates(dc *core.DaemonConfig, rows []core.SnapshotRow) []core.GwState {
	out := []core.GwState{}
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if g.Paused {
			continue
		}
		serving, serviceUp := map[string]bool{}, false
		for _, r := range rows {
			if r.GroupID == g.GroupID && r.Local {
				serving[r.AF] = r.State == "active" || r.State == "forward"
				serviceUp = serviceUp || r.ServiceUp
			}
		}
		ok := true
		for _, af := range []struct {
			name string
			vip  string
		}{{"v4", g.VIP4}, {"v6", g.VIP6}} {
			if af.vip != "" && !serving[af.name] {
				ok = false
			}
		}
		if !serviceUp {
			ok = false
		}
		out = append(out, core.GwState{GroupID: g.GroupID, Serving: ok})
	}
	return out
}

// fillUpSince adds since when the cluster has served each gateway without a break.
func (c *Cluster) FillUpSince(gs []core.GwState) {
	c.upMu.Lock()
	for i := range gs {
		if t, ok := c.gwUp[gs[i].GroupID]; ok {
			gs[i].UpSince = t.Unix()
		}
	}
	c.upMu.Unlock()
}

// gwUpSeconds is how long the cluster has served the gateway without a break (0: nobody serves it, or not known yet).
func (c *Cluster) GwUpSeconds(gid int) int64 {
	if c == nil {
		return 0
	}
	c.upMu.Lock()
	defer c.upMu.Unlock()
	if t, ok := c.gwUp[gid]; ok {
		return int64(time.Since(t) / time.Second)
	}
	return 0
}

// sampleGwUp keeps, for each gateway, since when somebody in the cluster has served it without a break.  A node's own time
// serving restarts with the node, so on a rolling update the longest of them would only reach back to the first node to
// come back.  Instead every node remembers the moment it first saw the gateway served, passes it on in its status message
// (GwState.UpSince), and takes the earliest of its own and what the members report: a node that restarts learns it again
// from the members still serving.  It is dropped when nobody serves the gateway (a real outage) and starts again then.
func (c *Cluster) SampleGwUp() {
	m := c.Mg
	if m == nil || !m.KnowsGateways() {
		return
	}
	mine := m.LocalGateways() // before c.mu: it takes its own locks
	type acc struct {
		serving bool
		best    time.Time // earliest start known
	}
	now := time.Now()
	by := map[int]*acc{}
	get := func(gid int) *acc {
		if by[gid] == nil {
			by[gid] = &acc{}
		}
		return by[gid]
	}
	note := func(a *acc, t time.Time) {
		if !t.IsZero() && (a.best.IsZero() || t.Before(a.best)) {
			a.best = t
		}
	}
	for _, g := range mine {
		a := get(g.GroupID)
		if g.Serving {
			a.serving = true
			note(a, now.Add(-time.Duration(g.ServingSec)*time.Second))
		}
	}
	c.Mu.Lock()
	for _, pi := range c.Info {
		if pi == nil || !pi.Reachable {
			continue
		}
		for _, g := range pi.Msg.Gateways {
			a := get(g.GroupID)
			if g.Serving {
				a.serving = true
				note(a, now.Add(-time.Duration(g.ServingSec)*time.Second))
			}
			if g.UpSince > 0 {
				note(a, time.Unix(g.UpSince, 0))
			}
		}
	}
	c.Mu.Unlock()
	c.upMu.Lock()
	defer c.upMu.Unlock()
	if c.gwUp == nil {
		c.gwUp = map[int]time.Time{}
	}
	for gid, a := range by {
		if !a.serving {
			delete(c.gwUp, gid) // nobody serves it now: the uptime starts again when somebody does
			continue
		}
		if t, ok := c.gwUp[gid]; ok {
			note(a, t)
		}
		c.gwUp[gid] = a.best
	}
	for gid := range c.gwUp {
		if by[gid] == nil {
			delete(c.gwUp, gid)
		}
	}
}

// safeToTakeDown reports whether this node may go down now: for every gateway
// it is serving, some other reachable member must be serving it too, so the
// gateway never goes unserved while members update one after another.
func SafeToTakeDown(mine []core.GwState, peers []core.PeerGateways) (bool, string) {
	for _, g := range mine {
		if !g.Serving {
			continue // already not serving: nothing more to lose
		}
		others, fresh, capable := 0, 0, 0
		for _, p := range peers {
			if p.Down {
				capable++ // not reachable now, and may be the one that could cover it
				continue
			}
			if !p.Known || !p.Offnet[g.GroupID] {
				capable++
			}
			if !p.Known || (p.Serving[g.GroupID] && !p.Fresh[g.GroupID]) { // an older node cannot say; assume it is fine
				others++
			} else if p.Serving[g.GroupID] {
				fresh++
			}
		}
		if others == 0 && fresh > 0 {
			return false, fmt.Sprintf("gateway %d is only just being served again by the other member — waiting a few seconds for clients to move back", g.GroupID)
		}
		if others == 0 && capable == 0 && len(peers) > 0 {
			continue // every other member is on another subnet and can never serve it: waiting would be for ever
		}
		if others == 0 {
			// say what each other member is doing, so the reason is not a guess
			var who []string
			for _, p := range peers {
				switch {
				case p.Down:
					who = append(who, p.Addr+" is not reachable")
				case p.Offnet[g.GroupID]:
					who = append(who, p.Addr+" cannot serve it (another subnet, or removed from the gateway)")
				case p.Serving[g.GroupID]:
					who = append(who, p.Addr+" has only just started serving it")
				default:
					who = append(who, p.Addr+" is not serving it (paused, still recovering, or its listener is not serving)")
				}
			}
			detail := "this is the only member"
			if len(who) > 0 {
				detail = strings.Join(who, "; ")
			}
			return false, fmt.Sprintf("gateway %d would have no other cluster member serving it (%s) — resume a node that has already updated, or force it with --update-apply --yes", g.GroupID, detail)
		}
	}
	return true, ""
}

// markGatewayExcluded marks, for each member, the gateways it has been removed from (a shared setting every node holds): it
// can never serve them, whatever version it runs and whatever it says, so it is no cover for them.  Both the
// "may I go now" check and the "must I wait for that member" check use it; without it in the second one every
// member looked held back by the safety rule and the update order (and with it the canary) was skipped.
func MarkGatewayExcluded(ps []core.PeerGateways, groups []core.GroupConfig) {
	for i := range ps {
		for _, g := range groups {
			if ps[i].NodeID != "" && core.ContainsStr(g.ExcludedNodes, ps[i].NodeID) {
				if ps[i].Offnet == nil {
					ps[i].Offnet = map[int]bool{}
				}
				ps[i].Offnet[g.GroupID] = true
			}
		}
	}
}

func (c *Cluster) PeerGateways() []core.PeerGateways {
	snap := c.Node.Snapshot()
	c.Mu.Lock()
	defer c.Mu.Unlock()
	var out []core.PeerGateways
	for _, p := range snap.Peers {
		pi := c.Info[p.Addr]
		if pi == nil || !pi.Reachable {
			out = append(out, core.PeerGateways{Addr: p.Addr, NodeID: p.NodeID, Down: true})
			continue
		}
		pg := core.PeerGateways{Addr: p.Addr, NodeID: p.NodeID, Known: pi.Msg.GwKnown, Serving: map[int]bool{}, Fresh: map[int]bool{}, Offnet: map[int]bool{}}
		for _, g := range pi.Msg.Gateways {
			pg.Serving[g.GroupID] = g.Serving
			pg.Fresh[g.GroupID] = g.Fresh
			pg.Offnet[g.GroupID] = g.Offnet
		}
		out = append(out, pg)
	}
	return out
}

// handleUsers applies an account change another member made (users.go).
func (c *Cluster) handleUsers(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var m core.UsersMsg
	if json.Unmarshal(body, &m) != nil || m.Op == "" {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	if m.Op == "list" { // a node that has just joined asks for the accounts
		b, _ := json.Marshal(map[string]any{"users": c.Mg.UsersExport()})
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(b)
		return
	}
	if err := c.Mg.UsersPeer(m, core.FirstNonEmpty(m.By, "a member")+" (via "+caller.Addr+")"); err != nil {
		core.JsonError(rw, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write([]byte(`{}`))
}

// learnPeerAddrs returns p with its alternative addresses brought up to date with the IP addresses the peer
// reported about itself (ips, without port): the IP alternatives are replaced by them, names are kept. ok is
// false when nothing changes. At most 12 alternatives are kept, as in refreshAlts.
func learnPeerAddrs(p core.ClusterPeer, ips []string) (core.ClusterPeer, bool) {
	_, port, err := net.SplitHostPort(p.Addr)
	if err != nil || len(ips) == 0 {
		return p, false
	}
	var alts []string
	for _, a := range p.Alts {
		if h, _, err := net.SplitHostPort(a); err == nil && net.ParseIP(h) == nil {
			alts = append(alts, a)
		}
	}
	var have []string
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			continue
		}
		a := net.JoinHostPort(ip, port)
		if a != p.Addr && !core.ContainsStr(alts, a) {
			have = append(have, a)
		}
	}
	alts = append(have, alts...)
	if len(alts) > 12 {
		alts = alts[:12]
	}
	if len(alts) == len(p.Alts) {
		same := true
		for i := range alts {
			if alts[i] != p.Alts[i] {
				same = false
			}
		}
		if same {
			return p, false
		}
	}
	p.Alts = alts
	return p, true
}

// knowsNode says whether a member with this node ID is already in the member list.
func (c *Cluster) knowsNode(id string) bool {
	for _, p := range c.Node.Snapshot().Peers {
		if p.NodeID == id {
			return true
		}
	}
	return false
}

// groupIDSet is the numbers of the gateways in a configuration.
func GroupIDSet(dc *core.DaemonConfig) map[int]bool {
	s := map[int]bool{}
	for _, g := range dc.Groups {
		s[g.GroupID] = true
	}
	return s
}

// PeerHandler answers a signed request from another node.
type PeerHandler func(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte)

// SetRoutes adds handlers that the layers above this one answer on the cluster port ("POST /cluster/proxy" -> handler),
// before the port is opened.  Each layer adds its own; a later call adds to the earlier ones.
func (c *Cluster) SetRoutes(routes map[string]PeerHandler) {
	c.Mu.Lock()
	if c.routes == nil {
		c.routes = map[string]PeerHandler{}
	}
	for p, h := range routes {
		c.routes[p] = h
	}
	c.Mu.Unlock()
}
