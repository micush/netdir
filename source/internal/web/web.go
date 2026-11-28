package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"netdir/internal/cluster"
	"netdir/internal/core"
	"netdir/internal/devices"
)

// webFS holds webui/ (the binary embeds it: embed.go).
var WebFS fs.FS

// failDelay slows down each failed login (a var so tests can shorten it).
var FailDelay = 400 * time.Millisecond

const SessionCookie = "__Host-netdir_session"

const sessionMaxAge = 12 * time.Hour

const groupRecheck = time.Minute

const maxBody = 1 << 20

const maxLoginBody = 4 << 10

const MaxUsernameLen = 128

const MaxFailKeys = 50000

const MaxLoginQueue = 32

// Authenticator checks passwords and group membership.  The production
// implementation is PAM + the system group database; tests substitute a fake.
type Authenticator interface {
	Authenticate(service, user, password string) error
	InGroup(user, group string) (bool, error)
}

type SysAuth struct{}

func (SysAuth) Authenticate(service, user, password string) error {
	return core.PamAuthenticate(service, user, password)
}

func (SysAuth) InGroup(username, group string) (bool, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return false, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	have := map[string]bool{}
	for _, id := range gids {
		have[id] = true
	}
	known := 0
	for _, name := range SplitGroups(group) {
		g, err := user.LookupGroup(name)
		if err != nil {
			continue // a group that does not exist here (the directory one on a node without a directory) is just empty
		}
		known++
		if have[g.Gid] {
			return true, nil
		}
	}
	if known == 0 {
		return false, fmt.Errorf("none of the groups %q exists on this machine", group)
	}
	return false, nil
}

// splitGroups is the login group setting as a list: names separated by commas (or spaces), without repeats.
func SplitGroups(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, g := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// WebServer is the HTTPS management GUI.  It runs inside the daemon and calls
// the supervisor directly, so everything the CLI can do is available to it.
type WebServer struct {
	Mg       WebHost `json:"-"`
	confPath string
	Status   StatusHost        `json:"-"`
	Auth     Authenticator     `json:"-"`
	Certs    *core.CertManager `json:"-"`

	Policy atomic.Pointer[core.WebConfig] `json:"-"` // live: group, pam_service, session idle

	Mu       sync.Mutex               `json:"-"`
	Sessions map[string]*core.Session `json:"-"` // by sessKey(cookie)
	StateDir string                   `json:"-"`
	noSave   atomic.Bool
	Fails    map[string]*core.FailRec `json:"-"`
	lockSeen map[string]time.Time     // when a refusal for a locked-out address was last logged (one line a minute, not one per try)
	LoginQ   chan struct{}            `json:"-"` // bounds the logins waiting for PAM

	sso      *ssoState
	applyMu  sync.Mutex
	mcpServe atomic.Pointer[http.HandlerFunc] // answers /mcp (the MCP layer sets it: SetMCP)
	Usage    *core.McpUsage                   `json:"-"` // what the MCP endpoint is used for (mcpusage.go)
	running  *core.WebConfig
	srv      *http.Server
	cancel   context.CancelFunc
}

// WebHost is what the web server needs from the management layer of its node (Mgmt).
type WebHost interface {
	LiveConfig() (*core.DaemonConfig, []byte, error)
	PutConfigBase(dc *core.DaemonConfig, actor, note, base string) error
	HoldBackFromNewGateways(dc *core.DaemonConfig, known map[int]bool)
	KeepNodePaused(dc *core.DaemonConfig)
	ConfigImport(raw []byte, actor, note string) (*core.DaemonConfig, error)
	VersionGet(id string) (cluster.VersionMeta, json.RawMessage, error)
	Op(cmd string, raw json.RawMessage, actor string) (any, error)
	UpdateUpload(body []byte, by string) (string, error)
	TshootNode(capture bool, actor string) ([]byte, error)
	TshootCluster(capture bool, actor string) ([]byte, error)
	CaptureClusterBundle() ([]byte, error)
	CapturePcap(limit int) (iface string, pcap []byte) // the buffer of this node's Capture page
	Cluster() *cluster.Cluster
	Updater() *core.Updater
	NodePaused() bool
	KnowsNodePause() bool
	Certs() *core.CertManager
	Backup() *core.BackupEngine
	StateDir() string
	ConfPath() string
	WebHandler() http.Handler                              // the web API, for requests relayed from other nodes and from MCP tools
	AttachWeb(w *WebServer, endSessions func(user string)) // the web server tells its node it is there
}

// StatusHost is what the web server needs from the status server of its node.
type StatusHost interface {
	Sup() *core.Supervisor
	MetricsText() string
	CanvasGroups() []core.CanvasGateway
	ViaServing(ctx context.Context, groups []core.CanvasGateway)
	AddPeerClients(ctx context.Context, groups []core.CanvasGateway)
	GatewaysVia(ctx context.Context, gs []core.GatewayGroup) []core.GatewayGroup
	IPNames() map[string]string
	Snapshot() []core.SnapshotRow
	AssertAGC() map[string]any
}

func NewWebServer(mg WebHost, status StatusHost, auth Authenticator) *WebServer {
	w := &WebServer{
		Mg: mg, confPath: mg.ConfPath(), Certs: mg.Certs(), Status: status, Auth: auth,
		Sessions: map[string]*core.Session{}, Fails: map[string]*core.FailRec{}, lockSeen: map[string]time.Time{},
		LoginQ: make(chan struct{}, MaxLoginQueue), sso: NewSSOState(),
	}
	d := core.DefaultWeb()
	w.Policy.Store(&d)
	w.StateDir = mg.StateDir()
	w.Usage = core.NewMCPUsage(w.StateDir)
	w.loadSessions()
	mg.AttachWeb(w, w.endSessionsFor)
	return w
}

// SetMCP gives the handler of /mcp (nil: there is none, and /mcp is not found).
func (w *WebServer) SetMCP(h http.HandlerFunc) {
	if h == nil {
		w.mcpServe.Store(nil)
		return
	}
	w.mcpServe.Store(&h)
}

func (w *WebServer) serveMCP(rw http.ResponseWriter, r *http.Request) {
	h := w.mcpServe.Load()
	if h == nil {
		http.NotFound(rw, r)
		return
	}
	(*h)(rw, r)
}

// endSessionsFor ends every session of user on this node.
func (w *WebServer) endSessionsFor(user string) {
	n := 0
	w.Mu.Lock()
	for k, s := range w.Sessions {
		if s.User == user {
			delete(w.Sessions, k)
			n++
		}
	}
	w.Mu.Unlock()
	if n > 0 {
		core.Infof("web: %d session(s) of %q ended (the account changed)", n, user)
		w.saveSessions()
	}
}

// ── lifecycle ────────────────────────────────────────────────────────────────

// Apply makes the listener match cfg: starts, stops or restarts it.  Policy
// fields (group, PAM service, idle timeout) take effect immediately.
func (w *WebServer) Apply(cfg core.WebConfig) {
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	c := cfg
	w.Policy.Store(&c)

	if w.running != nil && w.running.Listen == cfg.Listen {
		w.Certs.Refresh() // certificate changes apply live, no restart
		return
	}
	if w.running != nil {
		w.stopLocked()
		w.saveSessions() // the listener changed: everyone signs in again, and the file says so
	}
	if !core.PamAvailable {
		core.Errorf("web: GUI not started — this build has no PAM support (build natively with cgo and libpam0g-dev)")
		return
	}
	if err := w.Certs.Ensure(); err != nil {
		core.Errorf("web: GUI not started — TLS certificate: %v", err)
		return
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		core.Errorf("web: GUI not started — cannot listen on %s: %v", cfg.Listen, err)
		return
	}
	srv := &http.Server{
		Handler: w.Handler(),
		TLSConfig: &tls.Config{
			GetCertificate: w.Certs.GetCertificate,
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
	ctx, cancel := context.WithCancel(context.Background())
	w.srv, w.cancel = srv, cancel
	cc := cfg
	w.running = &cc
	core.WebServing.Store(true)
	ln = core.NoGatewayListener{Listener: ln, Blocked: w.isGatewayAddr} // the GUI is not served on a gateway address: /mcp has its own listener there
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			core.WebServing.Store(false) // a stop on purpose clears it in stopLocked, before any new listener starts
			core.Errorf("web: server stopped: %v", err)
		}
	}()
	go w.janitor(ctx)
	core.Infof("web: GUI listening on https://%s (login: members of group %q via PAM service %q)",
		cfg.Listen, cfg.Group, cfg.PAMService)
	w.sanityWarnings(cfg)
}

func (w *WebServer) sanityWarnings(cfg core.WebConfig) {
	found := 0
	for _, g := range SplitGroups(cfg.Group) {
		if _, err := user.LookupGroup(g); err == nil {
			found++
		}
	}
	if found == 0 {
		g := SplitGroups(cfg.Group)[0]
		core.Warnf("web: none of the login groups %q exists — nobody can log in. Create one and add users: groupadd %s; usermod -aG %s <user>",
			cfg.Group, g, g)
	}
	msg, err := fixSSSD(cfg.PAMService)
	if msg != "" && err == nil {
		core.Infof("web: sssd: %s", msg)
	}
	if err != nil {
		core.Warnf("web: sssd: %v", err)
	}
	if _, err := os.Stat("/etc/pam.d/" + cfg.PAMService); err != nil {
		core.Warnf("web: /etc/pam.d/%s not found — PAM will fall back to its 'other' policy, which usually denies every login (see contrib/pam.d/)", cfg.PAMService)
	}
}

func (w *WebServer) stopLocked() {
	core.WebServing.Store(false)
	if w.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		w.srv.Shutdown(ctx)
		cancel()
		w.srv.Close()
	}
	if w.cancel != nil {
		w.cancel()
	}
	w.srv, w.cancel, w.running = nil, nil, nil
	w.Mu.Lock()
	w.Sessions = map[string]*core.Session{} // a change of listener ends every session (the daemon stopping does not: see Stop)
	w.Mu.Unlock()
}

func (w *WebServer) Stop() {
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	w.noSave.Store(true) // the daemon is stopping, not signing anyone out: the file keeps the sessions
	w.stopLocked()
	w.Usage.Flush()
}

func (w *WebServer) janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			idle := w.Policy.Load().SessionIdle()
			w.Mu.Lock()
			for k, s := range w.Sessions {
				if now.Sub(s.Last) > idle || now.Sub(s.Created) > sessionMaxAge {
					delete(w.Sessions, k)
				}
			}
			pol := w.Policy.Load()
			for k, f := range w.Fails {
				if f.Inflight == 0 && now.After(f.Locked) && now.Sub(f.First) > pol.FailWindow() {
					delete(w.Fails, k)
				}
			}
			w.Mu.Unlock()
			w.saveSessions() // the idle times move with every request, so it is written once a minute
		}
	}
}

// ── routing ──────────────────────────────────────────────────────────────────

func (w *WebServer) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(WebFS, "webui")
	static := http.FileServerFS(sub)
	mux.Handle("GET /{$}", static)
	mux.HandleFunc("GET /app/{file}", serveAppJS)
	mux.Handle("GET /help.js", static)
	mux.HandleFunc("GET /metrics", w.HandleMetrics)
	mux.HandleFunc("/mcp", w.serveMCP) // the address decides (settings.mcp_acl); on a gateway address the MCP listener serves it (mcplisten.go), here only on the node's own
	mux.HandleFunc("GET /api/metrics/dashboard.json", w.authed(w.handleMetricsFile("grafana-dashboard.json", "application/json", "netdir-grafana-dashboard.json")))
	mux.HandleFunc("GET /api/metrics/alerts.yml", w.authed(w.handleMetricsFile("prometheus-alerts.yml", "application/yaml", "netdir-prometheus-alerts.yml")))
	mux.Handle("GET /style.css", static)

	mux.HandleFunc("POST /api/login", w.handleLogin)
	mux.HandleFunc("GET /api/login/state", w.handleLoginState)
	mux.HandleFunc("GET /api/sso/start", w.handleSSOStart)
	mux.HandleFunc("GET /api/sso/callback", w.handleSSOCallback)
	w.RegisterOAuth(mux, false) // MCP clients signing in with SSO (mcpoauth.go)
	mux.HandleFunc("POST /api/ldap/test", w.authed(w.handleLDAPTest))
	mux.HandleFunc("POST /api/logout", w.authed(w.handleLogout))
	mux.HandleFunc("GET /api/session", w.authed(w.handleSession))
	mux.HandleFunc("GET /api/gateways", w.authed(w.handleGateways))
	mux.HandleFunc("GET /api/neighbors", w.authed(w.handleNeighbors))
	mux.HandleFunc("GET /api/devices", w.authed(w.handleDevices))
	mux.HandleFunc("GET /api/devices/query", w.authed(w.HandleDeviceQuery))
	mux.HandleFunc("GET /api/canvas", w.authed(func(rw http.ResponseWriter, r *http.Request, s *core.Session) {
		t0 := time.Now()
		groups := w.Status.CanvasGroups()
		tLocal := time.Since(t0)
		var tVia, tPeers time.Duration
		if r.URL.Query().Get("own") == "" { // ?own=1: this node's own view, as asked by another node or by the sidebar
			t1 := time.Now()
			w.Status.ViaServing(r.Context(), groups)
			tVia = time.Since(t1)
			t2 := time.Now()
			w.Status.AddPeerClients(r.Context(), groups)
			tPeers = time.Since(t2)
		}
		if total := time.Since(t0); total > 2*time.Second { // the page is blank (no nodes, devices gray) until this answers: say which part took the time
			core.Warnf("web: /api/canvas took %s for %q (this node %s, the nodes that serve its gateways %s, their callers %s)", total.Round(100*time.Millisecond), s.User,
				tLocal.Round(100*time.Millisecond), tVia.Round(100*time.Millisecond), tPeers.Round(100*time.Millisecond))
		}
		if sc := devices.ScopeOf(s); sc.Limited() {
			keep := groups[:0]
			for _, g := range groups {
				if sc.AllowsGateway(g.GroupID) {
					keep = append(keep, g)
				}
			}
			groups = keep
		}
		core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": groups, "dnsdir": core.DnsdirInfo()})
	}))
	mux.HandleFunc("POST /api/assert-agc", w.authed(w.handleAssertAGC))
	mux.HandleFunc("GET /api/config", w.authed(w.handleGetConfig))
	mux.HandleFunc("PUT /api/config", w.authed(w.handlePutConfig))
	// raw uploads (release archive) are relayed too, so no JSON content-type rule here
	mux.HandleFunc("/api/proxy", w.authedCT(w.handleProxy, false))
	w.mgmtRoutes(mux)
	mux.HandleFunc("/api/", func(rw http.ResponseWriter, r *http.Request) {
		core.JsonError(rw, http.StatusNotFound, "not found")
	})
	return secure(mux)
}

// secure sets defensive headers on every response.  Scripts and styles are
// same-origin files only (no inline code), which the CSP enforces.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "+
			"img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(rw, r)
	})
}

// appJS holds the GUI's scripts (webui/app/*.js) with the daemon's version put in where they say @@BUILD@@: a page left open
// across an upgrade then knows it was loaded from an older daemon and reloads itself (see checkBuild in app/core.js).
var appJS = sync.OnceValue(func() map[string][]byte {
	out := map[string][]byte{}
	es, _ := fs.ReadDir(WebFS, "webui/app")
	for _, e := range es {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		b, _ := fs.ReadFile(WebFS, "webui/app/"+e.Name())
		out[e.Name()] = bytes.ReplaceAll(b, []byte("@@BUILD@@"), []byte(core.Version()))
	}
	return out
})

// serveAppJS answers GET /app/{file}.
func serveAppJS(rw http.ResponseWriter, r *http.Request) {
	b, ok := appJS()[r.PathValue("file")]
	if !ok {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	rw.Write(b)
}

type ctxKey struct{}

// authed requires a valid session and, for state-changing methods, a matching
// CSRF token, a JSON content type and a same-origin Origin header.
func (w *WebServer) authed(h func(http.ResponseWriter, *http.Request, *core.Session)) http.HandlerFunc {
	return w.authedCT(h, true)
}

// authedCT is authed with the content-type rule optional: the release-archive
// upload sends raw bytes (the CSRF token and same-origin checks still apply).
func (w *WebServer) authedCT(h func(http.ResponseWriter, *http.Request, *core.Session), requireJSON bool) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		// a request relayed by another cluster node: it was authenticated by the
		// signed cluster channel and the user was authenticated where they logged
		// in.  The context value can only be set in-process.
		if ps, ok := r.Context().Value(ProxyCtxKey{}).(*core.Session); ok {
			if w.ro(ps) && readOnlyDenied(r) && !readOnlyJob(r) {
				core.JsonError(rw, http.StatusForbidden, ReadOnlyMsg)
				return
			}
			h(rw, r, ps)
			return
		}
		s := w.Lookup(r)
		if s == nil {
			core.JsonError(rw, http.StatusUnauthorized, "not logged in")
			return
		}
		if w.ro(s) && readOnlyDenied(r) {
			core.JsonError(rw, http.StatusForbidden, ReadOnlyMsg)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				core.JsonError(rw, http.StatusForbidden, "cross-origin request refused")
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.Csrf)) != 1 {
				core.JsonError(rw, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
			if requireJSON && r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				core.JsonError(rw, http.StatusUnsupportedMediaType, "content type must be application/json")
				return
			}
		}
		h(rw, r, s)
	}
}

func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // non-browser client; CSRF token still required
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

// lookup returns the live session for the request cookie, refreshing its idle
// timer, or nil.  Group membership is re-checked periodically so removing a
// user from the group ends their session.
func (w *WebServer) Lookup(r *http.Request) *core.Session {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	pol := w.Policy.Load()
	now := time.Now()
	w.Mu.Lock()
	key := SessKey(c.Value)
	s := w.Sessions[key]
	if s == nil {
		w.Mu.Unlock()
		return nil
	}
	if now.Sub(s.Last) > pol.SessionIdle() || now.Sub(s.Created) > sessionMaxAge {
		delete(w.Sessions, key)
		user, ip := s.User, s.Ip
		w.Mu.Unlock()
		core.Infof("web: logout: %q signed out (session expired; signed in from %s)", user, core.FirstNonEmpty(ip, "an unknown address"))
		return nil
	}
	s.Last = now
	recheck := now.Sub(s.Checked) > groupRecheck
	uname := s.User
	w.Mu.Unlock()

	if recheck {
		var ok, ro bool
		var err error
		if s.Sso {
			ok, ro = pol.SsoLevel(uname, s.SsoProv)
		} else if s.Ldap && pol.LDAPConfig.Enabled() && !pol.LDAPConfig.HasBind() {
			ok, ro = true, w.ro(s) // no service account: there is nothing to look the person up with, the session runs its course
		} else if s.Ldap {
			o := pol.LDAPConfig.LdapFind(uname, "", false)
			ok, ro = o.OK, o.ReadOnly
			if o.Failed { // the directory could not be asked: the session stays until it can be
				core.Warnf("web: ldap: could not recheck %q, the session stays for now: %s", uname, o.Reason())
				ok, ro = true, w.ro(s)
			}
		} else {
			ok, ro, err = w.access(uname, pol)
		}
		if err != nil || !ok {
			core.Warnf("web: session for %q ended — no longer in group %q (signed in from %s)", uname, pol.Group, core.FirstNonEmpty(s.Ip, "an unknown address"))
			w.Mu.Lock()
			delete(w.Sessions, key)
			w.Mu.Unlock()
			return nil
		}
		w.Mu.Lock()
		s.Checked = now
		s.ReadOnly = ro
		w.Mu.Unlock()
	}
	return s
}

func RandToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ── login / logout ───────────────────────────────────────────────────────────

func validUsername(u string) bool {
	if u == "" || len(u) > MaxUsernameLen {
		return false
	}
	for _, c := range u {
		if unicode.IsControl(c) || c == ':' || c == '/' {
			return false
		}
	}
	return true
}

// loginKeys are what a login attempt is counted against: the address, and the address together with the user
// name.  There is deliberately no key for the user name alone: that would let anyone who can reach the page lock
// a known administrator out by failing a few logins for that name.
func LoginKeys(ip, user string) []string {
	return []string{"ip:" + ip, "ipuser:" + ip + "|" + strings.ToLower(user)}
}

// failRecLocked returns the record of key, started afresh when its window has run out; nil when it does not
// exist and none may be created (w.mu held).  Records of a user name seen from an address are not created once
// maxFailKeys are held, after the expired ones are swept; the per-address record always is (an address cannot be
// invented the way a user name can).
func (w *WebServer) failRecLocked(k string, now time.Time, pol *core.WebConfig, create bool) *core.FailRec {
	f := w.Fails[k]
	if f != nil {
		if f.Inflight == 0 && now.After(f.Locked) && now.Sub(f.First) > pol.FailWindow() {
			f.Count, f.First = 0, now
		}
		return f
	}
	if !create {
		return nil
	}
	if len(w.Fails) >= MaxFailKeys {
		for kk, ff := range w.Fails {
			if ff.Inflight == 0 && now.After(ff.Locked) && now.Sub(ff.First) > pol.FailWindow() {
				delete(w.Fails, kk)
			}
		}
		if len(w.Fails) >= MaxFailKeys && strings.HasPrefix(k, "ipuser:") {
			return nil
		}
	}
	f = &core.FailRec{First: now}
	w.Fails[k] = f
	return f
}

// throttled reports whether any of keys is currently locked out.
func (w *WebServer) Throttled(keys ...string) (time.Duration, bool) {
	now := time.Now()
	w.Mu.Lock()
	defer w.Mu.Unlock()
	for _, k := range keys {
		if f := w.Fails[k]; f != nil && now.Before(f.Locked) {
			return f.Locked.Sub(now), true
		}
	}
	return 0, false
}

// reserve claims one login attempt on every key before PAM is asked.  The lockout used to be checked first and
// the failure recorded only after PAM answered, so any number of parallel requests all passed the check and got
// a guess each.  Now the failures counted so far plus the attempts under way may not reach the limit: a request
// that would exceed it is refused (ok false, with how long to wait) without PAM being consulted.  A granted
// reservation is given back with release, which is also where a failure is counted.
func (w *WebServer) Reserve(keys ...string) (wait time.Duration, ok bool) {
	pol := w.Policy.Load()
	now := time.Now()
	w.Mu.Lock()
	defer w.Mu.Unlock()
	var got []*core.FailRec
	for _, k := range keys {
		f := w.failRecLocked(k, now, pol, true)
		if f == nil {
			continue
		}
		if now.Before(f.Locked) {
			wait = f.Locked.Sub(now)
		} else if f.Count+f.Inflight >= pol.MaxFailedLogins {
			wait = time.Second // attempts already under way may use up the allowance: try again shortly
		}
		if wait > 0 {
			for _, g := range got {
				g.Inflight--
			}
			return wait, false
		}
		f.Inflight++
		got = append(got, f)
	}
	return 0, true
}

// release ends a reservation made by reserve; failed counts the attempt as a failed login on every key and
// reports, if one of them is now locked out, for how long.  The number of attempts still allowed is deliberately
// not reported to anyone: it would tell a guesser how many tries it has.
func (w *WebServer) Release(failed bool, keys ...string) (lockedFor time.Duration) {
	pol := w.Policy.Load()
	now := time.Now()
	w.Mu.Lock()
	defer w.Mu.Unlock()
	for _, k := range keys {
		f := w.Fails[k]
		if f == nil {
			continue
		}
		if f.Inflight > 0 {
			f.Inflight--
		}
		if !failed {
			continue
		}
		if now.Sub(f.First) > pol.FailWindow() && !now.Before(f.Locked) {
			f.Count, f.First = 0, now
		}
		f.Count++
		if f.Count >= pol.MaxFailedLogins {
			f.Locked = now.Add(pol.Lockout())
			f.Count = 0
			f.First = now
		}
		if now.Before(f.Locked) {
			if d := f.Locked.Sub(now); d > lockedFor {
				lockedFor = d
			}
		}
	}
	return lockedFor
}

// loginState tells the login page whether the caller's address is locked out.
func (w *WebServer) handleLoginState(rw http.ResponseWriter, r *http.Request) {
	wait, locked := w.Throttled("ip:" + core.ClientIP(r))
	// Only whether this address is locked and for how long: the thresholds of the policy are not
	// told to someone who is not logged in.
	out := map[string]any{"ok": true, "locked": locked}
	var sso []map[string]string
	for _, p := range w.SsoCfg().Providers() {
		sso = append(sso, map[string]string{"id": p.Id, "title": p.Title})
	}
	if len(sso) > 0 {
		out["sso"] = sso
	}
	if locked {
		out["retry_after"] = int(wait.Seconds()) + 1
	}
	core.WriteJSON(rw, http.StatusOK, out)
}

func lockoutError(rw http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	rw.Header().Set("Retry-After", core.Itoa(secs))
	core.WriteJSON(rw, http.StatusTooManyRequests, map[string]any{
		"ok": false, "error": "Too many failed attempts.", "retry_after": secs})
}

func (w *WebServer) clearFailures(keys ...string) {
	w.Mu.Lock()
	for _, k := range keys {
		if f := w.Fails[k]; f != nil && f.Inflight == 0 {
			delete(w.Fails, k)
		} else if f != nil {
			f.Count = 0
		}
	}
	w.Mu.Unlock()
}

func (w *WebServer) handleLogin(rw http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		core.Warnf("web: login refused from %s: cross-origin request (Origin %q)", core.ClientIP(r), r.Header.Get("Origin"))
		core.JsonError(rw, http.StatusForbidden, "cross-origin request refused")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !core.ReadJSON(rw, r, maxLoginBody, &req) {
		return
	}
	ip := core.ClientIP(r)
	keys := LoginKeys(ip, req.Username)
	select {
	case w.LoginQ <- struct{}{}:
		defer func() { <-w.LoginQ }()
	default:
		core.Warnf("web: login refused from %s: too many logins at once", ip)
		rw.Header().Set("Retry-After", "2")
		core.JsonError(rw, http.StatusServiceUnavailable, "Too many logins at once; try again in a moment.")
		return
	}
	if wait, ok := w.Reserve(keys...); !ok {
		w.logLockedOut(ip, req.Username, wait)
		lockoutError(rw, wait)
		return
	}
	pol := w.Policy.Load()

	var reason string
	var readOnly, viaLDAP bool
	switch {
	case !validUsername(req.Username) || req.Password == "":
		reason = "malformed credentials"
	default:
		granted := false
		if err := w.Auth.Authenticate(pol.PAMService, req.Username, req.Password); err != nil {
			reason = "authentication failed: " + err.Error()
			if strings.HasPrefix(err.Error(), "pam account check") {
				if msg := sssdGPOProblem(pol.PAMService); msg != "" {
					reason += " (" + msg + ")"
				}
			}
		} else if ok, ro, err := w.access(req.Username, pol); err != nil {
			reason = "group lookup failed: " + err.Error()
		} else if !ok {
			reason = "not a member of group " + pol.Group
		} else {
			readOnly, granted = ro, true
		}
		if !granted && pol.LDAPConfig.Enabled() { // not a host account: the directory is asked
			if o := pol.LDAPConfig.LdapFind(req.Username, req.Password, true); o.OK {
				readOnly, viaLDAP, reason = o.ReadOnly, true, ""
			} else {
				reason += "; LDAP: " + o.Reason()
			}
		}
	}
	if reason != "" {
		lockedFor := w.Release(true, keys...)
		core.Warnf("web: login failed for %q from %s: %s", req.Username, ip, reason)
		time.Sleep(FailDelay)
		if lockedFor > 0 {
			core.Warnf("web: locking out %q from %s for %s after repeated failed logins", req.Username, ip, lockedFor.Round(time.Second))
			lockoutError(rw, lockedFor)
			return
		}
		// One message for every cause: don't reveal which part was wrong, which group is needed or
		// how many attempts are left.
		core.WriteJSON(rw, http.StatusUnauthorized, map[string]any{"ok": false,
			"error": "Login failed: wrong username or password, or not authorized."})
		return
	}
	w.Release(false, keys...)
	w.clearFailures(keys...)

	now := time.Now()
	s := &core.Session{User: req.Username, Csrf: RandToken(), Created: now, Last: now, Checked: now, ReadOnly: readOnly, Ip: ip, Ldap: viaLDAP}
	tok := RandToken()
	w.Mu.Lock()
	w.Sessions[SessKey(tok)] = s
	w.Mu.Unlock()
	w.saveSessions()
	http.SetCookie(rw, &http.Cookie{
		Name: SessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMaxAge.Seconds()),
	})
	if viaLDAP {
		core.Infof("web: login: %q signed in with LDAP from %s (%s)", req.Username, ip, AccessWord(readOnly))
	} else {
		core.Infof("web: login: %q signed in from %s (%s)", req.Username, ip, AccessWord(readOnly))
	}
	core.WriteJSON(rw, http.StatusOK, w.sessionInfo(s))
}

func (w *WebServer) handleLogout(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		w.Mu.Lock()
		delete(w.Sessions, SessKey(c.Value))
		w.Mu.Unlock()
		w.saveSessions()
	}
	http.SetCookie(rw, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	core.Infof("web: logout: %q signed out from %s (signed in from %s)", s.User, core.ClientIP(r), core.FirstNonEmpty(s.Ip, "an unknown address"))
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) sessionInfo(s *core.Session) map[string]any {
	host, _ := os.Hostname()
	return map[string]any{
		"ok": true, "user": s.User, "csrf": s.Csrf, "version": core.Version(),
		"hostname": host, "config_path": w.confPath,
		"idle_minutes": w.Policy.Load().SessionIdleMinutes, "read_only": w.ro(s), "sso": s.Sso,
	}
}

func (w *WebServer) handleSession(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	core.WriteJSON(rw, http.StatusOK, w.sessionInfo(s))
}

// ── read-only views (CLI: --show-gateways / --show-neighbors) ──

func (w *WebServer) handleGateways(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	gs := core.BuildGateways(w.Status.Snapshot())
	core.NameMembers(gs, w.Status.IPNames())
	core.NameGateways(gs, w.Status.Sup().Config())
	if sc := devices.ScopeOf(s); sc.Limited() { // a key or address limited to some devices sees the gateways it was given (devscope.go)
		keep := gs[:0]
		for _, g := range gs {
			if sc.AllowsGateway(g.GroupID) {
				keep = append(keep, g)
			}
		}
		gs = keep
	}
	if r.URL.Query().Get("own") == "" { // ?own=1: only what this node runs, as asked by another node
		gs = w.Status.GatewaysVia(r.Context(), gs)
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": gs})
}

func (w *WebServer) handleNeighbors(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	rows := w.Status.Snapshot()
	if r.URL.Query().Get("all") == "1" { // the Nodes page lists this node too
		core.SortRows(rows)
		core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": rows})
		return
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": core.PeersOnly(rows)})
}

// ── actions (CLI: --assert-agc) ──────────────────────────────────────────────

func (w *WebServer) handleAssertAGC(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	core.Warnf("web: %q asserted AGC on this node (from %s)", s.User, core.ClientIP(r))
	core.WriteJSON(rw, http.StatusOK, w.Status.AssertAGC())
}

// ── configuration (CLI: --show-config / --configure) ────────────────────────

func (w *WebServer) handleGetConfig(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	_, statErr := os.Stat(w.confPath)
	dc, err := core.LoadConfig(w.confPath)
	if err != nil {
		core.JsonError(rw, http.StatusInternalServerError, err.Error())
		return
	}
	var out any = dc
	if w.ro(s) {
		out = redactSecrets(dc) // a read-only account sees the settings, not the keys and passwords in them
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{
		"ok": true, "path": w.confPath, "exists": statErr == nil, "config": out, "base": core.ConfigBase(dc),
	})
}

func (w *WebServer) handlePutConfig(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	var req struct {
		Config json.RawMessage `json:"config"`
		Note   string          `json:"note"`
		Base   string          `json:"base"` // what the page read the configuration as (GET /api/config): refused when the shared settings have changed since
	}
	if !core.ReadJSON(rw, r, maxBody, &req) {
		return
	}
	if len(req.Config) == 0 {
		core.JsonError(rw, http.StatusBadRequest, "missing \"config\"")
		return
	}
	dc := core.NewDaemonConfig()
	if err := json.Unmarshal(req.Config, dc); err != nil {
		core.JsonError(rw, http.StatusBadRequest, "invalid config: "+err.Error())
		return
	}
	if err := dc.Validate(); err != nil {
		core.JsonError(rw, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if r.URL.Query().Get("dry_run") == "1" {
		core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "dry_run": true, "config": dc})
		return
	}

	// Every save says what it read (base).  One that does not comes from a page run by an older version (a Configure tab left open
	// across an update keeps its old code: it saved its old copy of the devices over an import) or from a script that never read it:
	// refused, so that nothing is overwritten without the writer knowing what it replaces.  A script that means to replace the
	// configuration says so with base "force".
	base := req.Base
	switch base {
	case "":
		core.Warnf("web: %q save refused: it carries no base (a page from an older version, or a script) (from %s)", s.User, core.ClientIP(r))
		core.JsonError(rw, http.StatusConflict, "this page is older than the daemon (it does not say which configuration it read): reload it (Ctrl+F5) and make the change again. Nothing was saved. A script that means to replace the configuration sends \"base\": \"force\".")
		return
	case "force":
		base = ""
	}
	core.Infof("web: %q saving %s (from %s)", s.User, w.confPath, core.ClientIP(r))
	w.Mg.KeepNodePaused(dc) // the page's copy may be older than the last pause or resume of this node
	if cur, _, err := w.Mg.LiveConfig(); err == nil {
		w.Mg.HoldBackFromNewGateways(dc, cluster.GroupIDSet(cur)) // a gateway made on this page runs on this node only
	}
	if err := w.Mg.PutConfigBase(dc, s.User, req.Note, base); err != nil {
		if errors.Is(err, core.ErrConfigChanged) {
			core.Warnf("web: %q save refused: the configuration changed since their page read it (from %s)", s.User, core.ClientIP(r))
			core.JsonError(rw, http.StatusConflict, err.Error())
			return
		}
		core.JsonError(rw, http.StatusInternalServerError, err.Error())
		return
	}
	newBase := core.ConfigBase(dc)
	if saved, _, err := w.Mg.LiveConfig(); err == nil {
		newBase = core.ConfigBase(saved)
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "config": dc, "base": newBase})
}

// logLockedOut records a login attempt that was refused because the address or the name is locked out: once a
// minute for each, so a guessing run is visible in the log without filling it.
func (w *WebServer) logLockedOut(ip, name string, wait time.Duration) {
	key := ip + "|" + name
	now := time.Now()
	w.Mu.Lock()
	last, seen := w.lockSeen[key]
	if seen && now.Sub(last) <= time.Minute {
		w.Mu.Unlock()
		return
	}
	if len(w.lockSeen) > 1000 {
		w.lockSeen = map[string]time.Time{}
	}
	w.lockSeen[key] = now
	w.Mu.Unlock()
	core.Warnf("web: login refused for %q from %s: locked out for another %s", name, ip, wait.Round(time.Second))
}

// handleLDAPTest tries the directory settings as saved and says what happened, step by step: with a user name (and a
// password) it does what a sign-in does, without a user name it only connects and binds the service account.
func (w *WebServer) handleLDAPTest(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !core.ReadJSON(rw, r, maxLoginBody, &req) {
		return
	}
	cfg := w.Policy.Load().LDAPConfig
	var o *core.LdapOutcome
	switch {
	case !cfg.Enabled():
		o = &core.LdapOutcome{Steps: []string{"LDAP is not set up yet: it needs a server, a search base and at least one group (and a bind account together with its password, or neither)"}}
	case strings.TrimSpace(req.Username) == "":
		o = &core.LdapOutcome{}
		if lc := cfg.LdapConnect(o); lc != nil {
			lc.Close()
			o.OK = true
			o.Step("the settings work; give a user name and password to try a person")
		}
	case req.Password == "" && !cfg.HasBind():
		o = &core.LdapOutcome{Steps: []string{"there is no bind account, so a person can only be tried with their password"}}
	default:
		o = cfg.LdapFind(strings.TrimSpace(req.Username), req.Password, req.Password != "")
		if o.OK && req.Password == "" {
			o.Step("no password was given, so it was not checked")
		}
	}
	core.Infof("web: ldap test by %q: ok=%v", s.User, o.OK)
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"ok": o.OK, "read_only": o.ReadOnly, "steps": o.Steps}})
}
