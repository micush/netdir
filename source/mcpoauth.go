package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// MCP sign-in with single sign-on: netdir is a small OAuth 2.1 authorization server for its own /mcp endpoint, as the MCP
// authorization specification asks (protected-resource and authorization-server metadata, dynamic client registration,
// authorization code with PKCE, refresh tokens).  A person is identified by the SSO login that already exists for the
// console (sso.go: Google, Microsoft Entra ID, any OpenID Connect provider) and gets the access written beside their
// address in settings.sso_users (ro or rw).  It is off unless sso_mcp is set and at least one provider and one user is
// set up; keys and the address list work as before.
//
// Nothing is stored.  Every client ID, flow state, code and token is a self-contained value, authenticated (or, for the
// flow state, encrypted) with a key derived from the cluster secret, so a node that did not hand a token out accepts it
// and a gateway address that moves between nodes in the middle of a sign-in does not break it.  Revocation is by the list:
// every request looks the address up in sso_users again, so removing it (or switching sso_mcp off) ends its access at once.
// Resetting the cluster secret ends every token.  A code is single use on the node that sees it first.
//
// The browser's part is /oauth/authorize (to the provider and back through /api/sso/callback on the MCP address, which
// must be registered with the provider like the console's own callback) and one page asking the person to allow the
// client, because anybody may register a client and a client's redirect address is where the code goes.

const (
	oauthPrefix     = "nd1."
	oauthStatePref  = "nds1."
	oauthAccessTTL  = time.Hour
	oauthRefreshTTL = 30 * 24 * time.Hour
	oauthRefreshMax = 90 * 24 * time.Hour // a refresh chain ends this long after the sign-in
	oauthCodeTTL    = time.Minute
	oauthFlowTTL    = 10 * time.Minute
	oauthConsentTTL = 5 * time.Minute
	oauthClientTTL  = 400 * 24 * time.Hour
	oauthMaxURIs    = 5
	oauthMaxURILen  = 300
	oauthMaxState   = 256
)

// oauthTok is the one shape every signed or sealed value has; each kind uses some of the fields.
type oauthTok struct {
	X  int64    `json:"x"`           // expires (unix seconds)
	E  string   `json:"e,omitempty"` // the person's e-mail address
	P  string   `json:"p,omitempty"` // the provider they signed in with (google, entra, oidc)
	C  string   `json:"c,omitempty"` // hash of the client ID
	R  string   `json:"r,omitempty"` // the client's redirect address
	Ch string   `json:"h,omitempty"` // PKCE challenge
	S  string   `json:"s,omitempty"` // the client's state
	M  string   `json:"m,omitempty"` // the client's name
	N  string   `json:"n,omitempty"` // nonce (flow) or unique id (code)
	V  string   `json:"v,omitempty"` // PKCE verifier of the provider leg (sealed state only)
	B  string   `json:"b,omitempty"` // the callback address registered with the provider
	O  int64    `json:"o,omitempty"` // when the sign-in was made (refresh chain)
	U  []string `json:"u,omitempty"` // registered redirect addresses (client ID)
}

// oauthLocal is the signing secret of a node that has no cluster node (tests); it lives as long as the process.
var oauthLocal = struct {
	once sync.Once
	b    []byte
}{}

func (w *WebServer) oauthKey(purpose string) []byte {
	var sec []byte
	if w.mg != nil && w.mg.cl != nil && w.mg.cl.node != nil {
		sec = w.mg.cl.node.Secret()
	}
	if len(sec) == 0 {
		oauthLocal.once.Do(func() { oauthLocal.b = make([]byte, 32); rand.Read(oauthLocal.b) })
		sec = oauthLocal.b
	}
	m := hmac.New(sha256.New, sec)
	m.Write([]byte("netdir-mcp-oauth-v1/" + purpose))
	return m.Sum(nil)
}

func (w *WebServer) oauthSign(kind string, t oauthTok) string {
	b, _ := json.Marshal(t)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, w.oauthKey("sign"))
	m.Write([]byte(kind + "." + p))
	return oauthPrefix + kind + "." + p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

var errOAuthBad = errors.New("not a valid token")
var errOAuthExpired = errors.New("the token has expired")

func (w *WebServer) oauthVerify(kind, tok string, now time.Time) (oauthTok, error) {
	var t oauthTok
	rest, ok := strings.CutPrefix(tok, oauthPrefix+kind+".")
	if !ok {
		return t, errOAuthBad
	}
	i := strings.LastIndexByte(rest, '.')
	if i < 0 {
		return t, errOAuthBad
	}
	p, mac := rest[:i], rest[i+1:]
	got, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil {
		return t, errOAuthBad
	}
	m := hmac.New(sha256.New, w.oauthKey("sign"))
	m.Write([]byte(kind + "." + p))
	if subtle.ConstantTimeCompare(got, m.Sum(nil)) != 1 {
		return t, errOAuthBad
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, errOAuthBad
	}
	if t.X == 0 || now.Unix() >= t.X {
		return t, errOAuthExpired
	}
	return t, nil
}

// oauthSeal encrypts a value for the browser to carry through the provider (it holds the PKCE verifier of that leg).
func (w *WebServer) oauthSeal(t oauthTok) string {
	b, _ := json.Marshal(t)
	blk, _ := aes.NewCipher(w.oauthKey("seal"))
	g, _ := cipher.NewGCM(blk)
	n := make([]byte, g.NonceSize())
	rand.Read(n)
	return oauthStatePref + base64.RawURLEncoding.EncodeToString(g.Seal(n, n, b, []byte("state")))
}

func (w *WebServer) oauthOpen(s string, now time.Time) (oauthTok, error) {
	var t oauthTok
	rest, ok := strings.CutPrefix(s, oauthStatePref)
	if !ok {
		return t, errOAuthBad
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	blk, _ := aes.NewCipher(w.oauthKey("seal"))
	g, _ := cipher.NewGCM(blk)
	if err != nil || len(raw) < g.NonceSize()+g.Overhead() {
		return t, errOAuthBad
	}
	b, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("state"))
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, errOAuthBad
	}
	if t.X == 0 || now.Unix() >= t.X {
		return t, errOAuthExpired
	}
	return t, nil
}

// oauthOn says whether MCP clients may sign in with SSO: switched on, with a provider and somebody who may.
func (w *WebServer) oauthOn() bool {
	c := w.ssoCfg()
	return c.MCPSignIn && len(c.Users) > 0 && len(c.providers()) > 0
}

// oauthBase is this server's own address as the client reached it.
func oauthBase(r *http.Request) string {
	if r.Host == "" || strings.ContainsAny(r.Host, " /\\@?#\t\r\n") {
		return ""
	}
	return "https://" + r.Host
}

func oauthCID(clientID string) string {
	h := sha256.Sum256([]byte(clientID))
	return base64.RawURLEncoding.EncodeToString(h[:12])
}

// oauthAccess checks an access token and says who it is for and what they may do now.
func (w *WebServer) oauthAccess(tok string) (email, prov string, readOnly bool, err error) {
	if !w.oauthOn() {
		return "", "", false, errOAuthBad
	}
	t, err := w.oauthVerify("at", tok, time.Now())
	if err != nil {
		return "", "", false, err
	}
	ok, ro := w.ssoCfg().ssoLevel(t.E, t.P)
	if !ok || w.ssoCfg().provider(t.P) == nil {
		return "", "", false, errors.New("this person may no longer sign in")
	}
	return t.E, t.P, ro, nil
}

// mcpChallenge sets the WWW-Authenticate header of a refusal; with SSO on it names the metadata a client starts from.
func (w *WebServer) mcpChallenge(rw http.ResponseWriter, r *http.Request, errCode string) {
	v := `Bearer realm="mcp"`
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	if w.oauthOn() {
		if b := oauthBase(r); b != "" {
			v += `, resource_metadata="` + b + `/.well-known/oauth-protected-resource"`
		}
	}
	rw.Header().Set("WWW-Authenticate", v)
}

// ---- routes ----

// registerOAuth adds the sign-in routes.  The MCP listeners on the gateway addresses serve only /mcp, so they get these
// too, with the callback of the provider (the console's own route has the same path and takes both kinds of sign-in).
func (w *WebServer) registerOAuth(mux *http.ServeMux, callback bool) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", w.handleOAuthResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", w.handleOAuthResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", w.handleOAuthMetadata)
	mux.HandleFunc("POST /oauth/register", w.handleOAuthRegister)
	mux.HandleFunc("GET /oauth/authorize", w.handleOAuthAuthorize)
	mux.HandleFunc("POST /oauth/consent", w.handleOAuthConsent)
	mux.HandleFunc("POST /oauth/token", w.handleOAuthToken)
	if callback {
		mux.HandleFunc("GET /api/sso/callback", w.handleOAuthCallbackOnly)
	}
}

func oauthJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(code)
	json.NewEncoder(rw).Encode(v)
}

func oauthErr(rw http.ResponseWriter, code int, e, desc string) {
	oauthJSON(rw, code, map[string]string{"error": e, "error_description": desc})
}

// oauthPage writes a small page with no style, no script and nothing loaded (the front-end rules of CLAUDE.md); its policy
// sets no form-action, because the answer to the allow form is a redirect to the client's address and some browsers apply
// form-action to redirects too.
func oauthPage(rw http.ResponseWriter, code int, title, body string) {
	h := rw.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	rw.WriteHeader(code)
	fmt.Fprintf(rw, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
</head><body>%s</body></html>`,
		html.EscapeString(title), body)
}

func oauthFailPage(rw http.ResponseWriter, code int, msg string) {
	oauthPage(rw, code, "netdir sign-in", `<h1>Sign-in not possible</h1><p>`+html.EscapeString(msg)+`</p>`)
}

func (w *WebServer) handleOAuthResource(rw http.ResponseWriter, r *http.Request) {
	b := oauthBase(r)
	if b == "" || !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	oauthJSON(rw, http.StatusOK, map[string]any{
		"resource": b + "/mcp", "authorization_servers": []string{b},
		"bearer_methods_supported": []string{"header"}, "resource_name": "netdir MCP",
	})
}

func (w *WebServer) handleOAuthMetadata(rw http.ResponseWriter, r *http.Request) {
	b := oauthBase(r)
	if b == "" || !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	oauthJSON(rw, http.StatusOK, map[string]any{
		"issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": b + "/oauth/token",
		"registration_endpoint":    b + "/oauth/register",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// ---- clients ----

var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// oauthRedirectOK says whether an address may be a client's redirect: https, http on this machine, or a private-use scheme
// named by a reverse domain name (RFC 8252).
func oauthRedirectOK(s string) bool {
	if s == "" || len(s) > oauthMaxURILen || strings.ContainsAny(s, " \t\r\n\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Fragment != "" || u.User != nil || u.Scheme == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		return loopbackHosts[u.Hostname()]
	case "javascript", "data", "file", "vbscript", "blob", "about", "ftp", "ws", "wss":
		return false
	}
	return strings.Contains(u.Scheme, ".")
}

// oauthRedirectMatches: the address is one registered, or a loopback address that differs from one only in its port.
func oauthRedirectMatches(reg []string, got string) bool {
	if !oauthRedirectOK(got) {
		return false
	}
	gu, _ := url.Parse(got)
	for _, r := range reg {
		if r == got {
			return true
		}
		ru, err := url.Parse(r)
		if err != nil || ru.Scheme != "http" || gu.Scheme != "http" || !loopbackHosts[ru.Hostname()] || !loopbackHosts[gu.Hostname()] {
			continue
		}
		if ru.Hostname() == gu.Hostname() && ru.Path == gu.Path && ru.RawQuery == gu.RawQuery {
			return true
		}
	}
	return false
}

func oauthCleanName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) || r == '<' || r == '>' {
			continue
		}
		b.WriteRune(r)
		if n++; n >= 60 {
			break
		}
	}
	if b.Len() == 0 {
		return "an MCP client"
	}
	return b.String()
}

func (w *WebServer) handleOAuthRegister(rw http.ResponseWriter, r *http.Request) {
	if !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		oauthErr(rw, http.StatusBadRequest, "invalid_client_metadata", "the request is not JSON")
		return
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > oauthMaxURIs {
		oauthErr(rw, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("give 1 to %d redirect_uris", oauthMaxURIs))
		return
	}
	for _, u := range in.RedirectURIs {
		if !oauthRedirectOK(u) {
			oauthErr(rw, http.StatusBadRequest, "invalid_redirect_uri", "a redirect_uri must be https, http on this machine (localhost, 127.0.0.1, [::1]) or a private-use scheme with a dot in it")
			return
		}
	}
	if in.AuthMethod != "" && in.AuthMethod != "none" {
		oauthErr(rw, http.StatusBadRequest, "invalid_client_metadata", "only public clients are supported (token_endpoint_auth_method none, with PKCE)")
		return
	}
	now := time.Now()
	name := oauthCleanName(in.ClientName)
	id := w.oauthSign("cid", oauthTok{X: now.Add(oauthClientTTL).Unix(), U: in.RedirectURIs, M: name})
	oauthJSON(rw, http.StatusCreated, map[string]any{
		"client_id": id, "client_id_issued_at": now.Unix(), "client_name": name, "redirect_uris": in.RedirectURIs,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	})
}

// ---- the browser's part ----

func oauthRedirect(rw http.ResponseWriter, r *http.Request, target string, vals url.Values, status int) {
	u, err := url.Parse(target)
	if err != nil {
		oauthFailPage(rw, http.StatusBadRequest, "The client's address is not usable.")
		return
	}
	q := u.Query()
	for k, v := range vals {
		if len(v) > 0 && v[0] != "" {
			q.Set(k, v[0])
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(rw, r, u.String(), status)
}

var pkceChallengeRE = base64.RawURLEncoding

func (w *WebServer) handleOAuthAuthorize(rw http.ResponseWriter, r *http.Request) {
	if !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	base := oauthBase(r)
	q := r.URL.Query()
	cl, err := w.oauthVerify("cid", q.Get("client_id"), time.Now())
	if err != nil {
		oauthFailPage(rw, http.StatusBadRequest, "This client is not registered here (or its registration has expired). The client should register again.")
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(cl.U) == 1 {
		redirect = cl.U[0]
	}
	if base == "" || !oauthRedirectMatches(cl.U, redirect) {
		oauthFailPage(rw, http.StatusBadRequest, "The redirect address is not one this client registered.")
		return
	}
	state := q.Get("state")
	if len(state) > oauthMaxState {
		oauthFailPage(rw, http.StatusBadRequest, "The state value is too long.")
		return
	}
	fail := func(code, desc string) {
		oauthRedirect(rw, r, redirect, url.Values{"error": {code}, "error_description": {desc}, "state": {state}}, http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	chal := q.Get("code_challenge")
	if raw, err := pkceChallengeRE.DecodeString(chal); q.Get("code_challenge_method") != "S256" || err != nil || len(raw) != 32 {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if res := strings.TrimRight(q.Get("resource"), "/"); res != "" && res != base && res != base+"/mcp" {
		fail("invalid_target", "this server issues tokens only for its own /mcp")
		return
	}
	cfg := w.ssoCfg()
	p := cfg.provider(q.Get("p"))
	if p == nil {
		provs := cfg.providers()
		if len(provs) != 1 {
			var b strings.Builder
			b.WriteString(`<h1>Sign in to netdir</h1><p><b>` + html.EscapeString(cl.M) + `</b> wants to use the netdir MCP endpoint. Sign in with:</p>`)
			for _, pr := range provs {
				q2 := r.URL.Query()
				q2.Set("p", pr.id)
				b.WriteString(`<a href="/oauth/authorize?` + html.EscapeString(q2.Encode()) + `">` + html.EscapeString(pr.title) + `</a> `)
			}
			oauthPage(rw, http.StatusOK, "netdir sign-in", b.String())
			return
		}
		p = &provs[0]
	}
	d, err := w.sso.discovery(p)
	if err != nil {
		warnf("mcp: sign-in: %s: %v", p.title, err)
		oauthFailPage(rw, http.StatusBadGateway, "Could not reach "+p.title+" to sign in.")
		return
	}
	verifier, nonce := randToken(), randToken()
	cb := base + "/api/sso/callback"
	st := w.oauthSeal(oauthTok{X: time.Now().Add(oauthFlowTTL).Unix(), P: p.id, N: nonce, V: verifier, B: cb,
		R: redirect, C: oauthCID(q.Get("client_id")), M: cl.M, Ch: chal, S: state})
	ch := sha256.Sum256([]byte(verifier))
	aq := url.Values{
		"response_type": {"code"}, "client_id": {p.clientID}, "redirect_uri": {cb}, "scope": {p.scope},
		"state": {st}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(ch[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range p.extra {
		aq[k] = v
	}
	// the cookie ties the way back to this browser, as for the console's own sign-in
	http.SetCookie(rw, &http.Cookie{Name: ssoCookie, Value: st, Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, d.AuthURL+sep+aq.Encode(), http.StatusFound)
}

// handleOAuthCallbackOnly is the provider's way back on an MCP listener: only a sign-in that /oauth/authorize started.
func (w *WebServer) handleOAuthCallbackOnly(rw http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Query().Get("state"), oauthStatePref) || !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	w.oauthCallback(rw, r)
}

func (w *WebServer) oauthCallback(rw http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	q := r.URL.Query()
	state := q.Get("state")
	clear := func() {
		http.SetCookie(rw, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	c, err := r.Cookie(ssoCookie)
	if err != nil || c.Value != state {
		warnf("mcp: sign-in refused from %s: it was not started in this browser", ip)
		clear()
		oauthFailPage(rw, http.StatusBadRequest, "That sign-in expired or was not started in this browser. Start it again from the client.")
		return
	}
	clear()
	st, err := w.oauthOpen(state, time.Now())
	if err != nil || !w.oauthOn() {
		oauthFailPage(rw, http.StatusBadRequest, "That sign-in expired. Start it again from the client.")
		return
	}
	cfg := w.ssoCfg()
	p := cfg.provider(st.P)
	if p == nil {
		oauthFailPage(rw, http.StatusBadRequest, "Single sign-on is no longer set up for this provider.")
		return
	}
	if e := q.Get("error"); e != "" {
		warnf("mcp: sign-in with %s from %s: the provider answered %q", p.title, ip, e)
		oauthRedirect(rw, r, st.R, url.Values{"error": {"access_denied"}, "error_description": {"the sign-in was cancelled or refused"}, "state": {st.S}}, http.StatusFound)
		return
	}
	code := q.Get("code")
	if code == "" {
		oauthFailPage(rw, http.StatusBadRequest, "The provider sent no code. Start it again from the client.")
		return
	}
	select {
	case w.loginQ <- struct{}{}:
		defer func() { <-w.loginQ }()
	default:
		oauthFailPage(rw, http.StatusServiceUnavailable, "Too many sign-ins at once; try again in a moment.")
		return
	}
	d, err := w.sso.discovery(p)
	if err != nil {
		warnf("mcp: sign-in: %s: %v", p.title, err)
		oauthFailPage(rw, http.StatusBadGateway, "Could not reach "+p.title+" to sign in.")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {st.B},
		"client_id": {p.clientID}, "client_secret": {p.secret}, "code_verifier": {st.V}}
	req, _ := http.NewRequest(http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	resp, err := p.client().Do(req)
	if err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if jerr := json.Unmarshal(b, &tr); jerr != nil || resp.StatusCode != http.StatusOK {
			if tr.Error != "" {
				err = fmt.Errorf("%s: %s", tr.Error, strings.SplitN(tr.Desc, "\n", 2)[0])
			} else {
				err = fmt.Errorf("the token endpoint answered %s", resp.Status)
			}
		}
	}
	if err != nil {
		warnf("mcp: sign-in with %s from %s: %v (is %s registered with the provider?)", p.title, ip, err, st.B)
		oauthFailPage(rw, http.StatusBadGateway, "Could not finish signing in with "+p.title+". The administrator should check the client ID and secret, and that "+st.B+" is registered with the provider.")
		return
	}
	email, err := w.sso.verifyIDToken(p, d, tr.IDToken, st.N, time.Now())
	if err != nil {
		warnf("mcp: sign-in with %s from %s refused: %v", p.title, ip, err)
		oauthFailPage(rw, http.StatusForbidden, "The sign-in could not be verified.")
		return
	}
	ok, readOnly := cfg.ssoLevel(email, p.id)
	if !ok {
		warnf("mcp: sign-in with %s: %q from %s is not on the list of users", p.title, email, ip)
		oauthFailPage(rw, http.StatusForbidden, email+" is not allowed to use this server.")
		return
	}
	cons := w.oauthSign("cons", oauthTok{X: time.Now().Add(oauthConsentTTL).Unix(), E: email, P: p.id, C: st.C, R: st.R, Ch: st.Ch, S: st.S, M: st.M})
	what := "read the devices (read-only access)"
	if !readOnly {
		what = "read the devices <b>and change them</b> (read-write access)"
	}
	dest := st.R
	if u, err := url.Parse(st.R); err == nil {
		dest = u.Scheme + "://" + u.Host
		if u.Host == "" {
			dest = u.Scheme + ":"
		}
	}
	oauthPage(rw, http.StatusOK, "netdir sign-in", `<h1>Allow access to netdir?</h1><p><b>`+html.EscapeString(st.M)+`</b> asks to use the netdir MCP endpoint as <b>`+html.EscapeString(email)+`</b>.</p>
<p>It will be able to `+what+`. The sign-in goes back to <code>`+html.EscapeString(dest)+`</code>; allow it only if you started this from that application.</p>
<form method="post" action="/oauth/consent"><input type="hidden" name="t" value="`+html.EscapeString(cons)+`"><button name="decision" value="allow">Allow</button><button name="decision" value="deny">Cancel</button></form>`)
}

func (w *WebServer) handleOAuthConsent(rw http.ResponseWriter, r *http.Request) {
	if !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, oauthBase(r)) {
		oauthFailPage(rw, http.StatusForbidden, "Cross-origin request refused.")
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 16<<10)
	if r.ParseForm() != nil {
		oauthFailPage(rw, http.StatusBadRequest, "The request is not valid.")
		return
	}
	t, err := w.oauthVerify("cons", r.PostForm.Get("t"), time.Now())
	if err != nil {
		oauthFailPage(rw, http.StatusBadRequest, "That page expired. Start the sign-in again from the client.")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		oauthRedirect(rw, r, t.R, url.Values{"error": {"access_denied"}, "error_description": {"the person did not allow it"}, "state": {t.S}}, http.StatusSeeOther)
		return
	}
	if ok, _ := w.ssoCfg().ssoLevel(t.E, t.P); !ok {
		oauthFailPage(rw, http.StatusForbidden, t.E+" is not allowed to use this server.")
		return
	}
	now := time.Now()
	code := w.oauthSign("code", oauthTok{X: now.Add(oauthCodeTTL).Unix(), E: t.E, P: t.P, C: t.C, R: t.R, Ch: t.Ch, N: randToken()[:22]})
	infof("mcp: %q signed in with %s for %q", t.E, t.P, t.M)
	oauthRedirect(rw, r, t.R, url.Values{"code": {code}, "state": {t.S}}, http.StatusSeeOther)
}

// ---- tokens ----

var oauthUsed = struct {
	sync.Mutex
	m map[string]int64
}{m: map[string]int64{}}

// oauthUseCode marks a code used; false when this node has seen it already.
func oauthUseCode(id string, exp int64) bool {
	u := &oauthUsed
	u.Lock()
	defer u.Unlock()
	now := time.Now().Unix()
	if len(u.m) > 512 {
		for k, x := range u.m {
			if x <= now {
				delete(u.m, k)
			}
		}
	}
	if _, seen := u.m[id]; seen || len(u.m) > 20000 {
		return false
	}
	u.m[id] = exp
	return true
}

func (w *WebServer) handleOAuthToken(rw http.ResponseWriter, r *http.Request) {
	if !w.oauthOn() {
		http.NotFound(rw, r)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 16<<10)
	if r.ParseForm() != nil {
		oauthErr(rw, http.StatusBadRequest, "invalid_request", "the request is not a form")
		return
	}
	f := r.PostForm
	cid := f.Get("client_id")
	cl, err := w.oauthVerify("cid", cid, time.Now())
	if err != nil {
		oauthErr(rw, http.StatusUnauthorized, "invalid_client", "this client is not registered here (or its registration has expired); register again")
		return
	}
	now := time.Now()
	var who oauthTok
	switch f.Get("grant_type") {
	case "authorization_code":
		t, err := w.oauthVerify("code", f.Get("code"), now)
		if err != nil || t.C != oauthCID(cid) {
			oauthErr(rw, http.StatusBadRequest, "invalid_grant", "the code is not valid or has expired")
			return
		}
		if ru := f.Get("redirect_uri"); (ru != "" && ru != t.R) || (ru == "" && !(len(cl.U) == 1 && cl.U[0] == t.R)) {
			oauthErr(rw, http.StatusBadRequest, "invalid_grant", "the redirect_uri is not the one the code was issued for")
			return
		}
		v := f.Get("code_verifier")
		sum := sha256.Sum256([]byte(v))
		if len(v) < 43 || len(v) > 128 || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(t.Ch)) != 1 {
			oauthErr(rw, http.StatusBadRequest, "invalid_grant", "the code_verifier does not match")
			return
		}
		if !oauthUseCode(t.N, t.X) {
			warnf("mcp: a code for %q was used twice", t.E)
			oauthErr(rw, http.StatusBadRequest, "invalid_grant", "the code was used already")
			return
		}
		who = oauthTok{E: t.E, P: t.P, C: t.C, O: now.Unix()}
	case "refresh_token":
		t, err := w.oauthVerify("rt", f.Get("refresh_token"), now)
		if err != nil || t.C != oauthCID(cid) {
			oauthErr(rw, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid or has expired")
			return
		}
		who = t
	default:
		oauthErr(rw, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	if ok, _ := w.ssoCfg().ssoLevel(who.E, who.P); !ok || w.ssoCfg().provider(who.P) == nil {
		oauthErr(rw, http.StatusBadRequest, "invalid_grant", "this person may no longer sign in")
		return
	}
	exp := now.Add(oauthRefreshTTL)
	if last := time.Unix(who.O, 0).Add(oauthRefreshMax); last.Before(exp) {
		exp = last
	}
	if !exp.After(now) {
		oauthErr(rw, http.StatusBadRequest, "invalid_grant", "the sign-in is too old; sign in again")
		return
	}
	at := w.oauthSign("at", oauthTok{X: now.Add(oauthAccessTTL).Unix(), E: who.E, P: who.P, C: who.C})
	rt := w.oauthSign("rt", oauthTok{X: exp.Unix(), E: who.E, P: who.P, C: who.C, O: who.O})
	oauthJSON(rw, http.StatusOK, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(oauthAccessTTL.Seconds()), "refresh_token": rt})
}
