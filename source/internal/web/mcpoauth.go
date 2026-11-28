package web

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
	"time"

	"netdir/internal/core"
)

func (w *WebServer) oauthKey(purpose string) []byte {
	var sec []byte
	if w.Mg != nil && w.Mg.Cluster() != nil && w.Mg.Cluster().Node != nil {
		sec = w.Mg.Cluster().Node.Secret()
	}
	if len(sec) == 0 {
		core.OauthLocal.Once.Do(func() { core.OauthLocal.B = make([]byte, 32); rand.Read(core.OauthLocal.B) })
		sec = core.OauthLocal.B
	}
	m := hmac.New(sha256.New, sec)
	m.Write([]byte("netdir-mcp-oauth-v1/" + purpose))
	return m.Sum(nil)
}

func (w *WebServer) OauthSign(kind string, t core.OauthTok) string {
	b, _ := json.Marshal(t)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, w.oauthKey("sign"))
	m.Write([]byte(kind + "." + p))
	return core.OauthPrefix + kind + "." + p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (w *WebServer) oauthVerify(kind, tok string, now time.Time) (core.OauthTok, error) {
	var t core.OauthTok
	rest, ok := strings.CutPrefix(tok, core.OauthPrefix+kind+".")
	if !ok {
		return t, core.ErrOAuthBad
	}
	i := strings.LastIndexByte(rest, '.')
	if i < 0 {
		return t, core.ErrOAuthBad
	}
	p, mac := rest[:i], rest[i+1:]
	got, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil {
		return t, core.ErrOAuthBad
	}
	m := hmac.New(sha256.New, w.oauthKey("sign"))
	m.Write([]byte(kind + "." + p))
	if subtle.ConstantTimeCompare(got, m.Sum(nil)) != 1 {
		return t, core.ErrOAuthBad
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, core.ErrOAuthBad
	}
	if t.X == 0 || now.Unix() >= t.X {
		return t, core.ErrOAuthExpired
	}
	return t, nil
}

// oauthSeal encrypts a value for the browser to carry through the provider (it holds the PKCE verifier of that leg).
func (w *WebServer) oauthSeal(t core.OauthTok) string {
	b, _ := json.Marshal(t)
	blk, _ := aes.NewCipher(w.oauthKey("seal"))
	g, _ := cipher.NewGCM(blk)
	n := make([]byte, g.NonceSize())
	rand.Read(n)
	return core.OauthStatePref + base64.RawURLEncoding.EncodeToString(g.Seal(n, n, b, []byte("state")))
}

func (w *WebServer) oauthOpen(s string, now time.Time) (core.OauthTok, error) {
	var t core.OauthTok
	rest, ok := strings.CutPrefix(s, core.OauthStatePref)
	if !ok {
		return t, core.ErrOAuthBad
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	blk, _ := aes.NewCipher(w.oauthKey("seal"))
	g, _ := cipher.NewGCM(blk)
	if err != nil || len(raw) < g.NonceSize()+g.Overhead() {
		return t, core.ErrOAuthBad
	}
	b, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("state"))
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, core.ErrOAuthBad
	}
	if t.X == 0 || now.Unix() >= t.X {
		return t, core.ErrOAuthExpired
	}
	return t, nil
}

// oauthOn says whether MCP clients may sign in with SSO: switched on, with a provider and somebody who may.
func (w *WebServer) OauthOn() bool {
	c := w.SsoCfg()
	return c.MCPSignIn && len(c.Users) > 0 && len(c.Providers()) > 0
}

// oauthAccess checks an access token and says who it is for and what they may do now.
func (w *WebServer) OauthAccess(tok string) (email, prov string, readOnly bool, err error) {
	if !w.OauthOn() {
		return "", "", false, core.ErrOAuthBad
	}
	t, err := w.oauthVerify("at", tok, time.Now())
	if err != nil {
		return "", "", false, err
	}
	ok, ro := w.SsoCfg().SsoLevel(t.E, t.P)
	if !ok || w.SsoCfg().Provider(t.P) == nil {
		return "", "", false, errors.New("this person may no longer sign in")
	}
	return t.E, t.P, ro, nil
}

// mcpChallenge sets the WWW-Authenticate header of a refusal; with SSO on it names the metadata a client starts from.
func (w *WebServer) McpChallenge(rw http.ResponseWriter, r *http.Request, errCode string) {
	v := `Bearer realm="mcp"`
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	if w.OauthOn() {
		if b := core.OauthBase(r); b != "" {
			v += `, resource_metadata="` + b + `/.well-known/oauth-protected-resource"`
		}
	}
	rw.Header().Set("WWW-Authenticate", v)
}

// ---- routes ----

// registerOAuth adds the sign-in routes.  The MCP listeners on the gateway addresses serve only /mcp, so they get these
// too, with the callback of the provider (the console's own route has the same path and takes both kinds of sign-in).
func (w *WebServer) RegisterOAuth(mux *http.ServeMux, callback bool) {
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

func (w *WebServer) handleOAuthResource(rw http.ResponseWriter, r *http.Request) {
	b := core.OauthBase(r)
	if b == "" || !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	core.OauthJSON(rw, http.StatusOK, map[string]any{
		"resource": b + "/mcp", "authorization_servers": []string{b},
		"bearer_methods_supported": []string{"header"}, "resource_name": "netdir MCP",
	})
}

func (w *WebServer) handleOAuthMetadata(rw http.ResponseWriter, r *http.Request) {
	b := core.OauthBase(r)
	if b == "" || !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	core.OauthJSON(rw, http.StatusOK, map[string]any{
		"issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": b + "/oauth/token",
		"registration_endpoint":    b + "/oauth/register",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (w *WebServer) handleOAuthRegister(rw http.ResponseWriter, r *http.Request) {
	if !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		core.OauthErr(rw, http.StatusBadRequest, "invalid_client_metadata", "the request is not JSON")
		return
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > core.OauthMaxURIs {
		core.OauthErr(rw, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("give 1 to %d redirect_uris", core.OauthMaxURIs))
		return
	}
	for _, u := range in.RedirectURIs {
		if !core.OauthRedirectOK(u) {
			core.OauthErr(rw, http.StatusBadRequest, "invalid_redirect_uri", "a redirect_uri must be https, http on this machine (localhost, 127.0.0.1, [::1]) or a private-use scheme with a dot in it")
			return
		}
	}
	if in.AuthMethod != "" && in.AuthMethod != "none" {
		core.OauthErr(rw, http.StatusBadRequest, "invalid_client_metadata", "only public clients are supported (token_endpoint_auth_method none, with PKCE)")
		return
	}
	now := time.Now()
	name := core.OauthCleanName(in.ClientName)
	id := w.OauthSign("cid", core.OauthTok{X: now.Add(core.OauthClientTTL).Unix(), U: in.RedirectURIs, M: name})
	core.OauthJSON(rw, http.StatusCreated, map[string]any{
		"client_id": id, "client_id_issued_at": now.Unix(), "client_name": name, "redirect_uris": in.RedirectURIs,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	})
}

func (w *WebServer) handleOAuthAuthorize(rw http.ResponseWriter, r *http.Request) {
	if !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	base := core.OauthBase(r)
	q := r.URL.Query()
	cl, err := w.oauthVerify("cid", q.Get("client_id"), time.Now())
	if err != nil {
		core.OauthFailPage(rw, http.StatusBadRequest, "This client is not registered here (or its registration has expired). The client should register again.")
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(cl.U) == 1 {
		redirect = cl.U[0]
	}
	if base == "" || !core.OauthRedirectMatches(cl.U, redirect) {
		core.OauthFailPage(rw, http.StatusBadRequest, "The redirect address is not one this client registered.")
		return
	}
	state := q.Get("state")
	if len(state) > core.OauthMaxState {
		core.OauthFailPage(rw, http.StatusBadRequest, "The state value is too long.")
		return
	}
	fail := func(code, desc string) {
		core.OauthRedirect(rw, r, redirect, url.Values{"error": {code}, "error_description": {desc}, "state": {state}}, http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	chal := q.Get("code_challenge")
	if raw, err := core.PkceChallengeRE.DecodeString(chal); q.Get("code_challenge_method") != "S256" || err != nil || len(raw) != 32 {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if res := strings.TrimRight(q.Get("resource"), "/"); res != "" && res != base && res != base+"/mcp" {
		fail("invalid_target", "this server issues tokens only for its own /mcp")
		return
	}
	cfg := w.SsoCfg()
	p := cfg.Provider(q.Get("p"))
	if p == nil {
		provs := cfg.Providers()
		if len(provs) != 1 {
			var b strings.Builder
			b.WriteString(`<h1>Sign in to netdir</h1><p><b>` + html.EscapeString(cl.M) + `</b> wants to use the netdir MCP endpoint. Sign in with:</p>`)
			for _, pr := range provs {
				q2 := r.URL.Query()
				q2.Set("p", pr.Id)
				b.WriteString(`<a href="/oauth/authorize?` + html.EscapeString(q2.Encode()) + `">` + html.EscapeString(pr.Title) + `</a> `)
			}
			core.OauthPage(rw, http.StatusOK, "netdir sign-in", b.String())
			return
		}
		p = &provs[0]
	}
	d, err := w.sso.Discovery(p)
	if err != nil {
		core.Warnf("mcp: sign-in: %s: %v", p.Title, err)
		core.OauthFailPage(rw, http.StatusBadGateway, "Could not reach "+p.Title+" to sign in.")
		return
	}
	verifier, nonce := RandToken(), RandToken()
	cb := base + "/api/sso/callback"
	st := w.oauthSeal(core.OauthTok{X: time.Now().Add(core.OauthFlowTTL).Unix(), P: p.Id, N: nonce, V: verifier, B: cb,
		R: redirect, C: core.OauthCID(q.Get("client_id")), M: cl.M, Ch: chal, S: state})
	ch := sha256.Sum256([]byte(verifier))
	aq := url.Values{
		"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {cb}, "scope": {p.Scope},
		"state": {st}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(ch[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range p.Extra {
		aq[k] = v
	}
	// the cookie ties the way back to this browser, as for the console's own sign-in
	http.SetCookie(rw, &http.Cookie{Name: SsoCookie, Value: st, Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, d.AuthURL+sep+aq.Encode(), http.StatusFound)
}

// handleOAuthCallbackOnly is the provider's way back on an MCP listener: only a sign-in that /oauth/authorize started.
func (w *WebServer) handleOAuthCallbackOnly(rw http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Query().Get("state"), core.OauthStatePref) || !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	w.oauthCallback(rw, r)
}

func (w *WebServer) oauthCallback(rw http.ResponseWriter, r *http.Request) {
	ip := core.ClientIP(r)
	q := r.URL.Query()
	state := q.Get("state")
	clear := func() {
		http.SetCookie(rw, &http.Cookie{Name: SsoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	c, err := r.Cookie(SsoCookie)
	if err != nil || c.Value != state {
		core.Warnf("mcp: sign-in refused from %s: it was not started in this browser", ip)
		clear()
		core.OauthFailPage(rw, http.StatusBadRequest, "That sign-in expired or was not started in this browser. Start it again from the client.")
		return
	}
	clear()
	st, err := w.oauthOpen(state, time.Now())
	if err != nil || !w.OauthOn() {
		core.OauthFailPage(rw, http.StatusBadRequest, "That sign-in expired. Start it again from the client.")
		return
	}
	cfg := w.SsoCfg()
	p := cfg.Provider(st.P)
	if p == nil {
		core.OauthFailPage(rw, http.StatusBadRequest, "Single sign-on is no longer set up for this provider.")
		return
	}
	if e := q.Get("error"); e != "" {
		core.Warnf("mcp: sign-in with %s from %s: the provider answered %q", p.Title, ip, e)
		core.OauthRedirect(rw, r, st.R, url.Values{"error": {"access_denied"}, "error_description": {"the sign-in was cancelled or refused"}, "state": {st.S}}, http.StatusFound)
		return
	}
	code := q.Get("code")
	if code == "" {
		core.OauthFailPage(rw, http.StatusBadRequest, "The provider sent no code. Start it again from the client.")
		return
	}
	select {
	case w.LoginQ <- struct{}{}:
		defer func() { <-w.LoginQ }()
	default:
		core.OauthFailPage(rw, http.StatusServiceUnavailable, "Too many sign-ins at once; try again in a moment.")
		return
	}
	d, err := w.sso.Discovery(p)
	if err != nil {
		core.Warnf("mcp: sign-in: %s: %v", p.Title, err)
		core.OauthFailPage(rw, http.StatusBadGateway, "Could not reach "+p.Title+" to sign in.")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {st.B},
		"client_id": {p.ClientID}, "client_secret": {p.Secret}, "code_verifier": {st.V}}
	req, _ := http.NewRequest(http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	resp, err := p.Client().Do(req)
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
		core.Warnf("mcp: sign-in with %s from %s: %v (is %s registered with the provider?)", p.Title, ip, err, st.B)
		core.OauthFailPage(rw, http.StatusBadGateway, "Could not finish signing in with "+p.Title+". The administrator should check the client ID and secret, and that "+st.B+" is registered with the provider.")
		return
	}
	email, err := w.sso.verifyIDToken(p, d, tr.IDToken, st.N, time.Now())
	if err != nil {
		core.Warnf("mcp: sign-in with %s from %s refused: %v", p.Title, ip, err)
		core.OauthFailPage(rw, http.StatusForbidden, "The sign-in could not be verified.")
		return
	}
	ok, readOnly := cfg.SsoLevel(email, p.Id)
	if !ok {
		core.Warnf("mcp: sign-in with %s: %q from %s is not on the list of users", p.Title, email, ip)
		core.OauthFailPage(rw, http.StatusForbidden, email+" is not allowed to use this server.")
		return
	}
	cons := w.OauthSign("cons", core.OauthTok{X: time.Now().Add(core.OauthConsentTTL).Unix(), E: email, P: p.Id, C: st.C, R: st.R, Ch: st.Ch, S: st.S, M: st.M})
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
	core.OauthPage(rw, http.StatusOK, "netdir sign-in", `<h1>Allow access to netdir?</h1><p><b>`+html.EscapeString(st.M)+`</b> asks to use the netdir MCP endpoint as <b>`+html.EscapeString(email)+`</b>.</p>
<p>It will be able to `+what+`. The sign-in goes back to <code>`+html.EscapeString(dest)+`</code>; allow it only if you started this from that application.</p>
<form method="post" action="/oauth/consent"><input type="hidden" name="t" value="`+html.EscapeString(cons)+`"><button name="decision" value="allow">Allow</button><button name="decision" value="deny">Cancel</button></form>`)
}

func (w *WebServer) handleOAuthConsent(rw http.ResponseWriter, r *http.Request) {
	if !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, core.OauthBase(r)) {
		core.OauthFailPage(rw, http.StatusForbidden, "Cross-origin request refused.")
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 16<<10)
	if r.ParseForm() != nil {
		core.OauthFailPage(rw, http.StatusBadRequest, "The request is not valid.")
		return
	}
	t, err := w.oauthVerify("cons", r.PostForm.Get("t"), time.Now())
	if err != nil {
		core.OauthFailPage(rw, http.StatusBadRequest, "That page expired. Start the sign-in again from the client.")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		core.OauthRedirect(rw, r, t.R, url.Values{"error": {"access_denied"}, "error_description": {"the person did not allow it"}, "state": {t.S}}, http.StatusSeeOther)
		return
	}
	if ok, _ := w.SsoCfg().SsoLevel(t.E, t.P); !ok {
		core.OauthFailPage(rw, http.StatusForbidden, t.E+" is not allowed to use this server.")
		return
	}
	now := time.Now()
	code := w.OauthSign("code", core.OauthTok{X: now.Add(core.OauthCodeTTL).Unix(), E: t.E, P: t.P, C: t.C, R: t.R, Ch: t.Ch, N: RandToken()[:22]})
	core.Infof("mcp: %q signed in with %s for %q", t.E, t.P, t.M)
	core.OauthRedirect(rw, r, t.R, url.Values{"code": {code}, "state": {t.S}}, http.StatusSeeOther)
}

func (w *WebServer) handleOAuthToken(rw http.ResponseWriter, r *http.Request) {
	if !w.OauthOn() {
		http.NotFound(rw, r)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 16<<10)
	if r.ParseForm() != nil {
		core.OauthErr(rw, http.StatusBadRequest, "invalid_request", "the request is not a form")
		return
	}
	f := r.PostForm
	cid := f.Get("client_id")
	cl, err := w.oauthVerify("cid", cid, time.Now())
	if err != nil {
		core.OauthErr(rw, http.StatusUnauthorized, "invalid_client", "this client is not registered here (or its registration has expired); register again")
		return
	}
	now := time.Now()
	var who core.OauthTok
	switch f.Get("grant_type") {
	case "authorization_code":
		t, err := w.oauthVerify("code", f.Get("code"), now)
		if err != nil || t.C != core.OauthCID(cid) {
			core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "the code is not valid or has expired")
			return
		}
		if ru := f.Get("redirect_uri"); (ru != "" && ru != t.R) || (ru == "" && !(len(cl.U) == 1 && cl.U[0] == t.R)) {
			core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "the redirect_uri is not the one the code was issued for")
			return
		}
		v := f.Get("code_verifier")
		sum := sha256.Sum256([]byte(v))
		if len(v) < 43 || len(v) > 128 || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(t.Ch)) != 1 {
			core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "the code_verifier does not match")
			return
		}
		if !core.OauthUseCode(t.N, t.X) {
			core.Warnf("mcp: a code for %q was used twice", t.E)
			core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "the code was used already")
			return
		}
		who = core.OauthTok{E: t.E, P: t.P, C: t.C, O: now.Unix()}
	case "refresh_token":
		t, err := w.oauthVerify("rt", f.Get("refresh_token"), now)
		if err != nil || t.C != core.OauthCID(cid) {
			core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid or has expired")
			return
		}
		who = t
	default:
		core.OauthErr(rw, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	if ok, _ := w.SsoCfg().SsoLevel(who.E, who.P); !ok || w.SsoCfg().Provider(who.P) == nil {
		core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "this person may no longer sign in")
		return
	}
	exp := now.Add(core.OauthRefreshTTL)
	if last := time.Unix(who.O, 0).Add(core.OauthRefreshMax); last.Before(exp) {
		exp = last
	}
	if !exp.After(now) {
		core.OauthErr(rw, http.StatusBadRequest, "invalid_grant", "the sign-in is too old; sign in again")
		return
	}
	at := w.OauthSign("at", core.OauthTok{X: now.Add(core.OauthAccessTTL).Unix(), E: who.E, P: who.P, C: who.C})
	rt := w.OauthSign("rt", core.OauthTok{X: exp.Unix(), E: who.E, P: who.P, C: who.C, O: who.O})
	core.OauthJSON(rw, http.StatusOK, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(core.OauthAccessTTL.Seconds()), "refresh_token": rt})
}
