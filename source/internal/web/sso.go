package web

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"netdir/internal/core"
)

type ssoDisc struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
	at       time.Time
}

type ssoKey struct {
	kid string
	pub *rsa.PublicKey
}

type ssoJWKS struct {
	keys    []ssoKey
	fetched time.Time
}

type ssoPending struct {
	provider, nonce, verifier, redirect string
	created                             time.Time
}

type ssoState struct {
	mu      sync.Mutex
	pending map[string]*ssoPending
	disc    map[string]*ssoDisc
	jwks    map[string]*ssoJWKS
}

func NewSSOState() *ssoState {
	return &ssoState{pending: map[string]*ssoPending{}, disc: map[string]*ssoDisc{}, jwks: map[string]*ssoJWKS{}}
}

func ssoURLOK(u string) bool {
	if core.SsoInsecure {
		return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
	}
	return strings.HasPrefix(u, "https://")
}

func ssoGetJSON(hc *http.Client, req *http.Request, v any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return json.Unmarshal(body, v)
}

func (s *ssoState) Discovery(p *core.SsoProvider) (*ssoDisc, error) {
	s.mu.Lock()
	d := s.disc[p.Disc]
	s.mu.Unlock()
	if d != nil && time.Since(d.at) < time.Hour {
		return d, nil
	}
	req, _ := http.NewRequest(http.MethodGet, p.Disc, nil)
	nd := &ssoDisc{}
	if err := ssoGetJSON(p.Client(), req, nd); err != nil {
		if d != nil {
			return d, nil // the provider is briefly unreachable: the last document still holds
		}
		return nil, err
	}
	if p.Issuer != "" && strings.TrimRight(nd.Issuer, "/") != p.Issuer { // a discovery document must name the issuer it was fetched from
		return nil, errors.New("the provider's discovery document names another issuer")
	}
	if nd.Issuer == "" || !ssoURLOK(nd.AuthURL) || !ssoURLOK(nd.TokenURL) || !ssoURLOK(nd.JWKSURI) {
		return nil, errors.New("the provider's discovery document is not usable")
	}
	nd.at = time.Now()
	s.mu.Lock()
	s.disc[p.Disc] = nd
	s.mu.Unlock()
	return nd, nil
}

func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// key finds the provider's signing key for kid, fetching the key set when it is old or the key is not in it.
func (s *ssoState) key(hc *http.Client, d *ssoDisc, kid string) (*rsa.PublicKey, error) {
	find := func(j *ssoJWKS) *rsa.PublicKey {
		if j == nil {
			return nil
		}
		for _, k := range j.keys {
			if k.kid == kid {
				return k.pub
			}
		}
		return nil
	}
	s.mu.Lock()
	j := s.jwks[d.JWKSURI]
	s.mu.Unlock()
	if k := find(j); k != nil && time.Since(j.fetched) < 6*time.Hour {
		return k, nil
	}
	if j != nil && time.Since(j.fetched) < time.Minute {
		return nil, errors.New("the token is signed with a key the provider does not publish")
	}
	req, _ := http.NewRequest(http.MethodGet, d.JWKSURI, nil)
	var doc struct {
		Keys []struct {
			Kty, Kid, N, E, Use, Alg string
		} `json:"keys"`
	}
	if err := ssoGetJSON(hc, req, &doc); err != nil {
		return nil, err
	}
	nj := &ssoJWKS{fetched: time.Now()}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := b64Int(k.N)
		e, err2 := b64Int(k.E)
		if err1 != nil || err2 != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || n.BitLen() < 2048 {
			continue
		}
		nj.keys = append(nj.keys, ssoKey{k.Kid, &rsa.PublicKey{N: n, E: int(e.Int64())}})
	}
	s.mu.Lock()
	s.jwks[d.JWKSURI] = nj
	s.mu.Unlock()
	if k := find(nj); k != nil {
		return k, nil
	}
	return nil, errors.New("the token is signed with a key the provider does not publish")
}

type ssoClaims struct {
	Iss           string          `json:"iss"`
	Aud           json.RawMessage `json:"aud"`
	Exp           float64         `json:"exp"`
	Nbf           float64         `json:"nbf"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified any             `json:"email_verified"`
	Preferred     string          `json:"preferred_username"`
	Tid           string          `json:"tid"`
}

func (c ssoClaims) audHas(id string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == id
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == id {
				return true
			}
		}
	}
	return false
}

// verifyIDToken checks an ID token and returns the e-mail address it vouches for.
func (s *ssoState) verifyIDToken(p *core.SsoProvider, d *ssoDisc, tok, nonce string, now time.Time) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("the ID token is malformed")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", errors.New("the ID token is malformed")
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "RS256" { // never "none", never a key-confusion HMAC
		return "", errors.New("the ID token is not signed with RS256")
	}
	pub, err := s.key(p.Client(), d, hdr.Kid)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return "", errors.New("the ID token's signature is wrong")
	}
	var c ssoClaims
	if json.Unmarshal(cb, &c) != nil {
		return "", errors.New("the ID token is malformed")
	}
	issOK := c.Iss == d.Issuer
	if p.Id == "google" && (c.Iss == "https://accounts.google.com" || c.Iss == "accounts.google.com") {
		issOK = true
	}
	if !issOK {
		return "", errors.New("the ID token comes from another issuer")
	}
	if !c.audHas(p.ClientID) {
		return "", errors.New("the ID token is for another application")
	}
	if c.Exp == 0 || now.After(time.Unix(int64(c.Exp), 0).Add(time.Minute)) {
		return "", errors.New("the ID token has expired")
	}
	if c.Nbf != 0 && now.Before(time.Unix(int64(c.Nbf), 0).Add(-time.Minute)) {
		return "", errors.New("the ID token is not valid yet")
	}
	if c.Nonce == "" || c.Nonce != nonce {
		return "", errors.New("the ID token answers another sign-in")
	}
	email := c.Email
	switch p.Id {
	case "google":
		if v, ok := c.EmailVerified.(bool); !(ok && v) {
			if sv, ok := c.EmailVerified.(string); !(ok && sv == "true") {
				return "", errors.New("Google has not verified this address")
			}
		}
	case "oidc":
		if v, ok := c.EmailVerified.(bool); !(ok && v) {
			if sv, ok := c.EmailVerified.(string); !(ok && sv == "true") {
				return "", errors.New("the provider has not verified this address")
			}
		}
	case "entra":
		if !strings.EqualFold(c.Tid, p.Tenant) {
			return "", errors.New("the account is from another tenant")
		}
		if email == "" {
			email = c.Preferred
		}
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if strings.Count(email, "@") != 1 {
		return "", errors.New("the provider sent no e-mail address")
	}
	return email, nil
}

// ---- web handlers ----

func (w *WebServer) SsoCfg() core.SSOConfig { return w.Policy.Load().SSOConfig }

func ssoBase(c core.SSOConfig, r *http.Request) string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return "https://" + r.Host
}

const SsoCookie = "__Host-netdir_sso"

func ssoFail(rw http.ResponseWriter, r *http.Request, msg string) {
	http.SetCookie(rw, &http.Cookie{Name: SsoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(rw, r, "/?sso_error="+url.QueryEscape(msg), http.StatusFound)
}

// handleSSOStart sends the browser to the provider.
func (w *WebServer) handleSSOStart(rw http.ResponseWriter, r *http.Request) {
	cfg := w.SsoCfg()
	p := cfg.Provider(r.URL.Query().Get("p"))
	if p == nil {
		http.NotFound(rw, r)
		return
	}
	d, err := w.sso.Discovery(p)
	if err != nil {
		core.Warnf("web: single sign-on: %s: %v", p.Title, err)
		ssoFail(rw, r, "Could not reach "+p.Title+" to sign in.")
		return
	}
	state, nonce, verifier := RandToken(), RandToken(), RandToken()
	redirect := ssoBase(cfg, r) + "/api/sso/callback"
	now := time.Now()
	w.sso.mu.Lock()
	for k, v := range w.sso.pending {
		if now.Sub(v.created) > 10*time.Minute {
			delete(w.sso.pending, k)
		}
	}
	if len(w.sso.pending) >= 2000 {
		w.sso.mu.Unlock()
		core.JsonError(rw, http.StatusServiceUnavailable, "Too many sign-ins at once; try again in a moment.")
		return
	}
	w.sso.pending[SessKey(state)] = &ssoPending{provider: p.Id, nonce: nonce, verifier: verifier, redirect: redirect, created: now}
	w.sso.mu.Unlock()
	ch := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {redirect}, "scope": {p.Scope},
		"state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(ch[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range p.Extra {
		q[k] = v
	}
	// the cookie ties the callback to this browser (a forged callback link cannot sign someone in as the attacker)
	http.SetCookie(rw, &http.Cookie{Name: SsoCookie, Value: state, Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	http.Redirect(rw, r, d.AuthURL+sep+q.Encode(), http.StatusFound)
}

// handleSSOCallback finishes a sign-in.
func (w *WebServer) handleSSOCallback(rw http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Query().Get("state"), core.OauthStatePref) { // a sign-in an MCP client started (mcpoauth.go)
		if !w.OauthOn() {
			http.NotFound(rw, r)
			return
		}
		w.oauthCallback(rw, r)
		return
	}
	ip := core.ClientIP(r)
	q := r.URL.Query()
	c, err := r.Cookie(SsoCookie)
	state := q.Get("state")
	if err != nil || state == "" || c.Value != state {
		core.Warnf("web: single sign-on refused from %s: the sign-in was not started in this browser", ip)
		ssoFail(rw, r, "That sign-in expired or was not started here. Try again.")
		return
	}
	w.sso.mu.Lock()
	pd := w.sso.pending[SessKey(state)]
	delete(w.sso.pending, SessKey(state))
	w.sso.mu.Unlock()
	if pd == nil || time.Since(pd.created) > 10*time.Minute {
		ssoFail(rw, r, "That sign-in expired. Try again.")
		return
	}
	cfg := w.SsoCfg()
	p := cfg.Provider(pd.provider)
	if p == nil {
		ssoFail(rw, r, "Single sign-on is no longer set up.")
		return
	}
	if e := q.Get("error"); e != "" {
		core.Warnf("web: single sign-on with %s from %s: the provider answered %q", p.Title, ip, e)
		ssoFail(rw, r, "The sign-in was cancelled or refused by "+p.Title+".")
		return
	}
	code := q.Get("code")
	if code == "" {
		ssoFail(rw, r, "The provider sent no code. Try again.")
		return
	}
	select {
	case w.LoginQ <- struct{}{}:
		defer func() { <-w.LoginQ }()
	default:
		ssoFail(rw, r, "Too many sign-ins at once; try again in a moment.")
		return
	}
	d, err := w.sso.Discovery(p)
	if err != nil {
		core.Warnf("web: single sign-on: %s: %v", p.Title, err)
		ssoFail(rw, r, "Could not reach "+p.Title+" to sign in.")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {pd.redirect},
		"client_id": {p.ClientID}, "client_secret": {p.Secret}, "code_verifier": {pd.verifier}}
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
		core.Warnf("web: single sign-on with %s from %s: %v", p.Title, ip, err)
		ssoFail(rw, r, "Could not finish signing in with "+p.Title+". Check the client ID and secret under Configure ▸ Users ▸ SSO.")
		return
	}
	email, err := w.sso.verifyIDToken(p, d, tr.IDToken, pd.nonce, time.Now())
	if err != nil {
		core.Warnf("web: single sign-on with %s from %s refused: %v", p.Title, ip, err)
		ssoFail(rw, r, "The sign-in could not be verified.")
		return
	}
	ok, readOnly := cfg.SsoLevel(email, p.Id)
	if !ok {
		core.Warnf("web: single sign-on with %s: %q from %s is not on the list of users", p.Title, email, ip)
		ssoFail(rw, r, email+" is not allowed to use this console.")
		return
	}
	now := time.Now()
	s := &core.Session{User: email, Csrf: RandToken(), Created: now, Last: now, Checked: now, ReadOnly: readOnly, Ip: ip, Sso: true, SsoProv: p.Id}
	tok := RandToken()
	w.Mu.Lock()
	w.Sessions[SessKey(tok)] = s
	w.Mu.Unlock()
	w.saveSessions()
	http.SetCookie(rw, &http.Cookie{Name: SsoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(rw, &http.Cookie{
		Name: SessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMaxAge.Seconds()),
	})
	core.Infof("web: login: %q signed in with %s from %s (%s)", email, p.Title, ip, AccessWord(readOnly))
	http.Redirect(rw, r, "/", http.StatusFound)
}
