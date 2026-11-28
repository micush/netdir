package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"netdir/internal/core"
	"netdir/internal/web"
)

type oauthT struct {
	t   *testing.T
	e   *webEnv
	f   *fakeIdP
	cid string
}

const oauthRedir = "http://localhost:53682/callback"

func newOAuthT(t *testing.T, users ...string) *oauthT {
	e, f := ssoEnv(t, users...)
	p := *e.ws.Policy.Load()
	p.MCPSignIn = true
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e.ws.Policy.Store(&p)
	e.mg.webH = e.ws.Handler()
	o := &oauthT{t: t, e: e, f: f}
	r := o.do("POST", "/oauth/register", `{"redirect_uris":["`+oauthRedir+`"],"client_name":"Test <b>client</b>"}`, "Content-Type", "application/json")
	if r.code != 201 {
		t.Fatalf("register: %d %s", r.code, r.raw)
	}
	o.cid, _ = r.body["client_id"].(string)
	return o
}

func (o *oauthT) do(method, path, body string, hdr ...string) resp {
	o.t.Helper()
	req, _ := http.NewRequest(method, o.e.ts.URL+path, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := o.e.client.Do(req)
	if err != nil {
		o.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp{res.StatusCode, m, raw, res.Header}
}

func (o *oauthT) form(path string, v url.Values, hdr ...string) resp {
	return o.do("POST", path, v.Encode(), append([]string{"Content-Type", "application/x-www-form-urlencoded"}, hdr...)...)
}

func pkce(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// authorize runs the browser through authorize, the provider and the callback, up to the page that asks to allow.  It returns
// that page's response.
func (o *oauthT) authorize(provider, verifier, state string, mut func(claims, hdr map[string]any)) resp {
	o.t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {o.cid}, "redirect_uri": {oauthRedir}, "code_challenge": {pkce(verifier)},
		"code_challenge_method": {"S256"}, "state": {state}, "p": {provider}}
	r := o.do("GET", "/oauth/authorize?"+q.Encode(), "")
	if r.code != 302 {
		o.t.Fatalf("authorize: %d %s", r.code, r.raw)
	}
	loc, _ := url.Parse(r.hdr.Get("Location"))
	aq := loc.Query()
	if aq.Get("code_challenge_method") != "S256" || aq.Get("nonce") == "" || !strings.HasSuffix(aq.Get("redirect_uri"), "/api/sso/callback") {
		o.t.Fatalf("provider request: %v", aq)
	}
	o.f.nonce, o.f.challnge, o.f.redirect, o.f.mut = aq.Get("nonce"), aq.Get("code_challenge"), aq.Get("redirect_uri"), mut
	var ck string
	for _, c := range (&http.Response{Header: r.hdr}).Cookies() {
		if c.Name == web.SsoCookie {
			if !c.HttpOnly || !c.Secure {
				o.t.Fatalf("cookie flags: %+v", c)
			}
			ck = c.Name + "=" + c.Value
		}
	}
	return o.do("GET", "/api/sso/callback?code=good-code&state="+url.QueryEscape(aq.Get("state")), "", "Cookie", ck)
}

var consentRE = regexp.MustCompile(`name="t" value="([^"]+)"`)

// signIn goes all the way to a redirect back to the client and returns its query.
func (o *oauthT) signIn(provider, verifier string, mut func(claims, hdr map[string]any)) url.Values {
	o.t.Helper()
	page := o.authorize(provider, verifier, "st-1", mut)
	m := consentRE.FindSubmatch(page.raw)
	if page.code != 200 || m == nil {
		o.t.Fatalf("consent page: %d %s", page.code, page.raw)
	}
	r := o.form("/oauth/consent", url.Values{"t": {string(m[1])}, "decision": {"allow"}})
	if r.code != 303 {
		o.t.Fatalf("consent: %d %s", r.code, r.raw)
	}
	loc, _ := url.Parse(r.hdr.Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != oauthRedir || loc.Query().Get("state") != "st-1" {
		o.t.Fatalf("redirect: %s", loc)
	}
	return loc.Query()
}

func (o *oauthT) token(code, verifier string) resp {
	return o.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {o.cid}, "redirect_uri": {oauthRedir}})
}

func (o *oauthT) mcp(tok, msg string) resp {
	hdr := []string{"Content-Type", "application/json"}
	if tok != "" {
		hdr = append(hdr, "Authorization", "Bearer "+tok)
	}
	return o.do("POST", "/mcp", msg, hdr...)
}

func (o *oauthT) tools(tok string) string {
	o.t.Helper()
	r := o.mcp(tok, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if r.code != 200 {
		o.t.Fatalf("tools/list: %d %s", r.code, r.raw)
	}
	return strings.Join(toolNames(o.t, r.body), " ")
}

func TestMCPOAuthSignIn(t *testing.T) {
	o := newOAuthT(t, "alice@example.com rw")
	for _, p := range []string{"google", "entra", "oidc"} { // every kind of provider signs in
		v := web.RandToken()
		q := o.signIn(p, v, nil)
		tr := o.token(q.Get("code"), v)
		if tr.code != 200 || tr.body["token_type"] != "Bearer" || tr.body["access_token"] == "" || tr.body["refresh_token"] == "" || tr.hdr.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: token: %d %s", p, tr.code, tr.raw)
		}
		at := tr.body["access_token"].(string)
		if !strings.Contains(o.tools(at), "device_change_raw") {
			t.Fatalf("%s: a read-write person has no change tool", p)
		}
		// the usage log names the person
		if r := o.mcp(at, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 200 {
			t.Fatalf("%s: ping: %d", p, r.code)
		}
	}
}

func TestMCPOAuthReadOnlyAndRevocation(t *testing.T) {
	o := newOAuthT(t, "alice@example.com ro")
	v := web.RandToken()
	tr := o.token(o.signIn("google", v, nil).Get("code"), v)
	at, rt := tr.body["access_token"].(string), tr.body["refresh_token"].(string)
	if names := o.tools(at); strings.Contains(names, "device_change_raw") || !strings.Contains(names, "list_devices") {
		t.Fatalf("read-only tools: %s", names)
	}
	// the list changes: the access follows at once, with no new sign-in
	p := *o.e.ws.Policy.Load()
	p.Users = []string{"alice@example.com rw"}
	p.Validate()
	o.e.ws.Policy.Store(&p)
	if !strings.Contains(o.tools(at), "device_change_raw") {
		t.Fatal("a promotion did not reach the token")
	}
	// a refresh gives a working token
	rf := o.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {o.cid}})
	if rf.code != 200 || o.mcp(rf.body["access_token"].(string), `{"jsonrpc":"2.0","id":1,"method":"ping"}`).code != 200 {
		t.Fatalf("refresh: %d %s", rf.code, rf.raw)
	}
	// removing the person ends both the token and the refresh
	p.Users = []string{"bob@example.com ro"}
	p.Validate()
	o.e.ws.Policy.Store(&p)
	r := o.mcp(at, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if r.code != 401 || !strings.Contains(r.hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("removed person: %d %v", r.code, r.hdr)
	}
	if rf := o.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {o.cid}}); rf.code != 400 || rf.body["error"] != "invalid_grant" {
		t.Fatalf("refresh after removal: %d %s", rf.code, rf.raw)
	}
	// switching the feature off ends it too
	p.Users = []string{"alice@example.com rw"}
	p.MCPSignIn = false
	p.Validate()
	o.e.ws.Policy.Store(&p)
	if r := o.mcp(at, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 { // it is only an unknown key now
		t.Fatalf("feature off: %d", r.code)
	}
}

func TestMCPOAuthChallengeAndMetadata(t *testing.T) {
	o := newOAuthT(t, "alice@example.com rw")
	r := o.mcp("", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if r.code != 401 || !strings.Contains(r.hdr.Get("WWW-Authenticate"), `resource_metadata="https://`) || !strings.Contains(r.hdr.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource") {
		t.Fatalf("challenge: %d %v", r.code, r.hdr)
	}
	pr := o.do("GET", "/.well-known/oauth-protected-resource", "")
	as := o.do("GET", "/.well-known/oauth-authorization-server", "")
	host := strings.TrimPrefix(o.e.ts.URL, "http://")
	if pr.code != 200 || pr.body["resource"] != "https://"+host+"/mcp" || as.code != 200 || as.body["issuer"] != "https://"+host ||
		as.body["token_endpoint"] != "https://"+host+"/oauth/token" || as.body["registration_endpoint"] != "https://"+host+"/oauth/register" {
		t.Fatalf("metadata: %s %s", pr.raw, as.raw)
	}
	if m := as.body["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Fatalf("pkce: %v", m)
	}
	// with several providers and none picked, the person chooses
	q := url.Values{"response_type": {"code"}, "client_id": {o.cid}, "redirect_uri": {oauthRedir}, "code_challenge": {pkce(web.RandToken())}, "code_challenge_method": {"S256"}}
	ch := o.do("GET", "/oauth/authorize?"+q.Encode(), "")
	if ch.code != 200 || !strings.Contains(string(ch.raw), "Company SSO") || !strings.Contains(string(ch.raw), "p=google") || strings.Contains(string(ch.raw), "<b>client</b>") {
		t.Fatalf("chooser: %d %s", ch.code, ch.raw)
	}
	if ch.hdr.Get("Content-Security-Policy") == "" || ch.hdr.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("page headers: %v", ch.hdr)
	}
	// off: nothing is there, and the old refusal stays a 403
	p := *o.e.ws.Policy.Load()
	p.MCPSignIn = false
	p.Validate()
	o.e.ws.Policy.Store(&p)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/oauth/authorize?" + q.Encode()} {
		if r := o.do("GET", path, ""); r.code != 404 {
			t.Fatalf("%s while off: %d", path, r.code)
		}
	}
	if r := o.do("POST", "/oauth/register", `{"redirect_uris":["http://localhost/cb"]}`); r.code != 404 {
		t.Fatalf("register while off: %d", r.code)
	}
	if r := o.mcp("", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 403 || r.hdr.Get("WWW-Authenticate") != "" {
		t.Fatalf("off: %d %v", r.code, r.hdr)
	}
}

func TestMCPOAuthRefusals(t *testing.T) {
	o := newOAuthT(t, "alice@example.com rw")
	// registration
	for _, body := range []string{`{}`, `{"redirect_uris":[]}`, `{"redirect_uris":["http://evil.example/cb"]}`, `{"redirect_uris":["javascript:alert(1)"]}`,
		`{"redirect_uris":["https://x.example/cb#f"]}`, `{"redirect_uris":["myapp://cb"]}`, `not json`,
		`{"redirect_uris":["http://localhost/cb"],"token_endpoint_auth_method":"client_secret_basic"}`} {
		if r := o.do("POST", "/oauth/register", body); r.code != 400 {
			t.Fatalf("register %s: %d", body, r.code)
		}
	}
	if r := o.do("POST", "/oauth/register", `{"redirect_uris":["https://claude.ai/api/mcp/auth_callback","com.example.app:/cb"]}`); r.code != 201 {
		t.Fatalf("register: %d %s", r.code, r.raw)
	}
	// authorize: an unknown client, a foreign redirect address and a missing challenge are not sent anywhere
	base := url.Values{"response_type": {"code"}, "client_id": {o.cid}, "redirect_uri": {oauthRedir}, "code_challenge": {pkce(web.RandToken())}, "code_challenge_method": {"S256"}, "p": {"google"}}
	with := func(k, v string) string {
		q := url.Values{}
		for a, b := range base {
			q[a] = b
		}
		q.Set(k, v)
		return "/oauth/authorize?" + q.Encode()
	}
	for _, c := range []struct{ path, why string }{
		{with("client_id", "nd1.cid.x.y"), "forged client"},
		{with("redirect_uri", "http://localhost:1/other"), "another path"},
		{with("redirect_uri", "https://evil.example/cb"), "another host"},
		{with("redirect_uri", "http://127.0.0.1:53682/callback"), "another loopback name"},
	} {
		if r := o.do("GET", c.path, ""); r.code != 400 || r.hdr.Get("Location") != "" {
			t.Fatalf("%s: %d %v", c.why, r.code, r.hdr)
		}
	}
	// a loopback address may differ in its port
	if r := o.do("GET", with("redirect_uri", "http://localhost:9999/callback"), ""); r.code != 302 {
		t.Fatalf("loopback port: %d", r.code)
	}
	for _, c := range []struct{ path, errCode string }{
		{with("code_challenge_method", "plain"), "invalid_request"},
		{with("code_challenge", "short"), "invalid_request"},
		{with("response_type", "token"), "unsupported_response_type"},
		{with("resource", "https://other.example/mcp"), "invalid_target"},
	} {
		r := o.do("GET", c.path, "")
		loc, _ := url.Parse(r.hdr.Get("Location"))
		if r.code != 302 || loc.Query().Get("error") != c.errCode || loc.Host != "localhost:53682" {
			t.Fatalf("%s: %d %v", c.errCode, r.code, r.hdr)
		}
	}
	// a person who is not on the list never gets the allow page
	page := o.authorize("google", web.RandToken(), "s", func(c, h map[string]any) { c["email"] = "mallory@example.com" })
	if page.code != 403 || consentRE.Match(page.raw) {
		t.Fatalf("not listed: %d %s", page.code, page.raw)
	}
	// a callback with no cookie, or another browser's state
	q := o.do("GET", "/oauth/authorize?"+base.Encode(), "")
	loc, _ := url.Parse(q.hdr.Get("Location"))
	if r := o.do("GET", "/api/sso/callback?code=good-code&state="+url.QueryEscape(loc.Query().Get("state")), ""); r.code != 400 {
		t.Fatalf("no cookie: %d", r.code)
	}
	if r := o.do("GET", "/api/sso/callback?code=x&state=nds1.garbage", "", "Cookie", web.SsoCookie+"=nds1.garbage"); r.code != 400 {
		t.Fatalf("garbage state: %d", r.code)
	}
	// the person says no
	page = o.authorize("google", web.RandToken(), "st-9", nil)
	m := consentRE.FindSubmatch(page.raw)
	if m == nil || !strings.Contains(string(page.raw), "alice@example.com") || !strings.Contains(string(page.raw), "localhost:53682") || strings.Contains(string(page.raw), "<b>client</b>") {
		t.Fatalf("consent page: %s", page.raw)
	}
	r := o.form("/oauth/consent", url.Values{"t": {string(m[1])}, "decision": {"deny"}})
	loc, _ = url.Parse(r.hdr.Get("Location"))
	if r.code != 303 || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "st-9" || loc.Query().Get("code") != "" {
		t.Fatalf("deny: %d %v", r.code, r.hdr)
	}
	// another origin cannot press the button; a tampered or foreign token is refused
	if r := o.form("/oauth/consent", url.Values{"t": {string(m[1])}, "decision": {"allow"}}, "Origin", "https://evil.example"); r.code != 403 {
		t.Fatalf("origin: %d", r.code)
	}
	if r := o.form("/oauth/consent", url.Values{"t": {string(m[1]) + "x"}, "decision": {"allow"}}); r.code != 400 {
		t.Fatalf("tampered consent: %d", r.code)
	}
	if r := o.form("/oauth/consent", url.Values{"t": {o.cid}, "decision": {"allow"}}); r.code != 400 {
		t.Fatalf("a client ID as consent: %d", r.code)
	}
}

func TestMCPOAuthTokenRules(t *testing.T) {
	o := newOAuthT(t, "alice@example.com rw")
	v := web.RandToken()
	code := o.signIn("google", v, nil).Get("code")
	bad := func(what string, r resp, want string) {
		t.Helper()
		if r.code != 400 && r.code != 401 || r.body["error"] != want {
			t.Fatalf("%s: %d %s", what, r.code, r.raw)
		}
	}
	bad("wrong verifier", o.token(code, web.RandToken()), "invalid_grant")
	bad("short verifier", o.token(code, "abc"), "invalid_grant")
	bad("another redirect", o.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}, "client_id": {o.cid}, "redirect_uri": {"http://localhost:1/x"}}), "invalid_grant")
	bad("unknown client", o.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}, "client_id": {"nd1.cid.a.b"}}), "invalid_client")
	// a code is for the client it was issued to
	other := o.do("POST", "/oauth/register", `{"redirect_uris":["`+oauthRedir+`"]}`)
	bad("another client", o.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}, "client_id": {other.body["client_id"].(string)}, "redirect_uri": {oauthRedir}}), "invalid_grant")
	bad("grant type", o.form("/oauth/token", url.Values{"grant_type": {"password"}, "client_id": {o.cid}}), "unsupported_grant_type")
	tr := o.token(code, v)
	if tr.code != 200 {
		t.Fatalf("good exchange after the refusals: %d %s", tr.code, tr.raw)
	}
	bad("the code a second time", o.token(code, v), "invalid_grant")
	// the tokens are not interchangeable
	at, rt := tr.body["access_token"].(string), tr.body["refresh_token"].(string)
	bad("access token as refresh", o.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {at}, "client_id": {o.cid}}), "invalid_grant")
	bad("refresh token as code", o.token(rt, v), "invalid_grant")
	if r := o.mcp(rt, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 {
		t.Fatalf("refresh token as access token: %d", r.code)
	}
	if r := o.mcp(code, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 {
		t.Fatalf("code as access token: %d", r.code)
	}
	if r := o.mcp(o.cid, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 {
		t.Fatalf("client id as access token: %d", r.code)
	}
	// a changed byte, and a token that has run out
	if r := o.mcp(at[:len(at)-2]+"AA", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 {
		t.Fatalf("tampered: %d", r.code)
	}
	old := o.e.ws.OauthSign("at", core.OauthTok{X: time.Now().Add(-time.Minute).Unix(), E: "alice@example.com", P: "google"})
	r := o.mcp(old, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if r.code != 401 || !strings.Contains(string(r.raw), "expired") {
		t.Fatalf("expired: %d %s", r.code, r.raw)
	}
	// a person the list names for another provider only
	odd := o.e.ws.OauthSign("at", core.OauthTok{X: time.Now().Add(time.Hour).Unix(), E: "alice@example.com", P: "nonesuch"})
	if r := o.mcp(odd, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 {
		t.Fatalf("unknown provider: %d", r.code)
	}
	// the chain ends 90 days after the sign-in
	longAgo := o.e.ws.OauthSign("rt", core.OauthTok{X: time.Now().Add(time.Hour).Unix(), E: "alice@example.com", P: "google", C: core.OauthCID(o.cid), O: time.Now().Add(-91 * 24 * time.Hour).Unix()})
	bad("old chain", o.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {longAgo}, "client_id": {o.cid}}), "invalid_grant")
}

// a key that happens to start like a token still works as a key, and keys and addresses are unchanged beside sign-in
func TestMCPOAuthKeepsKeysAndAddresses(t *testing.T) {
	o := newOAuthT(t, "alice@example.com rw")
	key := "nd1.this-is-a-key-with-more-than-thirty-two-chars"
	sup := o.e.ws.Status.Sup()
	sup.Mu.Lock()
	keys, err := core.NormMCPKeys([]core.MCPKey{{Name: "k", Access: "ro", Key: key}})
	if err != nil {
		sup.Mu.Unlock()
		t.Fatal(err)
	}
	sup.Dc.Settings.MCPKeys = keys
	sup.Dc.Settings.MCPACL = []string{"127.0.0.0/8"}
	sup.Mu.Unlock()
	if r := o.mcp(key, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 200 {
		t.Fatalf("key: %d %s", r.code, r.raw)
	}
	if r := o.mcp("", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 200 {
		t.Fatalf("address: %d", r.code)
	}
	if r := o.mcp("wrong-key-wrong-key-wrong-key-wrong-key", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.code != 401 {
		t.Fatalf("wrong key: %d", r.code)
	}
}
