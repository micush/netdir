package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
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
	OauthPrefix     = "nd1."
	OauthStatePref  = "nds1."
	OauthAccessTTL  = time.Hour
	OauthRefreshTTL = 30 * 24 * time.Hour
	OauthRefreshMax = 90 * 24 * time.Hour // a refresh chain ends this long after the sign-in
	OauthCodeTTL    = time.Minute
	OauthFlowTTL    = 10 * time.Minute
	OauthConsentTTL = 5 * time.Minute
	OauthClientTTL  = 400 * 24 * time.Hour
	OauthMaxURIs    = 5
	oauthMaxURILen  = 300
	OauthMaxState   = 256
)

// oauthTok is the one shape every signed or sealed value has; each kind uses some of the fields.
type OauthTok struct {
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
var OauthLocal = struct {
	Once sync.Once `json:"-"`
	B    []byte    `json:"-"`
}{}

var ErrOAuthBad = errors.New("not a valid token")
var ErrOAuthExpired = errors.New("the token has expired")

// oauthBase is this server's own address as the client reached it.
func OauthBase(r *http.Request) string {
	if r.Host == "" || strings.ContainsAny(r.Host, " /\\@?#\t\r\n") {
		return ""
	}
	return "https://" + r.Host
}

func OauthCID(clientID string) string {
	h := sha256.Sum256([]byte(clientID))
	return base64.RawURLEncoding.EncodeToString(h[:12])
}

func OauthJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(code)
	json.NewEncoder(rw).Encode(v)
}

func OauthErr(rw http.ResponseWriter, code int, e, desc string) {
	OauthJSON(rw, code, map[string]string{"error": e, "error_description": desc})
}

// oauthPage writes a small page with no style, no script and nothing loaded (the front-end rules of CLAUDE.md); its policy
// sets no form-action, because the answer to the allow form is a redirect to the client's address and some browsers apply
// form-action to redirects too.
func OauthPage(rw http.ResponseWriter, code int, title, body string) {
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

func OauthFailPage(rw http.ResponseWriter, code int, msg string) {
	OauthPage(rw, code, "netdir sign-in", `<h1>Sign-in not possible</h1><p>`+html.EscapeString(msg)+`</p>`)
}

// ---- clients ----

var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// oauthRedirectOK says whether an address may be a client's redirect: https, http on this machine, or a private-use scheme
// named by a reverse domain name (RFC 8252).
func OauthRedirectOK(s string) bool {
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
func OauthRedirectMatches(reg []string, got string) bool {
	if !OauthRedirectOK(got) {
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

func OauthCleanName(s string) string {
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

// ---- the browser's part ----

func OauthRedirect(rw http.ResponseWriter, r *http.Request, target string, vals url.Values, status int) {
	u, err := url.Parse(target)
	if err != nil {
		OauthFailPage(rw, http.StatusBadRequest, "The client's address is not usable.")
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

var PkceChallengeRE = base64.RawURLEncoding

// ---- tokens ----

var oauthUsed = struct {
	sync.Mutex
	m map[string]int64
}{m: map[string]int64{}}

// oauthUseCode marks a code used; false when this node has seen it already.
func OauthUseCode(id string, exp int64) bool {
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
