package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Single sign-on with Google or Microsoft Entra ID (OpenID Connect, authorization code flow with PKCE).
//
// The login page shows a button for each provider that is set up.  The button sends the browser to the provider; the
// provider sends it back to /api/sso/callback with a one-time code; the daemon trades the code for an ID token at the
// provider's token endpoint, checks the token (signature against the provider's published keys, issuer, audience, expiry,
// nonce), and signs the person in when their e-mail address is on the list of allowed users (sso_users), with the access
// level written beside it: rw (may change settings) or ro (may only look).  Password login through PAM is unchanged and
// stays available.  An SSO session is checked against the list every minute, like a PAM session against its group, so
// removing an address ends its sessions.
//
// Who may sign in is only ever decided by the list: a Google account or a Microsoft account that is not on it gets nothing.
// For Entra ID the tenant is fixed (the token's issuer and tid must be that tenant), so only that organisation's accounts
// are looked at.

// SSOConfig is the single sign-on part of the web block (flat keys in the file), shared by the cluster.
type SSOConfig struct {
	GoogleClientID     string `json:"sso_google_client_id,omitempty"`
	GoogleClientSecret string `json:"sso_google_client_secret,omitempty"`
	EntraTenant        string `json:"sso_entra_tenant,omitempty"`
	EntraClientID      string `json:"sso_entra_client_id,omitempty"`
	EntraClientSecret  string `json:"sso_entra_client_secret,omitempty"`
	// OIDC is any other OpenID Connect provider (Authentik, Keycloak, Authelia, ...): its issuer address, a name for the
	// button, and the client ID and secret registered with it.
	OIDCName         string `json:"sso_oidc_name,omitempty"`
	OIDCIssuer       string `json:"sso_oidc_issuer,omitempty"`
	OIDCClientID     string `json:"sso_oidc_client_id,omitempty"`
	OIDCClientSecret string `json:"sso_oidc_client_secret,omitempty"`
	// OIDCSkipVerify accepts any certificate the provider presents (a self-signed one, say).  The connection is still
	// encrypted, but nothing proves who is on the other end.
	OIDCSkipVerify bool `json:"sso_oidc_skip_verify,omitempty"`
	// Users are the people who may sign in: "alice@example.com rw" or "bob@example.com ro" (no level means ro).
	Users []string `json:"sso_users,omitempty"`
	// BaseURL is the address the provider sends the browser back to ("https://dns1.example.com:22161"); empty uses the
	// address the browser used to reach this node.  It must be registered with the provider as BaseURL/api/sso/callback.
	BaseURL string `json:"sso_base_url,omitempty"`
	// MCPSignIn lets an MCP client sign people in with the providers above (OAuth, mcpoauth.go): a person on Users gets
	// the access written beside their address.  Keys and the address list work as before.  Off unless set.
	MCPSignIn bool `json:"sso_mcp,omitempty"`
}

func (c SSOConfig) Empty() bool {
	return c.GoogleClientID == "" && c.GoogleClientSecret == "" && c.EntraTenant == "" && c.EntraClientID == "" &&
		c.EntraClientSecret == "" && c.OIDCName == "" && c.OIDCIssuer == "" && c.OIDCClientID == "" && c.OIDCClientSecret == "" && !c.OIDCSkipVerify &&
		len(c.Users) == 0 && c.BaseURL == "" && !c.MCPSignIn
}

func (c SSOConfig) clone() *SSOConfig {
	if c.Empty() {
		return nil
	}
	c.Users = append([]string(nil), c.Users...)
	return &c
}

var entraTenantRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

const ssoMaxUsers = 5000

// ssoProviderToken is the name a provider has in the users list: "google", "microsoft" (an Entra ID provider is "entra" inside) or "oidc".
func ssoProviderToken(id string) string {
	if id == "entra" {
		return "microsoft"
	}
	return id
}

// normalizeSSOUsers returns the list as "email level [provider]" lines, lower case, no repeats.  The provider (google or
// microsoft or oidc) is optional: without one the address may sign in with any provider that is set up.
func normalizeSSOUsers(in []string) ([]string, error) {
	var out []string
	seen := map[string]int{}
	for _, line := range in {
		f := strings.Fields(strings.ReplaceAll(line, ",", " "))
		for i := 0; i < len(f); i++ {
			email := strings.ToLower(f[i])
			if at := strings.IndexByte(email, '@'); at < 1 || at == len(email)-1 || strings.Count(email, "@") != 1 || len(email) > 254 || strings.ContainsAny(email, "<>\"'\\/") {
				return nil, fmt.Errorf("web: single sign-on user %q is not an e-mail address like alice@example.com", f[i])
			}
			level, prov := "ro", ""
			for i+1 < len(f) {
				switch strings.ToLower(f[i+1]) {
				case "rw", "read-write", "readwrite", "admin":
					level = "rw"
				case "ro", "read-only", "readonly", "read":
					level = "ro"
				case "google":
					prov = "google"
				case "microsoft", "entra", "azure", "ms":
					prov = "microsoft"
				case "oidc", "openid", "generic":
					prov = "oidc"
				case "any", "both":
					prov = ""
				default:
					goto done
				}
				i++
			}
		done:
			l := email + " " + level
			if prov != "" {
				l += " " + prov
			}
			if j, dup := seen[email]; dup {
				out[j] = l // the last one wins
				continue
			}
			seen[email] = len(out)
			out = append(out, l)
		}
	}
	if len(out) > ssoMaxUsers {
		return nil, fmt.Errorf("web: at most %d single sign-on users", ssoMaxUsers)
	}
	return out, nil
}

// validateSSO checks and tidies the single sign-on settings.  A provider counts as set up only when all its values are
// given; a half-filled one is not an error (the page saves as you type).
func (c *SSOConfig) ValidateSSO() error {
	c.GoogleClientID, c.GoogleClientSecret = strings.TrimSpace(c.GoogleClientID), strings.TrimSpace(c.GoogleClientSecret)
	c.EntraTenant, c.EntraClientID, c.EntraClientSecret = strings.ToLower(strings.TrimSpace(c.EntraTenant)), strings.TrimSpace(c.EntraClientID), strings.TrimSpace(c.EntraClientSecret)
	if c.EntraTenant != "" && !entraTenantRE.MatchString(c.EntraTenant) {
		return errors.New("web: sso_entra_tenant must be the Directory (tenant) ID, a GUID like 11111111-2222-3333-4444-555555555555")
	}
	c.OIDCName, c.OIDCIssuer = strings.TrimSpace(c.OIDCName), strings.TrimRight(strings.TrimSpace(c.OIDCIssuer), "/")
	c.OIDCClientID, c.OIDCClientSecret = strings.TrimSpace(c.OIDCClientID), strings.TrimSpace(c.OIDCClientSecret)
	if len(c.OIDCName) > 40 || strings.ContainsAny(c.OIDCName, "\r\n\t<>&\"'") {
		return errors.New("web: sso_oidc_name is the text of the button: up to 40 characters, without < > & or quotes")
	}
	if c.OIDCIssuer != "" {
		u, err := url.Parse(c.OIDCIssuer)
		if err != nil || (u.Scheme != "https" && !(SsoInsecure && u.Scheme == "http")) || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(c.OIDCIssuer, " \t\r\n") {
			return errors.New("web: sso_oidc_issuer must be the provider's issuer address, like https://auth.example.lan/realms/main (https)")
		}
	}
	for _, v := range []string{c.GoogleClientID, c.GoogleClientSecret, c.EntraClientID, c.EntraClientSecret, c.OIDCClientID, c.OIDCClientSecret} {
		if len(v) > 600 || strings.ContainsAny(v, " \t\r\n") {
			return errors.New("web: a single sign-on client ID or secret is too long or has spaces in it")
		}
	}
	if c.BaseURL != "" {
		c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
		u, err := url.Parse(c.BaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("web: sso_base_url must be an address like https://dns1.example.com:22161 (https, no path)")
		}
	}
	us, err := normalizeSSOUsers(c.Users)
	if err != nil {
		return err
	}
	c.Users = us
	return nil
}

// ssoLevel looks an address up in the list: whether it may sign in with the provider (its id, google or entra), and whether
// read-only.  An entry that names a provider admits the address only through that one.
func (c SSOConfig) SsoLevel(email, provider string) (ok, readOnly bool) {
	email = strings.ToLower(email)
	for _, l := range c.Users {
		f := strings.Fields(l)
		if len(f) < 1 || f[0] != email {
			continue
		}
		if len(f) >= 3 && f[2] != ssoProviderToken(provider) {
			return false, false
		}
		return true, len(f) < 2 || f[1] != "rw"
	}
	return false, false
}

// ---- providers ----

// The providers' own addresses (variables so the tests can point them at a fake provider).
var (
	SsoGoogleIssuer = "https://accounts.google.com"
	SsoEntraBase    = "https://login.microsoftonline.com"
	SsoInsecure     = false // tests: allow http:// provider addresses
	ssoHTTP         = Ipv4FirstClient(15 * time.Second)
)

type SsoProvider struct {
	Id, Title        string     `json:"-"`
	Issuer           string     `json:"-"` // oidc: the issuer the discovery document must name
	skipVerify       bool       // oidc: do not check the provider's certificate
	ClientID, Secret string     `json:"-"`
	Tenant           string     `json:"-"`
	Disc             string     `json:"-"` // discovery document address
	Extra            url.Values `json:"-"`
	Scope            string     `json:"-"`
}

func (c SSOConfig) Providers() []SsoProvider {
	var out []SsoProvider
	if c.GoogleClientID != "" && c.GoogleClientSecret != "" {
		out = append(out, SsoProvider{Id: "google", Title: "Google", ClientID: c.GoogleClientID, Secret: c.GoogleClientSecret,
			Disc: SsoGoogleIssuer + "/.well-known/openid-configuration", Scope: "openid email", Extra: url.Values{"prompt": {"select_account"}}})
	}
	if c.EntraTenant != "" && c.EntraClientID != "" && c.EntraClientSecret != "" {
		out = append(out, SsoProvider{Id: "entra", Title: "Microsoft", ClientID: c.EntraClientID, Secret: c.EntraClientSecret, Tenant: c.EntraTenant,
			Disc: SsoEntraBase + "/" + c.EntraTenant + "/v2.0/.well-known/openid-configuration", Scope: "openid email profile", Extra: url.Values{"prompt": {"select_account"}}})
	}
	if c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCClientSecret != "" {
		title := c.OIDCName
		if title == "" {
			title = "SSO"
		}
		out = append(out, SsoProvider{Id: "oidc", Title: title, ClientID: c.OIDCClientID, Secret: c.OIDCClientSecret, Issuer: c.OIDCIssuer,
			Disc: c.OIDCIssuer + "/.well-known/openid-configuration", Scope: "openid email profile", skipVerify: c.OIDCSkipVerify})
	}
	return out
}

func (c SSOConfig) Provider(id string) *SsoProvider {
	for _, p := range c.Providers() {
		if p.Id == id {
			p := p
			return &p
		}
	}
	return nil
}

// client is the HTTP client for talking to the provider: the ordinary one, or one that accepts any certificate when the
// administrator turned certificate checking off for this provider.
func (p *SsoProvider) Client() *http.Client {
	if !p.skipVerify {
		return ssoHTTP
	}
	warnNoCertCheck(p.Title)
	ssoInsecureClient.Do.Lock()
	defer ssoInsecureClient.Do.Unlock()
	if ssoInsecureClient.c == nil {
		ssoInsecureClient.c = &http.Client{Timeout: ssoHTTP.Timeout, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return DialPrefer4(ctx, &net.Dialer{Timeout: 10 * time.Second}, network, addr)
			},
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // Do not check the provider's certificate is on
		}}
	}
	return ssoInsecureClient.c
}

var ssoInsecureClient = struct {
	Do sync.Mutex
	c  *http.Client
}{}
