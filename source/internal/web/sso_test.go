package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestSSOConfigRules(t *testing.T) {
	c := core.SSOConfig{Users: []string{"Alice@Example.com rw, bob@example.com", "carol@example.com read-only", "alice@example.com ro"}}
	if err := c.ValidateSSO(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Users, "|"); got != "alice@example.com ro|bob@example.com ro|carol@example.com ro" {
		t.Fatalf("users: %s", got)
	}
	for _, bad := range []core.SSOConfig{
		{Users: []string{"not-an-email"}}, {Users: []string{"a@b@c"}}, {EntraTenant: "contoso.com"},
		{BaseURL: "http://x.example"}, {BaseURL: "https://x.example/path"}, {GoogleClientID: "has space"},
	} {
		if err := bad.ValidateSSO(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	// half set up is not an error and is not a provider
	h := core.SSOConfig{GoogleClientID: "x"}
	if err := h.ValidateSSO(); err != nil || len(h.Providers()) != 0 {
		t.Fatalf("half set up: %v %v", err, h.Providers())
	}
	// the cluster's document is unchanged while nothing is set, and carries the settings when they are
	dc := core.NewDaemonConfig()
	if core.SharedOf(dc).SSO != nil {
		t.Fatal("an empty SSO block appears in the shared document")
	}
	dc.Web.GoogleClientID, dc.Web.GoogleClientSecret, dc.Web.Users = "g", "s", []string{"a@b.co rw"}
	sc := core.SharedOf(dc)
	if sc.SSO == nil || sc.SSO.GoogleClientID != "g" {
		t.Fatal("not shared")
	}
	var back core.DaemonConfig
	b, _ := json.Marshal(dc)
	if err := json.Unmarshal(b, &back); err != nil || back.Web.GoogleClientSecret != "s" || len(back.Web.Users) != 1 {
		t.Fatalf("round trip: %v %+v", err, back.Web.SSOConfig)
	}
	// a read-only account is not shown the secrets
	red, _ := json.Marshal(redactSecrets(dc.Web))
	if strings.Contains(string(red), `"s"`) && strings.Contains(string(red), "sso_google_client_secret\":\"s") {
		t.Fatalf("secret shown: %s", red)
	}
}

// A provider with a certificate of its own (self-signed) is refused until "Do not check the provider's certificate" is on.
func TestSSOSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": "https://" + r.Host, "authorization_endpoint": "https://" + r.Host + "/auth",
			"token_endpoint": "https://" + r.Host + "/token", "jwks_uri": "https://" + r.Host + "/keys"})
	}))
	defer srv.Close()
	c := core.SSOConfig{OIDCIssuer: srv.URL, OIDCClientID: "c", OIDCClientSecret: "s"}
	if err := c.ValidateSSO(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSSOState().Discovery(c.Provider("oidc")); err == nil {
		t.Fatal("a self-signed certificate was accepted")
	}
	c.OIDCSkipVerify = true
	if d, err := NewSSOState().Discovery(c.Provider("oidc")); err != nil || d.Issuer != srv.URL {
		t.Fatalf("with the checkbox on: %v", err)
	}
	if c.Empty() || (core.SSOConfig{OIDCSkipVerify: true}).Empty() {
		t.Fatal("the checkbox alone must count as a setting")
	}
}
