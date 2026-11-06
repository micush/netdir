package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entra sign-in with a browser (the OAuth device code flow), instead of an app registration of your own.
//
// The daemon asks Microsoft for a code, the person opens https://microsoft.com/devicelogin on any computer, enters the code and signs in
// (multi-factor included), and the daemon, polling, receives a refresh token.  It is kept in the login as the token "rt:<refresh token>".
// The access tokens it makes carry the delegated permissions User.Read.All and Device.Read.All, so the driver sees what the signed-in
// account may see (every member of a tenant may read users and their devices by default; a tenant can restrict that, or can require
// consent for the client below).  The client is Microsoft's own public client "Microsoft Graph Command Line Tools", the one Graph
// PowerShell signs in with; it needs no secret.
//
// A refresh token answers with a new one now and then; the driver hands the new one to EntraRefreshed (set by the daemon, which stores it
// in the login), and the old one keeps working until it is replaced.  A refresh token that has not been used for 90 days, or that an
// administrator revoked, is refused: sign in again.

const (
	EntraPublicClient = "14d82eec-204b-4c2b-b7e8-296a70dab67e"
	entraRT           = "rt:"
)

// EntraRefreshed is called (in its own goroutine) when a sign-in's refresh token has been replaced; the daemon saves the new one.
var EntraRefreshed func(credential, oldToken, newToken string)

type entraSess struct {
	mu                    sync.Mutex
	orig, refresh, access string
	exp                   time.Time
}

var entraSessions sync.Map // credential name -> *entraSess: what a driver opened for each request shares

func entraScope(host string) string {
	h := "https://" + strings.Split(host, ":")[0]
	return h + "/User.Read.All " + h + "/Device.Read.All offline_access"
}

// entraLogin is the client of the sign-in host (option login_host, default login.microsoftonline.com).
func entraLogin(d Device) (*apiClient, error) {
	ld := Device{Name: d.Name, Address: firstOf(d.Options["login_host"], "login.microsoftonline.com"), Insecure: d.Insecure, CAPEM: d.CAPEM}
	if h, p, err := net.SplitHostPort(ld.Address); err == nil {
		ld.Address = h
		ld.Port, _ = strconv.Atoi(p)
	}
	return newAPIClient(ld, 443)
}

func entraTenantOf(d Device) string {
	return firstOf(strings.TrimSpace(d.Options["tenant"]), "organizations")
}

// delegated is the access token of a browser sign-in: the one held, or one asked for with the refresh token.
func (e *entra) delegated(ctx context.Context) (string, error) {
	v, _ := entraSessions.LoadOrStore(e.credName, &entraSess{orig: e.rt, refresh: e.rt})
	s := v.(*entraSess)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case e.rt == s.refresh:
		s.orig = e.rt
	case e.rt != s.orig: // the login was signed in again
		s.orig, s.refresh, s.access, s.exp = e.rt, e.rt, "", time.Time{}
	}
	if s.access != "" && time.Now().Add(time.Minute).Before(s.exp) {
		return s.access, nil
	}
	form := url.Values{"client_id": {EntraPublicClient}, "grant_type": {"refresh_token"}, "refresh_token": {s.refresh}, "scope": {entraScope(e.d.Address)}}
	b, err := e.login.do(ctx, http.MethodPost, "/"+url.PathEscape(e.tenant)+"/oauth2/v2.0/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && strings.Contains(se.Body, "invalid_grant") {
			return "", fmt.Errorf("the sign-in has expired or was revoked: sign in again (right-click the device ▸ Sign in with Microsoft, or netdir --device-signin %s)", e.d.Name)
		}
		return "", fmt.Errorf("sign-in to the tenant failed: %w", err)
	}
	var t struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Expires any    `json:"expires_in"`
	}
	if json.Unmarshal(b, &t) != nil || t.Access == "" {
		return "", errors.New("sign-in to the tenant: the answer holds no access token")
	}
	s.access = t.Access
	s.exp = time.Now().Add(time.Duration(num(t.Expires)) * time.Second)
	if num(t.Expires) <= 0 {
		s.exp = time.Now().Add(30 * time.Minute)
	}
	if t.Refresh != "" && t.Refresh != s.refresh {
		old := s.refresh
		s.refresh = t.Refresh
		if f := EntraRefreshed; f != nil {
			go f(e.credName, old, t.Refresh)
		}
	}
	return s.access, nil
}

// EntraCode is what a person needs to sign in; DeviceCode stays with the daemon.
type EntraCode struct {
	DeviceCode      string `json:"-"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// EntraStartSignin asks the tenant (option tenant, "organizations" without it) for a device code.
func EntraStartSignin(ctx context.Context, d Device) (EntraCode, error) {
	var c EntraCode
	if d.Platform != "entra" {
		return c, errors.New("only an Entra device is signed in this way")
	}
	if d.Address == "" {
		d.Address = "graph.microsoft.com"
	}
	login, err := entraLogin(d)
	if err != nil {
		return c, err
	}
	defer login.close()
	form := url.Values{"client_id": {EntraPublicClient}, "scope": {entraScope(d.Address)}}
	b, err := login.do(ctx, http.MethodPost, "/"+url.PathEscape(entraTenantOf(d))+"/oauth2/v2.0/devicecode", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		return c, fmt.Errorf("ask for a sign-in code: %w", err)
	}
	var r struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		URI        string `json:"verification_uri"`
		ExpiresIn  any    `json:"expires_in"`
		Interval   any    `json:"interval"`
	}
	if json.Unmarshal(b, &r) != nil || r.DeviceCode == "" || r.UserCode == "" {
		return c, errors.New("ask for a sign-in code: the answer holds no code")
	}
	c = EntraCode{DeviceCode: r.DeviceCode, UserCode: r.UserCode, VerificationURI: r.URI, ExpiresIn: int(num(r.ExpiresIn)), Interval: int(num(r.Interval))}
	if c.Interval < 1 {
		c.Interval = 5
	}
	if c.ExpiresIn < 1 {
		c.ExpiresIn = 900
	}
	if u, err := url.Parse(c.VerificationURI); err != nil || u.Scheme != "https" { // it is shown as a link: https only
		c.VerificationURI = "https://microsoft.com/devicelogin"
	}
	return c, nil
}

// EntraPollSignin asks whether the code has been used: pending, or the refresh token (to be stored as "rt:"+token).
func EntraPollSignin(ctx context.Context, d Device, deviceCode string) (refresh string, pending bool, err error) {
	if d.Address == "" {
		d.Address = "graph.microsoft.com"
	}
	login, err := entraLogin(d)
	if err != nil {
		return "", false, err
	}
	defer login.close()
	form := url.Values{"client_id": {EntraPublicClient}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode}}
	b, err := login.do(ctx, http.MethodPost, "/"+url.PathEscape(entraTenantOf(d))+"/oauth2/v2.0/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		var se *statusError
		if errors.As(err, &se) {
			var e struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			_ = json.Unmarshal([]byte(se.Body), &e)
			switch e.Error {
			case "authorization_pending", "slow_down":
				return "", true, nil
			case "authorization_declined":
				return "", false, errors.New("the sign-in was declined")
			case "expired_token", "bad_verification_code":
				return "", false, errors.New("the code has expired: start again")
			}
			if e.Error != "" {
				return "", false, fmt.Errorf("sign-in: %s: %s", e.Error, rawTrunc([]byte(strings.SplitN(e.Desc, "\r\n", 2)[0])))
			}
		}
		return "", false, fmt.Errorf("sign-in: %w", err)
	}
	var t struct {
		Refresh string `json:"refresh_token"`
	}
	if json.Unmarshal(b, &t) != nil || t.Refresh == "" {
		return "", false, errors.New("sign-in: Microsoft sent no refresh token (the offline_access permission was not granted)")
	}
	return t.Refresh, false, nil
}

// EntraStoredToken is how a refresh token is kept in a login.
func EntraStoredToken(refresh string) string { return entraRT + refresh }
