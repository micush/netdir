package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Technitium DNS Server (15.0 and later) over its HTTP API, /api/..., on its HTTPS port (53443 by default: turn on "Enable HTTPS
// for web service" in Settings ▸ Web Service; the default plain-HTTP port 5380 is never used, so the token never crosses the
// network in the clear).  The credential is an API token (Administration ▸ Sessions ▸ Create API Token), sent as
// "Authorization: Bearer TOKEN", never in a URL; or a user name and password, from which the driver logs in (POST
// /api/user/login, the password in the form body) and logs out in Close.
//
// Technitium's API does not keep reads and writes apart by method: a zone is deleted with a plain GET.  Nothing here may therefore
// be sent because "it is a GET".  Every request the driver makes, and every path APIGet is asked for, must name an endpoint
// whose last word is get, list or query (techRead), which are the endpoints that only read; the login and logout are the only others.
//
// Technitium is a DNS server, not a switch or a firewall, so only what fits is answered: facts, the addresses it listens on, health
// (the dashboard's statistics) and, through APIGet, everything it lists (zones, records, the cache, blocked and allowed domains,
// DHCP scopes and leases, apps, the query log).  Neighbors, routes, routing, firewall, VLANs, port counters, configuration (the
// backup is a file) and commands answer "unsupported".

func init() { Register("technitium", newTechnitium) }

type technitium struct {
	d      Device
	api    *apiClient
	user   string
	pass   string
	loaded bool // a session made by the driver's own login, closed in Close
	token  bool // the credential is an API token
}

func newTechnitium(d Device, c Credential) (Driver, error) {
	if c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: Technitium needs an API token, or a username and a password", d.Name)
	}
	api, err := newAPIClient(d, 53443)
	if err != nil {
		return nil, err
	}
	t := &technitium{d: d, api: api, user: c.Username, pass: c.Password, token: c.Token != ""}
	if t.token {
		api.hdr.Set("Authorization", "Bearer "+c.Token)
	}
	return t, nil
}

// techReadRE is the last word of an endpoint that only reads: get, list, query, and getTop, listStoreApps and the like.
var techReadRE = regexp.MustCompile(`^(get|list|query)([A-Z][A-Za-z0-9]*)?$`)

// techSecretParams are the request parameters that carry credentials: the driver sends them itself, a caller may not.
var techSecretParams = map[string]bool{"token": true, "pass": true, "password": true, "totp": true}

// techRead checks that a path names an endpoint that only reads, and has no credential in its query; it returns the path as it
// is to be sent.
func techRead(path string) (string, error) {
	p, q, _ := strings.Cut(path, "?")
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) < 3 || segs[0] != "api" {
		return "", errors.New("path: Technitium reads /api/<group>/<endpoint> (e.g. /api/zones/list or /api/dashboard/stats/get?type=LastHour)")
	}
	if !techReadRE.MatchString(segs[len(segs)-1]) {
		return "", fmt.Errorf("path: %q is not an endpoint that only reads: Technitium changes things with plain GET requests too, so only get, list and query endpoints are sent", segs[len(segs)-1])
	}
	qs, err := url.ParseQuery(q)
	if err != nil {
		return "", errors.New("path: the query is not valid")
	}
	for k := range qs {
		if techSecretParams[strings.ToLower(k)] {
			return "", fmt.Errorf("path: the parameter %q is sent by the driver, not by the caller", k)
		}
	}
	return path, nil
}

// do sends one request and returns the "response" of Technitium's envelope.  The HTTP status is 200 for an error too: the
// envelope says "error" or "invalid-token", which becomes a statusError (401 for a token the server does not know, else 400).
func (t *technitium) do(ctx context.Context, method, path string, form url.Values) (any, error) {
	var body any
	var hdr http.Header
	if form != nil {
		body, hdr = form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	}
	b, err := t.api.do(ctx, method, path, body, hdr)
	if err != nil {
		return nil, err
	}
	var env struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"errorMessage"`
		Response     any    `json:"response"`
		Token        string `json:"token"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("Technitium answered something that is not its JSON: %v", err)
	}
	switch env.Status {
	case "ok":
		if form != nil { // the login answers the token beside the response (or, on some releases, inside it)
			tok := env.Token
			if m, ok := env.Response.(map[string]any); ok && tok == "" {
				tok = str(m["token"])
			}
			if tok != "" {
				return map[string]any{"token": tok}, nil
			}
		}
		return env.Response, nil
	case "invalid-token":
		return nil, &statusError{Code: http.StatusUnauthorized, Body: firstOf(env.ErrorMessage, "invalid token")}
	case "2fa-required":
		return nil, &statusError{Code: http.StatusUnauthorized, Body: "the user needs a two-factor code: use an API token"}
	default:
		return nil, &statusError{Code: http.StatusBadRequest, Body: firstOf(env.ErrorMessage, "the request failed")}
	}
}

// login makes a session from the user name and password, unless the credential is a token.
func (t *technitium) login(ctx context.Context) error {
	if t.token || t.loaded {
		return nil
	}
	v, err := t.do(ctx, http.MethodPost, "/api/user/login", url.Values{"user": {t.user}, "pass": {t.pass}, "includeInfo": {"false"}})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	m, _ := v.(map[string]any)
	tok := str(m["token"])
	if tok == "" {
		return errors.New("login: the server sent no session token")
	}
	t.api.hdr.Set("Authorization", "Bearer "+tok)
	t.loaded = true
	return nil
}

// get reads an endpoint that only reads, as the object its response holds.
func (t *technitium) get(ctx context.Context, path string) (any, error) {
	p, err := techRead(path)
	if err != nil {
		return nil, err
	}
	if err := t.login(ctx); err != nil {
		return nil, err
	}
	return t.do(ctx, http.MethodGet, p, nil)
}

func (t *technitium) settings(ctx context.Context) (map[string]any, error) {
	v, err := t.get(ctx, "/api/settings/get")
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func (t *technitium) Facts(ctx context.Context) (Facts, error) {
	s, err := t.settings(ctx)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Vendor: "Technitium", Model: "DNS Server", Hostname: str(s["dnsServerDomain"]), OSVersion: str(s["version"])}
	if ts, err := time.Parse(time.RFC3339, str(s["uptimestamp"])); err == nil {
		if up := nowUnix() - ts.Unix(); up > 0 {
			f.UptimeS = up
		}
	}
	return f, nil
}

// Interfaces: Technitium has no interfaces of its own; the addresses it listens for DNS on are the nearest thing.
func (t *technitium) Interfaces(ctx context.Context) ([]Interface, error) {
	s, err := t.settings(ctx)
	if err != nil {
		return nil, err
	}
	var addrs []string
	if l, ok := s["dnsServerLocalEndPoints"].([]any); ok {
		for _, x := range l {
			if a := str(x); a != "" {
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	return []Interface{{Name: "dns", Addresses: addrs}}, nil
}

func (t *technitium) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (t *technitium) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (t *technitium) Show(context.Context, string) (string, error)  { return "", ErrUnsupported }

// Resources: the dashboard's statistics for the last hour and the last day (queries and their outcomes, cache entries, zones,
// clients).  Technitium reports no CPU, memory, disk or sensor readings through its API, so none are given.
func (t *technitium) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"stats_last_hour", "/api/dashboard/stats/get?type=LastHour"},
		{"stats_last_day", "/api/dashboard/stats/get?type=LastDay"},
	}, func(p string) (any, error) { return t.get(ctx, p) })
	return Resources{Details: d}, err
}

// APIGet reads an endpoint that only reads.
func (t *technitium) APIGet(ctx context.Context, path string) (any, bool, error) {
	v, err := t.get(ctx, path)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (t *technitium) APICatalog(ctx context.Context) (any, error) {
	return map[string]any{
		"how": "GET /api/<group>/<endpoint>?<parameters> reads it; the answer is the endpoint's response. Only endpoints whose name is get, list or query (or starts with one: getTop, listStoreApps) are sent, " +
			"because Technitium also changes things with plain GET requests. The token is sent by the driver, never as a parameter. Technitium's API documentation (APIDOCS.md) lists every endpoint and its parameters.",
		"examples": []string{"/api/settings/get", "/api/dashboard/stats/get?type=LastHour", "/api/dashboard/stats/getTop?type=LastDay&statsType=TopClients", "/api/zones/list",
			"/api/zones/records/get?domain=example.com&zone=example.com", "/api/cache/list", "/api/blocked/list", "/api/allowed/list", "/api/dhcp/scopes/list", "/api/dhcp/leases/list", "/api/apps/list"},
	}, nil
}

// Close ends a session the driver made; an API token is the person's own and is left alone.
func (t *technitium) Close(ctx context.Context) {
	if t.loaded {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = t.do(ctx, http.MethodPost, "/api/user/logout", url.Values{})
		t.loaded = false
	}
	t.api.close()
}
