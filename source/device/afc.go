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
	"sync"
)

// Aruba Fabric Composer (AFC), the on-site controller for Aruba CX VXLAN/EVPN fabrics, over its REST API at https://<host>/api/v1.
// The credential is a user name and a password: the driver asks for a token once (POST /api/v1/auth/token with the headers
// X-Auth-Username and X-Auth-Password; the token is in "result" of the answer), sends it as the Authorization header, asks for a new
// one when the old one is refused (a token lives 30 minutes), and deletes it in Close (a user may hold only ten).
//
// Reads are GETs of /api/v1/<resource> (fabrics, switches, vrfs, vlans, vlan_groups, ... as the AFC's own API Explorer lists them).
// Aruba's developer pages show the resources both below /api/v1/ and below /api/v1/api/, so a resource answered 404 at the first is
// tried at the second, and the one that answered is kept.
//
//	show <resource> [key=value ...]    the collection, with the query pairs as filters (name=..., fabric_uuid=...)
//
// Changes (RawChange, rw callers only): POST, PUT, PATCH or DELETE below /api/v1/, with the old state of a PUT kept and put back
// when the change fails in a way that may have changed something.  Users, roles, authentication servers, licences, backups and
// restores, upgrades and certificates are not changed here.
//
// Not tried against a real AFC: the names of the resources and their fields come from Aruba's developer pages and what an AFC's
// own API Explorer is said to show.

func init() { Register("afc", newAFC) }

type afc struct {
	d    Device
	api  *apiClient
	user string
	pass string

	mu     sync.Mutex
	tok    string
	prefix string // "/api/v1" or "/api/v1/api", whichever answered
}

const afcBase = "/api/v1"

var afcResRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,48}$`)

func newAFC(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Aruba Fabric Composer needs a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	return &afc{d: d, api: api, user: c.Username, pass: c.Password, prefix: afcBase}, nil
}

// login asks for a token unless there is one (force: the one held was refused).
func (a *afc) login(ctx context.Context, force bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok != "" && !force {
		return a.tok, nil
	}
	b, err := a.api.do(ctx, http.MethodPost, afcBase+"/auth/token", nil, http.Header{
		"X-Auth-Username": {a.user}, "X-Auth-Password": {a.pass}, "Content-Type": {"application/json"}})
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	var t struct {
		Result any `json:"result"`
	}
	if json.Unmarshal(b, &t) != nil || str(t.Result) == "" {
		return "", errors.New("login: the answer holds no token")
	}
	a.tok = str(t.Result)
	return a.tok, nil
}

func (a *afc) hdr(ctx context.Context) (http.Header, error) {
	t, err := a.login(ctx, false)
	if err != nil {
		return nil, err
	}
	return http.Header{"Authorization": {t}}, nil
}

// get reads one path below /api/v1 (p starts with "/").  A refused token is renewed once; a 404 is tried below /api/v1/api.
func (a *afc) get(ctx context.Context, p string) (any, error) {
	b, err := a.send(ctx, p)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", p, err)
	}
	return v, nil
}

func (a *afc) send(ctx context.Context, p string) ([]byte, error) {
	a.mu.Lock()
	prefix := a.prefix
	a.mu.Unlock()
	tryOnce := func(prefix string) ([]byte, error) {
		for renewed := false; ; renewed = true {
			h, err := a.hdr(ctx)
			if err != nil {
				return nil, err
			}
			b, err := a.api.do(ctx, http.MethodGet, prefix+p, nil, h)
			var se *statusError
			if err != nil && errors.As(err, &se) && se.Code == http.StatusUnauthorized && !renewed {
				if _, err := a.login(ctx, true); err != nil {
					return nil, err
				}
				continue
			}
			return b, err
		}
	}
	b, err := tryOnce(prefix)
	var se *statusError
	if err != nil && errors.As(err, &se) && se.Code == http.StatusNotFound {
		other := afcBase + "/api"
		if prefix != afcBase {
			other = afcBase
		}
		if b2, err2 := tryOnce(other); err2 == nil {
			a.mu.Lock()
			a.prefix = other
			a.mu.Unlock()
			return b2, nil
		}
	}
	return b, err
}

// list reads a collection and returns its "result" rows (AFC answers {"result": [...], "count": n, "page": {...}}).
func (a *afc) list(ctx context.Context, resource, query string) ([]map[string]any, error) {
	p := "/" + resource
	if query != "" {
		p += "?" + query
	}
	v, err := a.get(ctx, p)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return rows(m["result"]), nil
}

func (a *afc) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Hostname: a.d.Name, Vendor: "Aruba", Model: "Fabric Composer"}
	fabs, err := a.list(ctx, "fabrics", "")
	if err != nil {
		return f, err
	}
	names := []string{}
	for _, x := range fabs {
		names = append(names, str(x["name"]))
	}
	f.Model = fmt.Sprintf("Fabric Composer, %d fabric(s)", len(fabs))
	if len(names) > 0 {
		f.Model += ": " + strings.Join(names, ", ")
	}
	return f, nil
}

func (a *afc) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (a *afc) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (a *afc) Config(context.Context) (string, error)          { return "", ErrUnsupported }

// afcDeny are resources never read through this driver: they hold credentials, keys or the controller's own accounts.
var afcDeny = map[string]bool{"users": true, "roles": true, "tokens": true, "auth": true, "aaa": true, "ldap": true, "radius": true, "tacacs": true,
	"certificates": true, "keys": true, "secrets": true, "backups": true, "backup": true, "license": true, "licenses": true, "saml": true, "sso": true}

func afcSegOK(seg string) bool {
	return afcResRE.MatchString(strings.ToLower(seg)) || entraGUIDRE.MatchString(seg)
}

// afcRead checks a path for APIGet: /<resource>[/<uuid>[/<sub resource>]] with an optional query, no denied segment.
func afcRead(path string) (string, error) {
	p := path
	for _, pre := range []string{afcBase + "/api/", afcBase + "/"} {
		if strings.HasPrefix(p, pre) {
			p = "/" + strings.TrimPrefix(p, pre)
			break
		}
	}
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if !strings.HasPrefix(pp, "/") || len(segs) < 1 || len(segs) > 3 {
		return "", errors.New("path: /<resource>, /<resource>/<uuid> or /<resource>/<uuid>/<sub resource> (see device_api_catalog)")
	}
	for i, s := range segs {
		if (i == 0 || i == 2) && !afcResRE.MatchString(s) || i == 1 && !afcSegOK(s) {
			return "", fmt.Errorf("path: %q is not a resource name or a UUID", s)
		}
		if afcDeny[strings.ToLower(s)] {
			return "", fmt.Errorf("path: %q holds accounts, keys or licences and is not read here", s)
		}
	}
	return p, nil
}

func (a *afc) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show <resource> [name=value ...]   for example: show fabrics, show switches, show vrfs fabric_uuid=…")
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	res := strings.ToLower(f[1])
	if !afcResRE.MatchString(res) || afcDeny[res] {
		return "", usage
	}
	q := url.Values{}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !afcResRE.MatchString(strings.ToLower(k)) || v == "" || len(v) > 128 || strings.ContainsAny(v, "&#\"'`;<>") {
			return "", usage
		}
		q.Set(k, v)
	}
	rs, err := a.list(ctx, res, q.Encode())
	if err != nil {
		return "", err
	}
	for i := range rs {
		rs[i] = redactMap(rs[i])
	}
	b, _ := json.MarshalIndent(map[string]any{"resource": res, "count": len(rs), "result": rs}, "", "  ")
	return RedactText(string(b)), nil
}

func (a *afc) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := afcRead(path)
	if err != nil {
		return nil, false, err
	}
	v, err := a.get(ctx, p)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (a *afc) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET paths of the Aruba Fabric Composer API below /api/v1: /<resource>, /<resource>/<uuid>, /<resource>/<uuid>/<sub resource>, with ?name=… style filters. " +
			"Only GET is sent. The AFC's own API Explorer (the ? at the top right of its web page) lists every resource. Users, roles, authentication servers, tokens, keys, licences and backups are not read.",
		"examples": []string{"/fabrics", "/switches", "/vrfs", "/vlans", "/vlan_groups", "/switches/<uuid>"},
	}, nil
}

// ---- changes ----

var afcRawDeny = map[string]bool{"users": true, "roles": true, "tokens": true, "auth": true, "aaa": true, "ldap": true, "radius": true, "tacacs": true,
	"certificates": true, "keys": true, "secrets": true, "backup": true, "backups": true, "restore": true, "license": true, "licenses": true,
	"saml": true, "sso": true, "upgrade": true, "upgrades": true, "firmware": true, "reboot": true, "reset": true, "factory_reset": true, "shutdown": true}

func afcRawGuard(_, p string) error {
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change")
	}
	if strings.Contains(pp, "..") || strings.ContainsAny(pp, "\r\n\x00 ") || !strings.HasPrefix(pp, afcBase+"/") {
		return errors.New("path: Aruba Fabric Composer is changed below /api/v1/")
	}
	for _, s := range strings.Split(strings.Trim(strings.TrimPrefix(pp, afcBase), "/"), "/") {
		if afcRawDeny[strings.ToLower(s)] {
			return fmt.Errorf("path: %q is not changed here (accounts, keys, licences, backups, upgrades and reboots)", s)
		}
	}
	return nil
}

func (a *afc) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if len(r.Lines) > 0 {
		return RawResult{DryRun: dry}, errors.New("lines: Aruba Fabric Composer is changed with method, path and body")
	}
	h, err := a.hdr(ctx)
	if err != nil {
		return RawResult{DryRun: dry}, err
	}
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	if !strings.HasPrefix(r.Path, afcBase+"/") {
		r.Path = afcBase + "/" + strings.TrimPrefix(r.Path, "/")
	}
	return restRaw(ctx, restSpec{
		api: a.api, hdr: h, json: true,
		guard: afcRawGuard,
		restore: func(b []byte) (any, bool) {
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				return nil, false
			}
			if res, ok := m["result"]; ok { // a single record comes as {"result": {...}} or {"result": [{...}]}
				if l, ok := res.([]any); ok {
					if len(l) != 1 {
						return nil, false
					}
					return l[0], true
				}
				return res, res != nil
			}
			return m, len(m) > 0
		},
		alive: func(ctx context.Context) error { _, err := a.get(ctx, "/fabrics"); return err },
	}, r, dry)
}

func (a *afc) Close(ctx context.Context) {
	a.mu.Lock()
	t := a.tok
	a.tok = ""
	a.mu.Unlock()
	if t != "" { // free the token: a user may hold only ten
		c, cancel := cleanupCtx()
		defer cancel()
		_, _ = a.api.do(c, http.MethodDelete, afcBase+"/auth/token", nil, http.Header{"Authorization": {t}})
	}
	a.api.close()
}
