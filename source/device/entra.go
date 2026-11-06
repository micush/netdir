package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Microsoft Entra ID (Azure AD) through Microsoft Graph.  What it answers: which devices belong to a user.
//
// The credential is an app registration with the application permissions Device.Read.All and User.Read.All (admin consent given):
// the credential's Username is the application (client) ID and its Password the client secret; the tenant is the option
// "tenant" (a directory ID or a domain such as contoso.onmicrosoft.com).  A token is asked for once per driver with the client
// credentials flow (POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token), kept in memory, and sent as a Bearer
// token to https://graph.microsoft.com/v1.0.  A credential with only a Token uses that as the Bearer token as it is.  Options:
// "login_host" (default login.microsoftonline.com; login.microsoftonline.us for US Government), and the device's Address is the Graph
// host (default graph.microsoft.com; graph.microsoft.us).
//
// Reading sends only GET and APIGet reads only users, their devices, devices, and the organization.  A change is RawChange (rawmon.go:
// POST, PUT, PATCH, DELETE at /users, /devices, /groups, /organization; rw keys only; sign-in methods, passwords, keys, roles, consent,
// mail and files are refused).
//
//	show devices user=<user principal name | object ID | name>   the user's registered and owned devices, merged
//	show user user=<...>                                          the user (or the users that match a name)
//
// A name is looked up with startswith on the display name and the user principal name; a name that matches several users is not
// guessed, the candidates are listed.

func init() { Register("entra", newEntra) }

type entra struct {
	d        Device
	api      *apiClient
	login    *apiClient
	tenant   string
	id, pw   string
	rt       string // refresh token of a browser sign-in (the credential's token "rt:...")
	credName string

	mu  sync.Mutex
	tok string
	exp time.Time
}

var (
	entraTenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)
	entraGUIDRE   = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	entraUserRE   = regexp.MustCompile(`^[A-Za-z0-9 @._'#+-]{1,128}$`)
)

func newEntra(d Device, c Credential) (Driver, error) {
	e := &entra{d: d, tenant: strings.TrimSpace(d.Options["tenant"])}
	if strings.HasPrefix(c.Token, entraRT) {
		e.rt, e.credName = strings.TrimPrefix(c.Token, entraRT), c.Name
		if e.rt == "" {
			return nil, fmt.Errorf("device %s: not signed in: right-click the device ▸ Sign in with Microsoft (or netdir --device-signin %s)", d.Name, d.Name)
		}
		if e.tenant == "" {
			e.tenant = "organizations"
		}
		c.Token = ""
	}
	if e.rt == "" && c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: Entra needs a browser sign-in (an empty new login), or the application ID as the login's user name and the client secret as its password", d.Name)
	}
	if e.rt == "" && c.Token == "" && !entraTenantRE.MatchString(e.tenant) {
		return nil, fmt.Errorf("device %s: option tenant is the directory ID or domain (contoso.onmicrosoft.com)", d.Name)
	}
	e.id, e.pw = c.Username, c.Password
	if d.Address == "" {
		d.Address = "graph.microsoft.com"
		e.d = d
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	if c.Token != "" {
		e.tok, e.exp = c.Token, time.Now().Add(24*time.Hour)
	}
	login, err := entraLogin(d)
	if err != nil {
		return nil, err
	}
	e.api, e.login = api, login
	return e, nil
}

// token is the Bearer token: asked for when there is none or it is within a minute of its end.
func (e *entra) token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rt != "" {
		return e.delegated(ctx)
	}
	if e.tok != "" && time.Now().Add(time.Minute).Before(e.exp) {
		return e.tok, nil
	}
	if e.id == "" || e.pw == "" {
		return "", errors.New("the token has expired and there is no client secret to ask for another")
	}
	scope := "https://" + strings.Split(e.d.Address, ":")[0] + "/.default"
	form := url.Values{"client_id": {e.id}, "client_secret": {e.pw}, "scope": {scope}, "grant_type": {"client_credentials"}}
	b, err := e.login.do(ctx, http.MethodPost, "/"+url.PathEscape(e.tenant)+"/oauth2/v2.0/token", form.Encode(),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		return "", fmt.Errorf("sign-in to the tenant failed: %w", err)
	}
	var t struct {
		Token   string `json:"access_token"`
		Expires any    `json:"expires_in"`
	}
	if json.Unmarshal(b, &t) != nil || t.Token == "" {
		return "", errors.New("sign-in to the tenant: the answer holds no access token")
	}
	e.tok = t.Token
	e.exp = time.Now().Add(time.Duration(num(t.Expires)) * time.Second)
	if num(t.Expires) <= 0 {
		e.exp = time.Now().Add(30 * time.Minute)
	}
	return e.tok, nil
}

// entraWait is how long a 429 is waited out; a variable so tests are quick.
var entraWait = 2 * time.Second

const graphBase = "/v1.0"

// get is a GET of a path below /v1.0 (or an absolute @odata.nextLink on the same host, passed as its path and query).
func (e *entra) get(ctx context.Context, path string) (any, error) {
	for try := 0; ; try++ {
		tok, err := e.token(ctx)
		if err != nil {
			return nil, err
		}
		b, err := e.api.do(ctx, http.MethodGet, graphBase+path, nil, http.Header{"Authorization": {"Bearer " + tok}, "ConsistencyLevel": {"eventual"}})
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code == http.StatusTooManyRequests && try < 2 {
			if err := sleepCtx(ctx, entraWait); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var v any
		if len(strings.TrimSpace(string(b))) == 0 {
			return nil, nil
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
		}
		return v, nil
	}
}

// list reads a collection and follows @odata.nextLink (on the Graph host only) for at most 10 pages.
func (e *entra) list(ctx context.Context, path string) ([]map[string]any, error) {
	var out []map[string]any
	for page := 0; page < 10; page++ {
		v, err := e.get(ctx, path)
		if err != nil {
			return out, err
		}
		m, _ := v.(map[string]any)
		out = append(out, rows(m["value"])...)
		next := str(m["@odata.nextLink"])
		if next == "" {
			return out, nil
		}
		u, err := url.Parse(next)
		if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), strings.Split(e.d.Address, ":")[0]) || !strings.HasPrefix(u.Path, graphBase+"/") {
			return out, errors.New("the answer pointed to another host for its next page; it was not followed")
		}
		path = strings.TrimPrefix(u.Path, graphBase)
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
	}
	return out, errors.New("more than 10 pages: ask for less")
}

func (e *entra) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Microsoft Entra ID"}
	v, err := e.get(ctx, "/organization?$select=id,displayName,verifiedDomains")
	if err != nil {
		return f, err
	}
	m, _ := v.(map[string]any)
	o := rows(m["value"])
	if len(o) == 0 {
		return f, errors.New("the tenant answered no organization")
	}
	f.Hostname = firstOf(str(o[0]["displayName"]), e.tenant)
	f.Model = "Entra tenant " + str(o[0]["id"])
	return f, nil
}

func (e *entra) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (e *entra) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (e *entra) Config(context.Context) (string, error)          { return "", ErrUnsupported }

// ---- users and their devices ----

const (
	entraUserSel   = "$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,department,jobTitle"
	entraDeviceSel = "$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,managementType,accountEnabled,approximateLastSignInDateTime,registrationDateTime,manufacturer,model,profileType"
)

func odataQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// findUsers resolves what a caller typed: a directory object ID, a user principal name or mail address, or a name.
func (e *entra) findUsers(ctx context.Context, who string) ([]map[string]any, error) {
	who = strings.TrimSpace(who)
	if !entraUserRE.MatchString(who) {
		return nil, errors.New("user: a user principal name (alice@contoso.com), an object ID or a name; letters, digits and @ . _ ' # + - only")
	}
	one := func(path string) ([]map[string]any, error) {
		v, err := e.get(ctx, path)
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code == http.StatusNotFound {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if m, ok := v.(map[string]any); ok && str(m["id"]) != "" {
			return []map[string]any{m}, nil
		}
		return nil, nil
	}
	query := func(filter string) ([]map[string]any, error) {
		return e.list(ctx, "/users?$filter="+url.QueryEscape(filter)+"&$top=11&"+entraUserSel+"&$count=true")
	}
	switch {
	case entraGUIDRE.MatchString(who):
		return one("/users/" + who + "?" + entraUserSel)
	case strings.Contains(who, "@"):
		if u, err := one("/users/" + url.PathEscape(who) + "?" + entraUserSel); err != nil || len(u) > 0 {
			return u, err
		}
		return query("userPrincipalName eq " + odataQuote(who) + " or mail eq " + odataQuote(who))
	}
	q := odataQuote(who)
	// a short account name (msmith) is the start of the sign-in name, the mail nickname or the on-premises account name
	us, err := query("startswith(displayName," + q + ") or startswith(userPrincipalName," + q + ") or startswith(mailNickname," + q + ") or onPremisesSamAccountName eq " + q)
	var se *statusError
	if err != nil && errors.As(err, &se) && se.Code == http.StatusBadRequest { // a tenant or API that cannot filter on those: the plain lookup
		return query("startswith(displayName," + q + ") or startswith(userPrincipalName," + q + ")")
	}
	return us, err
}

// oneUser is findUsers that must find exactly one.
func (e *entra) oneUser(ctx context.Context, who string) (map[string]any, error) {
	us, err := e.findUsers(ctx, who)
	if err != nil {
		return nil, err
	}
	switch len(us) {
	case 0:
		return nil, fmt.Errorf("no user matches %q", who)
	case 1:
		return us[0], nil
	}
	var l []string
	for _, u := range us {
		l = append(l, str(u["displayName"])+" <"+str(u["userPrincipalName"])+">")
	}
	sort.Strings(l)
	if len(l) > 10 {
		l = append(l[:10], "…")
	}
	return nil, fmt.Errorf("%q matches several users; use the user principal name or object ID: %s", who, strings.Join(l, "; "))
}

// userDevices reads the devices registered to a user and the devices a user owns, merged by object ID.
func (e *entra) userDevices(ctx context.Context, user map[string]any) (any, error) {
	id := str(user["id"])
	if !entraGUIDRE.MatchString(id) {
		return nil, errors.New("the user has no usable object ID")
	}
	byID := map[string]map[string]any{}
	var order []string
	for _, rel := range []struct{ path, name string }{{"registeredDevices", "registered"}, {"ownedDevices", "owned"}} {
		l, err := e.list(ctx, "/users/"+id+"/"+rel.path+"/microsoft.graph.device?$top=999&"+entraDeviceSel)
		if err != nil {
			return nil, fmt.Errorf("%s devices: %w", rel.name, err)
		}
		for _, d := range l {
			k := str(d["id"])
			if byID[k] == nil {
				d = redactMap(d)
				delete(d, "@odata.type")
				byID[k] = d
				order = append(order, k)
			}
			byID[k]["relation"] = append(rels(byID[k]["relation"]), rel.name)
		}
	}
	devs := make([]map[string]any, 0, len(order))
	for _, k := range order {
		devs = append(devs, byID[k])
	}
	sort.SliceStable(devs, func(i, j int) bool {
		return strings.ToLower(str(devs[i]["displayName"])) < strings.ToLower(str(devs[j]["displayName"]))
	})
	return map[string]any{"user": redactMap(user), "count": len(devs), "devices": devs}, nil
}

func rels(v any) []string {
	s, _ := v.([]string)
	return s
}

// Show takes "show devices user=WHO" and "show user user=WHO" (WHO may also follow the name directly: show devices alice@contoso.com).
func (e *entra) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show devices user=<user principal name, object ID or name>  |  show user user=<...>")
	f := strings.Fields(cmd)
	if len(f) < 3 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	name := strings.ToLower(f[1])
	rest := strings.TrimSpace(cmd[strings.Index(strings.ToLower(cmd), name)+len(name):])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "user="))
	var out any
	switch name {
	case "devices":
		u, err := e.oneUser(ctx, rest)
		if err != nil {
			return "", err
		}
		if out, err = e.userDevices(ctx, u); err != nil {
			return "", err
		}
	case "user":
		us, err := e.findUsers(ctx, rest)
		if err != nil {
			return "", err
		}
		if len(us) == 0 {
			return "", fmt.Errorf("no user matches %q", rest)
		}
		for i := range us {
			us[i] = redactMap(us[i])
		}
		out = map[string]any{"users": us}
	default:
		return "", usage
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return RedactText(string(b)), nil
}

// ---- reading through the API ----

// entraPathRE: what APIGet reads: the organization, users (and their registered and owned devices), devices (and their owners,
// users and groups).  A user's mail, files, calendar and sign-in methods are never reached.
var entraPathRE = regexp.MustCompile(`^/(organization|users(/[^/?]+(/(registeredDevices|ownedDevices)(/microsoft\.graph\.device)?)?)?|devices(/[^/?]+(/(registeredOwners|registeredUsers|memberOf))?)?)$`)

func entraRead(path string) (string, error) {
	p := strings.TrimPrefix(path, graphBase)
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	if !entraPathRE.MatchString(pp) {
		return "", errors.New("path: Entra is read at /users, /users/{id}/registeredDevices, /users/{id}/ownedDevices, /devices, /devices/{id}/registeredOwners and /organization (see device_api_catalog)")
	}
	return p, nil
}

func (e *entra) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := entraRead(path)
	if err != nil {
		return nil, false, err
	}
	v, err := e.get(ctx, p)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (e *entra) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET Microsoft Graph v1.0 paths: /users?$filter=startswith(displayName,'Ali')&$select=id,displayName,userPrincipalName, /users/{id or user principal name}, " +
			"/users/{id}/registeredDevices, /users/{id}/ownedDevices, /devices?$filter=displayName eq 'LAPTOP-01', /devices/{id}/registeredOwners, /organization. " +
			"Reading sends only GET (changes are device_change_raw). The simplest question is the Show command: show devices user=alice@contoso.com.",
		"examples": []string{"/users/alice@contoso.com/registeredDevices", "/devices?$filter=startswith(displayName,'LAPTOP')&$select=id,displayName,operatingSystem", "/organization"},
	}, nil
}

func (e *entra) Close(context.Context) { e.api.close(); e.login.close() }

// UserDevices is UserDeviceLooker: the user and the devices, most recently signed in first (a device that never signed in last).
func (e *entra) UserDevices(ctx context.Context, who string) (map[string]any, []map[string]any, error) {
	u, err := e.oneUser(ctx, who)
	if err != nil {
		return nil, nil, err
	}
	v, err := e.userDevices(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	m, _ := v.(map[string]any)
	devs, _ := m["devices"].([]map[string]any)
	sort.SliceStable(devs, func(i, j int) bool {
		return str(devs[i]["approximateLastSignInDateTime"]) > str(devs[j]["approximateLastSignInDateTime"]) // RFC 3339 in UTC sorts as text
	})
	return redactMap(u), devs, nil
}
