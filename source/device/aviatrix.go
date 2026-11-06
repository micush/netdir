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
)

// Aviatrix (https://docs.aviatrix.com), the multicloud network platform, through the Controller's API: one URL, https://HOST/v2/api
// (option api_path: /v1/api for an old controller), and every call is an "action" with its parameters, sent as a form.  A call
// answers {"return": true|false, "results": ..., "reason": "..."}.  The credential is the controller's user name and password:
// the driver asks for an API token (action get_api_token), signs in with it in the header X-Access-Key (action login), gets a
// session ID (CID) and sends it in the form of every later call; a controller that answers neither signs in without the token.
// A session that has expired ("CID is invalid", "Invalid session. Please login again.") is renewed once.  Nothing goes into a URL:
// every call is a POST, also a read.
//
// The "device" is the Aviatrix Controller:
//
//   - Facts: the controller and how many gateways it manages.  Interfaces: the gateways (state, addresses, size, cloud, region).
//   - Show: "show gateways|transit|spoke|peerings", "show gateway NAME" (everything about one gateway: its summary, its details and
//     its peerings), and "show ACTION [name=value ...]" for any read action (list_..., get_..., show_...).
//   - APIGet: /ACTION?name=value, the same reads.  Actions that read users, passwords, keys, certificates, tokens, SAML, LDAP, backups
//     or administrators are refused.
//   - RawChange (rw keys only): Method POST, Body {"action": "edit_gw_config", ...} (or action=...&name=value), the controller's own
//     write.  The session ID is added.  Login, users and administrators, credentials, backups and restores, and deleting a gateway
//     are refused.
//
// The action names and result fields are those of Aviatrix's own Terraform provider; a controller release that names one
// otherwise answers with its reason.

func init() { Register("aviatrix", newAviatrix) }

type aviatrix struct {
	d    Device
	api  *apiClient
	path string
	user string
	pass string

	mu  sync.Mutex
	cid string
}

var (
	avxPathRE   = regexp.MustCompile(`^/v[0-9]+(\.[0-9]+)?/api$`)
	avxActionRE = regexp.MustCompile(`^[a-z][a-z0-9_]{2,80}$`)
	avxKeyRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
	avxValRE    = regexp.MustCompile(`^[A-Za-z0-9._:@/*+, -]{1,200}$`)
	avxReadRE   = regexp.MustCompile(`^(list|get|show)_[a-z0-9_]+$`)
	// parts of an action's name that mean the action reads or changes who may sign in, a credential, or a copy of the controller
	avxDenyWords = []string{"token", "password", "passwd", "secret", "key", "cert", "saml", "ldap", "duo", "radius", "user", "admin", "login", "logout", "backup",
		"restore", "credential", "account_password", "tacacs", "sso", "oidc", "license", "download"}
)

func avxDenied(action string) string {
	for _, w := range avxDenyWords {
		if strings.Contains(action, w) {
			return w
		}
	}
	return ""
}

func newAviatrix(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Aviatrix needs the controller's user name and password", d.Name)
	}
	a := &aviatrix{d: d, user: c.Username, pass: c.Password, path: firstOf(strings.TrimSpace(d.Options["api_path"]), "/v2/api")}
	if !avxPathRE.MatchString(a.path) {
		return nil, fmt.Errorf("device %s: option api_path is like /v2/api", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	a.api = api
	return a, nil
}

var avxForm = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}

type avxAnswer struct {
	Return  bool            `json:"return"`
	Results json.RawMessage `json:"results"`
	Reason  string          `json:"reason"`
	CID     string          `json:"CID"`
}

// post sends one form and reads the answer; it does not check "return".
func (a *aviatrix) post(ctx context.Context, f url.Values, hdr http.Header) (avxAnswer, error) {
	h := avxForm.Clone()
	for k, v := range hdr {
		h[k] = v
	}
	b, err := a.api.do(ctx, http.MethodPost, a.path, f.Encode(), h)
	if err != nil {
		return avxAnswer{}, err
	}
	var r avxAnswer
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("action %s: the answer is not the JSON expected: %v", f.Get("action"), err)
	}
	return r, nil
}

func (a *aviatrix) login(ctx context.Context) error {
	hdr := http.Header{}
	if t, err := a.post(ctx, url.Values{"action": {"get_api_token"}, "log_enable": {"true"}}, nil); err == nil && t.Return {
		var tok struct {
			T string `json:"api_token"`
		}
		if json.Unmarshal(t.Results, &tok) == nil && tok.T != "" {
			hdr.Set("X-Access-Key", tok.T)
		}
	}
	r, err := a.post(ctx, url.Values{"action": {"login"}, "username": {a.user}, "password": {a.pass}}, hdr)
	if err != nil {
		return fmt.Errorf("Aviatrix: sign-in failed: %w", err)
	}
	if !r.Return || r.CID == "" {
		return fmt.Errorf("Aviatrix: sign-in failed: %s", firstOf(RedactText(r.Reason), "the controller gave no session"))
	}
	a.cid = r.CID
	return nil
}

func avxExpired(reason string) bool {
	return strings.Contains(reason, "CID is invalid") || strings.Contains(reason, "Invalid session. Please login again.")
}

// call runs one action (signing in when there is no session, and once more when the session has expired) and returns the answer
// when the controller says "return": true.
func (a *aviatrix) call(ctx context.Context, action string, params url.Values) (avxAnswer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for try := 0; ; try++ {
		if a.cid == "" {
			if err := a.login(ctx); err != nil {
				return avxAnswer{}, err
			}
		}
		f := url.Values{}
		for k, v := range params {
			f[k] = v
		}
		f.Set("action", action)
		f.Set("CID", a.cid)
		r, err := a.post(ctx, f, nil)
		if err != nil {
			return r, err
		}
		if !r.Return && avxExpired(r.Reason) && try == 0 {
			a.cid = ""
			continue
		}
		if !r.Return {
			return r, fmt.Errorf("%s: %s", action, firstOf(RedactText(r.Reason), "the controller refused it"))
		}
		return r, nil
	}
}

// results decodes "results" into a value; an object, a list or a string.
func (r avxAnswer) results() any {
	var v any
	if len(r.Results) == 0 || json.Unmarshal(r.Results, &v) != nil {
		return nil
	}
	return v
}

func (a *aviatrix) gateways(ctx context.Context, params url.Values) ([]map[string]any, error) {
	r, err := a.call(ctx, "list_vpcs_summary", params)
	if err != nil {
		return nil, err
	}
	return rows(r.results()), nil
}

func (a *aviatrix) Facts(ctx context.Context) (Facts, error) {
	gws, err := a.gateways(ctx, nil)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Hostname: a.d.Address, Vendor: "Aviatrix", Model: fmt.Sprintf("Multicloud network controller: %d gateways", len(gws))}
	if r, err := a.call(ctx, "list_version_info", nil); err == nil {
		if m, ok := r.results().(map[string]any); ok {
			f.OSVersion = firstOf(str(m["current_version"]), str(m["version"]), str(m["current_release"]))
		}
	}
	return f, nil
}

func (a *aviatrix) Interfaces(ctx context.Context) ([]Interface, error) {
	gws, err := a.gateways(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(gws))
	for _, g := range gws {
		i := Interface{Name: firstOf(str(g["vpc_name"]), str(g["gw_name"]), str(g["vpc_id"])),
			Description: strings.TrimSpace(strings.Join([]string{str(g["cloud_type"]), str(g["account_name"]), firstOf(str(g["vpc_region"]), str(g["vpc_reg"])), str(g["vpc_size"])}, " "))}
		for _, k := range []string{"private_ip", "public_ip"} {
			if ip := str(g[k]); ip != "" {
				i.Addresses = append(i.Addresses, ip)
			}
		}
		if s := str(g["inst_state"]); s != "" {
			i.OperUp, i.AdminUp = boolp(s == "running"), boolp(s != "stopped")
		}
		out = append(out, i)
	}
	return out, nil
}

func (a *aviatrix) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (a *aviatrix) Config(context.Context) (string, error)        { return "", ErrUnsupported }

const avxUsage = "show gateways | transit | spoke | peerings | gateway NAME | ACTION [name=value ...] (ACTION is a read: list_..., get_..., show_...)"

func avxText(v any) string {
	b, _ := json.MarshalIndent(obsScrub(Redact(v)), "", "  ")
	return string(b)
}

// avxParams reads name=value words.
func avxParams(words []string) (url.Values, error) {
	q := url.Values{}
	for _, w := range words {
		k, v, ok := strings.Cut(w, "=")
		if !ok || !avxKeyRE.MatchString(k) || k == "action" || k == "cid" || k == "CID" || !avxValRE.MatchString(v) {
			return nil, fmt.Errorf("%q: a parameter is name=value, the name in lower case letters, digits and _, the value letters, digits and . _ : @ / * + , -", w)
		}
		if avxDenied(k) != "" {
			return nil, fmt.Errorf("%q: a parameter that names a password, key or token is not sent here", k)
		}
		q.Set(k, v)
	}
	return q, nil
}

func (a *aviatrix) read(ctx context.Context, action string, q url.Values) (any, error) {
	if !avxReadRE.MatchString(action) {
		return nil, fmt.Errorf("%q: not a read action (list_..., get_..., show_...); %s", action, avxUsage)
	}
	if w := avxDenied(action); w != "" {
		return nil, fmt.Errorf("%s: actions about users, passwords, keys, certificates, tokens, single sign-on and backups (%q) are not read here", action, w)
	}
	r, err := a.call(ctx, action, q)
	if err != nil {
		return nil, err
	}
	return r.results(), nil
}

func (a *aviatrix) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(avxUsage)
	}
	name := strings.ToLower(f[1])
	switch name {
	case "gateways", "transit", "spoke":
		q, err := avxParams(f[2:])
		if err != nil {
			return "", err
		}
		switch name {
		case "transit":
			q.Set("transit_only", "true")
		case "spoke":
			q.Set("spoke_only", "true")
		}
		v, err := a.read(ctx, "list_vpcs_summary", q)
		if err != nil {
			return "", err
		}
		return avxText(v), nil
	case "peerings":
		v, err := a.read(ctx, "list_inter_transit_gateway_peering", nil)
		if err != nil {
			return "", err
		}
		return avxText(v), nil
	case "gateway":
		if len(f) != 3 || !avxValRE.MatchString(f[2]) {
			return "", errors.New("show gateway NAME: the gateway's name (show gateways lists them)")
		}
		all, err := a.gatewayAll(ctx, f[2])
		if err != nil {
			return "", err
		}
		return avxText(all), nil
	}
	q, err := avxParams(f[2:])
	if err != nil {
		return "", err
	}
	v, err := a.read(ctx, f[1], q)
	if err != nil {
		return "", err
	}
	return avxText(v), nil
}

// gatewayAll answers everything about one gateway: its summary, its details and the transit peerings it is in.
func (a *aviatrix) gatewayAll(ctx context.Context, name string) (map[string]any, error) {
	out := map[string]any{"gateway": name}
	sum, err := a.read(ctx, "list_vpcs_summary", url.Values{"gateway_name": {name}})
	if err != nil {
		return nil, err
	}
	if len(rows(sum)) == 0 {
		return nil, fmt.Errorf("show gateway %s: the controller has no gateway of that name", name)
	}
	out["summary"] = sum
	var unavailable []string
	if v, err := a.read(ctx, "get_gateway_info", url.Values{"gateway_name": {name}}); err != nil {
		unavailable = append(unavailable, "details: "+err.Error())
	} else {
		out["details"] = v
	}
	if v, err := a.read(ctx, "list_inter_transit_gateway_peering", nil); err != nil {
		unavailable = append(unavailable, "peerings: "+err.Error())
	} else {
		var mine []any
		for _, pair := range avxFlatten(v) {
			if strings.Contains(toJSONString(pair), `"`+name+`"`) {
				mine = append(mine, pair)
			}
		}
		out["peerings"] = mine
	}
	if len(unavailable) > 0 {
		sort.Strings(unavailable)
		out["unavailable"] = unavailable
	}
	return out, nil
}

// avxFlatten turns the nested list of peerings ([][]peering) into one list of peerings.
func avxFlatten(v any) []any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []any
	for _, x := range l {
		if inner, ok := x.([]any); ok {
			out = append(out, inner...)
		} else {
			out = append(out, x)
		}
	}
	return out
}

func toJSONString(v any) string { b, _ := json.Marshal(v); return string(b) }

func (a *aviatrix) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	action := strings.TrimPrefix(pp, "/")
	if strings.Contains(action, "/") || action == "" {
		return nil, false, errors.New("path: /ACTION?name=value (a read: list_..., get_..., show_...; see device_api_catalog)")
	}
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return nil, false, errors.New("path: the query is not valid")
	}
	var words []string
	for k, vs := range vals {
		words = append(words, k+"="+vs[0])
	}
	q, err := avxParams(words)
	if err != nil {
		return nil, false, err
	}
	v, err := a.read(ctx, action, q)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (a *aviatrix) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "Every call is an action: /ACTION?name=value (sent to the controller as a form with the session ID added). Reads are actions named list_..., get_... and show_.... " +
			"Actions about users, passwords, keys, certificates, tokens, single sign-on and backups are refused. Changes are device_change_raw with {\"action\": \"...\", ...}.",
		"examples": []string{"/list_vpcs_summary", "/list_vpcs_summary?transit_only=true", "/list_vpcs_summary?gateway_name=transit1", "/get_gateway_info?gateway_name=transit1",
			"/list_inter_transit_gateway_peering", "/get_inter_transit_gateway_peering_details?gateway1=transit1&gateway2=transit2"},
		"tip": "show gateway NAME (device_show) answers everything about one gateway in one call.",
	}, nil
}

// RawChange: Method POST, Body {"action": "edit_gw_config", "gateway_name": "gw1", ...} or action=edit_gw_config&gateway_name=gw1.
func (a *aviatrix) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if len(r.Lines) > 0 {
		return res, errors.New("lines: Aviatrix is changed with an action and its parameters in the body")
	}
	if m := strings.ToUpper(strings.TrimSpace(r.Method)); m != http.MethodPost {
		return res, fmt.Errorf("method %q: use POST (the action is in the body)", r.Method)
	}
	if p := strings.TrimSpace(r.Path); p != "" && p != "/" && p != a.path {
		return res, fmt.Errorf("path %q: leave it empty; the action is in the body", r.Path)
	}
	if len(r.Body) > rawMaxBody || strings.ContainsRune(r.Body, 0) {
		return res, errors.New("body: larger than 256 KB, or not text")
	}
	f := url.Values{}
	if t := strings.TrimSpace(r.Body); strings.HasPrefix(t, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(t), &m) != nil {
			return res, errors.New("body: not valid JSON")
		}
		for k, v := range m {
			switch x := v.(type) {
			case string:
				f.Set(k, x)
			case bool, float64:
				f.Set(k, fmt.Sprint(x))
			default:
				b, _ := json.Marshal(x)
				f.Set(k, string(b))
			}
		}
	} else {
		var err error
		if f, err = url.ParseQuery(t); err != nil {
			return res, fmt.Errorf("body: not JSON and not name=value&name=value: %v", err)
		}
	}
	action := f.Get("action")
	if !avxActionRE.MatchString(action) {
		return res, errors.New("body: an \"action\" (edit_gw_config, ...) is required")
	}
	f.Del("CID") // the session is the driver's
	f.Del("cid")
	for k := range f {
		if k != "action" && !avxKeyRE.MatchString(k) {
			return res, fmt.Errorf("body: %q is not a parameter name", k)
		}
		if k != "action" && avxDenied(k) != "" {
			return res, fmt.Errorf("body: %q names a password, key, token or user: it is not sent here", k)
		}
	}
	if w := avxDenied(action); w != "" {
		return res, fmt.Errorf("action %s: login, users, administrators, credentials, certificates, single sign-on, backups and restores are not changed here (%q)", action, w)
	}
	if action == "delete_container" || action == "delete_public_subnet_filtering_gateway" {
		return res, errors.New("action: deleting a gateway is not done here")
	}
	if avxReadRE.MatchString(action) {
		return res, errors.New("action: that is a read: use device_show or device_api_get")
	}
	if dry {
		if gw := f.Get("gateway_name"); gw != "" {
			if v, err := a.read(ctx, "get_gateway_info", url.Values{"gateway_name": {gw}}); err == nil {
				res.Before = rawTrunc([]byte(toJSONString(Redact(v))))
			}
		}
		res.Note = fmt.Sprintf("would send the action %s with %d parameter(s); nothing was changed, and this program cannot put an Aviatrix change back", action, len(f)-1)
		return res, nil
	}
	params := url.Values{}
	for k, v := range f {
		if k != "action" {
			params[k] = v
		}
	}
	ans, err := a.call(ctx, action, params)
	if err != nil {
		return res, err
	}
	res.Applied = true
	res.Answer = rawTrunc([]byte(toJSONString(Redact(ans.results()))))
	res.Note = "Aviatrix keeps a change as made; this program cannot put it back. An action that runs in the background answers with a request ID: read its result with the matching get_ action"
	return res, nil
}

func (a *aviatrix) Close(context.Context) { a.api.close() }
