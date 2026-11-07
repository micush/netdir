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
	"strconv"
	"strings"
	"sync"
)

// Centreon (https://docs.centreon.com/docs/api/rest-api-v2), the monitoring platform built on Nagios/Engine, through its REST
// API v2: https://HOST/centreon/api/latest/... (option prefix: where Centreon is below the host, "/centreon" unless it says
// otherwise, "none" for the root; option api_version: "latest", or the release the URLs use, such as 24.04).  The credential is an
// API token (the credential's Token: a personal access token made in Centreon 23.10 and later), or a user name and a password: the
// driver signs in (POST /login) and sends the session token in the header X-AUTH-TOKEN; an expired session is renewed once.
// Nothing goes into a URL.
//
// Centreon is a monitor, not a switch: the "device" is the Centreon central server.
//
//   - Facts: the platform version and how many hosts it monitors.  Interfaces: the monitored hosts (name, address, up or not).
//   - Show: "show platform", "show pollers", "show hosts", "show host NAME" (everything Centreon knows about ONE host as one
//     answer: its monitoring record, its configuration, its services with their status and its recent timeline), "show services",
//     "show problems", "show hostgroups", "show servicegroups" and "show downtimes".
//   - APIGet: any read below /monitoring, /configuration and /platform.  Users, contacts, access rights, tokens, authentication
//     and administration are refused.
//   - RawChange (rw keys only): POST, PUT, PATCH and DELETE below /monitoring (acknowledge, downtime, check) and /configuration
//     (hosts, services, templates, groups, pollers).  Save exports the configuration to the pollers and reloads them.  Users,
//     contacts, access rights, tokens, authentication and administration are refused.
//
// What an answer holds that is a secret (an SNMP community, a password, a token) is hidden (Redact).  The field names are those of
// Centreon's own API; a release that names one otherwise still shows it, because "show host" keeps the whole record.

func init() { Register("centreon", newCentreon) }

type centreon struct {
	d      Device
	api    *apiClient
	prefix string // where Centreon is below the host: "/centreon" or ""
	ver    string // "latest" or a release
	user   string
	pass   string
	tok    string // an API token; "" when the driver signs in

	mu   sync.Mutex
	sess string // the session token of a sign-in
}

var (
	centPrefixRE = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*$`)
	centVerRE    = regexp.MustCompile(`^(latest|v?[0-9]{2}\.[0-9]{1,2})$`)
	centAPIRE    = regexp.MustCompile(`^/api/(latest|v?[0-9][0-9.]*)(/|$)`)
	centPathRE   = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~%-]+)*$`)
	centKeyRE    = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,60}$`)
	centRefRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
	centWordRE   = regexp.MustCompile(`^[A-Za-z0-9._:@/*-]{1,128}$`)
	centNumRE    = regexp.MustCompile(`^[0-9]{1,9}$`)
	// the parts of a path that are who may sign in, what they may do, and how: never read or written here
	centDenied = []string{"login", "logout", "users", "user", "contacts", "contact", "tokens", "token", "authentication", "administration",
		"acl", "access-groups", "access_groups", "passwords", "password", "providers", "vault", "security"}
)

const (
	centPage     = 100 // rows asked for in one page
	centMaxPages = 50  // pages read for one list (5000 rows)
	centSaveEP   = "/configuration/monitoring-servers/generate-and-reload"
)

func newCentreon(d Device, c Credential) (Driver, error) {
	if c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: Centreon needs an API token, or a user name and a password", d.Name)
	}
	x := &centreon{d: d, user: c.Username, pass: c.Password, tok: c.Token, prefix: "/centreon", ver: "latest"}
	if p := strings.TrimRight(strings.TrimSpace(d.Options["prefix"]), "/"); p != "" {
		if strings.EqualFold(p, "none") {
			x.prefix = ""
		} else if !centPrefixRE.MatchString(p) || strings.Contains(p, "..") {
			return nil, fmt.Errorf("device %s: option prefix is the path Centreon is served below, such as /centreon, or none", d.Name)
		} else {
			x.prefix = p
		}
	} else if strings.TrimSpace(d.Options["prefix"]) == "/" {
		x.prefix = ""
	}
	if v := strings.TrimSpace(d.Options["api_version"]); v != "" {
		if !centVerRE.MatchString(v) {
			return nil, fmt.Errorf("device %s: option api_version is latest, or a release such as 24.04", d.Name)
		}
		x.ver = v
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	x.api = api
	return x, nil
}

func (c *centreon) base() string { return c.prefix + "/api/" + c.ver }

// rel turns a path given with the prefix, or with /api/latest, into the path below the API ("/monitoring/hosts").
func (c *centreon) rel(p string) string {
	if c.prefix != "" && (p == c.prefix || strings.HasPrefix(p, c.prefix+"/")) {
		p = p[len(c.prefix):]
	}
	if m := centAPIRE.FindString(p); m != "" {
		p = "/" + p[len(m):]
	}
	return p
}

// session is the token the next request carries: the API token, or the session of a sign-in (made when there is none).
func (c *centreon) session(ctx context.Context) (string, error) {
	if c.tok != "" {
		return c.tok, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != "" {
		return c.sess, nil
	}
	body, _ := json.Marshal(map[string]any{"security": map[string]any{"credentials": map[string]any{"login": c.user, "password": c.pass}}})
	b, err := c.api.do(context.WithoutCancel(ctx), http.MethodPost, c.base()+"/login", body, jsonHdr())
	if err != nil {
		return "", fmt.Errorf("Centreon: sign-in failed: %w", err)
	}
	var r struct {
		Security struct {
			Token string `json:"token"`
		} `json:"security"`
	}
	if json.Unmarshal(b, &r) != nil || r.Security.Token == "" {
		return "", errors.New("Centreon: sign-in failed: the answer holds no session token")
	}
	c.sess = r.Security.Token
	return c.sess, nil
}

// do sends one request below the API with the session; a session that has expired (401) is renewed once.
func (c *centreon) do(ctx context.Context, method, path string, body any, h http.Header) ([]byte, error) {
	for try := 0; ; try++ {
		tok, err := c.session(ctx)
		if err != nil {
			return nil, err
		}
		hdr := http.Header{}
		for k, v := range h {
			hdr[k] = v
		}
		hdr.Set("X-Auth-Token", tok)
		b, err := c.api.do(ctx, method, c.base()+path, body, hdr)
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code == http.StatusUnauthorized {
			if c.tok != "" {
				return nil, fmt.Errorf("Centreon refused the API token (expired, or revoked): %w", err)
			}
			if try == 0 {
				c.mu.Lock()
				c.sess = ""
				c.mu.Unlock()
				continue
			}
		}
		return b, err
	}
}

func (c *centreon) get(ctx context.Context, path string) (any, error) {
	b, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
	}
	return v, nil
}

// centRows are the rows of an answer: {"result": [...], "meta": {...}} for a list, the object itself for one record.
func centRows(v any) []map[string]any {
	if m, ok := v.(map[string]any); ok {
		if r, ok := m["result"]; ok {
			return rows(r)
		}
	}
	return rows(v)
}

// centData is the data of an answer without its wrapper.
func centData(v any) any {
	if m, ok := v.(map[string]any); ok {
		if r, ok := m["result"]; ok {
			return r
		}
	}
	return v
}

func centTotal(v any) int {
	if m, ok := v.(map[string]any); ok {
		if meta, ok := m["meta"].(map[string]any); ok {
			return int(num(meta["total"]))
		}
	}
	return 0
}

// all reads a list page by page (at most maxPages of centPage rows) and says how many rows the server holds.
func (c *centreon) all(ctx context.Context, path string, q url.Values, maxPages int) ([]map[string]any, int, error) {
	var out []map[string]any
	total := 0
	for page := 1; page <= maxPages; page++ {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("limit", strconv.Itoa(centPage))
		qq.Set("page", strconv.Itoa(page))
		v, err := c.get(ctx, path+"?"+qq.Encode())
		if err != nil {
			return out, total, err
		}
		got := centRows(v)
		if t := centTotal(v); t > 0 {
			total = t
		}
		out = append(out, got...)
		if len(got) < centPage || (total > 0 && len(out) >= total) {
			break
		}
	}
	if total < len(out) {
		total = len(out)
	}
	return out, total, nil
}

// stateOf is the status code of a host or a service: 0 up/ok, 1 down/warning, 2 unreachable/critical, 3 unknown, 4 pending.
func stateOf(m map[string]any) (int64, bool) {
	if s, ok := m["status"].(map[string]any); ok {
		if _, has := s["code"]; has {
			return num(s["code"]), true
		}
	}
	if v, ok := m["state"]; ok {
		return num(v), true
	}
	return 0, false
}

func hostUp(h map[string]any) *bool {
	code, ok := stateOf(h)
	if !ok || code == 4 {
		return nil
	}
	return boolp(code == 0)
}

func (c *centreon) hosts(ctx context.Context, maxPages int) ([]map[string]any, int, error) {
	return c.all(ctx, "/monitoring/hosts", nil, maxPages)
}

func (c *centreon) Facts(ctx context.Context) (Facts, error) {
	if _, err := c.session(ctx); err != nil {
		return Facts{}, err
	}
	v, err := c.get(ctx, "/monitoring/hosts?limit=1&page=1")
	if err != nil {
		return Facts{}, err
	}
	total := centTotal(v)
	if total == 0 {
		total = len(centRows(v))
	}
	f := Facts{Hostname: c.d.Address, Vendor: "Centreon", Model: fmt.Sprintf("Monitoring platform: %d hosts", total)}
	if pv, err := c.get(ctx, "/platform/versions"); err == nil {
		if m, ok := pv.(map[string]any); ok {
			if w, ok := m["web"].(map[string]any); ok {
				f.OSVersion = firstOf(str(w["version"]), strings.Trim(strings.Join([]string{str(w["major"]), str(w["minor"]), str(w["fix"])}, "."), "."))
			}
		}
	}
	return f, nil
}

func (c *centreon) Interfaces(ctx context.Context) ([]Interface, error) {
	hs, _, err := c.hosts(ctx, centMaxPages)
	if err != nil && len(hs) == 0 {
		return nil, err
	}
	out := make([]Interface, 0, len(hs))
	for _, h := range hs {
		i := Interface{Name: firstOf(str(h["name"]), str(h["id"])), OperUp: hostUp(h)}
		i.Description = strings.TrimSpace(strings.Join([]string{str(h["alias"]), str(h["monitoring_server_name"])}, " "))
		if ip := str(h["address_ip"]); ip != "" {
			i.Addresses = []string{ip}
		}
		a, aok := h["active_checks"].(bool)
		p, pok := h["passive_checks"].(bool)
		if aok || pok {
			i.AdminUp = boolp(a || p)
		}
		out = append(out, i)
	}
	return out, nil
}

func (c *centreon) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (c *centreon) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (c *centreon) Close(context.Context)                         { c.api.close() }

const centUsage = "show platform | pollers | hosts [status=down|unreachable|up|pending] [search=TEXT] [limit=N] | host NAME|ID | services [host=NAME] [status=ok|warning|critical|unknown|problem] [search=TEXT] [limit=N] | problems | hostgroups | servicegroups | downtimes"

// centArgs reads name=value words; only the names in allowed are accepted.
func centArgs(words []string, allowed ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, w := range words {
		k, v, ok := strings.Cut(w, "=")
		k = strings.ToLower(k)
		if !ok || !centWordRE.MatchString(v) {
			return nil, fmt.Errorf("%q: an argument is name=value (%s)", w, strings.Join(allowed, ", "))
		}
		found := false
		for _, a := range allowed {
			found = found || a == k
		}
		if !found {
			return nil, fmt.Errorf("%q: not an argument here (%s)", k, strings.Join(allowed, ", "))
		}
		out[k] = v
	}
	if l, ok := out["limit"]; ok && (!centNumRE.MatchString(l) || l == "0") {
		return nil, errors.New("limit: a number above 0")
	}
	return out, nil
}

func centLimit(a map[string]string) int {
	if n, err := strconv.Atoi(a["limit"]); err == nil && n > 0 {
		return n
	}
	return 100
}

// centPick keeps the named fields of a record that it has.
func centPick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func centHostRow(h map[string]any) map[string]any {
	r := centPick(h, "id", "name", "alias", "address_ip", "status", "state", "last_check", "last_state_change", "monitoring_server_name", "acknowledged", "in_downtime", "active_checks", "passive_checks")
	if o := str(h["output"]); o != "" {
		if len(o) > 200 {
			o = o[:200] + "…"
		}
		r["output"] = o
	}
	return r
}

func centSvcRow(s map[string]any) map[string]any {
	r := centPick(s, "id", "description", "host", "host_id", "host_name", "status", "state", "last_check", "last_state_change", "acknowledged", "in_downtime", "active_checks", "passive_checks")
	if o := str(s["output"]); o != "" {
		if len(o) > 200 {
			o = o[:200] + "…"
		}
		r["output"] = o
	}
	return r
}

func centHostName(s map[string]any) string {
	if h, ok := s["host"].(map[string]any); ok {
		return firstOf(str(h["name"]), str(h["id"]))
	}
	return firstOf(str(s["host_name"]), str(s["host_id"]))
}

func centContains(hay string, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

var centStatusCodes = map[string][]int64{"up": {0}, "ok": {0}, "down": {1}, "warning": {1}, "unreachable": {2}, "critical": {2}, "unknown": {3}, "pending": {4}, "problem": {1, 2, 3}}

// centWant says whether a row has one of the status words' codes ("" wants every row).
func centWant(m map[string]any, status string) bool {
	if status == "" {
		return true
	}
	code, ok := stateOf(m)
	if !ok {
		return false
	}
	for _, c := range centStatusCodes[strings.ToLower(status)] {
		if c == code {
			return true
		}
	}
	return false
}

func centStatusOK(isHost bool, words ...string) error {
	for _, w := range words {
		if w == "" {
			continue
		}
		ok := false
		for k := range centStatusCodes {
			ok = ok || k == strings.ToLower(w)
		}
		if !ok {
			return fmt.Errorf("status %q: one of up, down, unreachable, pending (hosts), ok, warning, critical, unknown (services), problem", w)
		}
	}
	return nil
}

func (c *centreon) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(centUsage)
	}
	switch w := strings.ToLower(f[1]); w {
	case "platform", "pollers", "hostgroups", "servicegroups", "downtimes":
		if len(f) != 2 {
			return "", errors.New(centUsage)
		}
	}
	switch strings.ToLower(f[1]) {
	case "platform":
		v, err := c.get(ctx, "/platform/versions")
		if err != nil {
			return "", err
		}
		return obsText(v), nil
	case "pollers":
		rs, _, err := c.all(ctx, "/configuration/monitoring-servers", nil, 5)
		if err != nil {
			return "", err
		}
		return obsText(rs), nil
	case "hostgroups", "servicegroups", "downtimes":
		rs, total, err := c.all(ctx, "/monitoring/"+strings.ToLower(f[1]), nil, 5)
		if err != nil {
			return "", err
		}
		return obsText(map[string]any{"total": total, "result": rs}), nil
	case "hosts":
		a, err := centArgs(f[2:], "status", "search", "limit")
		if err != nil {
			return "", err
		}
		if err := centStatusOK(true, a["status"]); err != nil {
			return "", err
		}
		hs, total, err := c.hosts(ctx, centMaxPages)
		if err != nil && len(hs) == 0 {
			return "", err
		}
		var out []map[string]any
		for _, h := range hs {
			if !centWant(h, a["status"]) {
				continue
			}
			if s := a["search"]; s != "" && !centContains(str(h["name"])+" "+str(h["alias"])+" "+str(h["address_ip"]), s) {
				continue
			}
			out = append(out, centHostRow(h))
		}
		return centList(out, total, len(hs), centLimit(a)), nil
	case "host":
		if len(f) != 3 || !centRefRE.MatchString(f[2]) {
			return "", errors.New("show host NAME: the host's name, alias, address or ID (show hosts lists them)")
		}
		all, err := c.hostAll(ctx, f[2])
		if err != nil {
			return "", err
		}
		return obsText(all), nil
	case "services":
		a, err := centArgs(f[2:], "host", "status", "search", "limit")
		if err != nil {
			return "", err
		}
		if err := centStatusOK(false, a["status"]); err != nil {
			return "", err
		}
		path := "/monitoring/services"
		if h := a["host"]; h != "" {
			id, _, err := c.findHost(ctx, h)
			if err != nil {
				return "", err
			}
			path = "/monitoring/hosts/" + id + "/services"
		}
		ss, total, err := c.all(ctx, path, nil, centMaxPages)
		if err != nil && len(ss) == 0 {
			return "", err
		}
		var out []map[string]any
		for _, s := range ss {
			if !centWant(s, a["status"]) {
				continue
			}
			if x := a["search"]; x != "" && !centContains(str(s["description"])+" "+centHostName(s), x) {
				continue
			}
			out = append(out, centSvcRow(s))
		}
		return centList(out, total, len(ss), centLimit(a)), nil
	case "problems":
		if len(f) != 2 {
			return "", errors.New(centUsage)
		}
		hs, ht, herr := c.hosts(ctx, 20)
		ss, st, serr := c.all(ctx, "/monitoring/services", nil, 20)
		if herr != nil && serr != nil {
			return "", herr
		}
		res := map[string]any{"hosts_scanned": len(hs), "services_scanned": len(ss)}
		var bh, bs []map[string]any
		for _, h := range hs {
			if code, ok := stateOf(h); ok && (code == 1 || code == 2) {
				bh = append(bh, centHostRow(h))
			}
		}
		for _, s := range ss {
			if centWant(s, "problem") {
				bs = append(bs, centSvcRow(s))
			}
		}
		res["hosts"], res["services"] = bh, bs
		if ht > len(hs) || st > len(ss) {
			res["note"] = fmt.Sprintf("only the first %d hosts and %d services were scanned (Centreon holds %d and %d)", len(hs), len(ss), ht, st)
		}
		if herr != nil {
			res["hosts_error"] = RedactText(herr.Error())
		}
		if serr != nil {
			res["services_error"] = RedactText(serr.Error())
		}
		return obsText(res), nil
	}
	return "", errors.New(centUsage)
}

func centList(out []map[string]any, total, read, limit int) string {
	shown := out
	if len(shown) > limit {
		shown = shown[:limit]
	}
	res := map[string]any{"matching": len(out), "shown": len(shown), "result": shown}
	if total > read {
		res["note"] = fmt.Sprintf("Centreon holds %d rows; the first %d were read", total, read)
	}
	return obsText(res)
}

// findHost finds one host by ID, by name, or by alias or address.
func (c *centreon) findHost(ctx context.Context, ref string) (string, map[string]any, error) {
	if centNumRE.MatchString(ref) {
		v, err := c.get(ctx, "/monitoring/hosts/"+ref)
		if err != nil {
			return "", nil, fmt.Errorf("host %s: %w", ref, err)
		}
		if r := centRows(v); len(r) > 0 {
			return ref, r[0], nil
		}
		return "", nil, fmt.Errorf("no host %q", ref)
	}
	q := url.Values{"search": {toJSONString(map[string]any{"name": ref})}, "limit": {"10"}}
	if v, err := c.get(ctx, "/monitoring/hosts?"+q.Encode()); err == nil {
		for _, h := range centRows(v) {
			if strings.EqualFold(str(h["name"]), ref) && str(h["id"]) != "" {
				return str(h["id"]), h, nil
			}
		}
	}
	hs, _, err := c.hosts(ctx, 20)
	if err != nil && len(hs) == 0 {
		return "", nil, err
	}
	for _, h := range hs {
		if str(h["id"]) != "" && (strings.EqualFold(str(h["name"]), ref) || strings.EqualFold(str(h["alias"]), ref) || str(h["address_ip"]) == ref) {
			return str(h["id"]), h, nil
		}
	}
	return "", nil, fmt.Errorf("no host %q (show hosts lists them)", ref)
}

// hostAll answers everything Centreon knows about one host.  A part that cannot be read (the user may not see the configuration)
// is named under "errors"; the rest is still answered.
func (c *centreon) hostAll(ctx context.Context, ref string) (map[string]any, error) {
	id, row, err := c.findHost(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"host": row}
	errs := map[string]string{}
	part := func(key, path string) {
		v, err := c.get(ctx, path)
		if err != nil {
			errs[key] = RedactText(err.Error())
			return
		}
		if key == "host" {
			if r := centRows(v); len(r) > 0 {
				out["host"] = r[0]
			}
			return
		}
		out[key] = centData(v)
	}
	part("host", "/monitoring/hosts/"+id)
	part("configuration", "/configuration/hosts/"+id)
	if ss, total, err := c.all(ctx, "/monitoring/hosts/"+id+"/services", nil, 10); err != nil && len(ss) == 0 {
		errs["services"] = RedactText(err.Error())
	} else {
		out["services"] = ss
		out["services_total"] = total
	}
	part("timeline", "/monitoring/hosts/"+id+"/timeline?limit=50")
	if len(errs) > 0 {
		out["errors"] = errs
	}
	return out, nil
}

// ---- reading through the API ----

var centReadable = map[string]bool{"monitoring": true, "configuration": true, "platform": true}

// centQuery checks a query and writes it again in a fixed form.
func centQuery(qs string) (string, error) {
	if qs == "" {
		return "", nil
	}
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return "", errors.New("path: the query is not valid")
	}
	for k, vs := range vals {
		if !centKeyRE.MatchString(k) {
			return "", fmt.Errorf("path: %q is not a parameter name", k)
		}
		for _, v := range vs {
			if len(v) > 2000 || ctlRE.MatchString(v) {
				return "", fmt.Errorf("path: the value of %q is too long, or holds a control character", k)
			}
		}
	}
	return vals.Encode(), nil
}

func (c *centreon) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	pp = c.rel(pp)
	if !centPathRE.MatchString(pp) || strings.Contains(pp, "..") || strings.Contains(pp, "//") {
		return nil, false, errors.New("path: /monitoring/hosts, /configuration/hosts/12, /platform/versions (see device_api_catalog)")
	}
	if !centReadable[strings.SplitN(strings.TrimPrefix(pp, "/"), "/", 2)[0]] {
		return nil, false, errors.New("path: Centreon is read below /monitoring, /configuration and /platform")
	}
	if hasSeg(pp, centDenied...) {
		return nil, false, errors.New("path: users, contacts, access rights, tokens, authentication and administration are not read here")
	}
	enc, err := centQuery(qs)
	if err != nil {
		return nil, false, err
	}
	if enc != "" {
		pp += "?" + enc
	}
	v, err := c.get(ctx, pp)
	if err != nil {
		return nil, false, err
	}
	return obsScrub(Redact(v)), false, nil
}

func (c *centreon) APICatalog(context.Context) (any, error) {
	ex := []string{"/platform/versions", "/monitoring/hosts?limit=20&page=1", "/monitoring/hosts/12", "/monitoring/hosts/12/services", "/monitoring/hosts/12/timeline",
		"/monitoring/services", "/monitoring/resources", "/monitoring/hostgroups", "/monitoring/servicegroups", "/monitoring/downtimes", "/configuration/hosts",
		"/configuration/hosts/12", "/configuration/hosts/templates", "/configuration/hosts/groups", "/configuration/services/templates", "/configuration/commands",
		"/configuration/monitoring-servers", "/configuration/timeperiods"}
	sort.Strings(ex)
	return map[string]any{
		"how": "Paths below /monitoring, /configuration and /platform (the prefix and /api/latest are added). Lists take limit, page, sort_by and search " +
			"(search is JSON such as {\"name\":{\"$lk\":\"%web%\"}}). Users, contacts, access rights, tokens, authentication and administration are refused. " +
			"Changes are device_change_raw (POST, PUT, PATCH, DELETE); Save exports the configuration to the pollers and reloads them.",
		"examples": ex,
		"tip":      "show host NAME (device_show) answers everything about one host in one call; the full API is described at https://docs.centreon.com/docs/api/rest-api-v2/.",
	}, nil
}

// RawChange: Method POST, PUT, PATCH or DELETE, Path below /monitoring or /configuration, Body JSON.  Centreon applies a
// configuration change to the pollers only when it is exported: Save does it for every poller.
func (c *centreon) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	r.Path = c.rel(r.Path)
	if _, err := c.do(ctx, http.MethodGet, "/platform/versions", nil, nil); err != nil {
		return RawResult{DryRun: dry}, fmt.Errorf("Centreon did not answer a read (nothing was changed): %w", err)
	}
	tok, _ := c.session(ctx)
	h := jsonHdr()
	h.Set("X-Auth-Token", tok)
	res, err := restRaw(ctx, restSpec{
		api: c.api, hdr: h, auth: http.Header{"X-Auth-Token": {tok}, "Accept": {"application/json"}}, json: true,
		wire: func(p string) string { return c.base() + p },
		guard: func(_, p string) error {
			pp, _, _ := strings.Cut(p, "?")
			switch strings.SplitN(strings.TrimPrefix(pp, "/"), "/", 2)[0] {
			case "monitoring", "configuration":
			default:
				return errors.New("path: Centreon is changed below /monitoring and /configuration")
			}
			if hasSeg(pp, centDenied...) {
				return errors.New("path: users, contacts, access rights, tokens, login, authentication and administration are not changed here")
			}
			return nil
		},
		alive: func(ctx context.Context) error {
			_, err := c.get(ctx, "/platform/versions")
			return err
		},
		save: func(ctx context.Context) error {
			_, err := c.do(ctx, http.MethodPost, centSaveEP, "{}", jsonHdr())
			return err
		},
	}, r, dry)
	if err == nil && res.Applied && !res.Saved && strings.HasPrefix(r.Path, "/configuration") && res.Note == "" {
		res.Note = "Centreon keeps a configuration change in its database until it is exported to the pollers: send it again with save, or POST " + centSaveEP
	}
	return res, err
}
