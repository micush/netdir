package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// SMAX, Micro Focus (now OpenText) Service Management Automation X: the service desk behind the "Anywhere Service Portal"
// (https://HOST/saw/...), through its REST API (https://docs.microfocus.com, Developer guide ▸ Connect to the REST API):
//
//	sign-in   POST /auth/authentication-endpoint/authenticate/login?TENANTID=ID   body {"Login": "...", "Password": "..."}
//	          the answer is the token; every later request carries the header  Cookie: LWSSO_COOKIE_KEY=<token>
//	entities  GET  /rest/ID/ems/Request?layout=Id,DisplayLabel,...&filter=...&size=N&skip=N&order=...
//
// The option "tenant" is the tenant ID (the TENANTID=... in the address of the portal) and is required.  The credential is a user
// name and a password of an integration user, or of an account user with database authentication (single sign-on users cannot use
// the endpoint).  Nothing goes into a URL but the tenant ID.  Reads are GETs; a change is RawChange (below).
//
// SMAX is a service desk, not a switch: the "device" is the SMAX tenant.
//
//   - Facts: the tenant and whether it answers.  There are no interfaces, neighbors or configuration.
//   - Show: "show platform", "show requests|incidents|changes|problems [phase=NAME] [search=TEXT] [limit=N]" (newest first) and
//     "show request|incident|change|problem ID" (one record with its text).
//   - APIGet: /ems/Request, /ems/Incident, /ems/Change, /ems/Problem (and one record by ID).  People, groups, roles, users and the
//     rest of the tenant's settings are refused.
//   - RawChange (rw keys only, as everywhere: a read-only MCP caller has no tool for it): POST /ems/bulk with
//     {"operation": "CREATE" or "UPDATE", "entities": [{"entity_type": "Request", "properties": {...}}]} for Request, Incident,
//     Change and Problem.  DELETE operations and every other entity type (people, groups, roles, settings) are refused.  An
//     UPDATE cannot be put back by itself: nothing reads the old record first, so read it with "show request ID" before.
//     There is nothing to import: SMAX holds tickets, not network devices.
//
// The names of a record's properties are the tenant's own (they can be customized), and SMAX refuses a layout with a name it does
// not know (HTTP 400); the driver then asks again with a short layout.  Written against the documentation only; not run against
// a real tenant.

func init() { Register("smax", newSMAX) }

type smax struct {
	d      Device
	api    *apiClient
	tenant string
	user   string
	pass   string

	mu  sync.Mutex
	tok string
}

var (
	smaxTenantRE = regexp.MustCompile(`^[0-9]{3,20}$`)
	smaxLayoutRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]*(,[A-Za-z][A-Za-z0-9_.]*)*$`)
	smaxIDRE     = regexp.MustCompile(`^[0-9]{1,18}$`)
	smaxWordRE   = regexp.MustCompile(`^[A-Za-z0-9._:@/ *-]{1,128}$`)
	// the entities that are read: tickets.  People, groups, roles and settings are not among them.
	smaxTypes = map[string]string{"requests": "Request", "incidents": "Incident", "changes": "Change", "problems": "Problem",
		"request": "Request", "incident": "Incident", "change": "Change", "problem": "Problem"}
	smaxLayouts = map[string]string{"Request": "Id,DisplayLabel,Phase,Status,CreateTime,LastUpdateTime",
		"Incident": "Id,DisplayLabel,Phase,Status,Priority,CreateTime,LastUpdateTime",
		"Change":   "Id,DisplayLabel,Phase,Status,CreateTime,LastUpdateTime",
		"Problem":  "Id,DisplayLabel,Phase,Status,CreateTime,LastUpdateTime"}
	smaxOneLayout = "Id,DisplayLabel,Description,Phase,Status,CreateTime,LastUpdateTime"
	smaxMinLayout = "Id,DisplayLabel,CreateTime"
)

const (
	smaxPage     = 100
	smaxMaxPages = 5
)

func newSMAX(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: SMAX needs a user name and a password (an integration user, or an account user with database authentication)", d.Name)
	}
	t := strings.TrimSpace(d.Options["tenant"])
	if !smaxTenantRE.MatchString(t) {
		return nil, fmt.Errorf("device %s: option tenant is the tenant ID, the number after TENANTID= in the address of the portal", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	return &smax{d: d, api: api, tenant: t, user: c.Username, pass: c.Password}, nil
}

// token is the session token the next request carries (a sign-in is made when there is none).
func (s *smax) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok != "" {
		return s.tok, nil
	}
	body, _ := json.Marshal(map[string]string{"Login": s.user, "Password": s.pass})
	b, err := s.api.do(context.WithoutCancel(ctx), http.MethodPost, "/auth/authentication-endpoint/authenticate/login?TENANTID="+s.tenant, body, jsonHdr())
	if err != nil {
		return "", fmt.Errorf("SMAX: sign-in failed: %w", err)
	}
	t := strings.TrimSpace(string(b))
	var js any
	if json.Unmarshal(b, &js) == nil {
		switch v := js.(type) {
		case string:
			t = v
		case map[string]any:
			t = firstOf(str(v["token"]), str(v["LWSSO_COOKIE_KEY"]), str(v["lwsso"]))
		}
	}
	t = strings.Trim(t, "\" \r\n")
	if t == "" || strings.ContainsAny(t, " ;\r\n") {
		return "", errors.New("SMAX: sign-in failed: the answer holds no session token")
	}
	s.tok = t
	return t, nil
}

// get sends one GET below /rest/TENANT; a session that has expired (401) is renewed once.
func (s *smax) get(ctx context.Context, path string) (any, error) {
	for try := 0; ; try++ {
		tok, err := s.token(ctx)
		if err != nil {
			return nil, err
		}
		b, err := s.api.do(ctx, http.MethodGet, "/rest/"+s.tenant+path, nil, http.Header{"Cookie": {"LWSSO_COOKIE_KEY=" + tok}})
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code == http.StatusUnauthorized && try == 0 {
			s.mu.Lock()
			s.tok = ""
			s.mu.Unlock()
			continue
		}
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
}

// smaxRows flattens the entities of an answer: the properties of each, with the entity type.
func smaxRows(v any) []map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, e := range rows(m["entities"]) {
		r := map[string]any{}
		if p, ok := e["properties"].(map[string]any); ok {
			for k, x := range p {
				r[k] = x
			}
		}
		if t := str(e["entity_type"]); t != "" {
			r["entity_type"] = t
		}
		if rp, ok := e["related_properties"].(map[string]any); ok && len(rp) > 0 {
			r["related_properties"] = rp
		}
		out = append(out, r)
	}
	return out
}

// query reads entities of one type.  A layout or an order the tenant does not know is refused with 400: the read is then repeated
// with the short layout and no order.
func (s *smax) query(ctx context.Context, typ, layout string, q url.Values) (any, error) {
	build := func(layout string, withOrder bool) string {
		qq := url.Values{}
		for k, v := range q {
			if k == "order" && !withOrder {
				continue
			}
			qq[k] = v
		}
		qq.Set("layout", layout)
		return "/ems/" + typ + "?" + qq.Encode()
	}
	v, err := s.get(ctx, build(layout, true))
	var se *statusError
	if err != nil && errors.As(err, &se) && se.Code == http.StatusBadRequest && layout != smaxMinLayout {
		if v2, err2 := s.get(ctx, build(smaxMinLayout, false)); err2 == nil {
			return v2, nil
		}
	}
	return v, err
}

func (s *smax) Facts(ctx context.Context) (Facts, error) {
	if _, err := s.query(ctx, "Request", smaxMinLayout, url.Values{"size": {"1"}}); err != nil {
		return Facts{}, err
	}
	return Facts{Hostname: s.d.Address, Vendor: "Micro Focus", Model: "SMAX service desk, tenant " + s.tenant}, nil
}

func (s *smax) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (s *smax) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (s *smax) Config(context.Context) (string, error)          { return "", ErrUnsupported }
func (s *smax) Close(context.Context)                           { s.api.close() }

// smaxBulkCheck allows a bulk body that creates or updates tickets, and nothing else.
func smaxBulkCheck(body string) error {
	var b struct {
		Operation string           `json:"operation"`
		Entities  []map[string]any `json:"entities"`
	}
	if err := json.Unmarshal([]byte(body), &b); err != nil || len(b.Entities) == 0 {
		return errors.New(`body: {"operation": "CREATE" or "UPDATE", "entities": [{"entity_type": "Request", "properties": {...}}]}`)
	}
	if op := strings.ToUpper(b.Operation); op != "CREATE" && op != "UPDATE" {
		return fmt.Errorf("body: operation %q is refused: only CREATE and UPDATE are sent here (no deletes)", b.Operation)
	}
	if len(b.Entities) > 50 {
		return errors.New("body: at most 50 entities in one request")
	}
	for _, e := range b.Entities {
		t := str(e["entity_type"])
		ok := false
		for _, a := range smaxTypes {
			ok = ok || a == t
		}
		if !ok {
			return fmt.Errorf("body: entity_type %q is refused: Request, Incident, Change and Problem are changed here (not people, groups, roles or settings)", t)
		}
	}
	return nil
}

// RawChange: POST /ems/bulk, see the header.  A rw key only: the gate is the same as for every platform.
func (s *smax) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	r.Path = strings.TrimPrefix(r.Path, "/rest/"+s.tenant)
	tok, err := s.token(ctx)
	if err != nil {
		return RawResult{DryRun: dry}, err
	}
	h := jsonHdr()
	h.Set("Cookie", "LWSSO_COOKIE_KEY="+tok)
	return restRaw(ctx, restSpec{
		api: s.api, hdr: h, auth: http.Header{"Cookie": {"LWSSO_COOKIE_KEY=" + tok}, "Accept": {"application/json"}}, json: true,
		wire: func(p string) string { return "/rest/" + s.tenant + p },
		guard: func(method, p string) error {
			if method != http.MethodPost || p != "/ems/bulk" {
				return errors.New("method and path: SMAX is changed with POST /ems/bulk")
			}
			return smaxBulkCheck(r.Body)
		},
		alive: func(ctx context.Context) error {
			_, err := s.query(ctx, "Request", smaxMinLayout, url.Values{"size": {"1"}})
			return err
		},
	}, r, dry)
}

const smaxUsage = "show platform | requests|incidents|changes|problems [phase=NAME] [search=TEXT] [limit=N] | request|incident|change|problem ID"

func smaxArgs(words []string) (map[string]string, error) {
	out := map[string]string{}
	for _, w := range words {
		k, v, ok := strings.Cut(w, "=")
		k = strings.ToLower(k)
		if !ok || (k != "phase" && k != "search" && k != "limit") || !smaxWordRE.MatchString(v) || strings.Contains(v, " ") {
			return nil, fmt.Errorf("%q: an argument is phase=NAME, search=TEXT or limit=N (no spaces)", w)
		}
		out[k] = v
	}
	if l, ok := out["limit"]; ok && (!smaxIDRE.MatchString(l) || l == "0") {
		return nil, errors.New("limit: a number above 0")
	}
	return out, nil
}

func (s *smax) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(smaxUsage)
	}
	w := strings.ToLower(f[1])
	if w == "platform" {
		return obsText(map[string]any{"tenant": s.tenant, "entities": []string{"Request", "Incident", "Change", "Problem"}, "tip": smaxUsage}), nil
	}
	typ := smaxTypes[w]
	if typ == "" {
		return "", errors.New(smaxUsage)
	}
	if !strings.HasSuffix(w, "s") { // one record
		if len(f) != 3 || !smaxIDRE.MatchString(f[2]) {
			return "", fmt.Errorf("show %s ID: the number of the record (show %ss lists them)", w, w)
		}
		v, err := s.query(ctx, typ+"/"+f[2], smaxOneLayout, nil)
		if err != nil {
			return "", err
		}
		if r := smaxRows(v); len(r) > 0 {
			return obsText(r[0]), nil
		}
		return obsText(v), nil
	}
	a, err := smaxArgs(f[2:])
	if err != nil {
		return "", err
	}
	limit := 50
	if n, err := strconv.Atoi(a["limit"]); err == nil {
		limit = n
	}
	q := url.Values{"size": {strconv.Itoa(smaxPage)}, "order": {"LastUpdateTime desc"}}
	if p := a["phase"]; p != "" {
		q.Set("filter", "Phase='"+strings.ReplaceAll(p, "'", "''")+"'")
	}
	var out []map[string]any
	read := 0
	for page := 0; page < smaxMaxPages; page++ {
		q.Set("skip", strconv.Itoa(page*smaxPage))
		v, err := s.query(ctx, typ, smaxLayouts[typ], q)
		if err != nil {
			if len(out) == 0 && read == 0 {
				return "", err
			}
			break
		}
		got := smaxRows(v)
		read += len(got)
		for _, r := range got {
			if x := a["search"]; x == "" || d42Match(r, x) {
				out = append(out, r)
			}
		}
		if len(got) < smaxPage || len(out) >= limit {
			break
		}
	}
	shown := out
	if len(shown) > limit {
		shown = shown[:limit]
	}
	res := map[string]any{"matching": len(out), "shown": len(shown), "read": read, "result": shown}
	if a["search"] != "" {
		res["note"] = fmt.Sprintf("search looks in the %d newest rows that were read", read)
	}
	return obsText(res), nil
}

// ---- reading through the API ----

func (s *smax) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	pp = "/" + strings.TrimPrefix(pp, "/")
	pp = strings.TrimPrefix(pp, "/rest/"+s.tenant)
	pp = strings.TrimPrefix(strings.TrimPrefix(pp, "/ems"), "/")
	seg := strings.Split(strings.Trim(pp, "/"), "/")
	typ := ""
	for t := range smaxLayouts {
		if strings.EqualFold(t, seg[0]) {
			typ = t
		}
	}
	if typ == "" || len(seg) > 2 || (len(seg) == 2 && !smaxIDRE.MatchString(seg[1])) {
		return nil, false, errors.New("path: /ems/Request, /ems/Incident, /ems/Change or /ems/Problem, with an ID for one record (see device_api_catalog)")
	}
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return nil, false, errors.New("path: the query is not valid")
	}
	q := url.Values{}
	for k, vs := range vals {
		v := vs[0]
		switch strings.ToLower(k) {
		case "layout":
			if !smaxLayoutRE.MatchString(v) || len(v) > 2000 {
				return nil, false, errors.New("path: layout is the names of the properties, separated by commas")
			}
		case "filter", "order":
			if len(v) > 500 || junCtlRE.MatchString(v) {
				return nil, false, fmt.Errorf("path: %s is too long, or holds a control character", k)
			}
		case "size":
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 500 {
				return nil, false, errors.New("path: size is a number from 1 to 500")
			}
		case "skip":
			if !smaxIDRE.MatchString(v) {
				return nil, false, errors.New("path: skip is a number")
			}
		default:
			return nil, false, fmt.Errorf("path: %q is not a parameter here (layout, filter, order, size, skip)", k)
		}
		q.Set(strings.ToLower(k), v)
	}
	layout := q.Get("layout")
	if layout == "" {
		layout = smaxLayouts[typ]
	}
	q.Del("layout")
	if len(seg) == 2 {
		typ += "/" + seg[1]
	} else if q.Get("size") == "" {
		q.Set("size", "100")
	}
	v, err := s.query(ctx, typ, layout, q)
	if err != nil {
		return nil, false, err
	}
	return obsScrub(Redact(v)), false, nil
}

func (s *smax) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "Entities below /rest/<tenant>/ems: Request, Incident, Change and Problem (one record: /ems/Request/<id>). Parameters: layout (the properties wanted, " +
			"named one by one, no wildcard; the default is Id, DisplayLabel, Phase, Status, CreateTime, LastUpdateTime), filter (Phase='Validation', DisplayLabel sw('PROD')), " +
			"order (LastUpdateTime desc), size (up to 500) and skip. People, groups, roles and settings are refused. Changes are device_change_raw: POST /ems/bulk (CREATE or UPDATE of Request, Incident, Change, Problem).",
		"examples": []string{"/ems/Request?size=20", "/ems/Request?filter=Phase='Validation'&size=20", "/ems/Request/5013940?layout=Id,DisplayLabel,Description,Phase", "/ems/Incident?size=20"},
		"tip":      "show requests, show request ID (device_show) read the same in one call; property names are the tenant's own and may differ from these.",
	}, nil
}
