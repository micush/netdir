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

// The media applications of a home server: the *arr family (Sonarr, Radarr, Lidarr, Prowlarr), Bazarr, qBittorrent, Tautulli,
// Seerr (Overseerr / Jellyseerr), Plex Media Server and Jellyfin.  One engine (this file) drives them all from a table each
// (media_apps.go): how the API key is sent, where the API's root is, what "show NAME" reads, and what method CALL does.
//
// Every one of them serves plain HTTP unless it was set up for HTTPS, so these platforms, and only these, take the option
// scheme=http.  It is a deliberate exception to netdir's HTTPS-only rule: the API key then crosses the network in clear, and
// should stay on a trusted segment.  Without the option they are asked over HTTPS like every other platform.
//
// Options: scheme (https, the default, or http), url_base (the path the application is served below, e.g. /sonarr) and, for
// qBittorrent, auth=none (the Web UI lets this address in without a login: "Bypass authentication for clients in whitelisted
// IP subnets"; the credential then needs a token of any value, which is not sent).

// mshow is one "show NAME" read.
type mshow struct {
	path string   // below the API's root; {id} is the id= argument, {n} the lines= argument (default 50)
	args string   // other arguments it takes, by name, separated by spaces (each becomes a query parameter, or is resolved: mres)
	name string   // the field name= matches in each row ("" when the read has no name filter)
	cols []string // the fields kept of each row unless full=yes
	help string
}

// mres turns a title into an id: name=Blue Bloods into seriesId=123.
type mres struct {
	list, title, id string // the list to read, the field matched and the field that is the id
	param           string // the query parameter of a show read
	field           string // the body field of a CALL (a name ending in Ids is sent as a list)
}

// mcall is one action of method CALL.
type mcall struct {
	method, path string // {id} and {name} placeholders are filled from the body
	enc          string // how the rest of the body is sent: "json", "form", "query" or "" (nothing)
	before       string // what a dry run reads (with the same placeholders); "" reads nothing
	guard        bool   // refused while the guard lists are on (it deletes or restarts)
	help         string
}

type mediaSpec struct {
	platform, vendor, model string
	port                    int
	root                    string // the API's root ("/api/v3"; "" for Plex and Jellyfin)
	auth                    string // "header", "query" (apikey=), "login" (qBittorrent's cookie), "mediabrowser" (Jellyfin)
	hdr                     string // the header that holds the key
	facts                   func(ctx context.Context, m *media) (Facts, error)
	shows                   map[string]mshow
	res                     map[string]mres
	calls                   map[string]mcall
	anyCall                 func(m *media, action string, body map[string]any) (mcall, error) // an action not in calls (an *arr command)
	unwrap                  func(v any) (any, error)                                          // takes an envelope off (Tautulli)
	readOK                  func(path string) error                                           // more refusals of device_api_get (a GET that writes)
	alerts                  func(ctx context.Context, m *media) ([]string, error)             // nil: not an AlertReporter
	catalog                 []string                                                          // example paths for device_api_get
}

var mediaSpecs = map[string]*mediaSpec{}

func registerMedia(s *mediaSpec) {
	mediaSpecs[s.platform] = s
	defaultPorts[s.platform] = s.port
	Register(s.platform, func(d Device, c Credential) (Driver, error) {
		m, err := newMedia(s, d, c)
		if err != nil {
			return nil, err
		}
		if s.alerts != nil {
			return &mediaAlerts{m}, nil
		}
		return m, nil
	})
}

type media struct {
	spec   *mediaSpec
	d      Device
	cred   Credential
	api    *apiClient
	prefix string // url_base

	mu       sync.Mutex
	loggedIn bool
	webAPI   string // qBittorrent's web API version
}

// mediaAlerts is a media application that reports its own health warnings (the *arr family, Bazarr).
type mediaAlerts struct{ *media }

func (m *mediaAlerts) ActiveAlerts(ctx context.Context) ([]string, error) {
	return m.spec.alerts(ctx, m.media)
}

var urlBaseRE = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

func newMedia(s *mediaSpec, d Device, c Credential) (*media, error) {
	opt := func(k string) string { return strings.TrimSpace(d.Options[k]) }
	switch s.auth {
	case "login":
		if c.Password == "" && !strings.EqualFold(opt("auth"), "none") {
			return nil, fmt.Errorf("device %s: %s needs a credential with a user name and password (or the option auth=none for a whitelisted address)", d.Name, s.model)
		}
	default:
		if c.Token == "" {
			return nil, fmt.Errorf("device %s: %s needs a credential with its API key as the token", d.Name, s.model)
		}
	}
	api, err := newAPIClient(d, s.port)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(opt("scheme")) {
	case "", "https":
	case "http":
		api.base = "http://" + strings.TrimPrefix(api.base, "https://")
	default:
		return nil, fmt.Errorf("device %s: option scheme is https or http", d.Name)
	}
	pre := strings.TrimRight(opt("url_base"), "/")
	if pre != "" && (!urlBaseRE.MatchString(pre) || strings.Contains(pre, "/.")) {
		return nil, fmt.Errorf("device %s: option url_base is a path such as /sonarr", d.Name)
	}
	switch s.auth {
	case "header":
		api.hdr.Set(s.hdr, c.Token)
	case "mediabrowser":
		api.hdr.Set("Authorization", `MediaBrowser Client="netdir", Device="netdir", DeviceId="netdir", Version="1", Token="`+c.Token+`"`)
	}
	return &media{spec: s, d: d, cred: c, api: api, prefix: pre}, nil
}

func (m *media) err(e error) error {
	if e == nil {
		return nil
	}
	var se *statusError
	if errors.As(e, &se) {
		return &statusError{se.Code, scrub(se.Body, m.cred)}
	}
	return errors.New(scrub(e.Error(), m.cred))
}

// req sends one request below the API's root (path already holds the root) with the key, and logs in first where the
// application has a session.
func (m *media) req(ctx context.Context, method, path string, body any, hdr http.Header) ([]byte, error) {
	full := m.prefix + path
	if m.spec.auth == "query" {
		sep := "?"
		if strings.Contains(full, "?") {
			sep = "&"
		}
		full += sep + "apikey=" + url.QueryEscape(m.cred.Token)
	}
	if m.spec.auth == "login" {
		if err := m.login(ctx, false); err != nil {
			return nil, err
		}
		if hdr == nil {
			hdr = http.Header{}
		}
		hdr.Set("Referer", m.api.base)
	}
	b, err := m.api.do(ctx, method, full, body, hdr)
	var se *statusError
	if m.spec.auth == "login" && errors.As(err, &se) && se.Code == http.StatusForbidden && m.cred.Password != "" {
		if lerr := m.login(ctx, true); lerr != nil {
			return nil, lerr
		}
		b, err = m.api.do(ctx, method, full, body, hdr)
	}
	return b, m.err(err)
}

// login is qBittorrent's: a form login that sets the SID cookie (kept in the client's jar, never shown).
func (m *media) login(ctx context.Context, again bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cred.Password == "" || (m.loggedIn && !again) {
		return nil
	}
	form := url.Values{"username": {m.cred.Username}, "password": {m.cred.Password}}.Encode()
	hdr := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Referer": {m.api.base}, "Accept": {"text/plain"}}
	b, err := m.api.do(ctx, http.MethodPost, m.prefix+m.spec.root+"/auth/login", form, hdr)
	var se *statusError
	if errors.As(err, &se) {
		return fmt.Errorf("the login was refused: the device answered HTTP %d", se.Code)
	}
	if err != nil {
		return m.err(err)
	}
	if strings.TrimSpace(string(b)) != "Ok." {
		return errors.New("the login was refused: the device answered HTTP 400 (a wrong user name or password)")
	}
	m.loggedIn = true
	return nil
}

func (m *media) Close(ctx context.Context) {
	m.mu.Lock()
	in := m.loggedIn
	m.loggedIn = false
	m.mu.Unlock()
	if in {
		_, _ = m.api.do(ctx, http.MethodPost, m.prefix+m.spec.root+"/auth/logout", "", http.Header{"Referer": {m.api.base}})
	}
	m.api.close()
}

// get reads a path below the root as JSON (or as text when it is not JSON), with the envelope taken off.
func (m *media) get(ctx context.Context, path string) (any, error) {
	b, err := m.req(ctx, http.MethodGet, m.spec.root+path, nil, nil)
	if err != nil {
		return nil, err
	}
	return m.decode(b)
}

func (m *media) decode(b []byte) (any, error) {
	if strings.TrimSpace(string(b)) == "" {
		return nil, nil
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return strings.TrimSpace(string(b)), nil
	}
	if m.spec.unwrap != nil {
		return m.spec.unwrap(v)
	}
	return v, nil
}

func (m *media) getMap(ctx context.Context, path string) (map[string]any, error) {
	v, err := m.get(ctx, path)
	if err != nil {
		return nil, err
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("GET %s: the answer is not the JSON object expected", path)
	}
	return o, nil
}

func (m *media) Facts(ctx context.Context) (Facts, error)        { return m.spec.facts(ctx, m) }
func (m *media) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (m *media) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (m *media) Config(context.Context) (string, error)          { return "", ErrUnsupported }

func (m *media) showNames() []string {
	var ns []string
	for n := range m.spec.shows {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

func (m *media) callNames() []string {
	var ns []string
	for n := range m.spec.calls {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

var kvRE = regexp.MustCompile(`(?:^|\s)([a-z_]+)=`)

// parseKV reads "a=1 name=Blue Bloods b=2": a value runs to the next " word=", so it may hold spaces.
func parseKV(s string) (map[string]string, error) {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	idx := kvRE.FindAllStringSubmatchIndex(s, -1)
	if len(idx) == 0 || strings.TrimSpace(s[:idx[0][0]]) != "" {
		return nil, fmt.Errorf("%q: arguments are name=value", s)
	}
	for i, x := range idx {
		end := len(s)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		k, v := s[x[2]:x[3]], strings.TrimSpace(s[x[1]:end])
		if v == "" || len(v) > 256 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, fmt.Errorf("%s=: a value of 1 to 256 characters", k)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%s= given twice", k)
		}
		out[k] = v
	}
	return out, nil
}

func qesc(v string) string { return strings.ReplaceAll(url.QueryEscape(v), "+", "%20") }

// resolve turns a title into the id the API wants; a number is taken as the id.
func (m *media) resolve(ctx context.Context, r mres, v string) (string, error) {
	if _, err := strconv.Atoi(v); err == nil || (r.id == "hash" && hashRE.MatchString(v)) {
		return v, nil
	}
	l, err := m.get(ctx, r.list)
	if err != nil {
		return "", err
	}
	var exact, part []map[string]any
	for _, row := range listOf(l, 0) {
		t := str(row[r.title])
		switch {
		case strings.EqualFold(t, v):
			exact = append(exact, row)
		case strings.Contains(normName(t), normName(v)):
			part = append(part, row)
		}
	}
	hits := exact
	if len(hits) == 0 {
		hits = part
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("%q: nothing has that %s", v, r.title)
	case 1:
		if id := str(hits[0][r.id]); id != "" {
			return id, nil
		}
		return "", fmt.Errorf("%q: the match has no %s", v, r.id)
	}
	var ns []string
	for i, h := range hits {
		if i == 6 {
			ns = append(ns, "…")
			break
		}
		ns = append(ns, fmt.Sprintf("%s (%s)", str(h[r.title]), str(h[r.id])))
	}
	return "", fmt.Errorf("%q matches %d: %s; give the id or the exact name", v, len(hits), strings.Join(ns, ", "))
}

// normName is a title as name= compares it: lower case, with . _ and - as spaces (a release name: Blue.Bloods.S14E01).
func normName(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(strings.ToLower(s))), " ")
}

var hashRE = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
var fillRE = regexp.MustCompile(`^[A-Za-z0-9_.:|-]+$`)
var idArgRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// listOf finds the list of records in an answer: the answer itself, or the list under records, data, MediaContainer.Metadata and so on.
func listOf(v any, depth int) []map[string]any {
	switch t := v.(type) {
	case []any:
		return rows(t)
	case map[string]any:
		if depth > 3 {
			return nil
		}
		for _, k := range []string{"records", "data", "results", "Items", "MediaContainer", "Metadata", "Directory", "Hub", "Device", "Account", "Activity", "response", "torrents"} {
			if x, ok := t[k]; ok {
				if l := listOf(x, depth+1); l != nil {
					return l
				}
			}
		}
	}
	return nil
}

// Show reads one of the application's lists or records: show NAME [id=ID] [name=TITLE] [lines=N] [full=yes] [ARG=VALUE].
func (m *media) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", fmt.Errorf(`show NAME [id=ID] [name=TITLE] [lines=N] [full=yes], e.g. show status; names: %s`, strings.Join(m.showNames(), ", "))
	}
	sname := strings.ToLower(f[1])
	sh, ok := m.spec.shows[sname]
	if !ok {
		return "", fmt.Errorf("show %s: not a read %s has; names: %s", f[1], m.spec.model, strings.Join(m.showNames(), ", "))
	}
	rest := strings.TrimSpace(strings.TrimSpace(cmd)[len(f[0]):])[len(f[1]):]
	args, err := parseKV(rest)
	if err != nil {
		return "", err
	}
	allowed := map[string]bool{"full": true}
	for _, a := range strings.Fields(sh.args) {
		allowed[a] = true
	}
	if strings.Contains(sh.path, "{n}") {
		allowed["lines"] = true
	}
	if strings.Contains(sh.path, "{id}") {
		allowed["id"] = true
	}
	if sh.name != "" {
		allowed["name"] = true
	}
	var keys []string
	for k := range allowed {
		keys = append(keys, k+"=")
	}
	sort.Strings(keys)
	for k := range args {
		if !allowed[k] {
			return "", fmt.Errorf("%s=: show %s takes %s", k, sname, strings.Join(keys, " "))
		}
	}
	p := sh.path
	n := "50"
	if v, ok := args["lines"]; ok {
		x, err := strconv.Atoi(v)
		if err != nil || x < 1 || x > 2000 {
			return "", errors.New("lines=N: a number from 1 to 2000")
		}
		n = v
	}
	p = strings.ReplaceAll(p, "{n}", n)
	if strings.Contains(p, "{id}") {
		id, ok := args["id"]
		if !ok {
			return "", fmt.Errorf("show %s needs id=ID", sname)
		}
		if !idArgRE.MatchString(id) {
			return "", errors.New("id=: letters, digits and _ . : - only")
		}
		p = strings.ReplaceAll(p, "{id}", url.PathEscape(id))
	}
	var q []string
	for _, a := range strings.Fields(sh.args) {
		v, ok := args[a]
		if !ok {
			continue
		}
		if r, isRes := m.spec.res[a]; isRes {
			id, err := m.resolve(ctx, r, v)
			if err != nil {
				return "", err
			}
			q = append(q, r.param+"="+qesc(id))
			continue
		}
		q = append(q, a+"="+qesc(v))
	}
	if len(q) > 0 {
		sep := "?"
		if strings.Contains(p, "?") {
			sep = "&"
		}
		p += sep + strings.Join(q, "&")
	}
	v, err := m.get(ctx, p)
	if err != nil {
		return "", err
	}
	full := strings.EqualFold(args["full"], "yes") || strings.EqualFold(args["full"], "true")
	name, filter := args["name"]
	if (filter || (len(sh.cols) > 0 && !full)) && listOf(v, 0) != nil {
		var out []any
		for _, row := range listOf(v, 0) {
			if filter && !strings.Contains(normName(str(row[sh.name])), normName(name)) {
				continue
			}
			if full || len(sh.cols) == 0 {
				out = append(out, row)
				continue
			}
			pr := map[string]any{}
			for _, c := range sh.cols {
				if x, ok := row[c]; ok {
					pr[c] = x
				}
			}
			out = append(out, pr)
		}
		if out == nil {
			out = []any{}
		}
		v = map[string]any{"count": len(out), "rows": out}
	}
	return meJSON(v), nil
}

var secretQueryRE = regexp.MustCompile(`(?i)(^|[?&])[^=&]*(key|token|pass|sid|totp|secret)[^=&]*=`)

// APIGet reads any path below the API's root: GET only, never a key in the query, never a GET that changes something.
func (m *media) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := CheckAPIPath(path)
	if err != nil {
		return nil, false, err
	}
	if m.spec.root != "" && p != m.spec.root && !strings.HasPrefix(p, m.spec.root+"/") && !strings.HasPrefix(p, m.spec.root+"?") {
		return nil, false, fmt.Errorf("path: %s's API is below %s (e.g. %s)", m.spec.model, m.spec.root, m.spec.catalog[0])
	}
	if _, q, _ := strings.Cut(p, "?"); secretQueryRE.MatchString("?"+q) || strings.Contains(q, "%") && func() bool { _, e := url.ParseQuery(q); return e != nil }() {
		return nil, false, errors.New("path: a key, token or password in the query is never sent (the driver adds its own)")
	}
	if m.spec.readOK != nil {
		if err := m.spec.readOK(p); err != nil {
			return nil, false, err
		}
	}
	b, err := m.req(ctx, http.MethodGet, p, nil, nil)
	if err != nil {
		return nil, false, err
	}
	v, err := m.decode(b)
	if err != nil {
		return nil, false, err
	}
	if s, ok := v.(string); ok {
		return s, true, nil
	}
	return Redact(v), false, nil
}

func (m *media) APICatalog(context.Context) (any, error) {
	shows := map[string]string{}
	for n, s := range m.spec.shows {
		shows[n] = s.help
	}
	calls := map[string]string{}
	for n, c := range m.spec.calls {
		calls[n] = c.help
	}
	how := fmt.Sprintf("GET any path below %s with device_api_get (keys and passwords in the answer are hidden). device_show \"show NAME\" reads the lists below; "+
		"device_change_raw method CALL with an action as the path and its arguments as a JSON body changes things, or POST/PUT/PATCH/DELETE a path below %s with a JSON body.", firstOf(m.spec.root, "/"), firstOf(m.spec.root, "/"))
	out := map[string]any{"how": how, "examples": m.spec.catalog, "shows": shows, "calls": calls}
	if m.spec.anyCall != nil && m.spec.platform != "tautulli" {
		out["commands"] = "CALL with any command name of the API's /command endpoint as the path (RefreshSeries, RescanSeries, DownloadedEpisodesScan, RefreshMovie, MissingEpisodeSearch, ...); a title in the body (series, movie, artist) is turned into its id"
	}
	return out, nil
}

// fill puts the body's values into a path's {placeholders} and takes them out of the body.
func fill(tmpl string, body map[string]any) (string, error) {
	var bad error
	out := regexp.MustCompile(`\{([a-z_]+)\}`).ReplaceAllStringFunc(tmpl, func(ph string) string {
		k := ph[1 : len(ph)-1]
		v := bodyStr(body[k])
		if v == "" || len(v) > 8192 || !fillRE.MatchString(v) {
			if bad == nil {
				bad = fmt.Errorf(`body: %q is needed (letters, digits and _ . : - only)`, k)
			}
			return ph
		}
		delete(body, k)
		return url.PathEscape(v)
	})
	return out, bad
}

func bodyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []any:
		var ss []string
		for _, x := range t {
			ss = append(ss, bodyStr(x))
		}
		return strings.Join(ss, "|")
	case map[string]any:
		j, _ := json.Marshal(t)
		return string(j)
	case int:
		return strconv.Itoa(t)
	}
	return str(v)
}

// RawChange: method CALL runs one of the application's actions (path: the action, body: its arguments as a JSON object); POST,
// PUT, PATCH and DELETE send a path below the API's root as is.
func (m *media) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method != "CALL" {
		rr, err := r.checkREST("POST", "PUT", "PATCH", "DELETE")
		if err != nil {
			return res, fmt.Errorf("%v (or CALL with an action: %s)", err, strings.Join(m.callNames(), ", "))
		}
		if m.spec.platform == "tautulli" {
			return res, errors.New("Tautulli's API is changed with CALL and a command name, e.g. CALL terminate_session")
		}
		if m.spec.root != "" && !strings.HasPrefix(rr.Path, m.spec.root+"/") {
			return res, fmt.Errorf("path: below %s", m.spec.root)
		}
		if _, q, _ := strings.Cut(rr.Path, "?"); secretQueryRE.MatchString("?" + q) {
			return res, errors.New("path: a key, token or password in the query is never sent")
		}
		if guardsOn && method == "DELETE" {
			return res, errors.New("DELETE: refused while the guard lists are on (NETDIR_DEVICE_GUARDS=1)")
		}
		if method != "POST" {
			if b, err := m.req(ctx, http.MethodGet, rr.Path, nil, nil); err == nil {
				res.Before = m.trunc(b)
			}
		}
		if dry {
			res.Note = "dry run: nothing was sent; Before is what the path holds now"
			return res, nil
		}
		var body any
		hdr := http.Header{}
		if b := strings.TrimSpace(rr.Body); b != "" {
			body = b
			if b[0] == '{' || b[0] == '[' {
				hdr.Set("Content-Type", "application/json")
			} else {
				hdr.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
		b, err := m.req(ctx, method, rr.Path, body, hdr)
		if err != nil {
			return res, err
		}
		res.Applied, res.Answer = true, m.trunc(b)
		return res, nil
	}
	if len(r.Lines) > 0 {
		return res, errors.New("lines: an application is changed with CALL (an action) or a REST method")
	}
	if len(r.Body) > rawMaxBody || strings.ContainsRune(r.Body, 0) {
		return res, errors.New("body: larger than 256 KB, or not text")
	}
	body := map[string]any{}
	if strings.TrimSpace(r.Body) != "" {
		if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
			return res, errors.New("body: a JSON object of the action's arguments")
		}
	}
	action := strings.TrimSpace(r.Path)
	c, ok := m.spec.calls[action]
	if !ok {
		if m.spec.anyCall == nil || action == "" {
			return res, fmt.Errorf("path %q: the action to run: %s", r.Path, strings.Join(m.callNames(), ", "))
		}
		var err error
		if c, err = m.spec.anyCall(m, action, body); err != nil {
			return res, err
		}
	}
	if m.spec.platform == "qbittorrent" && (action == "stop" || action == "start") {
		m.mu.Lock()
		api := m.webAPI
		m.mu.Unlock()
		if api == "" {
			if v, err := m.get(ctx, "/app/webapiVersion"); err == nil {
				api = str(v)
				m.mu.Lock()
				m.webAPI = api
				m.mu.Unlock()
			}
		}
		if qbitLegacy(api) {
			c.path = map[string]string{"stop": "/torrents/pause", "start": "/torrents/resume"}[action]
		}
	}
	if guardsOn && c.guard {
		return res, fmt.Errorf("%s: refused while the guard lists are on (NETDIR_DEVICE_GUARDS=1): it deletes or restarts", action)
	}
	// titles to ids: {"series": "Blue Bloods"} is {"seriesId": 123}
	for k, rs := range m.spec.res {
		v, has := body[k]
		if !has || rs.field == "" {
			continue
		}
		id, err := m.resolve(ctx, rs, bodyStr(v))
		if err != nil {
			return res, err
		}
		delete(body, k)
		if strings.HasSuffix(rs.field, "Ids") {
			n, _ := strconv.Atoi(id)
			body[rs.field] = []any{n}
		} else if n, err := strconv.Atoi(id); err == nil && rs.id != "hash" {
			body[rs.field] = n
		} else {
			body[rs.field] = id
		}
	}
	if c.before != "" {
		bp, err := fill(m.spec.root+c.before, copyMap(body))
		if err == nil {
			if b, err := m.req(ctx, http.MethodGet, bp, nil, nil); err == nil {
				res.Before = m.trunc(b)
			} else {
				res.Before = "(not read: " + err.Error() + ")"
			}
		}
	}
	path, err := fill(m.spec.root+c.path, body)
	if err != nil {
		return res, err
	}
	var send any
	hdr := http.Header{}
	switch c.enc {
	case "json":
		send = body
	case "form", "query":
		vals := url.Values{}
		for k, v := range body {
			vals.Set(k, bodyStr(v))
		}
		if c.enc == "form" {
			send = vals.Encode()
			hdr.Set("Content-Type", "application/x-www-form-urlencoded")
		} else if len(vals) > 0 {
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			path += sep + strings.ReplaceAll(vals.Encode(), "+", "%20")
		}
	}
	if dry {
		what := c.method + " " + path
		if c.enc == "json" || c.enc == "form" {
			j, _ := json.Marshal(Redact(body))
			what += " " + string(j)
		}
		res.Note = "dry run: nothing was sent; it would send " + RedactText(what)
		return res, nil
	}
	b, err := m.req(ctx, c.method, path, send, hdr)
	if err != nil {
		return res, err
	}
	if m.spec.unwrap != nil {
		if _, err := m.decode(b); err != nil {
			return res, err
		}
	}
	res.Applied, res.Answer = true, m.trunc(b)
	return res, nil
}

func copyMap(m map[string]any) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// trunc is an answer as a write's result shows it: JSON with its secrets hidden, cut at 8 KB.
func (m *media) trunc(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		j, _ := json.Marshal(Redact(v))
		return rawTrunc(j)
	}
	return rawTrunc(b)
}
