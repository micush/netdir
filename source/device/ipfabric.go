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

// IP Fabric (https://docs.ipfabric.io), the network assurance platform, through its REST API: https://HOST/api/<version>/...
// The credential is an API token (the credential's Token, sent as the header "X-API-Token"), or a user name and password (POST
// /auth/login, then "Authorization: Bearer ACCESSTOKEN").  Neither ever goes into a URL.  The API version is asked of
// GET /api/version ({"apiVersion": "v7.3", "releaseVersion": "7.3.4+0"}) unless the option api_version (v7.3) says it.
//
// IP Fabric is a model of a whole network, not a device: the "device" here is the IP Fabric server.  What it knows is read from
// its tables: POST /tables/<section>/<table> with {"columns": [...], "filters": {...}, "pagination": {"limit": N, "start": N},
// "snapshot": "$last"} answers {"data": [...], "_meta": {"count": N}}.  The option snapshot (default $last) picks the snapshot.
//
//   - Facts: the release, and how many devices the snapshot holds.
//   - Interfaces: the interfaces table (every discovered device's, named "hostname:interface").
//   - Show: "show devices|interfaces|sites|arp|hosts|snapshots [snapshot=ID] [columns=a,b] [limit=N] [start=N] [sort=col|-col]
//     [column=value ...]", "show tables/<section>/<table> ..." for any other table, and "show device NAME": everything about one
//     discovered device (its record, its interfaces, its ARP entries) in one answer.
//   - APIGet: /tables/... (a read, sent as POST), /snapshots, /jobs, /version and /os/version.
//   - RawChange (rawmon.go-style, rw keys only): POST, PUT, PATCH, DELETE below /api/<version> (start, lock, load, unload and delete
//     snapshots, add and rediscover devices); users, tokens, login, single sign-on and licences are refused.
//
// The column names are the ones IP Fabric documents for these tables; a column a release does not have is refused by the server,
// and the answer says so (columns= picks the columns; the "?" on a table in the IP Fabric GUI describes it).  A secret found by
// name in an answer is hidden (Redact).

func init() { Register("ipfabric", newIPFabric) }

type ipfabric struct {
	d    Device
	api  *apiClient
	user string
	pass string
	snap string

	mu     sync.Mutex
	ver    string // "v7.3"
	rel    string // "7.3.4+0"
	auth   bool   // a token is set (or the login was done)
	ready_ bool   // the version is settled and the API answers below it
}

var (
	ipfRelRE  = regexp.MustCompile(`^([0-9]{1,2})\.([0-9]{1,2})`)
	ipfVerRE  = regexp.MustCompile(`^v[0-9]{1,2}(\.[0-9]{1,2})?$`)
	ipfSnapRE = regexp.MustCompile(`^(\$last|\$prev|\$lastLocked|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	ipfColRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,63}$`)
	ipfValRE  = regexp.MustCompile(`^[A-Za-z0-9._:@/*+-]{1,128}$`)
	ipfTabRE  = regexp.MustCompile(`^tables(/[A-Za-z0-9_-]{1,64}){1,6}$`)
)

func newIPFabric(d Device, c Credential) (Driver, error) {
	if c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: IP Fabric needs an API token, or a user name and a password", d.Name)
	}
	p := &ipfabric{d: d, user: c.Username, pass: c.Password, snap: strings.TrimSpace(d.Options["snapshot"]), ver: strings.TrimSpace(d.Options["api_version"])}
	if p.snap == "" {
		p.snap = "$last"
	}
	if !ipfSnapRE.MatchString(p.snap) {
		return nil, fmt.Errorf("device %s: option snapshot is $last, $prev, $lastLocked or a snapshot ID", d.Name)
	}
	if p.ver != "" && !ipfVerRE.MatchString(p.ver) {
		return nil, fmt.Errorf("device %s: option api_version is like v7.3", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		api.hdr.Set("X-API-Token", c.Token)
		p.auth = true
	}
	api.hdr.Set("User-Agent", "netdir")
	p.api = api
	return p, nil
}

// ready finds the API version, signs in (a user name and password) and checks that the API answers below /api/<version>: when the
// version /api/version names gets a 404, the release's major.minor, its major and v1 are tried before giving up.
func (p *ipfabric) ready(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready_ {
		return nil
	}
	var rel struct {
		API string `json:"apiVersion"`
		Rel string `json:"releaseVersion"`
	}
	if err := p.api.getJSON(ctx, "/api/version", &rel); err != nil {
		return fmt.Errorf("IP Fabric: reading /api/version: %w", err)
	}
	p.rel = firstOf(rel.Rel, "unknown")
	cands := []string{p.ver}
	if p.ver == "" {
		cands = []string{rel.API}
		if m := ipfRelRE.FindStringSubmatch(rel.Rel); m != nil {
			cands = append(cands, "v"+m[1]+"."+m[2], "v"+m[1])
		}
		cands = append(cands, "v1")
	}
	if !p.auth {
		ver := ""
		for _, c := range cands {
			if ipfVerRE.MatchString(c) {
				ver = c
				break
			}
		}
		if ver == "" {
			return errors.New("IP Fabric: /api/version names no API version: set the option api_version (v8.1)")
		}
		b, err := p.api.do(ctx, http.MethodPost, "/api/"+ver+"/auth/login", map[string]string{"username": p.user, "password": p.pass}, nil)
		if err != nil {
			return fmt.Errorf("IP Fabric: sign-in failed (POST /api/%s/auth/login): %w", ver, err)
		}
		var t struct {
			Access string `json:"accessToken"`
		}
		if json.Unmarshal(b, &t) != nil || t.Access == "" {
			return errors.New("IP Fabric: sign-in: the answer holds no access token")
		}
		p.api.hdr.Set("Authorization", "Bearer "+t.Access)
		p.auth = true
	}
	var tried []string
	for _, c := range cands {
		if !ipfVerRE.MatchString(c) {
			continue
		}
		for _, probe := range []string{"/os/version", "/snapshots"} {
			_, err := p.api.do(ctx, http.MethodGet, "/api/"+c+probe, nil, nil)
			var se *statusError
			if err == nil || (errors.As(err, &se) && se.Code != http.StatusNotFound) {
				p.ver = c // the route exists (a refused token is reported by the first real request)
				p.ready_ = true
				return nil
			}
			tried = append(tried, "/api/"+c+probe)
		}
	}
	return fmt.Errorf("IP Fabric %s answered 404 for %s: set the option api_version to the version in the API paths of this release (the GUI's Settings ▸ API documentation, /api/rapidoc/, shows them)", p.rel, strings.Join(tried, ", "))
}

func (p *ipfabric) path(rest string) string {
	return "/api/" + p.ver + "/" + strings.TrimPrefix(rest, "/")
}

// tableReq is one read of a table.
type tableReq struct {
	table   string // tables/inventory/devices
	columns []string
	filters map[string]any
	limit   int
	start   int
	sort    string // column, or -column
	snap    string // "" is the device's; "-" sends none (the snapshots table)
}

type tableAns struct {
	Rows  []map[string]any
	Count int64
}

func (p *ipfabric) read(ctx context.Context, q tableReq) (tableAns, error) {
	if err := p.ready(ctx); err != nil {
		return tableAns{}, err
	}
	if q.limit <= 0 || q.limit > 1000 {
		q.limit = 1000
	}
	body := map[string]any{"columns": q.columns, "pagination": map[string]any{"limit": q.limit, "start": q.start}}
	if q.filters != nil {
		body["filters"] = q.filters
	}
	if q.sort != "" {
		o, c := "asc", q.sort
		if strings.HasPrefix(c, "-") {
			o, c = "desc", c[1:]
		}
		body["sort"] = map[string]any{"column": c, "order": o}
	}
	if q.snap != "-" {
		body["snapshot"] = firstOf(q.snap, p.snap)
	}
	b, err := p.api.do(ctx, http.MethodPost, p.path(q.table), body, nil)
	if err != nil {
		return tableAns{}, fmt.Errorf("POST %s: %w", p.path(q.table), err)
	}
	var a struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			Count any `json:"count"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return tableAns{}, fmt.Errorf("POST %s: the answer is not the JSON expected: %v", q.table, err)
	}
	n := num(a.Meta.Count)
	if n == 0 {
		n = int64(len(a.Data))
	}
	return tableAns{Rows: a.Data, Count: n}, nil
}

// readTry reads with the full list of columns and, when the server refuses the request (a column its release does not have), again
// with the minimal ones.
func (p *ipfabric) readTry(ctx context.Context, q tableReq, minimal []string) (tableAns, error) {
	a, err := p.read(ctx, q)
	var se *statusError
	if err != nil && errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != 401 && se.Code != 403 && len(minimal) > 0 {
		q.columns = minimal
		if a2, err2 := p.read(ctx, q); err2 == nil {
			return a2, nil
		}
	}
	return a, err
}

// ipfTables are the tables with a name of their own and the columns IP Fabric documents for them.
var ipfTables = map[string]struct {
	path string
	cols []string
	min  []string
	snap string
}{
	"devices":    {"tables/inventory/devices", []string{"id", "hostname", "siteName", "loginIpv4", "vendor", "family", "platform", "model", "version", "sn", "uptime", "devType"}, []string{"id", "hostname"}, ""},
	"interfaces": {"tables/inventory/interfaces", []string{"id", "hostname", "intName", "dscr", "primaryIp", "mac", "mtu", "speed", "duplex", "l1", "l2"}, []string{"id", "hostname", "intName"}, ""},
	"sites":      {"tables/inventory/sites", []string{"id", "siteName", "devicesCount", "usersCount", "networksCount"}, []string{"id", "siteName"}, ""},
	"hosts":      {"tables/inventory/hosts", []string{"id", "hostname", "ip", "mac", "siteName"}, []string{"id", "ip"}, ""},
	"arp":        {"tables/addressing/arp", []string{"id", "hostname", "intName", "ip", "mac"}, []string{"id", "hostname", "ip"}, ""},
	"snapshots":  {"tables/management/snapshots", []string{"id", "name", "status", "locked", "totalDevCount", "interfaceCount", "userCount", "tsStart", "tsEnd", "isLastSnapshot"}, []string{"id", "status"}, "-"},
}

func ipfNames() string {
	n := make([]string, 0, len(ipfTables))
	for k := range ipfTables {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

func (p *ipfabric) Facts(ctx context.Context) (Facts, error) {
	if err := p.ready(ctx); err != nil {
		return Facts{}, err
	}
	f := Facts{Hostname: p.d.Address, Vendor: "IP Fabric", OSVersion: p.rel, Model: "Network assurance"}
	if a, err := p.read(ctx, tableReq{table: ipfTables["devices"].path, columns: []string{"id"}, limit: 1}); err == nil {
		f.Model = fmt.Sprintf("Network assurance: %d devices in %s", a.Count, p.snap)
	}
	return f, nil
}

func (p *ipfabric) Interfaces(ctx context.Context) ([]Interface, error) {
	t := ipfTables["interfaces"]
	var out []Interface
	for start := 0; start < 5000; start += 1000 {
		a, err := p.readTry(ctx, tableReq{table: t.path, columns: t.cols, limit: 1000, start: start}, t.min)
		if err != nil {
			return nil, err
		}
		for _, r := range a.Rows {
			i := Interface{Name: str(r["hostname"]) + ":" + str(r["intName"]), Description: str(r["dscr"]), MAC: obsMAC(str(r["mac"])), SpeedMbps: num(r["speed"]) / 1_000_000}
			if ip := str(r["primaryIp"]); ip != "" {
				i.Addresses = []string{ip}
			}
			if s := str(r["l1"]); s != "" {
				i.AdminUp = boolp(s != "down")
			}
			if s := str(r["l2"]); s != "" {
				i.OperUp = boolp(s == "up")
			}
			out = append(out, i)
		}
		if int64(start+len(a.Rows)) >= a.Count || len(a.Rows) < 1000 {
			break
		}
	}
	return out, nil
}

func (p *ipfabric) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (p *ipfabric) Config(context.Context) (string, error)        { return "", ErrUnsupported }

const ipfUsage = "show diagnose | show NAME [snapshot=ID] [columns=a,b] [limit=N] [start=N] [sort=col|-col] [column=value ...] | show device NAME | show tables/<section>/<table> ...; names: "

func ipfFilter(v string) any {
	switch v {
	case "true":
		return []any{"eq", true}
	case "false":
		return []any{"eq", false}
	}
	if strings.Contains(v, "*") {
		return []any{"like", strings.Trim(v, "*")}
	}
	return []any{"eq", v}
}

func ipfText(v any) string {
	b, _ := json.MarshalIndent(obsScrub(Redact(v)), "", "  ")
	return string(b)
}

func (p *ipfabric) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(ipfUsage + ipfNames())
	}
	name := f[1]
	if strings.EqualFold(name, "diagnose") && len(f) == 2 {
		return p.diagnose(ctx), nil
	}
	if strings.EqualFold(name, "device") {
		if len(f) != 3 || !ipfValRE.MatchString(f[2]) {
			return "", errors.New("show device NAME: the host name of a discovered device (show devices lists them)")
		}
		v, err := p.deviceAll(ctx, f[2])
		if err != nil {
			return "", err
		}
		return ipfText(v), nil
	}
	req := tableReq{limit: 100, filters: map[string]any{}}
	min := []string(nil)
	if t, ok := ipfTables[strings.ToLower(name)]; ok {
		req.table, req.columns, min, req.snap = t.path, t.cols, t.min, t.snap
	} else if ipfTabRE.MatchString(name) {
		req.table, req.columns = name, []string{"id"}
	} else {
		return "", fmt.Errorf("show %s: not a table the IP Fabric driver reads; names: %s, or tables/<section>/<table>", name, ipfNames())
	}
	for _, a := range f[2:] {
		k, v, ok := strings.Cut(a, "=")
		if !ok || !ipfColRE.MatchString(k) {
			return "", fmt.Errorf("%q: use name=value", a)
		}
		switch k {
		case "snapshot":
			if !ipfSnapRE.MatchString(v) {
				return "", errors.New("snapshot: $last, $prev, $lastLocked or a snapshot ID")
			}
			req.snap = v
		case "columns":
			req.columns, min = strings.Split(v, ","), nil
			for _, c := range req.columns {
				if !ipfColRE.MatchString(c) {
					return "", fmt.Errorf("columns: %q is not a column name", c)
				}
			}
		case "limit", "start":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || (k == "limit" && n > 1000) {
				return "", fmt.Errorf("%s: a number (limit at most 1000)", k)
			}
			if k == "limit" {
				req.limit = n
			} else {
				req.start = n
			}
		case "sort":
			if !ipfColRE.MatchString(strings.TrimPrefix(v, "-")) {
				return "", errors.New("sort: a column name, or -column for descending")
			}
			req.sort = v
		default:
			if !ipfValRE.MatchString(v) {
				return "", fmt.Errorf("%q: a filter value is letters, digits and . _ : @ / * + -", a)
			}
			req.filters[k] = ipfFilter(v)
		}
	}
	a, err := p.readTry(ctx, req, min)
	if err != nil {
		return "", p.hint(err, name)
	}
	return ipfText(map[string]any{"table": req.table, "count": a.Count, "start": req.start, "rows": a.Rows}), nil
}

func (p *ipfabric) hint(err error, name string) error {
	var se *statusError
	if errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != 401 && se.Code != 403 {
		return fmt.Errorf("%w (columns= picks the columns of %s; the ? on the table in the IP Fabric GUI lists them)", err, name)
	}
	return err
}

// deviceAll answers everything about one discovered device.
func (p *ipfabric) deviceAll(ctx context.Context, name string) (map[string]any, error) {
	t := ipfTables["devices"]
	a, err := p.readTry(ctx, tableReq{table: t.path, columns: t.cols, limit: 50, filters: map[string]any{"hostname": []any{"like", name}}}, t.min)
	if err != nil {
		return nil, p.hint(err, "devices")
	}
	var hit []map[string]any
	for _, r := range a.Rows {
		if strings.EqualFold(str(r["hostname"]), name) {
			hit = []map[string]any{r}
			break
		}
		hit = append(hit, r)
	}
	switch {
	case len(hit) == 0:
		return nil, fmt.Errorf("show device %s: no discovered device in snapshot %s has that host name (show devices hostname=*%s* lists the near ones)", name, p.snap, name)
	case len(hit) > 1:
		var n []string
		for i, r := range hit {
			if i == 10 {
				n = append(n, "…")
				break
			}
			n = append(n, str(r["hostname"]))
		}
		return nil, fmt.Errorf("show device %s: %d devices match (%s): use the whole host name", name, len(hit), strings.Join(n, ", "))
	}
	host := str(hit[0]["hostname"])
	out := map[string]any{"snapshot": p.snap, "device": hit[0]}
	var unavailable []string
	for _, k := range []string{"interfaces", "arp"} {
		tt := ipfTables[k]
		r, err := p.readTry(ctx, tableReq{table: tt.path, columns: tt.cols, limit: 1000, filters: map[string]any{"hostname": []any{"eq", host}}}, tt.min)
		if err != nil {
			unavailable = append(unavailable, k+": "+err.Error())
			continue
		}
		out[k] = r.Rows
	}
	if len(unavailable) > 0 {
		out["unavailable"] = unavailable
	}
	return out, nil
}

// ---- reading through the API ----

// ipfRead turns a path into what to ask: the part below /api/<version>, and for /tables/... the query as a table read.
func (p *ipfabric) ipfRead(path string) (string, url.Values, error) {
	pp, q, _ := strings.Cut(path, "?")
	if s, ok := strings.CutPrefix(pp, "/api/"); ok {
		_, rest, _ := strings.Cut(s, "/")
		pp = "/" + rest
		if s == "version" {
			pp = "/api/version"
		}
	}
	vals, err := url.ParseQuery(q)
	if err != nil || strings.Contains(pp, "..") || strings.ContainsAny(pp, " \r\n\x00") {
		return "", nil, errors.New("path: not a path of the IP Fabric API")
	}
	first := strings.SplitN(strings.TrimPrefix(pp, "/"), "/", 2)[0]
	switch first {
	case "tables", "snapshots", "jobs", "os", "version":
	case "api":
		if pp != "/api/version" {
			return "", nil, errors.New("path: IP Fabric is read at /tables/<section>/<table>, /snapshots, /jobs, /version and /os/version (see device_api_catalog)")
		}
	default:
		return "", nil, errors.New("path: IP Fabric is read at /tables/<section>/<table>, /snapshots, /jobs, /version and /os/version (see device_api_catalog)")
	}
	return pp, vals, nil
}

func (p *ipfabric) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, q, err := p.ipfRead(path)
	if err != nil {
		return nil, false, err
	}
	if err := p.ready(ctx); err != nil {
		return nil, false, err
	}
	if strings.HasPrefix(pp, "/tables/") {
		t := strings.TrimPrefix(pp, "/")
		if !ipfTabRE.MatchString(t) {
			return nil, false, errors.New("path: /tables/<section>/<table>")
		}
		req := tableReq{table: t, columns: []string{"id"}, limit: 100, filters: map[string]any{}, snap: q.Get("snapshot")}
		if req.snap != "" && !ipfSnapRE.MatchString(req.snap) {
			return nil, false, errors.New("snapshot: $last, $prev, $lastLocked or a snapshot ID")
		}
		for k, vs := range q {
			v := vs[0]
			switch k {
			case "snapshot":
			case "columns":
				req.columns = strings.Split(v, ",")
				for _, c := range req.columns {
					if !ipfColRE.MatchString(c) {
						return nil, false, fmt.Errorf("columns: %q is not a column name", c)
					}
				}
			case "limit", "start":
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 || n > 1000 {
					return nil, false, fmt.Errorf("%s: a number (limit at most 1000)", k)
				}
				if k == "limit" {
					req.limit = n
				} else {
					req.start = n
				}
			case "sort":
				req.sort = v
			default:
				if !ipfColRE.MatchString(k) || !ipfValRE.MatchString(v) {
					return nil, false, fmt.Errorf("filter %q: name=value", k)
				}
				req.filters[k] = ipfFilter(v)
			}
		}
		a, err := p.read(ctx, req)
		if err != nil {
			return nil, false, p.hint(err, t)
		}
		return Redact(map[string]any{"count": a.Count, "start": req.start, "data": a.Rows}), false, nil
	}
	wire := p.path(pp)
	if pp == "/api/version" {
		wire = pp
	}
	b, err := p.api.do(ctx, http.MethodGet, wire, nil, nil)
	if err != nil {
		return nil, false, fmt.Errorf("GET %s: %w", wire, err)
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		return Redact(v), false, nil
	}
	return string(b), true, nil
}

func (p *ipfabric) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "Tables are read with /tables/<section>/<table>?columns=a,b,c&limit=100&start=0&snapshot=$last&sort=col&column=value (sent to IP Fabric as a POST read; a value with * is a substring match). " +
			"Also GET /snapshots, /jobs, /version and /os/version. Table names and columns: the ? on a table in the IP Fabric GUI describes it. Reading sends no change; changes are device_change_raw.",
		"examples": []string{"/tables/inventory/devices?columns=id,hostname,siteName,vendor,version&limit=50", "/tables/inventory/interfaces?columns=hostname,intName,primaryIp&hostname=core1",
			"/tables/addressing/arp?columns=hostname,ip,mac&ip=10.0.0.1", "/tables/management/snapshots?columns=id,status,locked", "/snapshots", "/version"},
		"tip": "show device NAME (device_show) answers everything about one discovered device in one call.",
	}, nil
}

// ---- changes ----

// RawChange: Method POST, PUT, PATCH or DELETE and a Path below /api/<version> (/snapshots/<id>/lock, /snapshots/<id>/load, ...), Body JSON.
func (p *ipfabric) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if err := p.ready(ctx); err != nil {
		return RawResult{DryRun: dry}, err
	}
	if s, ok := strings.CutPrefix(r.Path, "/api/"+p.ver); ok {
		r.Path = s
	}
	return restRaw(ctx, restSpec{
		api: p.api, hdr: jsonHdr(), json: true,
		wire: p.path,
		guard: func(_, path string) error {
			if hasSeg(path, "users", "user", "tokens", "token", "auth", "login", "logout", "ldap", "saml", "oidc", "sso", "licenses", "license", "os") {
				return errors.New("path: users, tokens, login, single sign-on, licences and the system are not changed here")
			}
			return nil
		},
		alive: func(ctx context.Context) error {
			_, err := p.api.do(ctx, http.MethodGet, "/api/version", nil, nil)
			return err
		},
	}, r, dry)
}

func (p *ipfabric) Close(context.Context) { p.api.close() }

// diagnose sends a fixed set of requests and says, for each, what was asked and what IP Fabric answered, so that a "404 on
// everything" can be told from a refused token, a wrong path or a proxy.  It sends no change, and the credential is not printed.
func (p *ipfabric) diagnose(ctx context.Context) string {
	type probe struct {
		Request string `json:"request"`
		Auth    string `json:"auth"`
		Status  any    `json:"status"`
		Body    string `json:"body,omitempty"`
	}
	var out []probe
	noAuth, err := newAPIClient(p.d, 443)
	if err != nil {
		return "diagnose: " + err.Error()
	}
	defer noAuth.close()
	send := func(c *apiClient, auth, method, path string, body any, hdr http.Header) {
		b, err := c.do(ctx, method, path, body, hdr)
		pr := probe{Request: method + " " + path, Auth: auth, Status: 200}
		var se *statusError
		switch {
		case errors.As(err, &se):
			pr.Status, b = se.Code, []byte(se.Body)
		case err != nil:
			pr.Status, b = "error", []byte(err.Error())
		}
		pr.Body = RedactText(strings.Join(strings.Fields(string(b)), " "))
		if len(pr.Body) > 240 {
			pr.Body = pr.Body[:240] + "…"
		}
		out = append(out, pr)
	}
	send(noAuth, "none", "GET", "/api/version", nil, nil)
	var v struct {
		API string `json:"apiVersion"`
	}
	_ = p.api.getJSON(ctx, "/api/version", &v)
	ver := firstOf(p.d.Options["api_version"], v.API, "v1")
	creds := "token (X-API-Token)"
	if p.user != "" {
		creds = "user name and password"
		if err := p.ready(ctx); err != nil {
			out = append(out, probe{Request: "POST /api/" + ver + "/auth/login", Auth: creds, Status: "error", Body: RedactText(err.Error())})
		}
	}
	base := "/api/" + ver
	send(p.api, creds, "GET", base+"/os/version", nil, nil)
	send(noAuth, "none", "GET", base+"/os/version", nil, nil)
	send(p.api, creds, "GET", base+"/snapshots", nil, nil)
	send(p.api, creds, "POST", base+"/tables/inventory/sites", map[string]any{"columns": []string{"id"}, "pagination": map[string]any{"limit": 1, "start": 0}, "snapshot": "$last"}, nil)
	send(p.api, creds, "POST", base+"/tables/management/snapshots", map[string]any{"columns": []string{"id"}, "pagination": map[string]any{"limit": 1, "start": 0}}, nil)
	send(p.api, creds, "GET", "/api/", nil, nil)
	b, _ := json.MarshalIndent(map[string]any{"driver_version": ver, "release": p.rel, "probes": out,
		"how_to_read": "200: works. 401/403: the credential is refused or lacks a role. 404 with and without the credential: the path is wrong or something in front of IP Fabric hides it; 404 only with it: the credential is not accepted for this path."}, "", "  ")
	return string(b)
}
