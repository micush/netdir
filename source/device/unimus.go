package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Unimus (network configuration backup and change tracking), through its REST API: https://<host>/api/v3 (Unimus 2.2.0 and later; option
// api_version "v2" for 1.9 to 2.1).  The credential is the API token (Unimus: Settings > User management > API token), sent as
// "Authorization: Bearer <token>".  A Unimus listens on 8085 by default and speaks plain HTTP there; this driver only speaks HTTPS, so
// put Unimus behind a TLS proxy (or turn TLS on) and give the port when it is not 443.
//
// Without the option "device" the device is the Unimus server: Facts (health, number of devices), Show and APIGet for its inventory.
// With the option "device" (a device's address as Unimus has it, or its UUID) the device is one backed-up device: Config is the
// latest backup of that device (the same filter as a configuration read from the device itself is applied over MCP).
//
//	show health | devices [addresses=…] [vendors=…] [types=…] [models=…] | zones | tags | jobs | backups [device=<address|uuid>] [validSince=…]
//
// Changes (RawChange, rw callers only): POST, PUT, PATCH or DELETE below /api/v3/.  Pushing configuration to devices (jobs/push), uploading
// or deleting backups, credentials and connections, deleting devices and zones are never done here.
//
// Not tried against a real Unimus: paths and field names are from the published OpenAPI description of API v3 (the v3 one is a draft).

func init() { Register("unimus", newUnimus) }

type unimus struct {
	d    Device
	api  *apiClient
	dev  string
	ver  string // "v3" or "v2"; "auto" until the first answer says which one the server has
	base string // "/api/v3"
	mu   sync.Mutex
}

var (
	uniSegRE = regexp.MustCompile(`^[A-Za-z0-9_.:,@=~%-]{1,128}$`)
	uniDevRE = regexp.MustCompile(`^[A-Za-z0-9._:@/-]{1,128}$`)
	// uniDeny are the parts of the API that name credentials and connections.
	uniDeny = []string{"credential", "connection", "password", "clipassword", "enable", "token", "users", "license", "zone-proxy", "proxy"}
	// uniRoots are the first segments a read may start with.
	uniRoots = map[string]bool{"devices": true, "zones": true, "tags": true, "health": true, "jobs": true, "backups": true, "schedules": true, "system": true, "presets": true}
)

func newUnimus(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: Unimus needs an API token (Settings > User management > API token) as the token", d.Name)
	}
	u := &unimus{d: d, dev: strings.TrimSpace(d.Options["device"]), ver: strings.ToLower(strings.TrimSpace(d.Options["api_version"]))}
	if u.ver == "" {
		u.ver = "auto"
	}
	if u.ver != "v2" && u.ver != "v3" && u.ver != "auto" {
		return nil, fmt.Errorf("device %s: option api_version is v3 or v2", d.Name)
	}
	if u.dev != "" && !uniDevRE.MatchString(u.dev) {
		return nil, fmt.Errorf("device %s: option device is a device's address or its UUID", d.Name)
	}
	u.base = "/api/" + strings.Replace(u.ver, "auto", "v3", 1)
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	api.hdr.Set("Accept", "application/json")
	api.hdr.Set("User-Agent", "netdir")
	u.api = api
	return u, nil
}

// probe finds out which API version the server has when the option api_version is not set: v3 (Unimus 2.2 and later), else v2.
func (u *unimus) probe(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ver != "auto" {
		return nil
	}
	_, err := u.api.do(ctx, http.MethodGet, "/api/v3/health", nil, nil)
	var se *statusError
	switch {
	case err == nil:
		u.ver, u.base = "v3", "/api/v3"
	case errors.As(err, &se) && se.Code == http.StatusNotFound:
		if _, err2 := u.api.do(ctx, http.MethodGet, "/api/v2/health", nil, nil); err2 != nil {
			return fmt.Errorf("neither /api/v3 nor /api/v2 answers (is this the Unimus API port, and is the token right?): %w", err2)
		}
		u.ver, u.base = "v2", "/api/v2"
	default:
		return err
	}
	return nil
}

// get reads one path below the API base (p starts with "/") and returns the JSON; Unimus API v2 wraps answers in {"data": …}.
func (u *unimus) get(ctx context.Context, p string) (any, error) {
	if err := u.probe(ctx); err != nil {
		return nil, err
	}
	b, err := u.api.do(ctx, http.MethodGet, u.base+p, nil, nil)
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
	if m, ok := v.(map[string]any); ok && m["paginator"] == nil {
		if d, ok := m["data"]; ok { // API v2: {"data": …, "paging": {…}}
			if dm, ok := d.(map[string]any); ok && m["paging"] != nil {
				dm["paging"] = m["paging"]
				return dm, nil
			}
			if l, ok := d.([]any); ok && m["paging"] != nil {
				return map[string]any{"data": l, "paging": m["paging"]}, nil
			}
			return d, nil
		}
	}
	return v, nil
}

// list reads a collection page by page: key is the field holding the rows in v3 ("devices", "backups"), v2 answers a bare array.
func (u *unimus) list(ctx context.Context, path, key string, max int) ([]map[string]any, error) {
	var out []map[string]any
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for page := 0; page < 200; page++ {
		v, err := u.get(ctx, fmt.Sprintf("%s%spage=%d&size=100", path, sep, page))
		if err != nil {
			return out, err
		}
		var rs []map[string]any
		pages := int64(1)
		switch t := v.(type) {
		case map[string]any:
			rs = rows(t[key])
			if rs == nil {
				rs = rows(t["data"])
			}
			if p, ok := t["paginator"].(map[string]any); ok {
				pages = num(p["totalPages"])
			} else if p, ok := t["paging"].(map[string]any); ok {
				pages = num(p["totalPages"])
			}
		case []any:
			rs = rows(t)
			if len(rs) == 100 {
				pages = int64(page) + 2
			}
		}
		out = append(out, rs...)
		if max > 0 && len(out) >= max {
			return out[:max], nil
		}
		if int64(page)+1 >= pages || len(rs) == 0 {
			break
		}
	}
	return out, nil
}

func (u *unimus) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Hostname: u.d.Name, Vendor: "Unimus", Model: "Unimus"}
	h, err := u.get(ctx, "/health") // also finds the API version
	if err != nil {
		return f, err
	}
	status := ""
	if m, ok := h.(map[string]any); ok {
		status = str(m["status"])
	}
	if u.dev != "" {
		row, err := u.findDevice(ctx)
		if err != nil {
			return f, err
		}
		f.Hostname = firstOf(str(row["description"]), str(row["address"]), u.d.Name)
		f.Vendor = firstOf(str(row["deviceVendor"]), str(row["vendor"]), "Unimus")
		f.Model = firstOf(str(row["deviceModel"]), str(row["model"]), str(row["deviceType"]), str(row["type"]))
		return f, nil
	}
	f.Model = "Unimus"
	if status != "" {
		f.Model += ", " + strings.ToLower(status)
	}
	if u.ver == "v2" {
		if rs, err := u.list(ctx, "/devices", "devices", 0); err == nil {
			f.Model += fmt.Sprintf(", %d device(s)", len(rs))
		}
	} else if v, err := u.get(ctx, "/devices?page=0&size=1"); err == nil {
		if m, ok := v.(map[string]any); ok {
			for _, k := range []string{"paginator", "paging"} {
				if p, ok := m[k].(map[string]any); ok {
					if n := num(p["totalCount"]); n > 0 {
						f.Model += fmt.Sprintf(", %d device(s)", n)
					} else if n := num(p["totalElements"]); n > 0 {
						f.Model += fmt.Sprintf(", %d device(s)", n)
					}
				}
			}
		}
	}
	return f, nil
}

func (u *unimus) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (u *unimus) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }

// findDevice gives the device the option "device" names.
func (u *unimus) findDevice(ctx context.Context) (map[string]any, error) {
	return u.resolve(ctx, u.dev)
}

var uniNumRE = regexp.MustCompile(`^[0-9]{1,12}$`)

// resolve finds a device by its UUID or ID, its address, or its name (the description Unimus shows).
func (u *unimus) resolve(ctx context.Context, ref string) (map[string]any, error) {
	if err := u.probe(ctx); err != nil {
		return nil, err
	}
	nf := fmt.Errorf("Unimus has no device %q (an address, a name as Unimus shows it, or an ID)", ref)
	if entraGUIDRE.MatchString(ref) || uniNumRE.MatchString(ref) {
		v, err := u.get(ctx, "/devices/"+ref)
		if err != nil {
			return nil, err
		}
		if m, ok := v.(map[string]any); ok {
			return m, nil
		}
		return nil, nf
	}
	if u.ver == "v2" {
		if v, err := u.get(ctx, "/devices/findByAddress/"+url.PathEscape(ref)); err == nil {
			if m, ok := v.(map[string]any); ok && len(m) > 0 {
				return m, nil
			}
		}
	} else if rs, err := u.list(ctx, "/devices?addresses="+url.QueryEscape(ref), "devices", 2); err != nil {
		return nil, err
	} else if len(rs) > 0 {
		return rs[0], nil
	}
	rs, err := u.list(ctx, "/devices", "devices", 0)
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(ref)
	var part []map[string]any
	for _, r := range rs {
		d, ad := strings.ToLower(strings.TrimSpace(str(r["description"]))), strings.ToLower(str(r["address"]))
		if d == want || ad == want {
			return r, nil
		}
		if d != "" && (strings.HasPrefix(d, want) || strings.HasPrefix(d, want+".")) {
			part = append(part, r)
		}
	}
	if len(part) == 1 {
		return part[0], nil
	}
	if len(part) > 1 {
		return nil, fmt.Errorf("%q fits %d devices: give the address or the full name", ref, len(part))
	}
	return nil, nf
}

func uniID(m map[string]any) string { return firstOf(str(m["uuid"]), str(m["id"])) }

// id is the key a device or backup is addressed by in paths: the numeric "id" in API v2 (a row may hold a "uuid" too, which v2 refuses
// in a path), the "uuid" in v3.
func (u *unimus) id(m map[string]any) string {
	if u.ver == "v2" {
		return firstOf(str(m["id"]), str(m["uuid"]))
	}
	return uniID(m)
}

// Config is the latest backup of the device named by the option "device".
func (u *unimus) Config(ctx context.Context) (string, error) {
	if u.dev == "" {
		return "", ErrUnsupported
	}
	row, err := u.findDevice(ctx)
	if err != nil {
		return "", err
	}
	return u.backupText(ctx, row)
}

// backupText reads the latest backup of a device (a row of the device list).
func (u *unimus) backupText(ctx context.Context, row map[string]any) (string, error) {
	id := u.id(row)
	if id == "" {
		return "", errors.New("Unimus gave the device no ID")
	}
	var b map[string]any
	if u.ver == "v2" {
		v, err := u.get(ctx, "/devices/"+id+"/backups/latest")
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code >= 400 && se.Code < 500 { // this build wants the list form
			v2, err2 := u.get(ctx, "/devices/"+id+"/backups?latest=true")
			if err2 != nil {
				return "", fmt.Errorf("/devices/%s/backups/latest: %v; /devices/%s/backups?latest=true: %v", id, err, id, err2)
			}
			switch t := v2.(type) {
			case []any:
				if len(t) > 0 {
					v, err = t[0], nil
				}
			case map[string]any:
				if l, ok := t["data"].([]any); ok && len(l) > 0 {
					v, err = l[0], nil
				} else if l, ok := t["backups"].([]any); ok && len(l) > 0 {
					v, err = l[0], nil
				}
			}
		}
		if err != nil {
			return "", err
		}
		b, _ = v.(map[string]any)
	} else {
		rs, err := u.list(ctx, "/devices/backups?deviceUuids="+id+"&latest=true", "backups", 1)
		if err != nil {
			return "", err
		}
		if len(rs) > 0 {
			b = rs[0]
		}
		if len(rs) > 0 && uniContent(b) == "" {
			v, err := u.get(ctx, "/devices/"+id+"/backups/"+u.id(b))
			if err != nil {
				return "", err
			}
			b, _ = v.(map[string]any)
		}
	}
	if b == nil {
		return "", errors.New("Unimus holds no backup of this device yet")
	}
	if t := strings.ToUpper(str(b["type"])); t == "BINARY" {
		return "", errors.New("the latest backup is binary and is not shown")
	}
	txt := uniContent(b)
	if txt == "" {
		return "", errors.New("the backup has no text")
	}
	return txt, nil
}

// uniContent is the text of a backup: Unimus sends it Base64 encoded in "bytes".
func uniContent(b map[string]any) string {
	s, ok := b["bytes"].(string)
	if !ok || s == "" {
		return ""
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(raw)
	}
	return s
}

// uniStrip takes the text out of backups in an answer (it is read with Config, which filters it), keeping the rest.
func uniStrip(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if s, ok := x.(string); ok && k == "bytes" && len(s) > 40 {
				out[k] = "(the backup text: read it with the configuration of a device that has the option device)"
				continue
			}
			out[k] = uniStrip(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = uniStrip(x)
		}
		return out
	}
	return v
}

func uniDenied(pp string) string {
	for _, g := range strings.Split(strings.Trim(pp, "/"), "/") {
		lg := strings.ToLower(g)
		for _, d := range uniDeny {
			if strings.Contains(lg, d) {
				return g
			}
		}
	}
	return ""
}

// uniRead checks a path for APIGet and gives the path below the API base.
func (u *unimus) uniRead(path string) (string, error) {
	p := path
	for _, pre := range []string{"/api/v3", "/api/v2", "/api/v1"} {
		if strings.HasPrefix(p, pre+"/") {
			p = strings.TrimPrefix(p, pre)
			break
		}
	}
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	if !strings.HasPrefix(pp, "/") {
		return "", errors.New("path: /<resource>[/<uuid>[/...]] (see device_api_catalog)")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if len(segs) < 1 || len(segs) > 6 {
		return "", errors.New("path: /<resource>[/<uuid>[/...]] (see device_api_catalog)")
	}
	for _, g := range segs {
		if !uniSegRE.MatchString(g) {
			return "", fmt.Errorf("path: %q is not a resource name or a UUID", g)
		}
	}
	if !uniRoots[strings.ToLower(segs[0])] {
		return "", fmt.Errorf("path: %q is not read here (devices, backups, zones, tags, jobs, schedules, health)", segs[0])
	}
	if g := uniDenied(pp); g != "" {
		return "", fmt.Errorf("path: %q holds credentials or connections and is not read here", g)
	}
	return p, nil
}

func (u *unimus) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show health | devices [addresses=… vendors=… types=… models=…] | zones | tags | jobs | backups [device=<name|address|id>] | backup <name|address|id>   for example: show backup core1")
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	if strings.EqualFold(f[1], "backup") { // the text of the latest backup of one device, filtered like any configuration
		if len(f) != 3 || !uniDevRE.MatchString(f[2]) {
			return "", usage
		}
		row, err := u.resolve(ctx, f[2])
		if err != nil {
			return "", err
		}
		txt, err := u.backupText(ctx, row)
		if err != nil {
			return "", err
		}
		return RedactConfig(txt), nil
	}
	q := url.Values{}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !uniSegRE.MatchString(k) || v == "" || len(v) > 128 || strings.ContainsAny(v, "&#\"'`;<>") {
			return "", usage
		}
		q.Set(k, v)
	}
	var p string
	switch strings.ToLower(f[1]) {
	case "health":
		p = "/health"
	case "devices", "zones", "tags":
		p = "/" + strings.ToLower(f[1])
	case "jobs":
		p = "/jobs/tasks/status"
	case "backups":
		d := q.Get("device")
		q.Del("device")
		_ = u.probe(ctx)
		p = "/devices/backups"
		if u.ver == "v2" && d == "" {
			return "", errors.New("show backups device=<name|address|id>: Unimus API v2 lists the backups of one device")
		}
		if d != "" {
			row, err := u.resolve(ctx, d)
			if err != nil {
				return "", err
			}
			if u.ver == "v2" {
				p = "/devices/" + u.id(row) + "/backups"
			} else {
				q.Set("deviceUuids", u.id(row))
			}
		}
	default:
		return "", usage
	}
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	if g := uniDenied(p); g != "" {
		return "", usage
	}
	v, err := u.get(ctx, p)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(uniStrip(v)), "", "  ")
	return RedactText(string(b)), nil
}

func (u *unimus) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := u.uniRead(path)
	if err != nil {
		return nil, false, err
	}
	v, err := u.get(ctx, p)
	if err != nil {
		return nil, false, err
	}
	return Redact(uniStrip(v)), false, nil
}

func (u *unimus) APICatalog(ctx context.Context) (any, error) {
	_ = u.probe(ctx)
	if u.ver == "v2" {
		return map[string]any{
			"how": "GET paths of the Unimus API v2 this server speaks, below /api/v2: /devices, /devices/<id>, /devices/<id>/backups?latest=true, /devices/<id>/backups/latest, /health. " +
				"List paths take page and size. Only GET is sent. The text of a backup is not part of these answers: read it with the Show command `show backup <name|address|id>` or as the configuration of a device with the option device. Credentials and connections are not read.",
			"examples": []string{"/health", "/devices", "/devices/<id>", "/devices/<id>/backups?latest=true", "/devices/<id>/backups/latest"},
		}, nil
	}
	return map[string]any{
		"how": "GET paths of the Unimus API v3 below /api/v3: /devices, /devices/<uuid>, /devices/backups?deviceUuids=<uuid>&latest=true, /zones, /tags, /jobs/tasks/status, /health. " +
			"List paths take page and size. Only GET is sent. The text of a backup is not part of these answers: read it with the Show command `show backup <name|address|id>` or as the configuration of a device with the option device. Credentials and connections are not read.",
		"examples": []string{"/health", "/devices", "/devices?vendors=Cisco", "/devices/<uuid>", "/devices/backups?deviceUuids=<uuid>&latest=true", "/zones", "/tags", "/jobs/tasks/status"},
	}, nil
}

// ---- changes ----

var uniRawDeny = []string{"credential", "connection", "password", "enable", "token", "users", "license", "proxy", "push", "backups", "unbind", "bind_"}

func uniRawGuard(method, p string) error {
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change")
	}
	if !strings.HasPrefix(pp, "/api/v3/") && !strings.HasPrefix(pp, "/api/v2/") {
		return errors.New("path: Unimus is changed below /api/v3/")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	for _, g := range segs[2:] {
		lg := strings.ToLower(g)
		for _, d := range uniRawDeny {
			if strings.Contains(lg, d) {
				return fmt.Errorf("path: %q is not changed here (credentials, connections, backups, pushing configuration)", g)
			}
		}
	}
	if len(segs) < 3 {
		return errors.New("path: a resource below /api/v3/")
	}
	if method == http.MethodDelete {
		switch strings.ToLower(segs[2]) {
		case "devices", "zones", "backups", "schedules":
			return errors.New("path: devices, zones, backups and schedules are not deleted here")
		}
	}
	return nil
}

func (u *unimus) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if len(r.Lines) > 0 {
		return RawResult{DryRun: dry}, errors.New("lines: Unimus is changed with method, path and body")
	}
	if err := u.probe(ctx); err != nil {
		return RawResult{DryRun: dry}, err
	}
	if !strings.HasPrefix(r.Path, "/api/") {
		r.Path = u.base + "/" + strings.TrimPrefix(r.Path, "/")
	}
	h := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}}
	return restRaw(ctx, restSpec{
		api: u.api, hdr: h, json: true,
		guard: uniRawGuard,
		alive: func(ctx context.Context) error { _, err := u.get(ctx, "/health"); return err },
	}, r, dry)
}

func (u *unimus) Close(context.Context) { u.api.close() }

// ---- import ----

// uniPlatform picks the driver for a device from what Unimus says its vendor, type and model are.
func uniPlatform(vendor, typ, model string) string {
	all := strings.ToLower(vendor + " " + typ + " " + model)
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.Contains(all, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("cisco"):
		switch {
		case has("nx-os", "nxos", "nexus"):
			return "nxos"
		case has("ios-xe", "ios xe", "iosxe", "catalyst 9", "c9"):
			return "iosxe"
		case has("ios-xr", "ios xr", "asa", "wlc", "meraki", "sg ", "small business"):
			return ""
		case has("ios"):
			return "ios"
		}
	case has("arista"):
		return "eos"
	case has("aruba", "hpe", "hewlett"):
		if has("cx", "aos-cx", "aoscx") {
			return "aoscx"
		}
	case has("fortinet", "fortigate", "fortios"):
		return "fortios"
	case has("palo alto", "pan-os", "panos"):
		return "panos"
	case has("juniper", "junos"):
		return "junos"
	case has("f5", "big-ip", "bigip"):
		return "bigip"
	case has("infoblox"):
		return "nios"
	}
	return ""
}

// uniImportRead lists the devices Unimus backs up.
func uniImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newUnimus(d, c)
	if err != nil {
		return nil, err
	}
	u := drv.(*unimus)
	defer u.Close(context.WithoutCancel(ctx))
	rs, err := u.list(ctx, "/devices", "devices", 0)
	if err != nil {
		return nil, err
	}
	return uniImportRows(rs), nil
}

func uniImportRows(rs []map[string]any) []impRow {
	var out []impRow
	for _, r := range rs {
		addr := str(r["address"])
		vendor := firstOf(str(r["deviceVendor"]), str(r["vendor"]))
		typ := firstOf(str(r["deviceType"]), str(r["type"]))
		model := firstOf(str(r["deviceModel"]), str(r["model"]))
		desc := strings.TrimSpace(str(r["description"]))
		short := ""
		if desc != "" && !strings.ContainsAny(desc, " \t") && len(desc) <= 64 {
			short = desc
		}
		tags := append(impTag("vendor", vendor), impTag("type", typ)...)
		if v, ok := r["managed"].(bool); ok && !v {
			tags = append(tags, "unmanaged")
		}
		out = append(out, impRow{ID: uniID(r), Host: addr, Short: firstOf(short, addr),
			What: strings.TrimSpace(strings.Join([]string{vendor, typ, model}, " ")), Platform: uniPlatform(vendor, typ, model), Tags: tags})
	}
	return out
}
