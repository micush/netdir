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
	"sort"
	"strconv"
	"strings"
)

// Device42 (https://api.device42.com), the IT asset and network inventory (CMDB / IPAM), through its REST API:
// https://HOST/api/1.0/... and /api/2.0/... (port 443).  The credential is a user name and a password (HTTP basic authentication
// against a Device42 user; one that may only read is enough).  Neither ever goes into a URL.  Reads are GETs; a change is RawChange (below).
//
// Device42 is an inventory, not a switch: the "device" is the Device42 appliance.
//
//   - Facts: how many devices it holds.  Interfaces: the devices it holds (name, addresses).
//   - Show: "show platform", "show devices", "show device NAME|ID" (everything Device42 knows about ONE device: its record, and
//     its IP addresses, MAC addresses and switch ports), "show ips", "show subnets", "show vlans", "show racks", "show buildings",
//     "show macs", "show hardwares", "show vendors", "show customers".
//   - APIGet: any read below /api/1.0 and /api/2.0 (the version may be left out: 1.0 is the default).  Passwords, users, keys,
//     tokens and authentication are refused.
//   - RawChange (rw keys only, as everywhere: a read-only MCP caller has no tool for it): POST, PUT, PATCH or DELETE below
//     /api/1.0 and /api/2.0.  The body is form fields (name=core1&type=physical, Device42's usual form) or JSON.  POST to
//     /api/1.0/device/, /ips/, /subnets/, /vlans/ ... creates or updates by name, which is the way to change a record: PUT, PATCH
//     and DELETE first read the path (to keep a copy as "before"), and a path that cannot be read is not changed.  Passwords,
//     users, keys, tokens and authentication are refused.  Import: the devices Device42 holds are added to the inventory (import.go).
//
// The answers of Device42 differ between releases ({"Devices": [...]} or {"devices": [...], "total_count": N}); the driver finds
// the rows of an answer whatever its wrapper and keeps whole rows, so a field it does not know is still shown.  Secrets found by
// name in an answer are hidden (Redact).  Written against the documentation only; not run against a real Device42.

func init() { Register("device42", newDevice42) }

type device42 struct {
	d   Device
	api *apiClient
}

var (
	d42PathRE = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~%@:+-]+)*/?$`)
	d42KeyRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,60}$`)
	d42RefRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
	d42WordRE = regexp.MustCompile(`^[A-Za-z0-9._:@/*,-]{1,128}$`)
	d42VerRE  = regexp.MustCompile(`^/api/(1\.0|2\.0)(/|$)`)
	// the parts of a path that are who may sign in, with what, and the secrets Device42 keeps: never read here
	d42Denied = []string{"passwords", "password", "users", "user", "usersdata", "vault", "secrets", "secret", "keys", "apikeys", "api_keys",
		"tokens", "token", "auth", "authentication", "login", "logout", "credentials", "snmp", "certificates", "ssh_keys"}
)

const (
	d42Page     = 100
	d42MaxPages = 50
)

func newDevice42(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Device42 needs a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	api.hdr.Set("User-Agent", "netdir")
	return &device42{d: d, api: api}, nil
}

func (x *device42) get(ctx context.Context, path string) (any, error) {
	b, err := x.api.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON (is this the Device42 API?): %v", path, err)
	}
	return v, nil
}

func d42Total(v any) int {
	if m, ok := v.(map[string]any); ok {
		if n := num(m["total_count"]); n > 0 {
			return int(n)
		}
		for _, x := range m {
			if s, ok := x.(map[string]any); ok { // the total is inside the collection's own object in some releases
				if n := num(s["total_count"]); n > 0 {
					return int(n)
				}
			}
		}
	}
	return 0
}

// all reads a list page by page (limit and offset) and says how many rows Device42 holds.
func (x *device42) all(ctx context.Context, path string, q url.Values, maxPages int) ([]map[string]any, int, error) {
	var out []map[string]any
	total := 0
	for page := 0; page < maxPages; page++ {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("limit", strconv.Itoa(d42Page))
		qq.Set("offset", strconv.Itoa(page*d42Page))
		v, err := x.get(ctx, path+"?"+qq.Encode())
		if err != nil {
			return out, total, err
		}
		got := obsRows(v, "")
		if t := d42Total(v); t > 0 {
			total = t
		}
		out = append(out, got...)
		if len(got) < d42Page || (total > 0 && len(out) >= total) {
			break
		}
	}
	if total < len(out) {
		total = len(out)
	}
	return out, total, nil
}

// devices reads the devices with their details; a release without /devices/all/ answers 404, and the plain list is used.
func (x *device42) devices(ctx context.Context, q url.Values, maxPages int) ([]map[string]any, int, error) {
	rs, total, err := x.all(ctx, "/api/1.0/devices/all/", q, maxPages)
	var se *statusError
	if err != nil && len(rs) == 0 && errors.As(err, &se) && se.Code == http.StatusNotFound {
		return x.all(ctx, "/api/1.0/devices/", q, maxPages)
	}
	return rs, total, err
}

// d42IPs are the addresses a device row holds (ip_addresses as a list of {"ip": ...}, or of texts).
func d42IPs(r map[string]any) []string {
	var out []string
	for _, k := range []string{"ip_addresses", "ips", "ip"} {
		switch t := r[k].(type) {
		case []any:
			for _, e := range t {
				switch y := e.(type) {
				case map[string]any:
					if ip := firstOf(str(y["ip"]), str(y["ip_address"])); ip != "" {
						out = append(out, ip)
					}
				case string:
					out = append(out, y)
				}
			}
		case string:
			if t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func (x *device42) Facts(ctx context.Context) (Facts, error) {
	v, err := x.get(ctx, "/api/1.0/devices/?limit=1&offset=0")
	if err != nil {
		return Facts{}, err
	}
	total := d42Total(v)
	if total == 0 {
		total = len(obsRows(v, ""))
	}
	return Facts{Hostname: x.d.Address, Vendor: "Device42", Model: fmt.Sprintf("Inventory: %d devices", total)}, nil
}

func (x *device42) Interfaces(ctx context.Context) ([]Interface, error) {
	rs, _, err := x.devices(ctx, nil, d42MaxPages)
	if err != nil && len(rs) == 0 {
		return nil, err
	}
	out := make([]Interface, 0, len(rs))
	for _, r := range rs {
		i := Interface{Name: firstOf(str(r["name"]), str(r["device_id"])), Addresses: d42IPs(r),
			Description: strings.TrimSpace(strings.Join([]string{str(r["type"]), str(r["os"]), str(r["hardware"])}, " "))}
		if b, ok := r["in_service"].(bool); ok {
			i.AdminUp = boolp(b)
		} else if s := strings.ToLower(str(r["in_service"])); s == "yes" || s == "no" {
			i.AdminUp = boolp(s == "yes")
		}
		out = append(out, i)
	}
	return out, nil
}

func (x *device42) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (x *device42) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (x *device42) Close(context.Context)                         { x.api.close() }

// RawChange: see the header.  A rw key only: the gate is the same as for every platform.
func (x *device42) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if !strings.HasPrefix(r.Path, "/api/") {
		r.Path = "/api/1.0/" + strings.TrimPrefix(r.Path, "/")
	}
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}
	if t := strings.TrimSpace(r.Body); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		if !json.Valid([]byte(t)) {
			return RawResult{DryRun: dry}, errors.New("body: not valid JSON")
		}
		h.Set("Content-Type", "application/json")
	} else if t != "" {
		if _, err := url.ParseQuery(t); err != nil {
			return RawResult{DryRun: dry}, errors.New("body: form fields (name=core1&type=physical) or JSON")
		}
	}
	return restRaw(ctx, restSpec{
		api: x.api, hdr: h, auth: http.Header{"Accept": {"application/json"}},
		guard: func(_, p string) error {
			pp, _, _ := strings.Cut(p, "?")
			if !d42VerRE.MatchString(pp) || !d42PathRE.MatchString(pp) {
				return errors.New("path: Device42 is changed below /api/1.0/ and /api/2.0/")
			}
			if hasSeg(pp, d42Denied...) {
				return errors.New("path: passwords, users, keys, tokens and authentication are not changed here")
			}
			return nil
		},
		alive: func(ctx context.Context) error {
			_, err := x.get(ctx, "/api/1.0/devices/?limit=1&offset=0")
			return err
		},
	}, r, dry)
}

const d42Usage = "show platform | devices [search=TEXT] [os=NAME] [type=NAME] [limit=N] | device NAME|ID | ips|subnets|vlans|racks|buildings|macs|hardwares|vendors|customers [search=TEXT] [limit=N]"

// d42Lists are the plain lists "show" reads: the word, the path below /api/1.0 and the keys searched by "search=".
var d42Lists = map[string]string{"ips": "/api/1.0/ips/", "subnets": "/api/1.0/subnets/", "vlans": "/api/1.0/vlans/", "racks": "/api/1.0/racks/",
	"buildings": "/api/1.0/buildings/", "macs": "/api/1.0/macs/", "hardwares": "/api/1.0/hardwares/", "vendors": "/api/1.0/vendors/", "customers": "/api/1.0/customers/"}

func d42Args(words []string, allowed ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, w := range words {
		k, v, ok := strings.Cut(w, "=")
		k = strings.ToLower(k)
		if !ok || !d42WordRE.MatchString(v) {
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

// d42Match says whether any text value of a row holds the word.
func d42Match(r map[string]any, word string) bool {
	b, _ := json.Marshal(r)
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(word))
}

func d42List(rs []map[string]any, total, read, limit int, search string) string {
	var out []map[string]any
	for _, r := range rs {
		if search == "" || d42Match(r, search) {
			out = append(out, r)
		}
	}
	shown := out
	if len(shown) > limit {
		shown = shown[:limit]
	}
	res := map[string]any{"matching": len(out), "shown": len(shown), "result": shown}
	if total > read {
		res["note"] = fmt.Sprintf("Device42 holds %d rows; the first %d were read", total, read)
	}
	return obsText(res)
}

func d42Limit(a map[string]string) int {
	if n, err := strconv.Atoi(a["limit"]); err == nil && n > 0 {
		return n
	}
	return 100
}

func (x *device42) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(d42Usage)
	}
	w := strings.ToLower(f[1])
	switch {
	case w == "platform":
		v, err := x.get(ctx, "/api/1.0/version/")
		if err != nil {
			return "", err
		}
		return obsText(v), nil
	case w == "devices":
		a, err := d42Args(f[2:], "search", "os", "type", "limit")
		if err != nil {
			return "", err
		}
		q := url.Values{}
		if v := a["os"]; v != "" {
			q.Set("os_name", v)
		}
		if v := a["type"]; v != "" {
			q.Set("type", v)
		}
		rs, total, err := x.devices(ctx, q, d42MaxPages)
		if err != nil && len(rs) == 0 {
			return "", err
		}
		return d42List(rs, total, len(rs), d42Limit(a), a["search"]), nil
	case w == "device":
		if len(f) != 3 || !d42RefRE.MatchString(f[2]) {
			return "", errors.New("show device NAME|ID: the device's name or its Device42 ID (show devices lists them)")
		}
		all, err := x.deviceAll(ctx, f[2])
		if err != nil {
			return "", err
		}
		return obsText(all), nil
	case d42Lists[w] != "":
		a, err := d42Args(f[2:], "search", "limit")
		if err != nil {
			return "", err
		}
		rs, total, err := x.all(ctx, d42Lists[w], nil, d42MaxPages)
		if err != nil && len(rs) == 0 {
			return "", err
		}
		return d42List(rs, total, len(rs), d42Limit(a), a["search"]), nil
	}
	return "", errors.New(d42Usage)
}

// deviceAll answers everything Device42 knows about one device.  A part that cannot be read (the user may not see it) is named
// under "errors"; the rest is still answered.
func (x *device42) deviceAll(ctx context.Context, ref string) (map[string]any, error) {
	path := "/api/1.0/devices/name/" + url.PathEscape(ref) + "/"
	if centNumRE.MatchString(ref) {
		path = "/api/1.0/devices/id/" + ref + "/"
	}
	v, err := x.get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("device %s: %w", ref, err)
	}
	out := map[string]any{"device": v}
	errs := map[string]string{}
	id := ""
	if m, ok := v.(map[string]any); ok {
		id = str(m["device_id"])
	}
	if id == "" {
		if r := obsRows(v, ""); len(r) > 0 {
			id = str(r[0]["device_id"])
		}
	}
	if id != "" {
		q := url.Values{"device_id": {id}}
		for _, p := range []struct{ key, path string }{{"ips", "/api/1.0/ips/"}, {"macs", "/api/1.0/macs/"}, {"switchports", "/api/1.0/switchports/"}} {
			rs, total, err := x.all(ctx, p.path, q, 10)
			if err != nil && len(rs) == 0 {
				errs[p.key] = RedactText(err.Error())
				continue
			}
			out[p.key], out[p.key+"_total"] = rs, total
		}
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	return out, nil
}

// ---- reading through the API ----

func (x *device42) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	if !strings.HasPrefix(pp, "/api/") {
		pp = "/api/1.0/" + strings.TrimPrefix(pp, "/")
	}
	if !d42VerRE.MatchString(pp) || !d42PathRE.MatchString(pp) || strings.Contains(pp, "..") || strings.Contains(pp, "//") {
		return nil, false, errors.New("path: /api/1.0/devices/, /api/1.0/devices/name/core1/, /api/2.0/subnets/ (see device_api_catalog)")
	}
	if hasSeg(pp, d42Denied...) {
		return nil, false, errors.New("path: passwords, users, keys, tokens and authentication are not read here")
	}
	if qs != "" {
		vals, err := url.ParseQuery(qs)
		if err != nil {
			return nil, false, errors.New("path: the query is not valid")
		}
		for k, vs := range vals {
			if !d42KeyRE.MatchString(k) || strings.EqualFold(k, "password") {
				return nil, false, fmt.Errorf("path: %q is not a parameter name", k)
			}
			for _, v := range vs {
				if len(v) > 1000 || junCtlRE.MatchString(v) {
					return nil, false, fmt.Errorf("path: the value of %q is too long, or holds a control character", k)
				}
			}
		}
		pp += "?" + vals.Encode()
	}
	v, err := x.get(ctx, pp)
	if err != nil {
		return nil, false, err
	}
	return obsScrub(Redact(v)), false, nil
}

func (x *device42) APICatalog(context.Context) (any, error) {
	ex := []string{"/api/1.0/devices/", "/api/1.0/devices/all/?limit=20", "/api/1.0/devices/name/core1/", "/api/1.0/devices/id/12/", "/api/2.0/devices/",
		"/api/1.0/ips/", "/api/1.0/subnets/", "/api/1.0/vlans/", "/api/1.0/racks/", "/api/1.0/buildings/", "/api/1.0/macs/", "/api/1.0/switchports/",
		"/api/1.0/hardwares/", "/api/1.0/vendors/", "/api/1.0/customers/"}
	sort.Strings(ex)
	return map[string]any{
		"how": "GET paths below /api/1.0 and /api/2.0 (1.0 when the version is left out). Lists take limit and offset and filters by name (os_name, type, device_id, ...). " +
			"Passwords, users, keys, tokens and authentication are refused. Changes are device_change_raw (POST creates or updates, e.g. POST /api/1.0/device/ with name=core1&serial_no=S1).",
		"examples": ex,
		"tip":      "show device NAME (device_show) answers everything about one device in one call; the API is described at https://api.device42.com.",
	}, nil
}

// ---- import ----

// d42Platform picks a driver from what Device42 says a device is: its operating system, its manufacturer and its hardware model.
func d42Platform(os, vendor, hardware string) string {
	w := strings.ToLower(strings.Join([]string{os, vendor, hardware}, " "))
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.Contains(w, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("nx-os", "nxos", "nexus"):
		return "nxos"
	case has("ios xe", "ios-xe", "iosxe", "catalyst 9"):
		return "iosxe"
	case has("cisco") && has("ios"):
		return "ios"
	case has("juniper", "junos"):
		return "junos"
	case has("fortinet", "fortigate", "fortios"):
		return "fortios"
	case has("palo alto", "paloalto", "pan-os", "panos"):
		return "panos"
	case has("arista"):
		return "eos"
	case has("f5", "big-ip", "bigip"):
		return "bigip"
	case has("aos-cx", "aoscx", "arubaos-cx"):
		return "aoscx"
	case has("infoblox"):
		return "nios"
	case has("proxmox"):
		return "proxmox"
	case has("vmware vcenter", "vcenter"):
		return "vcenter"
	}
	return ""
}

func d42ImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newDevice42(d, c)
	if err != nil {
		return nil, err
	}
	x := drv.(*device42)
	defer x.Close(context.WithoutCancel(ctx))
	rs, _, err := x.devices(ctx, nil, d42MaxPages)
	if err != nil && len(rs) == 0 {
		return nil, err
	}
	var out []impRow
	for _, r := range rs {
		ips := d42IPs(r)
		host, alt := str(r["name"]), ""
		if len(ips) > 0 { // a name in an inventory is not always one the network resolves: reach it by its address
			host, alt = ips[0], str(r["name"])
		}
		what := strings.TrimSpace(strings.Join([]string{str(r["manufacturer"]), str(r["hardware"]), str(r["os"])}, " "))
		var tags []string
		tags = append(tags, impTag("site", firstOf(str(r["building"]), str(r["room"])))...)
		tags = append(tags, impTag("type", str(r["type"]))...)
		out = append(out, impRow{ID: str(r["device_id"]), Host: host, Alt: alt, Short: str(r["name"]), What: what,
			Platform: d42Platform(str(r["os"]), str(r["manufacturer"]), str(r["hardware"])), Tags: tags})
	}
	return out, nil
}
