package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RcodeZero (https://www.rcodezero.at, the anycast DNS service of nic.at), through its REST API: https://my.rcodezero.at/api/v1/...
// (the address defaults to my.rcodezero.at; option api_version is "v1" unless it says "v2", option prefix replaces /api/<version>
// as a whole).  The credential is an API token (the credential's Token, made in the portal under Settings ▸ API Tokens; sent as a
// Bearer token), never put in a URL.
//
// RcodeZero is a service, not a switch: the "device" is the RcodeZero account.
//
//   - Facts: the number of zones.  Interfaces: the zones (type and DNSSEC state).
//   - Show: "show zones", "show zone NAME" (the zone, its rrsets and its query statistics as one answer), "show rrsets zone=NAME
//     [type=] [search=]", "show stats [zone=NAME] [kind=queries]", "show messages", "show secondaries" and "show settings".
//   - APIGet: any read below /zones, /stats, /settings, /messages and /reports.  Transfer (TSIG) keys, API tokens and users are
//     refused.
//   - RawChange (rw keys only): POST, PUT, PATCH and DELETE below /zones and /settings: a PATCH of /zones/NAME/rrsets with a list
//     of {"name", "type", "changetype": "add|update|delete", "ttl", "records": [{"content"}]} changes records.  Deleting a whole
//     zone is refused (it takes every record with it).  Transfer keys, tokens and users are refused.
//
// A list is asked with page_size=-1 (everything) and, if the answer says there are more pages, the next ones are read.  What an
// answer holds that is a secret (a TSIG secret, a token) is hidden (Redact).  The field names are RcodeZero's.

func init() { Register("rcode0", newRcode0) }

type rcode0 struct {
	d    Device
	api  *apiClient
	root string // "/api/v1"
}

var (
	rcReadable = map[string]bool{"zones": true, "stats": true, "settings": true, "messages": true, "reports": true}
	rcWritable = map[string]bool{"zones": true, "settings": true}
	rcDenied   = []string{"tsig", "tsigin", "tsigout", "tsigkeys", "tokens", "token", "apitokens", "users", "user", "passwords", "password", "login", "logout"}
	rcVerRE    = regexp.MustCompile(`^v[12]$`)
)

const rcMaxPages = 50

func newRcode0(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: RcodeZero needs an API token (Settings ▸ API Tokens)", d.Name)
	}
	if strings.ContainsAny(c.Token, "\r\n\x00 ") {
		return nil, fmt.Errorf("device %s: the API token holds a space or a control character", d.Name)
	}
	if d.Address == "" {
		d.Address = "my.rcodezero.at"
	}
	root := "/api/v1"
	if v := strings.TrimSpace(d.Options["api_version"]); v != "" {
		if !rcVerRE.MatchString(v) {
			return nil, fmt.Errorf("device %s: option api_version is v1 or v2", d.Name)
		}
		root = "/api/" + v
	}
	if strings.TrimSpace(d.Options["prefix"]) != "" {
		p, err := dnsPrefix(d, root)
		if err != nil {
			return nil, fmt.Errorf("device %s: %v", d.Name, err)
		}
		root = p
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	api.hdr.Set("User-Agent", "netdir")
	return &rcode0{d: d, api: api, root: root}, nil
}

func (x *rcode0) get(ctx context.Context, path string) (any, error) {
	v, _, err := dnsRead(ctx, x.api, x.root+path)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Code == http.StatusUnauthorized {
			return nil, fmt.Errorf("RcodeZero refused the API token (wrong, revoked, or for another account): %w", err)
		}
	}
	return v, err
}

// rcRows are the rows of an answer: {"data": [...]} for a list, or the list itself.
func rcRows(v any) []map[string]any {
	if m, ok := v.(map[string]any); ok {
		if d, ok := m["data"]; ok {
			return rows(d)
		}
	}
	return rows(v)
}

// all reads a list: page_size=-1 asks for everything; when the answer still says there are more pages, they are read too.
func (x *rcode0) all(ctx context.Context, path string) ([]map[string]any, error) {
	var out []map[string]any
	for page := 1; page <= rcMaxPages; page++ {
		q := url.Values{"page_size": {"-1"}}
		if page > 1 {
			q.Set("page", strconv.Itoa(page))
		}
		v, err := x.get(ctx, path+"?"+q.Encode())
		if err != nil {
			return out, err
		}
		out = append(out, rcRows(v)...)
		m, _ := v.(map[string]any)
		if m == nil || num(m["last_page"]) <= int64(page) {
			break
		}
	}
	return out, nil
}

func (x *rcode0) zones(ctx context.Context) ([]map[string]any, error) { return x.all(ctx, "/zones") }

func (x *rcode0) Facts(ctx context.Context) (Facts, error) {
	zs, err := x.zones(ctx)
	if err != nil {
		return Facts{}, err
	}
	return Facts{Hostname: x.d.Address, Vendor: "RcodeZero", Model: fmt.Sprintf("Anycast DNS: %d zones", len(zs))}, nil
}

func (x *rcode0) Interfaces(ctx context.Context) ([]Interface, error) {
	zs, err := x.zones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(zs))
	for _, z := range zs {
		var d []string
		if t := str(z["type"]); t != "" {
			d = append(d, strings.ToLower(t))
		}
		if s := str(z["dnssec_status"]); s != "" {
			d = append(d, "DNSSEC "+strings.ToLower(s))
		}
		out = append(out, Interface{Name: firstOf(str(z["domain"]), str(z["id"])), Description: strings.Join(d, ", ")})
	}
	return out, nil
}

func (x *rcode0) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (x *rcode0) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (x *rcode0) Close(context.Context)                         { x.api.close() }

const rcUsage = "show zones [search=TEXT] [limit=N] | zone NAME | rrsets zone=NAME [type=TYPE] [search=TEXT] [limit=N] | stats [zone=NAME] [kind=queries] | messages | secondaries | settings"

func (x *rcode0) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(rcUsage)
	}
	switch w := strings.ToLower(f[1]); w {
	case "messages", "secondaries", "settings":
		if len(f) != 2 {
			return "", errors.New(rcUsage)
		}
		p := map[string]string{"messages": "/messages", "secondaries": "/settings/secondaries", "settings": "/settings"}[w]
		v, err := x.get(ctx, p)
		if err != nil {
			return "", err
		}
		return dnsText(v), nil
	case "zones":
		a, err := centArgs(f[2:], "search", "limit")
		if err != nil {
			return "", err
		}
		zs, err := x.zones(ctx)
		if err != nil && len(zs) == 0 {
			return "", err
		}
		var out []map[string]any
		for _, z := range zs {
			if s := a["search"]; s != "" && !centContains(str(z["domain"]), s) {
				continue
			}
			out = append(out, z)
		}
		return nsList(out, len(zs), centLimit(a), ""), nil
	case "zone":
		if len(f) != 3 || !dnsZoneRE.MatchString(f[2]) {
			return "", errors.New("show zone NAME: the zone's name (show zones lists them)")
		}
		z, err := x.get(ctx, "/zones/"+f[2])
		if err != nil {
			return "", err
		}
		out := map[string]any{"zone": z}
		errs := map[string]string{}
		if rs, err := x.all(ctx, "/zones/"+f[2]+"/rrsets"); err != nil && len(rs) == 0 {
			errs["rrsets"] = RedactText(err.Error())
		} else {
			shown := make([]map[string]any, 0, len(rs))
			for _, r := range rs {
				shown = append(shown, dnsRecordRow(r))
			}
			if len(shown) > 500 {
				shown = shown[:500]
			}
			out["rrsets_total"], out["rrsets"] = len(rs), shown
		}
		if s, err := x.get(ctx, "/zones/"+f[2]+"/stats/queries"); err != nil {
			errs["stats"] = RedactText(err.Error())
		} else {
			out["stats"] = s
		}
		if len(errs) > 0 {
			out["errors"] = errs
		}
		return dnsText(out), nil
	case "rrsets":
		a, err := centArgs(f[2:], "zone", "type", "search", "limit")
		if err != nil {
			return "", err
		}
		if !dnsZoneRE.MatchString(a["zone"]) {
			return "", errors.New("show rrsets zone=NAME: the zone's name")
		}
		if t := a["type"]; t != "" && !dnsTypeRE.MatchString(t) {
			return "", errors.New("type: a record type such as A, AAAA, CNAME, MX, TXT")
		}
		rs, err := x.all(ctx, "/zones/"+a["zone"]+"/rrsets")
		if err != nil && len(rs) == 0 {
			return "", err
		}
		var out []map[string]any
		for _, r := range rs {
			if t := a["type"]; t != "" && !strings.EqualFold(str(r["type"]), t) {
				continue
			}
			if s := a["search"]; s != "" && !centContains(str(r["name"])+" "+fmt.Sprint(r["records"]), s) {
				continue
			}
			out = append(out, dnsRecordRow(r))
		}
		return nsList(out, len(rs), centLimit(a), ""), nil
	case "stats":
		a, err := centArgs(f[2:], "zone", "kind")
		if err != nil {
			return "", err
		}
		kind := firstOf(a["kind"], "queries")
		if !dnsKindRE.MatchString(kind) {
			return "", errors.New("kind: queries, magnitude, qnames, nxdomains (a zone) or queries, countries, topzones (the account)")
		}
		p := "/stats/" + kind
		if z := a["zone"]; z != "" {
			if !dnsZoneRE.MatchString(z) {
				return "", errors.New("zone: the zone's name")
			}
			p = "/zones/" + z + "/stats/" + kind
		}
		v, err := x.get(ctx, p)
		if err != nil {
			return "", err
		}
		return dnsText(v), nil
	}
	return "", errors.New(rcUsage)
}

// ---- reading through the API ----

func (x *rcode0) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	pp = dnsRel(x.root, pp)
	if !dnsPathRE.MatchString(pp) || strings.Contains(pp, "..") || strings.Contains(pp, "//") {
		return nil, false, errors.New("path: /zones, /zones/example.com/rrsets, /zones/example.com/stats/queries, /messages (see device_api_catalog)")
	}
	if !rcReadable[dnsSegs(pp)[0]] {
		return nil, false, errors.New("path: RcodeZero is read below /zones, /stats, /settings, /messages and /reports")
	}
	if hasSeg(pp, rcDenied...) {
		return nil, false, errors.New("path: transfer (TSIG) keys, API tokens and users are not read here")
	}
	enc, err := centQuery(qs)
	if err != nil {
		return nil, false, err
	}
	if enc != "" {
		pp += "?" + enc
	}
	v, text, err := dnsRead(ctx, x.api, x.root+pp)
	if err != nil {
		return nil, false, err
	}
	if text {
		return v, true, nil
	}
	return obsScrub(Redact(dnsHide(v))), false, nil
}

func (x *rcode0) APICatalog(context.Context) (any, error) {
	ex := []string{"/zones", "/zones/example.com", "/zones/example.com/rrsets", "/zones/example.com/stats/queries", "/zones/example.com/stats/magnitude",
		"/zones/example.com/stats/qnames", "/zones/example.com/stats/nxdomains", "/stats/queries", "/stats/countries", "/stats/topzones", "/settings",
		"/settings/secondaries", "/messages", "/reports/zones"}
	sort.Strings(ex)
	return map[string]any{
		"how": "Paths below /zones, /stats, /settings, /messages and /reports (/api/v1 is added; add ?page_size=-1 for a whole list). Transfer (TSIG) keys, " +
			"API tokens and users are refused. Changes are device_change_raw: PATCH /zones/NAME/rrsets with a list of rrsets (changetype add, update or delete), " +
			"POST /zones to add a zone, POST /zones/NAME/retrieve, sign or unsign; deleting a whole zone is refused.",
		"examples": ex,
		"tip":      "show zone NAME (device_show) answers a zone with its rrsets and query statistics in one call; the API is described at https://my.rcodezero.at/openapi/.",
	}, nil
}

// ---- changes ----

func rcGuard(method, p string) error {
	pp, _, _ := strings.Cut(p, "?")
	if !dnsPathRE.MatchString(pp) {
		return errors.New("path: /zones/example.com/rrsets")
	}
	segs := dnsSegs(pp)
	if !rcWritable[segs[0]] {
		return errors.New("path: RcodeZero is changed below /zones and /settings")
	}
	if hasSeg(pp, rcDenied...) {
		return errors.New("path: transfer (TSIG) keys, API tokens and users are not changed here")
	}
	if method == http.MethodDelete && segs[0] == "zones" && len(segs) <= 2 {
		return errors.New("path: a whole zone is not deleted here, it takes every record with it: delete its rrsets with a PATCH (changetype delete), or use the portal")
	}
	return nil
}

// RawChange: Method POST, PUT, PATCH or DELETE, Path below /zones or /settings, Body JSON.
func (x *rcode0) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	r.Path = dnsRel(x.root, r.Path)
	res, err := restRaw(ctx, restSpec{
		api: x.api, hdr: jsonHdr(), auth: http.Header{"Accept": {"application/json"}}, json: true,
		wire:  func(p string) string { return x.root + p },
		guard: rcGuard,
		alive: func(ctx context.Context) error {
			_, err := x.get(ctx, "/zones?page_size=1")
			return err
		},
	}, r, dry)
	if err == nil && res.Applied && r.Method != http.MethodPost && res.Before != "" {
		res.Note = strings.TrimSpace(res.Note + " The copy in 'before' shows what was there; it is not put back by itself.")
	}
	return res, err
}
