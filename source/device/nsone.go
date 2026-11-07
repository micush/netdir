package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// NS1 (IBM NS1 Connect, https://developer.ibm.com/apis/catalog/ns1--ns1-api/), the hosted DNS and traffic steering service, through
// its REST API: https://api.nsone.net/v1/... (the address defaults to api.nsone.net; a private NS1 deployment gives its own, and the
// option prefix the path, "/v1" unless it says otherwise).  The credential is an API key (the credential's Token, made in the portal
// under Account Settings ▸ API Keys; a key with only the read permissions reads and nothing more), sent in the header X-NSONE-Key.
// The key is never put in a URL.
//
// NS1 is a service, not a switch: the "device" is the NS1 account.
//
//   - Facts: the number of zones.  Interfaces: the zones.
//   - Show: "show zones", "show zone NAME" (the zone and its records as one answer), "show records zone=NAME [type=] [search=]",
//     "show record ZONE DOMAIN TYPE" (the answers, filter chain and metadata of one record), "show monitors", "show datasources",
//     "show feeds source=ID", "show networks", "show qps" and "show usage".
//   - APIGet: any read below /zones, /data, /monitoring, /networks, /stats, /views, /search, /export and /account.  API keys, users,
//     teams, account settings, billing, TSIG keys and notification lists (they hold webhook addresses) are refused.
//   - RawChange (rw keys only): PUT (NS1's create), POST (its update) and DELETE below /zones, /data, /monitoring, /networks and
//     /views.  Deleting a whole zone is refused (delete its records, or use the portal): it takes every record with it.  A POST
//     (an update) is read first, so the answer holds a "before" copy; it is not put back by itself.
//
// A zone's records come in pages of 2500; "show zone" reads the first page and says when that page was full.  What an answer holds
// that is a secret (a data source's key, a monitor's authentication, a TSIG secret) is hidden (Redact).  The field names are NS1's.

func init() { Register("nsone", newNsone) }

type nsone struct {
	d      Device
	api    *apiClient
	prefix string // "/v1"
}

const nsPage = 2500 // records NS1 sends in one page of a zone

var (
	// the first segments of the paths that are read, and those that are changed
	nsReadable = map[string]bool{"zones": true, "data": true, "monitoring": true, "networks": true, "stats": true, "views": true, "search": true, "export": true, "account": true}
	nsWritable = map[string]bool{"zones": true, "data": true, "monitoring": true, "networks": true, "views": true}
	// parts of a path that are who may use the account, its keys and where it sends notices: never read or written here
	nsDenied = []string{"apikeys", "users", "teams", "settings", "otps", "subusers", "billing", "invoices", "payment", "tsig", "lists", "notifications"}
)

func newNsone(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: NS1 needs an API key as the token (Account Settings ▸ API Keys)", d.Name)
	}
	if strings.ContainsAny(c.Token, "\r\n\x00 ") {
		return nil, fmt.Errorf("device %s: the API key holds a space or a control character", d.Name)
	}
	if d.Address == "" {
		d.Address = "api.nsone.net"
	}
	pf, err := dnsPrefix(d, "/v1")
	if err != nil {
		return nil, fmt.Errorf("device %s: %v", d.Name, err)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("X-NSONE-Key", c.Token)
	api.hdr.Set("User-Agent", "netdir")
	return &nsone{d: d, api: api, prefix: pf}, nil
}

func (n *nsone) get(ctx context.Context, path string) (any, error) {
	v, _, err := dnsRead(ctx, n.api, n.prefix+path)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
			return nil, fmt.Errorf("NS1 refused the API key for %s (wrong, revoked, or without the permission): %w", path, err)
		}
	}
	return v, err
}

func (n *nsone) zones(ctx context.Context) ([]map[string]any, error) {
	v, err := n.get(ctx, "/zones")
	if err != nil {
		return nil, err
	}
	return rows(v), nil
}

func (n *nsone) Facts(ctx context.Context) (Facts, error) {
	zs, err := n.zones(ctx)
	if err != nil {
		return Facts{}, err
	}
	return Facts{Hostname: n.d.Address, Vendor: "NS1", Model: fmt.Sprintf("Managed DNS: %d zones", len(zs))}, nil
}

func (n *nsone) Interfaces(ctx context.Context) ([]Interface, error) {
	zs, err := n.zones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(zs))
	for _, z := range zs {
		i := Interface{Name: firstOf(str(z["zone"]), str(z["id"]))}
		var d []string
		if b, ok := z["dnssec"].(bool); ok && b {
			d = append(d, "DNSSEC")
		}
		if s, ok := z["secondary"].(map[string]any); ok {
			if b, _ := s["enabled"].(bool); b {
				d = append(d, "secondary")
			}
		}
		if p, ok := z["primary"].(map[string]any); ok {
			if b, _ := p["enabled"].(bool); b {
				d = append(d, "primary")
			}
		}
		if n := num(z["records_count"]); n > 0 {
			d = append(d, fmt.Sprintf("%d records", n))
		}
		i.Description = strings.Join(d, ", ")
		out = append(out, i)
	}
	return out, nil
}

func (n *nsone) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (n *nsone) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (n *nsone) Close(context.Context)                         { n.api.close() }

const nsUsage = "show zones [search=TEXT] [limit=N] | zone NAME [limit=N] | records zone=NAME [type=TYPE] [search=TEXT] [limit=N] | record ZONE DOMAIN TYPE | monitors | datasources | feeds source=ID | networks | qps | usage"

var nsSimple = map[string]string{"monitors": "/monitoring/jobs", "datasources": "/data/sources", "networks": "/networks", "qps": "/stats/qps", "usage": "/stats/usage"}

func nsList(rs []map[string]any, total, limit int, note string) string {
	shown := rs
	if len(shown) > limit {
		shown = shown[:limit]
	}
	res := map[string]any{"total": total, "shown": len(shown), "result": shown}
	if note != "" {
		res["note"] = note
	}
	return dnsText(res)
}

func (n *nsone) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(nsUsage)
	}
	w := strings.ToLower(f[1])
	if p, ok := nsSimple[w]; ok {
		if len(f) != 2 {
			return "", errors.New(nsUsage)
		}
		v, err := n.get(ctx, p)
		if err != nil {
			return "", err
		}
		return dnsText(v), nil
	}
	switch w {
	case "zones":
		a, err := centArgs(f[2:], "search", "limit")
		if err != nil {
			return "", err
		}
		zs, err := n.zones(ctx)
		if err != nil {
			return "", err
		}
		var out []map[string]any
		for _, z := range zs {
			if s := a["search"]; s != "" && !centContains(str(z["zone"]), s) {
				continue
			}
			out = append(out, z)
		}
		return nsList(out, len(zs), centLimit(a), ""), nil
	case "zone":
		if len(f) < 3 || !dnsZoneRE.MatchString(f[2]) {
			return "", errors.New("show zone NAME [limit=N]: the zone's name (show zones lists them)")
		}
		a, err := centArgs(f[3:], "limit")
		if err != nil {
			return "", err
		}
		v, err := n.get(ctx, "/zones/"+f[2])
		if err != nil {
			return "", err
		}
		z, _ := v.(map[string]any)
		if z == nil {
			return "", fmt.Errorf("zone %s: the answer is not a zone", f[2])
		}
		recs := rows(z["records"])
		out := map[string]any{}
		for k, x := range z {
			if k != "records" {
				out[k] = x
			}
		}
		shown := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			shown = append(shown, dnsRecordRow(r))
		}
		lim := 500
		if a["limit"] != "" {
			lim = centLimit(a)
		}
		if len(shown) > lim {
			shown = shown[:lim]
		}
		out["records_total"], out["records_shown"], out["records"] = len(recs), len(shown), shown
		if len(recs) >= nsPage {
			out["note"] = fmt.Sprintf("NS1 sends a zone's records in pages of %d and this is the first: the zone may hold more (show records zone=%s type=A narrows, or read /zones/%s with the API request)", nsPage, f[2], f[2])
		}
		return dnsText(out), nil
	case "records":
		a, err := centArgs(f[2:], "zone", "type", "search", "limit")
		if err != nil {
			return "", err
		}
		if !dnsZoneRE.MatchString(a["zone"]) {
			return "", errors.New("show records zone=NAME: the zone's name")
		}
		if t := a["type"]; t != "" && !dnsTypeRE.MatchString(t) {
			return "", errors.New("type: a record type such as A, AAAA, CNAME, MX, TXT")
		}
		v, err := n.get(ctx, "/zones/"+a["zone"])
		if err != nil {
			return "", err
		}
		z, _ := v.(map[string]any)
		recs := rows(z["records"])
		var out []map[string]any
		for _, r := range recs {
			if t := a["type"]; t != "" && !strings.EqualFold(str(r["type"]), t) {
				continue
			}
			if s := a["search"]; s != "" && !centContains(str(r["domain"])+" "+fmt.Sprint(r["short_answers"]), s) {
				continue
			}
			out = append(out, dnsRecordRow(r))
		}
		note := ""
		if len(recs) >= nsPage {
			note = fmt.Sprintf("only the first page of %d records was read", nsPage)
		}
		return nsList(out, len(recs), centLimit(a), note), nil
	case "record":
		if len(f) != 5 || !dnsZoneRE.MatchString(f[2]) || !dnsNameRE.MatchString(f[3]) || !dnsTypeRE.MatchString(f[4]) {
			return "", errors.New("show record ZONE DOMAIN TYPE: for example show record example.com www.example.com A")
		}
		v, err := n.get(ctx, "/zones/"+f[2]+"/"+f[3]+"/"+strings.ToUpper(f[4]))
		if err != nil {
			return "", err
		}
		return dnsText(v), nil
	case "feeds":
		a, err := centArgs(f[2:], "source")
		if err != nil {
			return "", err
		}
		if !centRefRE.MatchString(a["source"]) {
			return "", errors.New("show feeds source=ID: the data source's ID (show datasources lists them)")
		}
		v, err := n.get(ctx, "/data/feeds/"+a["source"])
		if err != nil {
			return "", err
		}
		return dnsText(v), nil
	}
	return "", errors.New(nsUsage)
}

// ---- reading through the API ----

func (n *nsone) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	pp = dnsRel(n.prefix, pp)
	if !dnsPathRE.MatchString(pp) || strings.Contains(pp, "..") || strings.Contains(pp, "//") {
		return nil, false, errors.New("path: /zones, /zones/example.com, /zones/example.com/www.example.com/A, /monitoring/jobs (see device_api_catalog)")
	}
	if !nsReadable[dnsSegs(pp)[0]] {
		return nil, false, errors.New("path: NS1 is read below /zones, /data, /monitoring, /networks, /stats, /views, /search, /export and /account")
	}
	if hasSeg(pp, nsDenied...) {
		return nil, false, errors.New("path: API keys, users, teams, account settings, billing, TSIG keys and notification lists are not read here")
	}
	enc, err := centQuery(qs)
	if err != nil {
		return nil, false, err
	}
	if enc != "" {
		pp += "?" + enc
	}
	v, text, err := dnsRead(ctx, n.api, n.prefix+pp)
	if err != nil {
		return nil, false, err
	}
	if text {
		return v, true, nil
	}
	return obsScrub(Redact(dnsHide(v))), false, nil
}

func (n *nsone) APICatalog(context.Context) (any, error) {
	ex := []string{"/zones", "/zones/example.com", "/zones/example.com/www.example.com/A", "/zones/example.com/versions", "/zones/example.com/dnssec",
		"/data/sources", "/data/feeds/SOURCEID", "/monitoring/jobs", "/monitoring/jobs/JOBID", "/networks", "/stats/qps", "/stats/qps/example.com",
		"/stats/usage", "/stats/usage/example.com/www.example.com/A", "/views", "/search?q=example&type=zone", "/account/plan", "/account/usagewarnings"}
	sort.Strings(ex)
	return map[string]any{
		"how": "Paths below /zones, /data, /monitoring, /networks, /stats, /views, /search, /export and /account (the prefix /v1 is added). A zone's records come " +
			"in pages of 2500. API keys, users, teams, account settings, billing, TSIG keys and notification lists are refused. Changes are device_change_raw: " +
			"PUT creates, POST updates, DELETE removes (not a whole zone).",
		"examples": ex,
		"tip":      "show zone NAME (device_show) answers a zone with its records in one call; the full API is described at https://developer.ibm.com/apis/catalog/ns1--ns1-api/.",
	}, nil
}

// ---- changes ----

func nsGuard(method, p string) error {
	switch method {
	case http.MethodPut, http.MethodPost, http.MethodDelete:
	default:
		return errors.New("method: NS1 creates with PUT, updates with POST and removes with DELETE")
	}
	pp, _, _ := strings.Cut(p, "?")
	if !dnsPathRE.MatchString(pp) {
		return errors.New("path: /zones/example.com/www.example.com/A")
	}
	segs := dnsSegs(pp)
	if !nsWritable[segs[0]] {
		return errors.New("path: NS1 is changed below /zones, /data, /monitoring, /networks and /views")
	}
	if hasSeg(pp, nsDenied...) {
		return errors.New("path: API keys, users, teams, account settings, billing, TSIG keys and notification lists are not changed here")
	}
	if method == http.MethodDelete && segs[0] == "zones" && len(segs) == 1 {
		return errors.New("path: a DELETE needs the path of one thing")
	}
	if method == http.MethodDelete && segs[0] == "zones" && len(segs) == 2 {
		return errors.New("path: a whole zone is not deleted here, it takes every record with it: delete its records one by one, or use the NS1 portal")
	}
	return nil
}

// RawChange: Method PUT (create), POST (update) or DELETE, Path below /zones, /data, /monitoring, /networks or /views, Body JSON.
func (n *nsone) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	r.Path = dnsRel(n.prefix, r.Path)
	before := ""
	if c, err := r.checkREST(http.MethodPost, http.MethodPut, http.MethodDelete); err == nil && c.Method == http.MethodPost && nsGuard(c.Method, c.Path) == nil && len(dnsSegs(c.Path)) >= 2 {
		// NS1 updates with POST, which restRaw does not read first: the copy is taken here
		if b, err := n.api.do(ctx, http.MethodGet, n.prefix+c.Path, nil, nil); err == nil {
			before = rawTrunc(b)
		}
	}
	res, err := restRaw(ctx, restSpec{
		api: n.api, hdr: jsonHdr(), auth: http.Header{"Accept": {"application/json"}}, json: true,
		wire:  func(p string) string { return n.prefix + p },
		guard: nsGuard,
		alive: func(ctx context.Context) error {
			_, err := n.get(ctx, "/zones")
			return err
		},
	}, r, dry)
	if before != "" && res.Before == "" {
		res.Before = before
		if res.Applied {
			res.Note = strings.TrimSpace(res.Note + " NS1 changed what 'before' shows; it is not put back by itself: send the old state again to undo.")
		}
	}
	return res, err
}
