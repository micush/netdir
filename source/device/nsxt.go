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
)

// VMware NSX (NSX-T), through the NSX Manager's REST API: the Manager API below /api/v1 and the Policy API below
// /policy/api/v1.  The credential is a user name and a password, sent as HTTP basic authentication with every request (NSX
// Manager accepts it on its API), so there is no session to keep or to end.  Give the cluster's virtual address, or one
// Manager node.
//
//	show <path> [key=value ...]    a GET: show transport-nodes, show logical-switches, show infra/tier-0s, show cluster/status
//	                               (a path that begins with infra, global-infra or orgs is the Policy API, any other the Manager API)
//
// Not tried against a real Manager: the paths and the names of fields are from VMware's API documentation.

func init() { Register("nsxt", newNSXT) }

type nsxt struct {
	d   Device
	api *apiClient
}

var nsxSegRE = regexp.MustCompile(`^[A-Za-z0-9_.:,@=~%-]{1,128}$`)

// nsxDeny are the parts of the API that hold accounts, certificates, keys, directory logins, backups and licences.
var nsxDeny = []string{"users", "aaa", "trust-management", "certificate", "vidm", "ldap", "passphrase", "password", "api-key", "secret", "license", "backup", "token", "principal", "credential"}

func newNSXT(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: NSX Manager needs a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	return &nsxt{d: d, api: api}, nil
}

func (n *nsxt) get(ctx context.Context, p string) (any, error) {
	b, err := n.api.do(ctx, http.MethodGet, p, nil, nil)
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
	return v, nil
}

func (n *nsxt) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Hostname: n.d.Name, Vendor: "VMware", Model: "NSX Manager"}
	v, err := n.get(ctx, "/api/v1/node/version")
	if err != nil {
		return f, err
	}
	if m, ok := v.(map[string]any); ok {
		f.OSVersion = str(m["product_version"])
		if f.OSVersion == "" {
			f.OSVersion = str(m["node_version"])
		}
	}
	if sv, err := n.get(ctx, "/api/v1/node/status"); err == nil {
		if m, ok := sv.(map[string]any); ok {
			if ss, ok := m["system_status"].(map[string]any); ok {
				f.UptimeS = num(ss["uptime"]) / 1000
			}
		}
	}
	if nv, err := n.get(ctx, "/api/v1/node"); err == nil {
		if m, ok := nv.(map[string]any); ok {
			for _, k := range []string{"hostname", "fqdn"} {
				if h := str(m[k]); h != "" {
					f.Hostname = h
					break
				}
			}
		}
	}
	return f, nil
}

func (n *nsxt) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (n *nsxt) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (n *nsxt) Config(context.Context) (string, error)          { return "", ErrUnsupported }

// nsxPath gives a path of the API: /api/v1/..., /policy/api/v1/..., or a shorthand.
func nsxPath(path string) (string, string, error) {
	p := path
	switch {
	case strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/policy/api/"):
	case strings.HasPrefix(p, "/infra") || strings.HasPrefix(p, "/global-infra") || strings.HasPrefix(p, "/orgs"):
		p = "/policy/api/v1" + p
	default:
		p = "/api/v1" + p
	}
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", "", errors.New("path: the query is not valid")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if len(segs) < 3 || len(segs) > 14 {
		return "", "", errors.New("path: /api/v1/<resource>... or /policy/api/v1/<resource>... (see device_api_catalog)")
	}
	for _, g := range segs {
		if !nsxSegRE.MatchString(g) {
			return "", "", fmt.Errorf("path: %q is not a resource name", g)
		}
	}
	return p, pp, nil
}

func nsxDenied(pp string, words []string) string {
	for _, g := range strings.Split(strings.Trim(pp, "/"), "/") {
		for _, d := range words {
			if strings.Contains(strings.ToLower(g), d) {
				return g
			}
		}
	}
	return ""
}

func nsxRead(path string) (string, error) {
	p, pp, err := nsxPath(path)
	if err != nil {
		return "", err
	}
	if g := nsxDenied(pp, nsxDeny); g != "" {
		return "", fmt.Errorf("path: %q holds accounts, certificates, keys or licences and is not read here", g)
	}
	return p, nil
}

func (n *nsxt) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show <path> [key=value ...]   for example: show transport-nodes, show logical-switches, show infra/tier-0s, show cluster/status, show alarms status=OPEN")
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	q := url.Values{}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !sdSegRE.MatchString(k) || v == "" || len(v) > 128 || strings.ContainsAny(v, "&#\"'`;<>") {
			return "", usage
		}
		q.Set(k, v)
	}
	p := "/" + strings.Trim(f[1], "/")
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	p, err := nsxRead(p)
	if err != nil {
		return "", err
	}
	v, err := n.get(ctx, p)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

func (n *nsxt) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := nsxRead(path)
	if err != nil {
		return nil, false, err
	}
	v, err := n.get(ctx, p)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (n *nsxt) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET paths of the NSX Manager API: /api/v1/... (Manager API) and /policy/api/v1/... (Policy API), with an optional ?key=value query (page size: page_size, cursor: cursor). Only GET is sent. " +
			"Users, certificates, keys, directory logins, backups and licences are not read. The API reference is at https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api.",
		"examples": []string{"/api/v1/node/version", "/api/v1/cluster/status", "/api/v1/transport-nodes", "/api/v1/logical-switches", "/api/v1/fabric/nodes",
			"/policy/api/v1/infra/tier-0s", "/policy/api/v1/infra/tier-1s", "/policy/api/v1/infra/segments", "/policy/api/v1/infra/domains/default/security-policies", "/api/v1/alarms?status=OPEN"},
	}, nil
}

var nsxRawDeny = []string{"users", "aaa", "trust-management", "certificate", "vidm", "ldap", "passphrase", "password", "api-key", "secret", "license", "backup", "token",
	"principal", "credential", "reboot", "shutdown", "restart", "restore", "upgrade", "node/services", "factory"}

func nsxRawGuard(_, p string) error {
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change")
	}
	if !strings.HasPrefix(pp, "/api/") && !strings.HasPrefix(pp, "/policy/api/") {
		return errors.New("path: NSX Manager is changed below /api/ or /policy/api/")
	}
	if g := nsxDenied(pp, nsxRawDeny); g != "" {
		return fmt.Errorf("path: %q is not changed here (accounts, certificates, keys, backups, upgrades and restarts)", g)
	}
	if strings.Contains(strings.ToLower(pp), "node/services") {
		return errors.New("path: the services of the Manager are not changed here")
	}
	return nil
}

func (n *nsxt) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if len(r.Lines) > 0 {
		return RawResult{DryRun: dry}, errors.New("lines: NSX Manager is changed with method, path and body")
	}
	h := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}}
	return restRaw(ctx, restSpec{
		api: n.api, hdr: h, json: true,
		guard: nsxRawGuard,
		alive: func(ctx context.Context) error { _, err := n.get(ctx, "/api/v1/node/version"); return err },
	}, r, dry)
}

func (n *nsxt) Close(context.Context) { n.api.close() }
