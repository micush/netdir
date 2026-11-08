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

// Cisco ACI, through the APIC's REST API.  The credential is a user name and a password.  The driver logs in once
// (POST /api/aaaLogin.json; the APIC-cookie it sets is kept), logs in again when the session is refused, and logs out in Close.
//
//	show <class> [key=value ...]    the objects of a class of the object model: show fvTenant, show faultInst severity=critical,
//	                                show fvAEPg; the pairs are equality filters on the class's own properties
//	show mo <dn>                    one object and its children's count: show mo uni/tn-common
//
// The device is the APIC (use the cluster's address or one APIC).  Facts are the APIC's own (topSystem); interfaces and
// neighbors are those of every node of the fabric, named node-<id>/<port>; the configuration is the tenants' configuration
// as the APIC holds it (properties of configuration only), as JSON.
//
// Not tried against a real APIC: the class and property names are from Cisco's object model documentation.

func init() { Register("aci", newACI) }

type aci struct {
	d    Device
	api  *apiClient
	user string
	pass string

	mu sync.Mutex
	in bool
}

var (
	aciClassRE = regexp.MustCompile(`^[a-z][A-Za-z0-9]{1,60}$`)
	aciPropRE  = regexp.MustCompile(`^[a-z][A-Za-z0-9]{0,40}$`)
	aciDNRE    = regexp.MustCompile(`^[A-Za-z0-9_.:/\[\]@=,+-]{1,512}$`)
	aciNodeRE  = regexp.MustCompile(`node-(\d+)`)
	aciIfRE    = regexp.MustCompile(`if-\[([^\]]+)\]`)
	aciPhysRE  = regexp.MustCompile(`^(.*?/sys)/phys-\[([^\]]+)\]`)
)

// aciDeny are parts of the object model that hold logins, keys, certificates and communities (matched in lower case inside a path).
var aciDeny = []string{"aaa", "pki", "keyring", "snmpcomm", "snmpuser", "tacacs", "radius", "ldap", "userdomain", "userext", "cryptkey", "pwd", "secret", "password", "apiuser"}

func newACI(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: the APIC needs a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	return &aci{d: d, api: api, user: c.Username, pass: c.Password}, nil
}

func (a *aci) login(ctx context.Context, force bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.in && !force {
		return nil
	}
	body := map[string]any{"aaaUser": map[string]any{"attributes": map[string]any{"name": a.user, "pwd": a.pass}}}
	if _, err := a.api.do(ctx, http.MethodPost, "/api/aaaLogin.json", body, nil); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	a.in = true
	return nil
}

func (a *aci) get(ctx context.Context, p string) (any, error) {
	for renewed := false; ; renewed = true {
		if err := a.login(ctx, false); err != nil {
			return nil, err
		}
		b, err := a.api.do(ctx, http.MethodGet, p, nil, nil)
		var se *statusError
		if err != nil && errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) && !renewed {
			if err := a.login(ctx, true); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", p, err)
		}
		return v, nil
	}
}

// objects reads a class and returns the properties of each object ({"fvTenant": {"attributes": {...}}} becomes the attributes).
func (a *aci) objects(ctx context.Context, class string, query url.Values) ([]map[string]any, error) {
	p := "/api/node/class/" + class + ".json"
	if len(query) > 0 {
		p += "?" + query.Encode()
	}
	v, err := a.get(ctx, p)
	if err != nil {
		return nil, err
	}
	return aciAttrs(v), nil
}

func aciAttrs(v any) []map[string]any {
	m, _ := v.(map[string]any)
	var out []map[string]any
	for _, it := range rows(m["imdata"]) {
		for _, body := range it {
			if b, ok := body.(map[string]any); ok {
				if at, ok := b["attributes"].(map[string]any); ok {
					out = append(out, at)
				}
			}
		}
	}
	return out
}

func (a *aci) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Hostname: a.d.Name, Vendor: "Cisco", Model: "ACI APIC"}
	q := url.Values{"query-target-filter": {`eq(topSystem.role,"controller")`}}
	sys, err := a.objects(ctx, "topSystem", q)
	if err != nil {
		return f, err
	}
	if len(sys) == 0 {
		return f, errors.New("the APIC lists no controller")
	}
	pick := sys[0]
	for _, s := range sys {
		if str(s["oobMgmtAddr"]) == a.d.Address || str(s["address"]) == a.d.Address || str(s["inbMgmtAddr"]) == a.d.Address || str(s["name"]) == a.d.Address {
			pick = s
			break
		}
	}
	if h := str(pick["name"]); h != "" {
		f.Hostname = h
	}
	f.OSVersion, f.Serial = str(pick["version"]), str(pick["serial"])
	f.UptimeS = aciUptime(str(pick["systemUpTime"]))
	f.Model = fmt.Sprintf("ACI APIC, cluster of %d", len(sys))
	if fab := str(pick["fabricDomain"]); fab != "" {
		f.Model += ", fabric " + fab
	}
	return f, nil
}

// aciUptime reads "dd:hh:mm:ss.mmm".
func aciUptime(s string) int64 {
	p := strings.Split(strings.SplitN(s, ".", 2)[0], ":")
	if len(p) != 4 {
		return 0
	}
	var n [4]int64
	for i, x := range p {
		v, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0
		}
		n[i] = v
	}
	return ((n[0]*24+n[1])*60+n[2])*60 + n[3]
}

func aciSpeed(s string) int64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	for suf, mul := range map[string]int64{"T": 1000000, "G": 1000, "M": 1} {
		if strings.HasSuffix(s, suf) {
			if v, err := strconv.ParseInt(strings.TrimSuffix(s, suf), 10, 64); err == nil {
				return v * mul
			}
		}
	}
	return 0
}

func (a *aci) Interfaces(ctx context.Context) ([]Interface, error) {
	phys, err := a.objects(ctx, "l1PhysIf", url.Values{"page-size": {"20000"}})
	if err != nil {
		return nil, err
	}
	oper := map[string]map[string]any{}
	if es, err := a.objects(ctx, "ethpmPhysIf", url.Values{"page-size": {"20000"}}); err == nil {
		for _, e := range es {
			if m := aciPhysRE.FindStringSubmatch(str(e["dn"])); m != nil {
				oper[m[1]+"/phys-["+m[2]+"]"] = e
			}
		}
	}
	out := make([]Interface, 0, len(phys))
	for _, p := range phys {
		dn := str(p["dn"])
		node := aciNodeRE.FindString(dn)
		i := Interface{Name: node + "/" + str(p["id"]), Description: str(p["descr"])}
		if s := str(p["adminSt"]); s != "" {
			i.AdminUp = boolp(s == "up")
		}
		i.SpeedMbps = aciSpeed(str(p["speed"]))
		if m := aciPhysRE.FindStringSubmatch(dn); m != nil {
			if e, ok := oper[m[1]+"/phys-["+m[2]+"]"]; ok {
				if s := str(e["operSt"]); s != "" {
					i.OperUp = boolp(s == "up")
				}
				if sp := aciSpeed(str(e["operSpeed"])); sp > 0 {
					i.SpeedMbps = sp
				}
			}
		}
		out = append(out, i)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Name < out[y].Name })
	return out, nil
}

func (a *aci) Neighbors(ctx context.Context) ([]Neighbor, error) {
	var out []Neighbor
	ls, err1 := a.objects(ctx, "lldpAdjEp", url.Values{"page-size": {"20000"}})
	for _, l := range ls {
		dn := str(l["dn"])
		n := Neighbor{Protocol: "lldp", LocalPort: aciNodeRE.FindString(dn) + "/" + aciSub(aciIfRE, dn), RemoteName: str(l["sysName"]),
			RemotePort: str(l["portIdV"]), RemoteAddr: str(l["mgmtIp"]), RemoteDesc: str(l["sysDesc"])}
		if d := str(l["portDesc"]); d != "" && n.RemotePort == "" {
			n.RemotePort = d
		}
		out = append(out, n)
	}
	cs, err2 := a.objects(ctx, "cdpAdjEp", url.Values{"page-size": {"20000"}})
	for _, c := range cs {
		dn := str(c["dn"])
		out = append(out, Neighbor{Protocol: "cdp", LocalPort: aciNodeRE.FindString(dn) + "/" + aciSub(aciIfRE, dn), RemoteName: str(c["devId"]),
			RemotePort: str(c["portId"]), RemoteAddr: str(c["mgmtIp"]), RemoteDesc: str(c["platId"])})
	}
	if len(out) == 0 && err1 != nil && err2 != nil {
		return nil, err1
	}
	sort.SliceStable(out, func(x, y int) bool { return out[x].LocalPort < out[y].LocalPort })
	return out, nil
}

func aciSub(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Config is the configuration of the tenants as the APIC holds it, as JSON.
func (a *aci) Config(ctx context.Context) (string, error) {
	v, err := a.get(ctx, "/api/node/class/fvTenant.json?rsp-subtree=full&rsp-prop-include=config-only")
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return string(b), nil
}

// aciPath checks a path for a read: below /api, a class or an object, as JSON.
func aciPath(path string) (string, error) {
	p := path
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	ok := false
	for _, pre := range []string{"/api/node/class/", "/api/class/", "/api/node/mo/", "/api/mo/"} {
		ok = ok || strings.HasPrefix(pp, pre)
	}
	if !ok || !strings.HasSuffix(pp, ".json") || !aciDNRE.MatchString(strings.TrimSuffix(pp, ".json")) {
		return "", errors.New("path: /api/node/class/<class>.json or /api/node/mo/<dn>.json, with an optional ?query (see device_api_catalog)")
	}
	lp := strings.ToLower(pp + "?" + q)
	for _, d := range aciDeny {
		if strings.Contains(lp, d) {
			return "", fmt.Errorf("path: %q is part of the logins, keys, certificates or communities that are not read here", d)
		}
	}
	return p, nil
}

func (a *aci) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show <class> [property=value ...]   for example: show fvTenant, show faultInst severity=critical, show fvAEPg;   show mo <dn>   for example: show mo uni/tn-common")
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	var p string
	if strings.EqualFold(f[1], "mo") {
		if len(f) != 3 || !aciDNRE.MatchString(f[2]) {
			return "", usage
		}
		p = "/api/node/mo/" + f[2] + ".json"
	} else {
		class := f[1]
		if !aciClassRE.MatchString(class) {
			return "", usage
		}
		var conds []string
		for _, kv := range f[2:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || !aciPropRE.MatchString(k) || v == "" || len(v) > 128 || strings.ContainsAny(v, "&#\"'`;<>()") {
				return "", usage
			}
			conds = append(conds, fmt.Sprintf(`eq(%s.%s,"%s")`, class, k, v))
		}
		q := url.Values{"page-size": {"500"}}
		switch len(conds) {
		case 0:
		case 1:
			q.Set("query-target-filter", conds[0])
		default:
			q.Set("query-target-filter", "and("+strings.Join(conds, ",")+")")
		}
		p = "/api/node/class/" + class + ".json?" + q.Encode()
	}
	p, err := aciPath(p)
	if err != nil {
		return "", err
	}
	v, err := a.get(ctx, p)
	if err != nil {
		return "", err
	}
	at := aciAttrs(v)
	for i := range at {
		at[i] = redactMap(at[i])
	}
	b, _ := json.MarshalIndent(map[string]any{"count": len(at), "objects": at}, "", "  ")
	return RedactText(string(b)), nil
}

func (a *aci) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := aciPath(path)
	if err != nil {
		return nil, false, err
	}
	v, err := a.get(ctx, p)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (a *aci) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET paths of the APIC REST API: /api/node/class/<class>.json (the objects of a class) and /api/node/mo/<dn>.json (one object), with the APIC's own query options " +
			"(query-target-filter=eq(class.property,\"value\"), rsp-subtree=children, page-size=...). Only GET is sent. Logins, keys, certificates and communities are not read.",
		"examples": []string{"/api/node/class/fvTenant.json", "/api/node/class/fvAEPg.json", "/api/node/class/fabricNode.json", "/api/node/class/topSystem.json",
			"/api/node/class/faultInst.json?query-target-filter=eq(faultInst.severity,\"critical\")", "/api/node/mo/uni/tn-common.json?rsp-subtree=children",
			"/api/node/class/healthInst.json", "/api/node/class/l1PhysIf.json", "/api/node/class/lldpAdjEp.json", "/api/node/class/fvCEp.json (endpoints)"},
	}, nil
}

func aciRawGuard(_, p string) error {
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change")
	}
	if !(strings.HasPrefix(pp, "/api/node/mo/") || strings.HasPrefix(pp, "/api/mo/")) || !strings.HasSuffix(pp, ".json") || !aciDNRE.MatchString(strings.TrimSuffix(pp, ".json")) {
		return errors.New("path: the APIC is changed with /api/node/mo/<dn>.json")
	}
	lp := strings.ToLower(pp)
	for _, d := range append(append([]string{}, aciDeny...), "firmware", "fwgrp", "maintp", "trigger", "reboot", "decommission", "snapshot", "export", "import") {
		if strings.Contains(lp, d) {
			return fmt.Errorf("path: %q is not changed here (logins, keys, firmware, restarts, exports and imports)", d)
		}
	}
	return nil
}

func (a *aci) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if len(r.Lines) > 0 {
		return RawResult{DryRun: dry}, errors.New("lines: the APIC is changed with method, path and body")
	}
	if m := strings.ToUpper(r.Method); m != http.MethodPost && m != http.MethodDelete {
		return RawResult{DryRun: dry}, errors.New("method: the APIC is changed with POST (create or modify) or DELETE")
	}
	if err := a.login(ctx, false); err != nil {
		return RawResult{DryRun: dry}, err
	}
	h := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}}
	return restRaw(ctx, restSpec{
		api: a.api, hdr: h, json: true,
		guard: aciRawGuard,
		alive: func(ctx context.Context) error {
			_, err := a.get(ctx, "/api/node/class/topSystem.json?page-size=1")
			return err
		},
	}, r, dry)
}

func (a *aci) Close(ctx context.Context) {
	a.mu.Lock()
	in := a.in
	a.in = false
	a.mu.Unlock()
	if in {
		c, cancel := cleanupCtx()
		defer cancel()
		_, _ = a.api.do(c, http.MethodPost, "/api/aaaLogout.json", map[string]any{"aaaUser": map[string]any{"attributes": map[string]any{"name": a.user}}}, nil)
	}
	a.api.close()
}
