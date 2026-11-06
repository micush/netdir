package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// F5 BIG-IP (TMOS 13 and later) over iControl REST, /mgmt/tm/..., on the management address (HTTPS, 443).  The credential is a
// user name and password (HTTP basic authentication, an account with the "Guest" or "Auditor" role is enough for reading), or a
// token in the credential's Token (sent as X-F5-Auth-Token, from POST /mgmt/shared/authn/login).
//
// Reads: facts and interfaces (cm/device, net/interface, net/self), port counters (net/interface/stats), routes (net/route),
// routing protocols, AFM firewall policy, VLANs, health, and everything else TMOS has through APIGet (virtual servers, pools and
// their statistics, nodes, monitors, profiles, ...).  BIG-IP has no CLI over REST except util/bash, which runs shell commands and
// is never sent by a read; Show and Config answer ErrUnsupported (the configuration is bigip.conf, a file, or a UCS archive,
// which holds the box's keys).  Neighbors answer ErrUnsupported too: read net/lldp-neighbors through APIGet where the release has it.

func init() { Register("bigip", newBigIP) }

type bigip struct {
	d   Device
	api *apiClient
}

func newBigIP(d Device, c Credential) (Driver, error) {
	if c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: BIG-IP needs a username and a password, or an auth token", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		api.hdr.Set("X-F5-Auth-Token", c.Token)
	} else {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(c.Username, c.Password)
		api.hdr.Set("Authorization", req.Header.Get("Authorization"))
	}
	return &bigip{d: d, api: api}, nil
}

func (b *bigip) get(ctx context.Context, p string) (any, error) {
	var v any
	if err := b.api.getJSON(ctx, p, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// items is the "items" list of a collection answer.
func (b *bigip) items(ctx context.Context, p string) ([]map[string]any, error) {
	v, err := b.get(ctx, p)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return rows(m["items"]), nil
}

// base is a name without its partition path: "/Common/internal" -> "internal".
func base(n string) string {
	if i := strings.LastIndex(n, "/"); i >= 0 {
		return n[i+1:]
	}
	return n
}

func (b *bigip) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "F5"}
	devs, err := b.items(ctx, "/mgmt/tm/cm/device")
	if err != nil {
		return f, err
	}
	var self map[string]any
	for _, d := range devs {
		if str(d["selfDevice"]) == "true" {
			self = d
		}
	}
	if self == nil && len(devs) == 1 {
		self = devs[0]
	}
	if self == nil {
		return f, errors.New("cm/device lists no self device")
	}
	f.Hostname = firstOf(str(self["hostname"]), str(self["name"]))
	f.Model = firstOf(str(self["marketingName"]), str(self["platformId"]))
	f.Serial = str(self["chassisId"])
	f.OSVersion = str(self["version"])
	if b2 := str(self["build"]); b2 != "" && f.OSVersion != "" {
		f.OSVersion += " build " + b2
	}
	return f, nil
}

func (b *bigip) selfIPs(ctx context.Context) []Interface {
	selfs, err := b.items(ctx, "/mgmt/tm/net/self")
	if err != nil {
		return nil
	}
	var out []Interface
	for _, s := range selfs {
		a := str(s["address"])
		if a == "" {
			continue
		}
		// "10.0.0.1%1/24": the route domain is not part of the address
		if i := strings.Index(a, "%"); i >= 0 {
			if j := strings.Index(a[i:], "/"); j >= 0 {
				a = a[:i] + a[i+j:]
			} else {
				a = a[:i]
			}
		}
		out = append(out, Interface{Name: "self " + str(s["name"]), Addresses: []string{a}, Description: "self IP on VLAN " + base(str(s["vlan"]))})
	}
	return out
}

func f5Interface(r map[string]any) Interface {
	i := Interface{Name: str(r["name"]), Description: str(r["description"]), MAC: str(r["macAddress"])}
	switch {
	case str(r["disabled"]) == "true":
		i.AdminUp = boolp(false)
	case str(r["enabled"]) == "true" || r["enabled"] == true:
		i.AdminUp = boolp(true)
	}
	if s := str(r["mediaActive"]); s != "" && s != "none" {
		i.OperUp = boolp(true)
	} else if r["mediaActive"] != nil {
		i.OperUp = boolp(false)
	}
	return i
}

func (b *bigip) Interfaces(ctx context.Context) ([]Interface, error) {
	ifs, err := b.items(ctx, "/mgmt/tm/net/interface")
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, r := range ifs {
		out = append(out, f5Interface(r))
	}
	sort.Slice(out, func(a, c int) bool { return out[a].Name < out[c].Name })
	return append(out, b.selfIPs(ctx)...), nil
}

// entries digs the per-object statistics out of iControl's nestedStats envelope: each entry's key is the object's URL, its
// value another nestedStats whose entries are {description} or {value}.
func f5Stats(v any) map[string]map[string]any {
	out := map[string]map[string]any{}
	m, _ := v.(map[string]any)
	es, _ := m["entries"].(map[string]any)
	for _, e := range es {
		em, _ := e.(map[string]any)
		ns, _ := em["nestedStats"].(map[string]any)
		fields, _ := ns["entries"].(map[string]any)
		flat := map[string]any{}
		for k, x := range fields {
			xm, _ := x.(map[string]any)
			if d, ok := xm["description"]; ok {
				flat[k] = d
			} else if val, ok := xm["value"]; ok {
				flat[k] = val
			}
		}
		if name := str(flat["tmName"]); name != "" {
			out[name] = flat
		}
	}
	return out
}

func (b *bigip) Ports(ctx context.Context) ([]Port, error) {
	cfg, err := b.items(ctx, "/mgmt/tm/net/interface")
	if err != nil {
		return nil, err
	}
	var st map[string]map[string]any
	if v, err := b.get(ctx, "/mgmt/tm/net/interface/stats"); err == nil {
		st = f5Stats(v)
	}
	out := make([]Port, 0, len(cfg))
	for _, r := range cfg {
		p := Port{Interface: f5Interface(r), Type: "ethernet", MTU: num(r["mtu"]), Properties: redactMap(r)}
		if s, ok := st[p.Name]; ok {
			if str(s["status"]) != "" {
				p.OperUp = boolp(str(s["status"]) == "up")
			}
			p.Counters = Counters{InOctets: num(s["counters.bitsIn"]) / 8, OutOctets: num(s["counters.bitsOut"]) / 8,
				InPackets: num(s["counters.pktsIn"]), OutPackets: num(s["counters.pktsOut"]),
				InErrors: num(s["counters.errorsIn"]), OutErrors: num(s["counters.errorsOut"]),
				InDiscards: num(s["counters.dropsIn"]), OutDiscards: num(s["counters.dropsOut"]), All: s}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(a, c int) bool { return out[a].Name < out[c].Name })
	return out, nil
}

func (b *bigip) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (b *bigip) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (b *bigip) Show(context.Context, string) (string, error)  { return "", ErrUnsupported }

func (b *bigip) Routes(ctx context.Context) ([]Route, error) {
	rs, err := b.items(ctx, "/mgmt/tm/net/route")
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, r := range rs {
		p := str(r["network"])
		if p == "default" {
			p = "0.0.0.0/0"
		} else if p == "default-inet6" {
			p = "::/0"
		}
		nh := firstOf(str(r["gw"]), str(r["pool"]), str(r["interface"]))
		out = append(out, Route{Protocol: "static", Prefix: p, NextHop: nh, Interface: base(str(r["tmInterface"])), Raw: redactMap(r)})
	}
	return out, nil
}

func (b *bigip) Routing(ctx context.Context) (Routing, error) {
	return gather([]part{
		{"static_routes", "/mgmt/tm/net/route"},
		{"bgp", "/mgmt/tm/net/routing/bgp"},
		{"ospf", "/mgmt/tm/net/routing/ospf"},
		{"bfd", "/mgmt/tm/net/routing/bfd"},
		{"route_domains", "/mgmt/tm/net/route-domain"},
	}, func(p string) (any, error) { return b.get(ctx, p) })
}

// Firewall: the AFM (firewall module) policy and the objects it uses, and the NAT policy; "unavailable" names what a box
// without AFM does not have.  Virtual servers and pools are LTM, not firewall: read them through APIGet.
func (b *bigip) Firewall(ctx context.Context) (Firewall, error) {
	return gather([]part{
		{"policies", "/mgmt/tm/security/firewall/policy?expandSubcollections=true"},
		{"rule_lists", "/mgmt/tm/security/firewall/rule-list?expandSubcollections=true"},
		{"address_lists", "/mgmt/tm/security/firewall/address-list"},
		{"port_lists", "/mgmt/tm/security/firewall/port-list"},
		{"nat_policies", "/mgmt/tm/security/nat/policy?expandSubcollections=true"},
	}, func(p string) (any, error) { return b.get(ctx, p) })
}

// Resources: what the box says about its CPU, memory, disks and hardware, whole (BIG-IP's statistics are nested per object, so
// they are not boiled down to a percentage here), and the high-availability state.
func (b *bigip) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"cpu", "/mgmt/tm/sys/cpu"},
		{"memory", "/mgmt/tm/sys/memory"},
		{"host_info", "/mgmt/tm/sys/host-info"},
		{"disk", "/mgmt/tm/sys/disk/logical-disk"},
		{"failover", "/mgmt/tm/cm/failover-status"},
	}, func(p string) (any, error) { return b.get(ctx, p) })
	return Resources{Details: d}, err
}

func (b *bigip) VLANs(ctx context.Context) ([]VLAN, error) {
	vs, err := b.items(ctx, "/mgmt/tm/net/vlan?expandSubcollections=true")
	if err != nil {
		return nil, err
	}
	var out []VLAN
	for _, r := range vs {
		v := VLAN{ID: num(r["tag"]), Name: str(r["name"]), Status: "active", Raw: redactMap(r)}
		if ir, ok := r["interfacesReference"].(map[string]any); ok {
			for _, i := range rows(ir["items"]) {
				if n := str(i["name"]); n != "" {
					v.Ports = append(v.Ports, n)
				}
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(a, c int) bool { return out[a].ID < out[c].ID })
	return out, nil
}

// bigipRead says whether a path of iControl REST only reads: /mgmt/<...>, and not the places that run commands, move files or
// make sessions.  Reads are GET only; the methods that change things are never sent by APIGet.
func bigipRead(path string) (string, error) {
	p, q, _ := strings.Cut(path, "?")
	lp := strings.ToLower(strings.Trim(p, "/"))
	if !strings.HasPrefix(lp, "mgmt/") {
		return "", errors.New("path: BIG-IP reads /mgmt/tm/... (e.g. /mgmt/tm/ltm/virtual or /mgmt/tm/ltm/pool?expandSubcollections=true)")
	}
	segs := strings.Split(lp, "/")
	for i, s := range segs {
		switch {
		case s == "util" && i >= 2 && segs[i-1] == "tm": // util/bash, util/ping, ...: they run things
			return "", errors.New("path: /mgmt/tm/util runs commands and is not read here")
		case s == "authn" || s == "authz" || s == "file-transfer" || s == "ucs" && i >= 2 && segs[i-1] == "sys" || s == "tasks":
			return "", fmt.Errorf("path: %q is not a read (logins, file transfers, archives, tasks) and is not sent", s)
		}
	}
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	return path, nil
}

func (b *bigip) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := bigipRead(path)
	if err != nil {
		return nil, false, err
	}
	return apiGet(ctx, b.api, p, nil)
}

func (b *bigip) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET /mgmt/tm/<module>/<collection> lists objects as {items: [...]}; ?expandSubcollections=true adds their sub-collections (pool members, rules), " +
			"?$select=name,address picks fields, ?$filter=partition eq Common filters, ?$top=N&$skip=M pages, /mgmt/tm/<module>/<collection>/stats the statistics, and ~Common~name is an object in a partition. " +
			"Only GET is sent; /mgmt/tm/util (it runs shell commands), logins, file transfers and UCS archives are not read here.",
		"examples": []string{"/mgmt/tm/ltm/virtual?expandSubcollections=true", "/mgmt/tm/ltm/virtual/stats", "/mgmt/tm/ltm/pool?expandSubcollections=true", "/mgmt/tm/ltm/pool/~Common~web/members/stats",
			"/mgmt/tm/ltm/node", "/mgmt/tm/ltm/monitor/http", "/mgmt/tm/sys/version", "/mgmt/tm/cm/sync-status", "/mgmt/tm/cm/failover-status", "/mgmt/tm/net/trunk", "/mgmt/tm/sys/performance/all-stats"},
	}, nil
}

func (b *bigip) Close(context.Context) { b.api.close() }
