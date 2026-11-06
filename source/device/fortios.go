package device

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Fortinet FortiGate (FortiOS 6.4 and later) over its REST API, /api/v2/monitor/... and /api/v2/cmdb/..., with an API
// token (System ▸ Administrators ▸ Create New ▸ REST API Admin) sent as "Authorization: Bearer TOKEN".  A read-only
// admin profile is enough for everything here.  The option "vdom" picks the VDOM (default: the token's own).
//
// FortiOS's REST API runs no CLI commands, so Show answers ErrUnsupported.

func init() { Register("fortios", newFortiOS) }

type fortios struct {
	d    Device
	api  *apiClient
	vdom string
}

func newFortiOS(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: FortiOS needs an API token (a REST API admin)", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	return &fortios{d: d, api: api, vdom: d.Options["vdom"]}, nil
}

// path adds the VDOM, when one is set, to a request.
func (f *fortios) path(p string) string {
	if f.vdom == "" {
		return p
	}
	sep := "?"
	if strings.Contains(p, "?") {
		sep = "&"
	}
	return p + sep + "vdom=" + url.QueryEscape(f.vdom)
}

// answer is FortiOS's envelope around every answer.
type fortiAnswer struct {
	Status  string `json:"status"`
	Serial  string `json:"serial"`
	Version string `json:"version"`
	Build   int64  `json:"build"`
	Results any    `json:"results"`
}

func (f *fortios) get(ctx context.Context, p string) (fortiAnswer, error) {
	var a fortiAnswer
	if err := f.api.getJSON(ctx, f.path(p), &a); err != nil {
		return a, err
	}
	if a.Status != "" && a.Status != "success" {
		return a, fmt.Errorf("GET %s: FortiOS answered status %q", p, a.Status)
	}
	return a, nil
}

func (f *fortios) Facts(ctx context.Context) (Facts, error) {
	a, err := f.get(ctx, "/api/v2/monitor/system/status")
	if err != nil {
		return Facts{}, err
	}
	r, _ := a.Results.(map[string]any)
	out := Facts{Vendor: "Fortinet", Hostname: str(r["hostname"]), Serial: a.Serial, OSVersion: strings.TrimPrefix(a.Version, "v")}
	out.Model = firstOf(str(r["model"]), strings.TrimSpace(str(r["model_name"])+" "+str(r["model_number"])))
	if a.Build > 0 && out.OSVersion != "" {
		out.OSVersion += fmt.Sprintf(" build %d", a.Build)
	}
	// uptime: the time of the last reboot, in ms, as the web UI reads it; left out if this release does not answer it
	if s, err := f.get(ctx, "/api/v2/monitor/web-ui/state"); err == nil {
		if m, ok := s.Results.(map[string]any); ok {
			if rb := num(m["utc_last_reboot"]); rb > 0 {
				out.UptimeS = nowUnix() - rb/1000
			}
		}
	}
	return out, nil
}

func (f *fortios) Interfaces(ctx context.Context) ([]Interface, error) {
	mon, err := f.get(ctx, "/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true")
	if err != nil {
		return nil, err
	}
	// the description and the admin status are configuration, not state: from cmdb
	conf := map[string]map[string]any{}
	if c, err := f.get(ctx, "/api/v2/cmdb/system/interface?format=name|description|status|alias"); err == nil {
		for _, r := range rows(c.Results) {
			conf[str(r["name"])] = r
		}
	}
	var list []map[string]any
	switch t := mon.Results.(type) {
	case map[string]any: // keyed by name
		for _, v := range t {
			if m, ok := v.(map[string]any); ok {
				list = append(list, m)
			}
		}
	default:
		list = rows(t)
	}
	out := make([]Interface, 0, len(list))
	for _, r := range list {
		i := Interface{Name: str(r["name"]), MAC: str(r["mac"])}
		if l, ok := r["link"].(bool); ok {
			i.OperUp = boolp(l)
		}
		if sp := num(r["speed"]); sp > 0 { // Mbit/s
			i.SpeedMbps = sp
		}
		if ip := str(r["ip"]); ip != "" && ip != "0.0.0.0" {
			if m := num(r["mask"]); m > 0 {
				ip += fmt.Sprintf("/%d", m)
			}
			i.Addresses = []string{ip}
		}
		if c := conf[i.Name]; c != nil {
			i.Description = firstOf(str(c["description"]), str(c["alias"]))
			if s := str(c["status"]); s != "" {
				i.AdminUp = boolp(s == "up")
			}
		} else {
			i.Description = str(r["alias"])
		}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// monitorRows reads a monitor or cmdb endpoint's results as a list, whatever shape it answers (a list, or a map by name).
func (f *fortios) results(ctx context.Context, p string) (any, error) {
	a, err := f.get(ctx, p)
	if err != nil {
		return nil, err
	}
	return a.Results, nil
}

// Ports are the monitor row of each interface (rx/tx bytes, packets, errors, link, speed, duplex, ...) with the interface's
// whole configuration from cmdb as its properties.
func (f *fortios) Ports(ctx context.Context) ([]Port, error) {
	ifs, err := f.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	mon, err := f.results(ctx, "/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true")
	if err != nil {
		return nil, err
	}
	var list []map[string]any
	if m, ok := mon.(map[string]any); ok {
		for k, v := range m {
			if r, ok := v.(map[string]any); ok {
				if str(r["name"]) == "" {
					r["name"] = k
				}
				list = append(list, r)
			}
		}
	} else {
		list = rows(mon)
	}
	monBy := map[string]map[string]any{}
	for _, r := range list {
		monBy[str(r["name"])] = r
	}
	conf := map[string]map[string]any{}
	if c, err := f.results(ctx, "/api/v2/cmdb/system/interface"); err == nil {
		for _, r := range rows(c) {
			conf[str(r["name"])] = r
		}
	}
	out := make([]Port, 0, len(ifs))
	for _, i := range ifs {
		p := Port{Interface: i}
		props := map[string]any{}
		if c := conf[i.Name]; c != nil {
			for k, v := range redactMap(c) {
				props[k] = v
			}
			p.Type, p.MTU = str(c["type"]), num(c["mtu"])
		}
		if m := monBy[i.Name]; m != nil {
			p.Counters = countersOf(redactMap(m))
			p.Duplex = str(m["duplex"])
			props["monitor"] = redactMap(m)
		}
		p.Properties = props
		out = append(out, p)
	}
	return out, nil
}

// Routes is the IPv4 and IPv6 routing table (the monitor lists the connected, static and learned routes with their type).
func (f *fortios) Routes(ctx context.Context) ([]Route, error) {
	var out []Route
	for _, p := range []string{"/api/v2/monitor/router/ipv4", "/api/v2/monitor/router/ipv6"} {
		v, err := f.results(ctx, p)
		if err != nil {
			if _, ok := err.(*statusError); ok && len(out) > 0 {
				continue // IPv6 routing not offered: the IPv4 table stands
			}
			return nil, err
		}
		for _, r := range rows(v) {
			ip := firstOf(str(r["ip_mask"]), str(r["subnet"]), str(r["prefix"]))
			out = append(out, Route{Protocol: str(r["type"]), Prefix: ip, NextHop: str(r["gateway"]), Interface: str(r["interface"]),
				Metric: num(r["metric"]), Distance: num(r["distance"]), VRF: str(r["vrf"]), Raw: redactMap(r)})
		}
	}
	return out, nil
}

// Routing: the live state of OSPF and BGP from the monitor, and the configuration of every routing protocol from cmdb.
func (f *fortios) Routing(ctx context.Context) (Routing, error) {
	return gather([]part{
		{"statistics", "/api/v2/monitor/router/statistics"},
		{"ospf_neighbors", "/api/v2/monitor/router/ospf/neighbors"},
		{"ospf6_neighbors", "/api/v2/monitor/router/ospf6/neighbors"},
		{"bgp_neighbors", "/api/v2/monitor/router/bgp/neighbors"},
		{"bgp_neighbors_ipv6", "/api/v2/monitor/router/bgp/neighbors6"},
		{"bgp_paths", "/api/v2/monitor/router/bgp/paths"},
		{"bgp_paths_ipv6", "/api/v2/monitor/router/bgp/paths6"},
		{"policy_routes", "/api/v2/monitor/router/policy"},
		{"config_static", "/api/v2/cmdb/router/static"},
		{"config_static6", "/api/v2/cmdb/router/static6"},
		{"config_ospf", "/api/v2/cmdb/router/ospf"},
		{"config_ospf6", "/api/v2/cmdb/router/ospf6"},
		{"config_bgp", "/api/v2/cmdb/router/bgp"},
		{"config_rip", "/api/v2/cmdb/router/rip"},
		{"config_ripng", "/api/v2/cmdb/router/ripng"},
		{"config_isis", "/api/v2/cmdb/router/isis"},
		{"config_bfd", "/api/v2/cmdb/router/bfd"},
		{"config_policy", "/api/v2/cmdb/router/policy"},
		{"config_route_map", "/api/v2/cmdb/router/route-map"},
		{"config_prefix_list", "/api/v2/cmdb/router/prefix-list"},
		{"config_access_list", "/api/v2/cmdb/router/access-list"},
	}, func(p string) (any, error) { return f.results(ctx, p) })
}

// Firewall: the policies with their hit counters, bytes, packets, last use and sessions (monitor), and the rules and objects
// they use (cmdb): policies, addresses and groups, services, virtual IPs, IP pools, NAT, shapers, local-in and DoS policies.
func (f *fortios) Firewall(ctx context.Context) (Firewall, error) {
	return gather([]part{
		{"policy_stats", "/api/v2/monitor/firewall/policy"},
		{"policy6_stats", "/api/v2/monitor/firewall/policy6"},
		{"proxy_policy_stats", "/api/v2/monitor/firewall/proxy-policy"},
		{"local_in_stats", "/api/v2/monitor/firewall/local-in"},
		{"shaper_stats", "/api/v2/monitor/firewall/shaper"},
		{"session_summary", "/api/v2/monitor/firewall/session/summary"},
		{"policies", "/api/v2/cmdb/firewall/policy"},
		{"policies6", "/api/v2/cmdb/firewall/policy6"},
		{"local_in_policies", "/api/v2/cmdb/firewall/local-in-policy"},
		{"dos_policies", "/api/v2/cmdb/firewall/DoS-policy"},
		{"central_snat", "/api/v2/cmdb/firewall/central-snat-map"},
		{"addresses", "/api/v2/cmdb/firewall/address"},
		{"address_groups", "/api/v2/cmdb/firewall/addrgrp"},
		{"services", "/api/v2/cmdb/firewall.service/custom"},
		{"service_groups", "/api/v2/cmdb/firewall.service/group"},
		{"virtual_ips", "/api/v2/cmdb/firewall/vip"},
		{"ip_pools", "/api/v2/cmdb/firewall/ippool"},
		{"traffic_shapers", "/api/v2/cmdb/firewall.shaper/traffic-shaper"},
		{"shaping_policies", "/api/v2/cmdb/firewall/shaping-policy"},
	}, func(p string) (any, error) { return f.results(ctx, p) })
}

// Resources: the resource usage (CPU, memory, disk and session percentages, with their history) and the hardware sensors.
func (f *fortios) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"resource_usage", "/api/v2/monitor/system/resource/usage"},
		{"sensors", "/api/v2/monitor/system/sensor-info"},
	}, func(p string) (any, error) { return f.results(ctx, p) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	// each resource is a list of {current, historical}, or a bare number on some releases
	cur := func(v any) (float64, bool) {
		if l, ok := v.([]any); ok && len(l) > 0 {
			v = l[0]
		}
		if m, ok := v.(map[string]any); ok {
			c, has := m["current"]
			return flt(c), has
		}
		if v == nil {
			return 0, false
		}
		return flt(v), true
	}
	if u, ok := d.Protocols["resource_usage"].(map[string]any); ok {
		if c, ok := cur(u["cpu"]); ok {
			out.CPU = &CPU{Now: c}
		}
		if c, ok := cur(u["mem"]); ok {
			out.Memory = []Memory{{Name: "memory", UsedPercent: c}}
		}
		if c, ok := cur(u["disk"]); ok {
			out.Storage = []Storage{{Name: "disk", UsedPercent: c}}
		}
	}
	for _, r := range rows(d.Protocols["sensors"]) {
		name := str(r["name"])
		s := Sensor{Name: name, State: firstOf(str(r["status"]), str(r["alarm"]), str(r["state"])), Units: firstOf(str(r["unit"]), str(r["units"])), Raw: r}
		s.Kind = sensorKind(name+" "+str(r["type"]), s.Units)
		if v, ok := r["value"]; ok {
			s.Reading = new(float64)
			*s.Reading = flt(v)
		}
		out.Sensors = append(out.Sensors, s)
	}
	return out, nil
}

// VLANs are the VLAN interfaces (their ID, name, parent interface and status).
func (f *fortios) VLANs(ctx context.Context) ([]VLAN, error) {
	v, err := f.results(ctx, "/api/v2/cmdb/system/interface")
	if err != nil {
		return nil, err
	}
	var out []VLAN
	for _, r := range rows(v) {
		if id := num(r["vlanid"]); id > 0 || str(r["type"]) == "vlan" {
			l := VLAN{ID: num(r["vlanid"]), Name: str(r["name"]), Status: str(r["status"]), Raw: redactMap(r)}
			if p := str(r["interface"]); p != "" {
				l.Ports = []string{p}
			}
			out = append(out, l)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

// APIGet reads any monitor, cmdb or log resource.  Downloads (backups, certificates, packet captures) are refused.
func (f *fortios) APIGet(ctx context.Context, path string) (any, bool, error) {
	ok := false
	for _, pre := range []string{"/api/v2/monitor/", "/api/v2/cmdb/", "/api/v2/log/"} {
		ok = ok || strings.HasPrefix(path, pre)
	}
	if !ok {
		return nil, false, fmt.Errorf("path: FortiOS reads /api/v2/monitor/..., /api/v2/cmdb/... and /api/v2/log/...")
	}
	lp := strings.ToLower(path)
	for _, w := range []string{"backup", "download", "/export", "/packet-capture", "/certificate/", "restore"} {
		if strings.Contains(lp, w) {
			return nil, false, fmt.Errorf("path: %q downloads or changes something and is not read here", w)
		}
	}
	return apiGet(ctx, f.api, f.path(path), nil)
}

// APICatalog: FortiOS has no index of its API.  The cmdb tables and the monitor endpoints are in Fortinet's API
// documentation; this says how to look a table up.
func (f *fortios) APICatalog(ctx context.Context) (any, error) {
	return map[string]any{
		"how": "GET /api/v2/cmdb/<path>/<table> is configuration, /api/v2/monitor/<path> is live state, /api/v2/log/<device>/<type> is logs. " +
			"Add ?action=schema to a cmdb path to list that table's fields; ?format=name|status picks fields; ?with_meta=1 adds the entry counts. " +
			"Fortinet's FortiOS REST API reference lists every endpoint; FortiOS has no index to ask.",
		"examples": []string{"/api/v2/monitor/system/status", "/api/v2/monitor/system/resource/usage", "/api/v2/cmdb/firewall/policy", "/api/v2/cmdb/system/interface?action=schema"},
	}, nil
}

// Neighbors needs LLDP reception on the interfaces (config system interface ▸ set lldp-reception enable).
func (f *fortios) Neighbors(ctx context.Context) ([]Neighbor, error) {
	a, err := f.get(ctx, "/api/v2/monitor/network/lldp/neighbors")
	if err != nil {
		return nil, err
	}
	var out []Neighbor
	for _, r := range rows(a.Results) {
		n := Neighbor{LocalPort: firstOf(str(r["port_name"]), str(r["port"]), str(r["interface"])),
			RemoteName: firstOf(str(r["system_name"]), str(r["chassis_id"])), RemotePort: firstOf(str(r["port_id"]), str(r["port_description"])),
			RemoteDesc: str(r["system_description"]), Protocol: "lldp", Detail: redactMap(r)}
		for _, ad := range rows(r["addresses"]) {
			if n.RemoteAddr = str(ad["address"]); n.RemoteAddr != "" {
				break
			}
		}
		out = append(out, n)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].LocalPort < out[y].LocalPort })
	return out, nil
}

// Config is the full configuration file, as System ▸ Configuration ▸ Backup saves it.  Older releases answer a GET;
// 7.4 and later want a POST.
func (f *fortios) Config(ctx context.Context) (string, error) {
	scope := "global"
	if f.vdom != "" {
		scope = "vdom"
	}
	b, err := f.api.do(ctx, http.MethodGet, f.path("/api/v2/monitor/system/config/backup?scope="+scope), nil, http.Header{"Accept": {"*/*"}})
	if se, ok := err.(*statusError); ok && (se.Code == http.StatusMethodNotAllowed || se.Code == http.StatusNotFound) {
		b, err = f.api.do(ctx, http.MethodPost, f.path("/api/v2/monitor/system/config/backup"),
			map[string]string{"destination": "file", "scope": scope}, http.Header{"Accept": {"*/*"}})
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (f *fortios) Show(context.Context, string) (string, error) { return "", ErrUnsupported }

func (f *fortios) Close(context.Context) { f.api.close() }
