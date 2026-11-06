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
	"strings"
	"time"
)

// Aruba ArubaOS-CX (10.04 and later) over its REST API, /rest/<version>/...  The credential is a user name and a password:
// the driver logs in once (POST /rest/<version>/login, the credentials in the form body, never in a URL), keeps the session
// cookie and logs out in Close.  The login is the only POST; everything else is a GET.  The option "api_version" picks the
// REST version ("v10.09" by default; a release that does not have it answers 404 and the option names one it has).
//
// ArubaOS-CX's REST API runs no CLI commands, so Show answers ErrUnsupported.
//
// A resource is read with ?depth=2 (a collection with its members in full, not as URIs) and ?selector=status, configuration
// or statistics, the way the API's own documentation does.  The names of the REST keys come from Aruba's API reference;
// the ones that were only seen in the test stub are listed in the changelog.

func init() { Register("aoscx", newAOSCX) }

var cxVersionRE = regexp.MustCompile(`^v\d{1,2}(\.\d{1,2})?$`)

type aoscx struct {
	d      Device
	api    *apiClient
	user   string
	pass   string
	ver    string
	loaded bool // logged in
}

func newAOSCX(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: ArubaOS-CX needs a username and a password", d.Name)
	}
	ver := d.Options["api_version"]
	if ver == "" {
		ver = "v10.09"
	}
	if !cxVersionRE.MatchString(ver) {
		return nil, fmt.Errorf("device %s: option api_version %q is not a REST version such as v10.09", d.Name, ver)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	return &aoscx{d: d, api: api, user: c.Username, pass: c.Password, ver: ver}, nil
}

func (a *aoscx) path(p string) string { return "/rest/" + a.ver + p }

// login opens the session, once.
func (a *aoscx) login(ctx context.Context) error {
	if a.loaded {
		return nil
	}
	form := url.Values{"username": {a.user}, "password": {a.pass}}.Encode()
	_, err := a.api.do(ctx, http.MethodPost, a.path("/login"), form, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"*/*"}})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	a.loaded = true
	return nil
}

// get reads a resource as JSON; p is below /rest/<version>.
func (a *aoscx) get(ctx context.Context, p string) (any, error) {
	if err := a.login(ctx); err != nil {
		return nil, err
	}
	var v any
	if err := a.api.getJSON(ctx, a.path(p), &v); err != nil {
		return nil, err
	}
	return v, nil
}

// getSel reads a resource once for each selector and merges what the answers say about it (status over configuration);
// a selector the device refuses is skipped, and the last error is returned when none is answered.
func (a *aoscx) getSel(ctx context.Context, p string, sels ...string) (map[string]any, error) {
	out := map[string]any{}
	var last error
	got := false
	for _, s := range sels {
		sep := "?"
		if strings.Contains(p, "?") {
			sep = "&"
		}
		v, err := a.get(ctx, p+sep+"selector="+s)
		if err != nil {
			if isDeviceRefusal(err) {
				last = err
				continue
			}
			return nil, err
		}
		if m, ok := v.(map[string]any); ok {
			got = true
			for k, x := range m {
				out[k] = x
			}
		}
	}
	if !got {
		if last == nil {
			last = errors.New("the device answered nothing")
		}
		return nil, last
	}
	return out, nil
}

// cxItems reads a collection answered with depth=2: an object keyed by the member's name (URL-encoded) holding its attributes,
// or a list.  A member without a "name" attribute is named by its key.
func cxItems(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) > 0 {
			all := true
			for _, x := range t {
				if _, ok := x.(map[string]any); !ok {
					all = false
					break
				}
			}
			if !all { // one object, not a collection
				return []map[string]any{t}
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]map[string]any, 0, len(t))
		for _, k := range keys {
			m := t[k].(map[string]any)
			if str(m["name"]) == "" {
				c := make(map[string]any, len(m)+1)
				for kk, vv := range m {
					c[kk] = vv
				}
				c["name"] = cxUnescape(k)
				m = c
			}
			out = append(out, m)
		}
		return out
	case []any:
		return rows(t)
	}
	return nil
}

func cxUnescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// cxKeys are the names of a collection read with depth=1 (an object keyed by name, the values URIs) or a list of URIs.
func cxKeys(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k := range t {
			out = append(out, cxUnescape(k))
		}
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, cxLast(s))
			}
		}
	}
	sort.Strings(out)
	return out
}

// cxLast is the last path segment of a URI, decoded ("/rest/v10.09/system/interfaces/1%2F1%2F1" -> "1/1/1").
func cxLast(s string) string {
	s, _, _ = strings.Cut(s, "?")
	return cxUnescape(s[strings.LastIndex(s, "/")+1:])
}

// cxRefs are the names a reference attribute points at: an object keyed by name (or whose values are URIs), a URI, or a list.
func cxRefs(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{cxLast(t)}
		}
	case map[string]any:
		return cxKeys(t)
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, cxRefs(x)...)
		}
		return out
	}
	return nil
}

func cxEsc(s string) string { return url.PathEscape(s) }

func (a *aoscx) Facts(ctx context.Context) (Facts, error) {
	sys, err := a.getSel(ctx, "/system", "status", "configuration")
	if err != nil {
		return Facts{}, err
	}
	out := Facts{Vendor: "Aruba", Hostname: str(sys["hostname"]), Model: str(sys["platform_name"]), OSVersion: str(sys["software_version"])}
	if bt := num(sys["boot_time"]); bt > 0 {
		if bt > 1e11 { // milliseconds
			bt /= 1000
		}
		if up := nowUnix() - bt; up > 0 {
			out.UptimeS = up
		}
	}
	// the serial number and the product name are the chassis's
	if ch, err := a.getSel(ctx, "/system/subsystems/"+cxEsc("chassis,1"), "status"); err == nil {
		if pi, ok := ch["product_info"].(map[string]any); ok {
			out.Serial = str(pi["serial_number"])
			out.Model = firstOf(str(pi["product_name"]), out.Model)
		}
	}
	return out, nil
}

// interfaces reads the interfaces by selector: status (state, speed, MAC), configuration (description, addresses, VLANs) and,
// for ports, statistics.
func (a *aoscx) ifaceMaps(ctx context.Context, sel string) (map[string]map[string]any, error) {
	v, err := a.get(ctx, "/system/interfaces?depth=2&selector="+sel)
	if err != nil {
		return nil, err
	}
	m := map[string]map[string]any{}
	for _, r := range cxItems(v) {
		m[str(r["name"])] = r
	}
	return m, nil
}

func (a *aoscx) ifaces(ctx context.Context) ([]Interface, map[string]map[string]any, map[string]map[string]any, error) {
	st, err := a.ifaceMaps(ctx, "status")
	if err != nil {
		return nil, nil, nil, err
	}
	cf, err := a.ifaceMaps(ctx, "configuration")
	if err != nil {
		if !isDeviceRefusal(err) {
			return nil, nil, nil, err
		}
		cf = map[string]map[string]any{}
	}
	names := map[string]bool{}
	for n := range st {
		names[n] = true
	}
	for n := range cf {
		names[n] = true
	}
	var out []Interface
	for n := range names {
		s, c := st[n], cf[n]
		i := Interface{Name: n, Description: str(c["description"])}
		if st := str(s["admin_state"]); st != "" {
			i.AdminUp = boolp(st == "up")
		} else if uc, ok := c["user_config"].(map[string]any); ok && str(uc["admin"]) != "" {
			i.AdminUp = boolp(str(uc["admin"]) == "up")
		}
		if l := str(s["link_state"]); l != "" {
			i.OperUp = boolp(l == "up")
		}
		if sp := num(s["link_speed"]); sp > 0 { // bits per second
			i.SpeedMbps = sp / 1_000_000
		}
		i.MAC = firstOf(str(s["mac_in_use"]), str(c["mac"]))
		if ip := firstOf(str(c["ip4_address"]), str(s["ip4_address"])); ip != "" {
			i.Addresses = append(i.Addresses, ip)
		}
		for _, k := range []string{"ip4_address_secondary"} {
			if l, ok := c[k].([]any); ok {
				for _, x := range l {
					if s := str(x); s != "" {
						i.Addresses = append(i.Addresses, s)
					}
				}
			}
		}
		if m, ok := c["ip6_address"].(map[string]any); ok {
			for _, k := range cxKeys(m) {
				i.Addresses = append(i.Addresses, k)
			}
		}
		out = append(out, i)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Name < out[y].Name })
	return out, st, cf, nil
}

func (a *aoscx) Interfaces(ctx context.Context) ([]Interface, error) {
	out, _, _, err := a.ifaces(ctx)
	return out, err
}

// Ports are the interfaces with their statistics (rx/tx bytes, packets, errors, drops) and every attribute of their status
// and configuration as properties.
func (a *aoscx) Ports(ctx context.Context) ([]Port, error) {
	ifs, st, cf, err := a.ifaces(ctx)
	if err != nil {
		return nil, err
	}
	stats, err := a.ifaceMaps(ctx, "statistics")
	if err != nil {
		if !isDeviceRefusal(err) {
			return nil, err
		}
		stats = map[string]map[string]any{}
	}
	out := make([]Port, 0, len(ifs))
	for _, i := range ifs {
		p := Port{Interface: i, Type: str(st[i.Name]["type"]), MTU: num(st[i.Name]["mtu"]), Duplex: str(st[i.Name]["duplex"])}
		if p.Type == "" {
			p.Type = str(cf[i.Name]["type"])
		}
		if m := stats[i.Name]; m != nil {
			s, ok := m["statistics"].(map[string]any)
			if !ok {
				s = m
			}
			p.Counters = countersOf(redactMap(s))
			p.Counters.InDiscards = firstNum(p.Counters.InDiscards, num(s["rx_dropped"]))
			p.Counters.OutDiscards = firstNum(p.Counters.OutDiscards, num(s["tx_dropped"]))
		}
		p.Properties = map[string]any{}
		if m := st[i.Name]; m != nil {
			p.Properties["status"] = redactMap(m)
		}
		if m := cf[i.Name]; m != nil {
			p.Properties["configuration"] = redactMap(m)
		}
		out = append(out, p)
	}
	return out, nil
}

func firstNum(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

// Neighbors are the LLDP neighbors of each port that is up (a request per port: the API has the neighbors below the port).
func (a *aoscx) Neighbors(ctx context.Context) ([]Neighbor, error) {
	ifs, _, _, err := a.ifaces(ctx)
	if err != nil {
		return nil, err
	}
	var out []Neighbor
	n := 0
	for _, i := range ifs {
		if !strings.Contains(i.Name, "/") || i.OperUp != nil && !*i.OperUp { // a front-panel port (1/1/1), and one that is up
			continue
		}
		if n++; n > 256 {
			break
		}
		v, err := a.get(ctx, "/system/interfaces/"+cxEsc(i.Name)+"/lldp_neighbors?depth=2")
		if err != nil {
			if isDeviceRefusal(err) {
				continue
			}
			return nil, err
		}
		for _, r := range cxItems(v) {
			info, _ := r["neighbor_info"].(map[string]any)
			at := func(k string) string { return firstOf(str(info[k]), str(r[k])) }
			nb := Neighbor{LocalPort: i.Name, RemoteName: at("chassis_name"), RemotePort: firstOf(str(r["port_id"]), at("port_description")),
				RemoteDesc: at("chassis_description"), Protocol: "lldp", Detail: redactMap(r)}
			if nb.RemoteName == "" {
				nb.RemoteName = str(r["chassis_id"])
			}
			ip, _, _ := strings.Cut(at("mgmt_ip_list"), ",")
			nb.RemoteAddr = strings.TrimSpace(ip)
			out = append(out, nb)
		}
	}
	return out, nil
}

// Config is the running configuration as the API's fullconfigs resource answers it (JSON), indented.
func (a *aoscx) Config(ctx context.Context) (string, error) {
	if err := a.login(ctx); err != nil {
		return "", err
	}
	b, err := a.api.do(ctx, http.MethodGet, a.path("/fullconfigs/running-config"), nil, nil)
	if err != nil {
		return "", err
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		if ind, err := json.MarshalIndent(v, "", "  "); err == nil {
			return string(ind), nil
		}
	}
	return string(b), nil
}

func (a *aoscx) Show(context.Context, string) (string, error) { return "", ErrUnsupported }

// vrfs are the names of the VRFs, "default" first.
func (a *aoscx) vrfs(ctx context.Context) ([]string, error) {
	v, err := a.get(ctx, "/system/vrfs?depth=1")
	if err != nil {
		return nil, err
	}
	names := cxKeys(v)
	sort.SliceStable(names, func(x, y int) bool { return names[x] == "default" && names[y] != "default" })
	if len(names) > 16 {
		names = names[:16]
	}
	return names, nil
}

// Routes are the routes of every VRF (one entry per next hop).
func (a *aoscx) Routes(ctx context.Context) ([]Route, error) {
	vrfs, err := a.vrfs(ctx)
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, vrf := range vrfs {
		v, err := a.get(ctx, "/system/vrfs/"+cxEsc(vrf)+"/routes?depth=3")
		if err != nil {
			if isDeviceRefusal(err) {
				continue
			}
			return nil, err
		}
		for _, r := range cxItems(v) {
			base := Route{Protocol: str(r["from"]), Prefix: firstOf(str(r["prefix"]), str(r["name"])), VRF: vrf, Distance: num(r["distance"]), Metric: num(r["metric"])}
			nhs := cxItems(r["nexthops"])
			if len(nhs) == 0 {
				base.Raw = redactMap(r)
				out = append(out, base)
				continue
			}
			for _, nh := range nhs {
				rt := base
				rt.NextHop = str(nh["ip_address"])
				if p := cxRefs(nh["port"]); len(p) > 0 {
					rt.Interface = p[0]
				} else if m, ok := nh["port"].(map[string]any); ok {
					rt.Interface = str(m["name"])
				}
				rt.Raw = redactMap(r)
				out = append(out, rt)
			}
		}
	}
	return out, nil
}

// Routing: the configuration and state of BGP, OSPF and the static routes of each VRF, and the route maps and prefix lists.
func (a *aoscx) Routing(ctx context.Context) (Routing, error) {
	vrfs, err := a.vrfs(ctx)
	if err != nil {
		return Routing{}, err
	}
	var parts []part
	for _, vrf := range vrfs {
		e := cxEsc(vrf)
		parts = append(parts,
			part{"bgp_routers_" + vrf, "/system/vrfs/" + e + "/bgp_routers?depth=4"},
			part{"ospf_routers_" + vrf, "/system/vrfs/" + e + "/ospf_routers?depth=4"},
			part{"ospfv3_routers_" + vrf, "/system/vrfs/" + e + "/ospfv3_routers?depth=4"},
			part{"static_routes_" + vrf, "/system/vrfs/" + e + "/static_routes?depth=3"})
	}
	parts = append(parts, part{"route_maps", "/system/route_maps?depth=3"}, part{"prefix_lists", "/system/prefix_lists?depth=3"})
	return gather(parts, func(p string) (any, error) { return a.get(ctx, p) })
}

// Firewall: the ACLs with their entries and hit counters, the object groups and the policies.
func (a *aoscx) Firewall(ctx context.Context) (Firewall, error) {
	return gather([]part{
		{"acls", "/system/acls?depth=3"},
		{"acl_statistics", "/system/acls?depth=3&selector=statistics"},
		{"object_groups", "/system/object_groups?depth=2"},
		{"classes", "/system/classes?depth=3"},
		{"policies", "/system/policies?depth=3"},
	}, func(p string) (any, error) { return a.get(ctx, p) })
}

// Resources: CPU and memory from the subsystems' resource utilization, fans, temperatures and power supplies from the
// subsystems' children.
func (a *aoscx) Resources(ctx context.Context) (Resources, error) {
	v, err := a.get(ctx, "/system/subsystems?depth=1")
	if err != nil {
		return Resources{}, err
	}
	subs := cxKeys(v)
	if len(subs) > 32 {
		subs = subs[:32]
	}
	var parts []part
	for _, s := range subs {
		e := "/system/subsystems/" + cxEsc(s)
		parts = append(parts, part{s, e + "?selector=status"},
			part{s + " fans", e + "/fans?depth=2&selector=status"},
			part{s + " temp_sensors", e + "/temp_sensors?depth=2&selector=status"},
			part{s + " power_supplies", e + "/power_supplies?depth=2&selector=status"})
	}
	d, err := gather(parts, func(p string) (any, error) { return a.get(ctx, p) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	for _, s := range subs {
		if m, ok := d.Protocols[s].(map[string]any); ok && out.CPU == nil {
			if ru, ok := m["resource_utilization"].(map[string]any); ok {
				if _, has := ru["cpu"]; has {
					out.CPU = &CPU{Now: flt(ru["cpu"])}
				}
				if _, has := ru["memory"]; has {
					out.Memory = []Memory{{Name: "system", UsedPercent: flt(ru["memory"])}}
				}
			}
		}
		for _, r := range cxItems(d.Protocols[s+" fans"]) {
			sn := Sensor{Name: str(r["name"]), Kind: "fan", State: str(r["status"]), Units: "rpm", Raw: r}
			if _, ok := r["speed"]; ok {
				sn.Reading = new(float64)
				*sn.Reading = flt(r["speed"])
			}
			out.Sensors = append(out.Sensors, sn)
		}
		for _, r := range cxItems(d.Protocols[s+" temp_sensors"]) {
			sn := Sensor{Name: str(r["name"]), Kind: "temperature", State: str(r["status"]), Units: "C", Raw: r}
			if _, ok := r["temperature"]; ok {
				t := flt(r["temperature"])
				if t >= 1000 || t <= -1000 { // the API counts millidegrees
					t /= 1000
				}
				sn.Reading = &t
			}
			out.Sensors = append(out.Sensors, sn)
		}
		for _, r := range cxItems(d.Protocols[s+" power_supplies"]) {
			sn := Sensor{Name: str(r["name"]), Kind: "psu", State: str(r["status"]), Units: "W", Raw: r}
			if ch, ok := r["characteristics"].(map[string]any); ok {
				if _, ok := ch["instantaneous_power"]; ok {
					sn.Reading = new(float64)
					*sn.Reading = flt(ch["instantaneous_power"])
				}
			}
			out.Sensors = append(out.Sensors, sn)
		}
	}
	return out, nil
}

// VLANs are the VLANs with their state, and the ports that carry each (an access or native VLAN, or a trunk's allowed VLANs).
func (a *aoscx) VLANs(ctx context.Context) ([]VLAN, error) {
	v, err := a.get(ctx, "/system/vlans?depth=2")
	if err != nil {
		return nil, err
	}
	cf, err := a.ifaceMaps(ctx, "configuration")
	if err != nil {
		if !isDeviceRefusal(err) {
			return nil, err
		}
		cf = nil
	}
	ports := map[int64][]string{}
	for n, c := range cf {
		seen := map[int64]bool{}
		for _, k := range []string{"vlan_tag", "vlan_trunks"} {
			for _, id := range cxRefs(c[k]) {
				if x := num(id); x > 0 && !seen[x] {
					seen[x] = true
					ports[x] = append(ports[x], n)
				}
			}
		}
	}
	var out []VLAN
	for _, r := range cxItems(v) {
		id := num(r["id"])
		if id == 0 {
			id = num(r["name"])
		}
		l := VLAN{ID: id, Name: str(r["name"]), Status: firstOf(str(r["oper_state"]), str(r["admin"])), Raw: redactMap(r)}
		if n := str(r["name"]); n == str(id) { // the key is its name when the VLAN has none
			l.Name = ""
		}
		l.Ports = ports[id]
		sort.Strings(l.Ports)
		out = append(out, l)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].ID < out[y].ID })
	return out, nil
}

// APIGet reads any resource below /rest/.  The login and logout resources are not read here.
func (a *aoscx) APIGet(ctx context.Context, path string) (any, bool, error) {
	if !strings.HasPrefix(path, "/rest/") {
		return nil, false, errors.New("path: ArubaOS-CX reads /rest/<version>/... (e.g. /rest/v10.09/system/vrfs?depth=2)")
	}
	p, _, _ := strings.Cut(strings.ToLower(path), "?")
	for _, seg := range strings.Split(p, "/") {
		if seg == "login" || seg == "logout" {
			return nil, false, errors.New("path: the login and logout resources are not read here")
		}
	}
	if err := a.login(ctx); err != nil {
		return nil, false, err
	}
	return apiGet(ctx, a.api, path, nil)
}

func (a *aoscx) APICatalog(ctx context.Context) (any, error) {
	return map[string]any{
		"how": "GET /rest/" + a.ver + "/<resource> reads it. ?depth=1 lists a collection's members as URIs, ?depth=2 and more expand them. " +
			"?selector=configuration, status or statistics picks the part of the attributes; use one, a plain GET of a big resource is heavy on the switch. " +
			"A key with / or , in it is URL-encoded (interface 1/1/1 is 1%2F1%2F1). Aruba's AOS-CX REST API reference lists every resource; the switch has no index to ask. " +
			"The option api_version on the device picks the REST version (it is " + a.ver + ").",
		"examples": []string{"/rest/" + a.ver + "/system?selector=status", "/rest/" + a.ver + "/system/interfaces?depth=2&selector=status",
			"/rest/" + a.ver + "/system/vrfs/default/routes?depth=3", "/rest/" + a.ver + "/system/vlans?depth=2", "/rest/" + a.ver + "/system/acls?depth=3"},
	}, nil
}

// Close logs out, so the session does not stay one of the user's few.
func (a *aoscx) Close(ctx context.Context) {
	if a.loaded {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = a.api.do(ctx, http.MethodPost, a.path("/logout"), nil, http.Header{"Accept": {"*/*"}})
		a.loaded = false
	}
	a.api.close()
}
