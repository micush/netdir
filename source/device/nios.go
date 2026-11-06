package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Infoblox NIOS (the DNS, DHCP and IPAM appliance, a grid of members) over its WAPI, /wapi/<version>/..., with HTTP basic
// authentication as an admin whose group may read ("superuser" is not needed: a read-only admin group is enough).  The option
// "wapi_version" picks the WAPI version ("v2.12" by default; NIOS 8.5 and later have it).  Only GET is ever sent: the
// function calls (?_function=...), which change things or make backups, are refused.
//
// NIOS is not a switch or a firewall: it has no LLDP neighbors, routing table, VLANs or running configuration, and no CLI
// over its API, so those answer ErrUnsupported.  What it has is read through its objects: facts and interfaces from the grid
// members, health (the capacity report and each member's services) as resources, and every object type (networks, zones,
// records, leases, ...) through the API request (APIGet).

func init() { Register("nios", newNIOS) }

var niosVersionRE = regexp.MustCompile(`^v\d{1,2}(\.\d{1,2}){1,2}$`)

type nios struct {
	d   Device
	api *apiClient
	ver string
}

func newNIOS(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Infoblox WAPI needs a username and a password", d.Name)
	}
	ver := d.Options["wapi_version"]
	if ver == "" {
		ver = "v2.12"
	}
	if !niosVersionRE.MatchString(ver) {
		return nil, fmt.Errorf("device %s: option wapi_version %q is not a WAPI version such as v2.12", d.Name, ver)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(c.Username, c.Password)
	api.hdr.Set("Authorization", req.Header.Get("Authorization"))
	return &nios{d: d, api: api, ver: ver}, nil
}

// get reads an object type with its query ("member?_return_fields=host_name"), below /wapi/<version>/.
func (n *nios) get(ctx context.Context, p string) (any, error) {
	var v any
	if err := n.api.getJSON(ctx, "/wapi/"+n.ver+"/"+p, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// objects reads a type with the fields wanted.  WAPI answers at most 1000 objects here (a larger number is cut, not an error).
func (n *nios) objects(ctx context.Context, typ, fields string, extra ...string) ([]map[string]any, error) {
	q := "_return_fields=" + url.QueryEscape(fields) + "&_max_results=1000"
	for _, e := range extra {
		q += "&" + e
	}
	v, err := n.get(ctx, typ+"?"+q)
	if err != nil {
		return nil, err
	}
	return rows(v), nil
}

func sub(m map[string]any, k string) map[string]any {
	s, _ := m[k].(map[string]any)
	return s
}

// firstRow is the first entry of a list of objects, an empty map when there is none.
func firstRow(v any) map[string]any {
	if r := rows(v); len(r) > 0 {
		return r[0]
	}
	return map[string]any{}
}

// self picks the member the device's address is: its VIP or its host name; the only member when there is one.
func (n *nios) self(members []map[string]any) map[string]any {
	for _, m := range members {
		if a := str(sub(m, "vip_setting")["address"]); (a != "" && a == n.d.Address) || strings.EqualFold(str(m["host_name"]), n.d.Address) {
			return m
		}
	}
	if len(members) == 1 {
		return members[0]
	}
	return nil
}

const niosMemberFields = "host_name,platform,vip_setting,ipv6_setting,node_info"

func (n *nios) Facts(ctx context.Context) (Facts, error) {
	members, err := n.objects(ctx, "member", niosMemberFields)
	if err != nil {
		return Facts{}, err
	}
	out := Facts{Vendor: "Infoblox"}
	m := n.self(members)
	if m == nil {
		// an address that is not a member's (a host name, a grid master candidate's other address): the grid is what answered
		if g, err := n.objects(ctx, "grid", "name"); err == nil && len(g) > 0 {
			out.Hostname = str(g[0]["name"])
		}
		return out, nil
	}
	out.Hostname = str(m["host_name"])
	ni := firstRow(m["node_info"])
	out.Model = firstOf(str(ni["hwmodel"]), str(ni["hwplatform"]), str(m["platform"]))
	out.Serial = str(ni["hwid"])
	// the NIOS version is the physical node's upgrade status; left out when this release does not answer it
	if ups, err := n.objects(ctx, "upgradestatus", "current_version,member,ipv4_address", "type=PNODE"); err == nil {
		for _, u := range ups {
			if str(u["member"]) == out.Hostname || str(u["ipv4_address"]) == str(sub(m, "vip_setting")["address"]) || len(ups) == 1 {
				out.OSVersion = str(u["current_version"])
				break
			}
		}
	}
	return out, nil
}

// cidr is an address with its dotted mask as "a.b.c.d/n".
func cidr(addr, mask string) string {
	if b := maskBits(mask); b > 0 {
		return fmt.Sprintf("%s/%d", addr, b)
	}
	return addr
}

// memberInterfaces are the addresses a member has: LAN1 (the VIP), LAN2, MGMT and the HA port.
func memberInterfaces(m map[string]any, prefix string) []Interface {
	var out []Interface
	add := func(name string, addrs ...string) {
		var a []string
		for _, x := range addrs {
			if x != "" {
				a = append(a, x)
			}
		}
		if len(a) > 0 {
			out = append(out, Interface{Name: prefix + name, Addresses: a})
		}
	}
	vip := sub(m, "vip_setting")
	v6 := sub(m, "ipv6_setting")
	var v6a string
	if b, _ := v6["enabled"].(bool); b && str(v6["virtual_ip"]) != "" {
		v6a = fmt.Sprintf("%s/%d", str(v6["virtual_ip"]), num(v6["cidr_prefix"]))
	}
	add("lan1", cidr(str(vip["address"]), str(vip["subnet_mask"])), v6a)
	ni := firstRow(m["node_info"])
	if s := sub(ni, "lan2_network_setting"); s != nil {
		add("lan2", cidr(str(s["address"]), str(s["subnet_mask"])))
	}
	if s := sub(ni, "mgmt_network_setting"); s != nil {
		add("mgmt", cidr(str(s["address"]), str(s["subnet_mask"])))
	}
	if s := sub(ni, "lan_ha_port_setting"); s != nil {
		add("ha", str(s["ha_ip_address"]))
	}
	return out
}

// Interfaces are the addresses of the member the device is, or of every member (named host/lan1) when it is not one.
func (n *nios) Interfaces(ctx context.Context) ([]Interface, error) {
	members, err := n.objects(ctx, "member", niosMemberFields)
	if err != nil {
		return nil, err
	}
	if m := n.self(members); m != nil {
		return memberInterfaces(m, ""), nil
	}
	var out []Interface
	for _, m := range members {
		out = append(out, memberInterfaces(m, str(m["host_name"])+"/")...)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func (n *nios) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (n *nios) Config(context.Context) (string, error)        { return "", ErrUnsupported }
func (n *nios) Show(context.Context, string) (string, error)  { return "", ErrUnsupported }

// Resources: the capacity report (the objects each member holds against what its hardware is rated for) and the state of
// each member's services.  NIOS reports no CPU, memory or sensor readings through WAPI.
func (n *nios) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"capacity_report", "capacityreport?_return_fields=" + url.QueryEscape("name,hardware_type,role,percent_used,total_objects,max_capacity") + "&_max_results=1000"},
		{"members", "member?_return_fields=" + url.QueryEscape("host_name,node_info") + "&_max_results=1000"},
	}, func(p string) (any, error) { return n.get(ctx, p) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	for _, r := range rows(d.Protocols["capacity_report"]) {
		out.Storage = append(out.Storage, Storage{Name: "object capacity " + str(r["name"]), UsedPercent: flt(r["percent_used"])})
	}
	ms := rows(d.Protocols["members"])
	for _, m := range ms {
		for _, ni := range rows(m["node_info"]) {
			for _, s := range rows(ni["service_status"]) {
				name := str(s["service"])
				if len(ms) > 1 {
					name = str(m["host_name"]) + " " + name
				}
				out.Sensors = append(out.Sensors, Sensor{Name: name, Kind: "other", State: strings.ToLower(str(s["status"])), Raw: s})
			}
		}
	}
	return out, nil
}

// APIGet reads any object type below /wapi/<version>/.  Function calls and file operations are not read here.
func (n *nios) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, q, _ := strings.Cut(path, "?")
	segs := strings.Split(strings.Trim(strings.ToLower(p), "/"), "/")
	if len(segs) < 2 || segs[0] != "wapi" || !niosVersionRE.MatchString(segs[1]) {
		return nil, false, errors.New("path: Infoblox reads /wapi/<version>/<object type> (e.g. /wapi/" + n.ver + "/network?_max_results=50)")
	}
	for _, s := range segs[2:] {
		if s == "fileop" || s == "request" || strings.HasPrefix(s, "restartservices") {
			return nil, false, fmt.Errorf("path: %q changes something or downloads a file and is not read here", s)
		}
	}
	if qs, err := url.ParseQuery(q); err != nil {
		return nil, false, errors.New("path: the query is not valid")
	} else {
		for k := range qs {
			lk := strings.ToLower(k)
			if lk == "_function" || lk == "_method" || lk == "_object" || strings.HasPrefix(lk, "_function") {
				return nil, false, errors.New("path: function calls change things and are not sent")
			}
		}
	}
	return apiGet(ctx, n.api, path, nil)
}

// APICatalog is WAPI's own list of the object types this release has.
func (n *nios) APICatalog(ctx context.Context) (any, error) {
	out := map[string]any{
		"how": "GET /wapi/" + n.ver + "/<object type>?<field>=<value> searches (=, ~= for a regular expression, :=, <=, >=), " +
			"_return_fields=a,b picks the fields, _max_results=N the most objects, _paging=1 with _max_results pages through more than 1000 (the answer holds next_page_id). " +
			"An object's _ref is its path: GET /wapi/" + n.ver + "/<_ref>. /wapi/" + n.ver + "/<object type>?_schema describes one type. " +
			"Infoblox's WAPI documentation lists every object type and field. Function calls are not sent.",
		"examples": []string{"/wapi/" + n.ver + "/grid", "/wapi/" + n.ver + "/member?_return_fields=host_name,node_info", "/wapi/" + n.ver + "/network?_max_results=50",
			"/wapi/" + n.ver + "/zone_auth?_return_fields=fqdn,view", "/wapi/" + n.ver + "/record:a?name~=example&_max_results=20", "/wapi/" + n.ver + "/lease?_max_results=50",
			"/wapi/" + n.ver + "/range?_max_results=50"},
	}
	if v, err := n.get(ctx, "?_schema"); err == nil {
		if m, ok := v.(map[string]any); ok {
			for _, k := range []string{"supported_objects", "supported_versions", "requested_version"} {
				if x, ok := m[k]; ok {
					out[k] = x
				}
			}
		}
	}
	return out, nil
}

func (n *nios) Close(context.Context) { n.api.close() }
