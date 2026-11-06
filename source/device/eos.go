package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Arista EOS over eAPI, the JSON-RPC interface at /command-api (POST {"method":"runCmds"}).  HTTP basic authentication as a user
// whose privilege level lets it run the show commands (15 for the running configuration); on the switch:
// "management api http-commands", "protocol https" and "no shutdown".  Only runCmds with the format "json" or "text" is ever
// sent, with one command per request, and every command goes through CheckShow: nothing that writes, and no "enable" or
// "configure" (so the user must already have the privilege).
//
// The structured answers are the ones of "show ... | json": the names are Arista's (modelName, interfaceStatus,
// lineProtocolStatus, interfaceCounters, lldpNeighborInfo, ...).

func init() { Register("eos", newEOS) }

type eos struct {
	d   Device
	api *apiClient
}

func newEOS(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: eAPI needs a username and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(c.Username, c.Password)
	api.hdr.Set("Authorization", req.Header.Get("Authorization"))
	return &eos{d: d, api: api}, nil
}

// eosError is a command eAPI answered with an error (the HTTP request itself worked): a command the release or the hardware
// does not have, an incomplete command, one the user may not run.  It unwraps to a statusError, so gather lists the part as
// unavailable.
type eosError struct {
	se       *statusError
	cmd, msg string
}

func (e *eosError) Error() string {
	return fmt.Sprintf("eAPI %q: %s (code %d)", e.cmd, e.msg, e.se.Code)
}
func (e *eosError) Unwrap() error { return e.se }

// run sends one show command and returns its answer: a JSON object for the format "json", the text for "text".
func (e *eos) run(ctx context.Context, format, cmd string) (any, error) {
	if format != "json" && format != "text" {
		return nil, fmt.Errorf("eAPI: the format %q is never sent", format)
	}
	if _, err := CheckShow(cmd); err != nil {
		return nil, err
	}
	m, err := e.post(ctx, []string{cmd}, format)
	if err != nil {
		return nil, err
	}
	if len(m.Result) == 0 {
		return nil, fmt.Errorf("eAPI %q: there is no result in the answer", cmd)
	}
	if format == "text" {
		if o, ok := m.Result[0].(map[string]any); ok {
			return str(o["output"]), nil
		}
		return "", nil
	}
	return m.Result[0], nil
}

// eosAnswer is the body of an eAPI answer.
type eosAnswer struct {
	Result []any `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// post sends commands in one eAPI request and returns the answer; an error the device answered is an eosError.  Only run (a show
// command, checked by CheckShow) and cfg (a configuration change built from a typed Change) call it.
func (e *eos) post(ctx context.Context, cmds []string, format string) (eosAnswer, error) {
	var m eosAnswer
	req := map[string]any{"jsonrpc": "2.0", "method": "runCmds", "id": "netdir",
		"params": map[string]any{"version": 1, "cmds": cmds, "format": format}}
	b, err := e.api.do(ctx, http.MethodPost, "/command-api", req, nil)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("eAPI %q: the answer is not JSON: %v", cmds[0], err)
	}
	if m.Error != nil {
		msg := firstOf(strings.TrimSpace(m.Error.Message), "the command failed")
		return m, &eosError{se: &statusError{Code: http.StatusBadRequest, Body: msg}, cmd: cmds[len(cmds)-1], msg: msg}
	}
	return m, nil
}

func (e *eos) get(ctx context.Context, cmd string) (any, error) { return e.run(ctx, "json", cmd) }

// obj is a command's answer as an object.
func (e *eos) obj(ctx context.Context, cmd string) (map[string]any, error) {
	v, err := e.get(ctx, cmd)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func (e *eos) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Arista"}
	v, err := e.obj(ctx, "show version")
	if err != nil {
		return f, err
	}
	f.Model, f.OSVersion, f.Serial = str(v["modelName"]), str(v["version"]), str(v["serialNumber"])
	if bt := int64(flt(v["bootupTimestamp"])); bt > 0 {
		if up := nowUnix() - bt; up > 0 {
			f.UptimeS = up
		}
	}
	if h, err := e.obj(ctx, "show hostname"); err == nil {
		f.Hostname = firstOf(str(h["hostname"]), str(h["fqdn"]))
	} else if !isDeviceRefusal(err) {
		return f, err
	}
	return f, nil
}

// sortedKeys are the keys of a map, in order.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// eosIfaces reads "show interfaces" as a list of its interfaces' objects, in name order, each with its name.
func (e *eos) eosIfaces(ctx context.Context) ([]map[string]any, error) {
	v, err := e.obj(ctx, "show interfaces")
	if err != nil {
		return nil, err
	}
	im, _ := v["interfaces"].(map[string]any)
	var out []map[string]any
	for _, k := range sortedKeys(im) {
		if m, ok := im[k].(map[string]any); ok {
			if str(m["name"]) == "" {
				c := make(map[string]any, len(m)+1)
				for kk, vv := range m {
					c[kk] = vv
				}
				c["name"] = k
				m = c
			}
			out = append(out, m)
		}
	}
	return out, nil
}

func eosInterface(r map[string]any) Interface {
	i := Interface{Name: str(r["name"]), Description: str(r["description"]), MAC: firstOf(str(r["physicalAddress"]), str(r["burnedInAddress"]))}
	if s := str(r["interfaceStatus"]); s != "" { // "disabled" is shut down; connected, notconnect, errdisabled are enabled
		i.AdminUp = boolp(s != "disabled")
	}
	if s := str(r["lineProtocolStatus"]); s != "" {
		i.OperUp = boolp(s == "up")
	}
	if bw := num(r["bandwidth"]); bw >= 1_000_000 { // bit/s; a virtual interface says 0
		i.SpeedMbps = bw / 1_000_000
	}
	for _, a := range rows(r["interfaceAddress"]) {
		if p := sub(a, "primaryIp"); p != nil && str(p["address"]) != "" && str(p["address"]) != "0.0.0.0" {
			i.Addresses = append(i.Addresses, fmt.Sprintf("%s/%d", str(p["address"]), num(p["maskLen"])))
		}
		for _, s := range rows(a["secondaryIpsOrderedList"]) {
			if str(s["address"]) != "" {
				i.Addresses = append(i.Addresses, fmt.Sprintf("%s/%d", str(s["address"]), num(s["maskLen"])))
			}
		}
	}
	if v6 := sub(r, "interfaceAddressIp6"); v6 != nil {
		for _, a := range rows(v6["globalUnicastIp6s"]) {
			if ad := str(a["address"]); ad != "" {
				if _, plen, ok := strings.Cut(str(a["subnet"]), "/"); ok {
					ad += "/" + plen
				}
				i.Addresses = append(i.Addresses, ad)
			}
		}
	}
	return i
}

func (e *eos) Interfaces(ctx context.Context) ([]Interface, error) {
	l, err := e.eosIfaces(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(l))
	for _, r := range l {
		out = append(out, eosInterface(r))
	}
	return out, nil
}

// Ports are the interfaces with their counters (interfaceCounters) and every attribute of the interface as properties.
func (e *eos) Ports(ctx context.Context) ([]Port, error) {
	l, err := e.eosIfaces(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Port, 0, len(l))
	for _, r := range l {
		p := Port{Interface: eosInterface(r), Type: str(r["interfaceType"]), MTU: num(r["mtu"]), Duplex: strings.ToLower(strings.TrimPrefix(str(r["duplex"]), "duplex"))}
		props := map[string]any{}
		for k, v := range redactMap(r) {
			if k != "interfaceCounters" {
				props[k] = v
			}
		}
		p.Properties = props
		if c := sub(r, "interfaceCounters"); c != nil {
			rc := redactMap(c)
			p.Counters = Counters{
				InOctets: num(c["inOctets"]), InUnicast: num(c["inUcastPkts"]), InMulticast: num(c["inMulticastPkts"]), InBroadcast: num(c["inBroadcastPkts"]),
				InDiscards: num(c["inDiscards"]), InErrors: num(c["totalInErrors"]),
				OutOctets: num(c["outOctets"]), OutUnicast: num(c["outUcastPkts"]), OutMulticast: num(c["outMulticastPkts"]), OutBroadcast: num(c["outBroadcastPkts"]),
				OutDiscards: num(c["outDiscards"]), OutErrors: num(c["totalOutErrors"]),
				RxPPS: int64(flt(c["inPktsRate"])), TxPPS: int64(flt(c["outPktsRate"])), RxKbps: int64(flt(c["inBitsRate"])) / 1000, TxKbps: int64(flt(c["outBitsRate"])) / 1000,
				Flaps: num(c["linkStatusChanges"]), All: rc,
			}
			p.Counters.InPackets = p.Counters.InUnicast + p.Counters.InMulticast + p.Counters.InBroadcast
			p.Counters.OutPackets = p.Counters.OutUnicast + p.Counters.OutMulticast + p.Counters.OutBroadcast
		}
		out = append(out, p)
	}
	return out, nil
}

// Neighbors are the LLDP neighbors with their details.
func (e *eos) Neighbors(ctx context.Context) ([]Neighbor, error) {
	v, err := e.obj(ctx, "show lldp neighbors detail")
	if err != nil {
		return nil, err
	}
	nm, _ := v["lldpNeighbors"].(map[string]any)
	var out []Neighbor
	for _, port := range sortedKeys(nm) {
		pm, _ := nm[port].(map[string]any)
		for _, r := range rows(pm["lldpNeighborInfo"]) {
			ni := sub(r, "neighborInterfaceInfo")
			n := Neighbor{LocalPort: port, RemoteName: firstOf(str(r["systemName"]), str(r["chassisId"])),
				RemotePort: strings.Trim(firstOf(str(ni["interfaceId_v2"]), str(ni["interfaceId"]), str(ni["interfaceDescription"])), `"`),
				RemoteDesc: strings.TrimSpace(str(r["systemDescription"])),
				RemoteAddr: "",
				Protocol:   "lldp",
				Detail:     redactMap(r),
			}
			for _, a := range rows(r["managementAddresses"]) {
				if n.RemoteAddr = str(a["address"]); n.RemoteAddr != "" {
					break
				}
			}
			out = append(out, n)
		}
	}
	return out, nil
}

// Routes are the IPv4 and IPv6 routes of every VRF, one entry per next hop.
func (e *eos) Routes(ctx context.Context) ([]Route, error) {
	var out []Route
	for i, cmd := range []string{"show ip route vrf all", "show ipv6 route vrf all"} {
		v, err := e.obj(ctx, cmd)
		if err != nil {
			if i > 0 && isDeviceRefusal(err) {
				continue // IPv6 routing is not on: the IPv4 table stands
			}
			return nil, err
		}
		vrfs, _ := v["vrfs"].(map[string]any)
		for _, vrf := range sortedKeys(vrfs) {
			vm, _ := vrfs[vrf].(map[string]any)
			rt := sub(vm, "routes")
			for _, prefix := range sortedKeys(rt) {
				r, _ := rt[prefix].(map[string]any)
				base := Route{Protocol: str(r["routeType"]), Prefix: prefix, VRF: vrf, Distance: num(r["preference"]), Metric: num(r["metric"])}
				vias := rows(r["vias"])
				if len(vias) == 0 {
					base.Raw = redactMap(r)
					out = append(out, base)
					continue
				}
				for _, via := range vias {
					rr := base
					rr.NextHop, rr.Interface = str(via["nexthopAddr"]), str(via["interface"])
					rr.Raw = redactMap(r)
					out = append(out, rr)
				}
			}
		}
	}
	return out, nil
}

// Routing: the state of BGP, OSPF, IS-IS, BFD, VRRP and MLAG, the route summary, the route maps and the prefix lists.
func (e *eos) Routing(ctx context.Context) (Routing, error) {
	return gather([]part{
		{"route_summary", "show ip route summary vrf all"},
		{"bgp_summary", "show ip bgp summary vrf all"},
		{"bgp_ipv6_summary", "show ipv6 bgp summary vrf all"},
		{"bgp_evpn_summary", "show bgp evpn summary"},
		{"ospf", "show ip ospf vrf all"},
		{"ospf_neighbors", "show ip ospf neighbor vrf all"},
		{"ospf_interfaces", "show ip ospf interface vrf all"},
		{"ospf3_neighbors", "show ipv6 ospf neighbor vrf all"},
		{"isis_neighbors", "show isis neighbors"},
		{"bfd_peers", "show bfd peers"},
		{"vrrp", "show vrrp"},
		{"mlag", "show mlag"},
		{"route_maps", "show route-map"},
		{"prefix_lists", "show ip prefix-list"},
	}, func(cmd string) (any, error) { return e.get(ctx, cmd) })
}

// Firewall: the access lists (with the entries' match counters where the switch counts them).
func (e *eos) Firewall(ctx context.Context) (Firewall, error) {
	return gather([]part{
		{"ip_access_lists", "show ip access-lists"},
		{"ipv6_access_lists", "show ipv6 access-lists"},
		{"mac_access_lists", "show mac access-lists"},
		{"ip_access_lists_summary", "show ip access-lists summary"},
	}, func(cmd string) (any, error) { return e.get(ctx, cmd) })
}

// findKey collects the values of every key of that name in an answer, at any depth (EOS nests its sensors under the
// slots of the chassis, the power supplies and the cards).
func findKey(v any, key string) []map[string]any {
	var out []map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, k := range sortedKeys(t) {
				if k == key {
					out = append(out, rows(t[k])...)
					continue
				}
				walk(t[k])
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(v)
	return out
}

// Resources: memory from "show version", CPU from "show processes top once", fans, temperatures and power supplies from
// "show environment".  The details hold each answer whole.
func (e *eos) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"version", "show version"},
		{"processes_top", "show processes top once"},
		{"cooling", "show environment cooling"},
		{"temperature", "show environment temperature"},
		{"power", "show environment power"},
	}, func(cmd string) (any, error) { return e.get(ctx, cmd) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	if v, ok := d.Protocols["version"].(map[string]any); ok {
		if tot := num(v["memTotal"]); tot > 0 { // kB
			free := num(v["memFree"])
			out.Memory = []Memory{{Name: "system", Total: tot * 1024, Free: free * 1024, Used: (tot - free) * 1024, UsedPercent: pct(tot-free, tot)}}
		}
	}
	if v, ok := d.Protocols["processes_top"].(map[string]any); ok {
		if c := sub(sub(v, "cpuInfo"), "%Cpu(s)"); c != nil {
			if _, has := c["idle"]; has {
				out.CPU = &CPU{Now: 100 - flt(c["idle"])}
			}
		}
	}
	for _, slot := range findKey(d.Protocols["cooling"], "fans") {
		s := Sensor{Name: str(slot["label"]), Kind: "fan", State: str(slot["status"]), Units: "%", Raw: slot}
		if _, ok := slot["actualSpeed"]; ok {
			s.Reading = new(float64)
			*s.Reading = flt(slot["actualSpeed"])
		}
		out.Sensors = append(out.Sensors, s)
	}
	for _, t := range findKey(d.Protocols["temperature"], "tempSensors") {
		s := Sensor{Name: firstOf(str(t["name"]), str(t["description"])), Kind: "temperature", State: str(t["hwStatus"]), Units: "C", Raw: t}
		if _, ok := t["currentTemperature"]; ok {
			s.Reading = new(float64)
			*s.Reading = flt(t["currentTemperature"])
		}
		out.Sensors = append(out.Sensors, s)
	}
	if pm, ok := d.Protocols["power"].(map[string]any); ok {
		ps, _ := pm["powerSupplies"].(map[string]any)
		for _, k := range sortedKeys(ps) {
			r, _ := ps[k].(map[string]any)
			s := Sensor{Name: "PSU " + k, Kind: "psu", State: str(r["state"]), Units: "W", Raw: r}
			if _, ok := r["outputPower"]; ok {
				s.Reading = new(float64)
				*s.Reading = flt(r["outputPower"])
			}
			out.Sensors = append(out.Sensors, s)
		}
	}
	return out, nil
}

// VLANs are the VLANs with their state and member ports.
func (e *eos) VLANs(ctx context.Context) ([]VLAN, error) {
	v, err := e.obj(ctx, "show vlan")
	if err != nil {
		return nil, err
	}
	vm, _ := v["vlans"].(map[string]any)
	var out []VLAN
	for k, x := range vm {
		r, _ := x.(map[string]any)
		l := VLAN{ID: num(k), Name: str(r["name"]), Status: str(r["status"]), Raw: redactMap(r)}
		if im, ok := r["interfaces"].(map[string]any); ok && len(im) > 0 {
			l.Ports = sortedKeys(im)
		}
		out = append(out, l)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

// Config is "show running-config" as the CLI prints it.
func (e *eos) Config(ctx context.Context) (string, error) { return e.text(ctx, "show running-config") }

// Show runs one show command and returns the text the CLI prints.
func (e *eos) Show(ctx context.Context, cmd string) (string, error) { return e.text(ctx, cmd) }

func (e *eos) text(ctx context.Context, cmd string) (string, error) {
	v, err := e.run(ctx, "text", cmd)
	if err != nil {
		return "", err
	}
	s, _ := v.(string)
	return s, nil
}

// eosCommand turns an API path into the command it names: /eapi/show/ip/route/vrf/all is "show ip route vrf all" (a word with
// a / in it, an interface, is written with %2F).  ?format=text asks for the text the CLI prints.
func eosCommand(path string) (cmd, format string, err error) {
	p, q, _ := strings.Cut(path, "?")
	if !strings.HasPrefix(p, "/eapi/") {
		return "", "", fmt.Errorf("path: Arista eAPI reads /eapi/<command words>, e.g. /eapi/show/version or /eapi/show/interfaces/Ethernet1%%2F1")
	}
	var words []string
	for _, w := range strings.Split(strings.Trim(strings.TrimPrefix(p, "/eapi/"), "/"), "/") {
		u, err := url.PathUnescape(w)
		if err != nil || u == "" {
			return "", "", fmt.Errorf("path: %q is not a command word", w)
		}
		words = append(words, u)
	}
	qs, err := url.ParseQuery(q)
	if err != nil {
		return "", "", fmt.Errorf("path: the query: %v", err)
	}
	format = "json"
	for k, v := range qs {
		if k != "format" || len(v) != 1 || v[0] != "json" && v[0] != "text" {
			return "", "", fmt.Errorf("path: only ?format=json or ?format=text may follow the command")
		}
		format = v[0]
	}
	cmd = strings.Join(words, " ")
	if _, err := CheckShow(cmd); err != nil {
		return "", "", err
	}
	return cmd, format, nil
}

// APIGet runs the show command a path names.  A JSON answer has its secrets hidden; ?format=text is text, for read-write
// callers only.
func (e *eos) APIGet(ctx context.Context, path string) (any, bool, error) {
	cmd, format, err := eosCommand(path)
	if err != nil {
		return nil, false, err
	}
	v, err := e.run(ctx, format, cmd)
	if err != nil {
		return nil, false, err
	}
	if format == "text" {
		return v, true, nil
	}
	return Redact(v), false, nil
}

func (e *eos) APICatalog(ctx context.Context) (any, error) {
	return map[string]any{
		"how": "eAPI runs CLI show commands. GET /eapi/<command words> runs one and answers its structured (JSON) result: /eapi/show/ip/route/vrf/all is \"show ip route vrf all\". " +
			"A word with a / in it is written with %2F (/eapi/show/interfaces/Ethernet1%2F1). Add ?format=text for the text the CLI prints (a command that has no structured form needs it). " +
			"Only show commands are run. Arista's eAPI command documentation lists what each command answers; add | json on the switch to see the structure.",
		"examples": []string{"/eapi/show/version", "/eapi/show/interfaces", "/eapi/show/ip/bgp/summary/vrf/all", "/eapi/show/lldp/neighbors/detail", "/eapi/show/vlan", "/eapi/show/running-config?format=text"},
	}, nil
}

func (e *eos) Close(context.Context) { e.api.close() }
