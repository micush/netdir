package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cisco Nexus (NX-OS) over NX-API, with HTTP basic authentication as a user whose role may run show commands (network-operator
// is enough).  The switch needs:
//
//	feature nxapi
//	nxapi https port 443
//	username netdir role network-operator password <password>
//
// (add "nxapi use-vrf management" when the gateway reaches the switch through its management VRF).  Two parts of NX-API are used:
//
//   - NX-API CLI, POST /ins, runs show commands.  The named requests (facts, interfaces, ports, neighbors, routes, routing,
//     firewall, resources, vlans) ask for structured JSON ("cli_show"); Config and Show ask for the text the CLI prints
//     ("cli_show_ascii").  Only those two request types are ever sent, never "cli_conf" or "bash", and every command passes
//     CheckShow first, the driver's own included.
//   - NX-API REST, GET /api/mo/... and /api/class/..., the object model, for APIGet.  It logs in to a session (aaaLogin) the first
//     time a request needs it, and out again when the driver is closed.

func init() { Register("nxos", newNXOS) }

const (
	nxShow  = "cli_show"       // a show command, answered as structured JSON
	nxASCII = "cli_show_ascii" // a show command, answered as the text the CLI prints
)

type nxos struct {
	d          Device
	api        *apiClient
	user, pass string
	session    bool // the NX-API REST login was made
}

func newNXOS(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: NX-API needs a username and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(c.Username, c.Password)
	api.hdr.Set("Authorization", req.Header.Get("Authorization"))
	return &nxos{d: d, api: api, user: c.Username, pass: c.Password}, nil
}

// nxError is a command NX-API answered with an error code (the HTTP request itself worked): a command the release or the
// configured features do not have, for one.  It unwraps to a statusError, so gather lists the part as unavailable.
type nxError struct {
	se       *statusError
	cmd, msg string
}

func (e *nxError) Error() string {
	return fmt.Sprintf("NX-API %q: %s (code %d)", e.cmd, e.msg, e.se.Code)
}
func (e *nxError) Unwrap() error { return e.se }

// isDeviceRefusal says whether err is the device refusing a request (a command it lacks, a feature that is off) rather than a
// failure to reach it or to log in: a wrong password (401, 403) is never taken for "nothing there".
func isDeviceRefusal(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.Code != http.StatusUnauthorized && se.Code != http.StatusForbidden
}

// run sends one show command through NX-API CLI and returns the body of its answer: a JSON value for nxShow, text for nxASCII.
func (x *nxos) run(ctx context.Context, typ, cmd string) (any, error) {
	if typ != nxShow && typ != nxASCII {
		return nil, fmt.Errorf("NX-API: a request of type %q is never sent", typ)
	}
	if _, err := CheckShow(cmd); err != nil {
		return nil, err
	}
	req := map[string]any{"ins_api": map[string]any{"version": "1.0", "type": typ, "chunk": "0", "sid": "1", "input": cmd, "output_format": "json"}}
	b, err := x.api.do(ctx, http.MethodPost, "/ins", req, nil)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("NX-API %q: the answer is not JSON: %v", cmd, err)
	}
	ins, _ := m["ins_api"].(map[string]any)
	outs, _ := ins["outputs"].(map[string]any)
	outputs := rows(outs["output"])
	if len(outputs) == 0 {
		return nil, fmt.Errorf("NX-API %q: there is no output in the answer", cmd)
	}
	o := outputs[0]
	if code := str(o["code"]); code != "200" {
		c := int(num(o["code"]))
		if c < 100 || c > 599 {
			c = http.StatusBadRequest
		}
		msg := firstOf(strings.TrimSpace(str(o["msg"])), "the command failed")
		return nil, &nxError{se: &statusError{Code: c, Body: msg}, cmd: cmd, msg: msg}
	}
	return o["body"], nil
}

// get runs a command for its structured answer.
func (x *nxos) get(ctx context.Context, cmd string) (any, error) { return x.run(ctx, nxShow, cmd) }

// text runs a command for the text the CLI prints.
func (x *nxos) text(ctx context.Context, cmd string) (string, error) {
	v, err := x.run(ctx, nxASCII, cmd)
	if err != nil {
		return "", err
	}
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	}
	b, _ := json.MarshalIndent(v, "", "  ") // a release that answers structured data to an ASCII request
	return string(b), nil
}

// nxRows finds a table (TABLE_x) anywhere in an answer and returns its rows (ROW_x).  NX-API nests its tables differently from
// release to release and writes a table of one row as an object, not a list.
func nxRows(v any, table string) []map[string]any {
	row := "ROW_" + strings.TrimPrefix(table, "TABLE_")
	var out []map[string]any
	var walk func(v any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			if tv, ok := t[table]; ok {
				if tm, ok := tv.(map[string]any); ok {
					out = rows(tm[row])
				}
				return true // an empty table is "" or missing its rows
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if walk(t[k]) {
					return true
				}
			}
		case []any:
			for _, e := range t {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	walk(v)
	return out
}

func (x *nxos) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Cisco"}
	v, err := x.get(ctx, "show version")
	if err != nil {
		return f, err
	}
	m, _ := v.(map[string]any)
	f.Hostname = str(m["host_name"])
	f.OSVersion = nxVersion(firstOf(str(m["nxos_ver_str"]), str(m["sys_ver_str"]), str(m["kickstart_ver_str"]), str(m["rr_sys_ver"])))
	f.Serial = str(m["proc_board_id"])
	f.Model = nxModel(str(m["chassis_id"]))
	if secs := num(m["kern_uptm_days"])*86400 + num(m["kern_uptm_hrs"])*3600 + num(m["kern_uptm_mins"])*60 + num(m["kern_uptm_secs"]); secs > 0 {
		f.UptimeS = secs
	}
	// the chassis line of the inventory has the part number and the serial number of the box itself (the first, on a chassis with modules)
	if inv, err := x.get(ctx, "show inventory"); err == nil {
		for _, r := range nxRows(inv, "TABLE_inv") {
			if strings.EqualFold(strings.Trim(strings.TrimSpace(str(r["name"])), `"`), "chassis") {
				f.Model = firstOf(str(r["productid"]), f.Model)
				f.Serial = firstOf(str(r["serialnum"]), f.Serial)
				break
			}
		}
	} else if !isDeviceRefusal(err) {
		return f, err
	}
	return f, nil
}

// nxVersion is the release without the build detail ("9.2(2) [build 9.2(1.47)]" -> "9.2(2)").
func nxVersion(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " ["); i > 0 {
		s = s[:i]
	}
	return s
}

// nxModel is the model out of the chassis description ("Nexus9000 C9396PX Chassis" -> "C9396PX").
func nxModel(s string) string {
	var out []string
	for _, w := range strings.Fields(s) {
		lw := strings.ToLower(w)
		if lw == "cisco" || lw == "chassis" || strings.HasPrefix(lw, "nexus") {
			continue
		}
		out = append(out, w)
	}
	return strings.Join(out, " ")
}

// nxIfName gives the names NX-OS prints in different places one spelling ("Eth1/1" and "Ethernet1/1", "Po1" and "port-channel1").
func nxIfName(s string) string {
	s = strings.TrimSpace(s)
	l := strings.ToLower(s)
	digitAt := func(i int) bool { return len(s) > i && s[i] >= '0' && s[i] <= '9' }
	switch {
	case strings.HasPrefix(l, "ethernet"):
		return "Ethernet" + s[len("ethernet"):]
	case strings.HasPrefix(l, "eth") && digitAt(3):
		return "Ethernet" + s[3:]
	case strings.HasPrefix(l, "po") && digitAt(2):
		return "port-channel" + s[2:]
	}
	return s
}

// nxInterface is the common shape of one row of show interface (Ethernet, mgmt, loopback and port-channel rows use eth_* keys,
// VLAN interfaces svi_*).
func nxInterface(r map[string]any) Interface {
	name := str(r["interface"])
	i := Interface{Name: name, Description: firstOf(str(r["desc"]), str(r["svi_desc"])),
		MAC: firstOf(str(r["eth_hw_addr"]), str(r["svi_mac"]), str(r["svi_hw_addr"]))}
	if s := firstOf(str(r["admin_state"]), str(r["svi_admin_state"])); s != "" {
		i.AdminUp = boolp(s == "up")
	}
	if s := firstOf(str(r["state"]), str(r["svi_line_proto"])); s != "" {
		i.OperUp = boolp(s == "up")
	}
	i.SpeedMbps = nxSpeedMbps(r, name)
	for _, p := range [][2]string{{"eth_ip_addr", "eth_ip_mask"}, {"svi_ip_addr", "svi_ip_mask"}} {
		if ip := str(r[p[0]]); ip != "" && ip != "0.0.0.0" {
			if m := str(r[p[1]]); m != "" {
				ip += "/" + m
			}
			i.Addresses = append(i.Addresses, ip)
		}
	}
	return i
}

// nxSpeedMbps reads "10 Gb/s" or "1000 Mb/s"; a port that has not negotiated says "auto-speed", and then the nominal bandwidth
// (kbit/s) stands.  A virtual interface has no speed.
func nxSpeedMbps(r map[string]any, name string) int64 {
	if f := strings.Fields(strings.ToLower(str(r["eth_speed"]))); len(f) >= 2 {
		if n, err := strconv.ParseFloat(f[0], 64); err == nil {
			switch {
			case strings.HasPrefix(f[1], "gb"):
				return int64(n * 1000)
			case strings.HasPrefix(f[1], "mb"):
				return int64(n)
			case strings.HasPrefix(f[1], "kb"):
				return int64(n / 1000)
			}
		}
	}
	l := strings.ToLower(name)
	for _, virt := range []string{"loopback", "vlan", "nve", "tunnel", "mgmt"} {
		if strings.HasPrefix(l, virt) {
			return 0
		}
	}
	if bw := num(r["eth_bw"]); bw > 0 {
		return bw / 1000
	}
	return 0
}

func (x *nxos) interfaceRows(ctx context.Context) ([]map[string]any, error) {
	v, err := x.get(ctx, "show interface")
	if err != nil {
		return nil, err
	}
	return nxRows(v, "TABLE_interface"), nil
}

func (x *nxos) Interfaces(ctx context.Context) ([]Interface, error) {
	rs, err := x.interfaceRows(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(rs))
	for _, r := range rs {
		out = append(out, nxInterface(r))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// numericFields are the entries of r whose value is a number (or a string of one): the counters and sizes of an interface row.
func numericFields(r map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range r {
		switch t := v.(type) {
		case float64:
			out[k] = t
		case string:
			if _, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
				out[k] = t
			}
		}
	}
	return out
}

// nxCounters reads the eth_* statistics of one show interface row.  The rates are the 30-second ones (load-interval 1).
func nxCounters(r map[string]any) Counters {
	n := func(k string) int64 { return num(r[k]) }
	c := Counters{
		InOctets: n("eth_inbytes"), InPackets: n("eth_inpkts"), InUnicast: n("eth_inucast"), InMulticast: n("eth_inmcast"), InBroadcast: n("eth_inbcast"),
		InDiscards: n("eth_indiscard"), InErrors: n("eth_inerr"),
		OutOctets: n("eth_outbytes"), OutPackets: n("eth_outpkts"), OutUnicast: n("eth_outucast"), OutMulticast: n("eth_outmcast"), OutBroadcast: n("eth_outbcast"),
		OutDiscards: n("eth_outdiscard"), OutErrors: n("eth_outerr"),
		RxPPS: n("eth_inrate1_pkts"), TxPPS: n("eth_outrate1_pkts"), RxKbps: n("eth_inrate1_bits") / 1000, TxKbps: n("eth_outrate1_bits") / 1000,
		All: numericFields(r),
	}
	if c.InPackets == 0 {
		c.InPackets = c.InUnicast + c.InMulticast + c.InBroadcast
	}
	if c.OutPackets == 0 {
		c.OutPackets = c.OutUnicast + c.OutMulticast + c.OutBroadcast
	}
	return c
}

// Ports are the rows of show interface with their counters, and every property the row has.
func (x *nxos) Ports(ctx context.Context) ([]Port, error) {
	rs, err := x.interfaceRows(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Port, 0, len(rs))
	for _, r := range rs {
		out = append(out, Port{Interface: nxInterface(r), Type: firstOf(str(r["eth_hw_desc"]), str(r["medium"])), MTU: num(firstAny(r["eth_mtu"], r["svi_mtu"])),
			Duplex: str(r["eth_duplex"]), Counters: nxCounters(r), Properties: redactMap(r)})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// Neighbors are the LLDP neighbors, and the CDP ones on the ports LLDP has none for.  A neighbor protocol that is off on the
// switch (no "feature lldp") is no neighbors, not an error.
func (x *nxos) Neighbors(ctx context.Context) ([]Neighbor, error) {
	var out []Neighbor
	seen := map[string]bool{}
	v, err := x.get(ctx, "show lldp neighbors detail")
	switch {
	case err == nil:
		for _, r := range nxRows(v, "TABLE_nbor_detail") {
			lp := nxIfName(str(r["l_port_id"]))
			n := Neighbor{LocalPort: lp, RemoteName: str(r["sys_name"]), RemotePort: firstOf(str(r["port_id"]), str(r["port_desc"])),
				RemoteDesc: str(r["sys_desc"]), RemoteAddr: firstOf(str(r["mgmt_addr"]), str(r["mgmt_addr_ipv6"])), Protocol: "lldp", Detail: redactMap(r)}
			if n.RemoteAddr == "not advertised" {
				n.RemoteAddr = ""
			}
			out = append(out, n)
			seen[strings.ToLower(lp)] = true
		}
	case !isDeviceRefusal(err):
		return nil, err
	}
	v, err = x.get(ctx, "show cdp neighbors detail")
	switch {
	case err == nil:
		for _, r := range nxRows(v, "TABLE_cdp_neighbor_detail_info") {
			lp := nxIfName(str(r["intf_id"]))
			if seen[strings.ToLower(lp)] {
				continue
			}
			out = append(out, Neighbor{LocalPort: lp, RemoteName: cdpName(str(r["device_id"])), RemotePort: str(r["port_id"]), RemoteDesc: str(r["platform_id"]),
				RemoteAddr: firstOf(str(r["v4mgmtaddr"]), str(r["v4addr"])), Protocol: "cdp", Detail: redactMap(r)})
		}
	case !isDeviceRefusal(err):
		return nil, err
	}
	sort.Slice(out, func(a, b int) bool { return out[a].LocalPort < out[b].LocalPort })
	return out, nil
}

// cdpName drops the serial number Nexus switches append to their CDP device ID ("n9k-2(SAL1819ABCD)" -> "n9k-2").
func cdpName(s string) string {
	if i := strings.LastIndex(s, "("); i > 0 && strings.HasSuffix(s, ")") {
		if in := s[i+1 : len(s)-1]; len(in) >= 8 && !strings.ContainsAny(in, " ,") {
			return s[:i]
		}
	}
	return s
}

// Routes are the IPv4 and IPv6 routing tables of every VRF, one route per next hop.
func (x *nxos) Routes(ctx context.Context) ([]Route, error) {
	var out []Route
	var last error
	for _, cmd := range []string{"show ip route vrf all", "show ipv6 route vrf all"} {
		v, err := x.get(ctx, cmd)
		if err != nil {
			if isDeviceRefusal(err) {
				last = err // no IPv6 routing, or an IPv4-only release: the other table stands
				continue
			}
			return nil, err
		}
		for _, vrf := range nxRows(v, "TABLE_vrf") {
			name := str(vrf["vrf-name-out"])
			for _, af := range nxRows(vrf, "TABLE_addrf") {
				for _, pf := range nxRows(af, "TABLE_prefix") {
					prefix := str(pf["ipprefix"])
					for _, p := range nxRows(pf, "TABLE_path") {
						raw := map[string]any{"ipprefix": prefix, "addrf": str(af["addrf"]), "vrf": name}
						for k, pv := range p {
							raw[k] = pv
						}
						out = append(out, Route{Protocol: nxProtocol(str(p["clientname"])), Prefix: prefix, NextHop: str(p["ipnexthop"]), Interface: str(p["ifname"]),
							Metric: num(p["metric"]), Distance: num(p["pref"]), VRF: name, Raw: redactMap(raw)})
					}
				}
			}
		}
	}
	if len(out) == 0 && last != nil {
		return nil, last
	}
	return out, nil
}

// nxProtocol names the protocol of a route from NX-OS's client name ("ospf-1", "bgp-65000", "direct", "am").
func nxProtocol(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	if i := strings.Index(c, "-"); i > 0 {
		c = c[:i]
	}
	switch c {
	case "direct":
		return "connected"
	case "am":
		return "host"
	}
	return c
}

// Routing: the state of each routing protocol, from show commands (structured), and the static routes.
func (x *nxos) Routing(ctx context.Context) (Routing, error) {
	return gather([]part{
		{"static", "show ip route static vrf all"},
		{"static_ipv6", "show ipv6 route static vrf all"},
		{"ospf", "show ip ospf neighbors vrf all"},
		{"ospf_interfaces", "show ip ospf interface vrf all"},
		{"ospfv3", "show ospfv3 neighbors vrf all"},
		{"bgp", "show bgp ipv4 unicast summary vrf all"},
		{"bgp_ipv6", "show bgp ipv6 unicast summary vrf all"},
		{"bgp_l2vpn_evpn", "show bgp l2vpn evpn summary"},
		{"bgp_sessions", "show bgp sessions vrf all"},
		{"eigrp", "show ip eigrp neighbors vrf all"},
		{"isis", "show isis adjacency vrf all"},
		{"rip", "show ip rip neighbor vrf all"},
		{"bfd", "show bfd neighbors"},
		{"pim", "show ip pim neighbor vrf all"},
		{"vrf", "show vrf all"},
	}, func(c string) (any, error) { return x.get(ctx, c) })
}

// Firewall: a switch filters with access lists; these are the IPv4, IPv6 and MAC lists with the match counter of each entry
// (where "statistics per-entry" is set), the object groups, and the control-plane policy with its counters.
func (x *nxos) Firewall(ctx context.Context) (Firewall, error) {
	return gather([]part{
		{"ip_access_lists", "show ip access-lists"},
		{"ipv6_access_lists", "show ipv6 access-lists"},
		{"mac_access_lists", "show mac access-lists"},
		{"object_groups", "show object-group"},
		{"copp", "show policy-map interface control-plane"},
	}, func(c string) (any, error) { return x.get(ctx, c) })
}

// Resources: CPU and memory of the supervisor, the modules, and the environment (fans, temperatures, power supplies).  NX-API
// has no structured file system list, so storage is not answered.
func (x *nxos) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"system_resources", "show system resources"},
		{"modules", "show module"},
		{"fans", "show environment fan"},
		{"temperature", "show environment temperature"},
		{"power", "show environment power"},
		{"hardware_inventory", "show inventory"},
	}, func(c string) (any, error) { return x.get(ctx, c) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	if m, ok := d.Protocols["system_resources"].(map[string]any); ok {
		if str(m["cpu_state_idle"]) != "" {
			out.CPU = &CPU{Now: math.Round((100-flt(m["cpu_state_idle"]))*100) / 100} // percent, 2 decimals
		}
		if total := num(m["memory_usage_total"]) * 1024; total > 0 { // the answer is in KB
			mem := Memory{Name: "system", Total: total, Used: num(m["memory_usage_used"]) * 1024, Free: num(m["memory_usage_free"]) * 1024}
			mem.UsedPercent = pct(mem.Used, mem.Total)
			out.Memory = append(out.Memory, mem)
		}
	}
	for _, r := range nxRows(d.Protocols["fans"], "TABLE_faninfo") {
		out.Sensors = append(out.Sensors, Sensor{Name: str(r["fanname"]), Kind: "fan", State: str(r["fanstatus"]), Raw: r})
	}
	for _, r := range nxRows(d.Protocols["temperature"], "TABLE_tempinfo") {
		s := Sensor{Name: strings.TrimSpace("module " + str(r["tempmod"]) + " " + str(r["sensor"])), Kind: "temperature", State: str(r["alarmstatus"]), Units: "celsius", Raw: r}
		if _, has := r["curtemp"]; has {
			s.Reading = new(float64)
			*s.Reading = flt(r["curtemp"])
		}
		out.Sensors = append(out.Sensors, s)
	}
	for _, r := range nxRows(d.Protocols["power"], "TABLE_psinfo") {
		s := Sensor{Name: strings.TrimSpace("PS" + str(r["psnum"]) + " " + str(r["psmodel"])), Kind: "psu", State: firstOf(str(r["ps_status"]), str(r["ps_state"])), Raw: r}
		if w := str(r["actual_out"]); w != "" {
			s.Units = "W"
			s.Reading = new(float64)
			*s.Reading = flt(w) // "98 W"
		}
		out.Sensors = append(out.Sensors, s)
	}
	return out, nil
}

// VLANs are the rows of show vlan brief.
func (x *nxos) VLANs(ctx context.Context) ([]VLAN, error) {
	v, err := x.get(ctx, "show vlan brief")
	if err != nil {
		return nil, err
	}
	var out []VLAN
	for _, r := range nxRows(v, "TABLE_vlanbriefxbrief") {
		l := VLAN{ID: num(r["vlanshowbr-vlanid"]), Name: str(r["vlanshowbr-vlanname"]), Status: str(r["vlanshowbr-vlanstate"]), Raw: redactMap(r)}
		for _, p := range strings.Split(str(r["vlanshowplist-ifidx"]), ",") {
			if p = strings.TrimSpace(p); p != "" {
				l.Ports = append(l.Ports, nxIfName(p))
			}
		}
		out = append(out, l)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

// Config is the running configuration as show running-config prints it.
func (x *nxos) Config(ctx context.Context) (string, error) { return x.text(ctx, "show running-config") }

// Show runs one show command and returns the text the CLI prints.  Output filters work as on the switch ("| include", "| json").
func (x *nxos) Show(ctx context.Context, cmd string) (string, error) {
	cmd, err := CheckShow(cmd)
	if err != nil {
		return "", err
	}
	return x.text(ctx, cmd)
}

// nxRESTPrefixes are the parts of NX-API REST that are read: the object model, by managed object or by class.
var nxRESTPrefixes = []string{"/api/mo/", "/api/class/", "/api/node/mo/", "/api/node/class/"}

// login starts the NX-API REST session (a cookie, kept by the client).
func (x *nxos) login(ctx context.Context) error {
	if x.session {
		return nil
	}
	body := map[string]any{"aaaUser": map[string]any{"attributes": map[string]any{"name": x.user, "pwd": x.pass}}}
	if _, err := x.api.do(ctx, http.MethodPost, "/api/aaaLogin.json", body, nil); err != nil {
		return fmt.Errorf("NX-API REST login (feature nxapi, release 7.0(3)I2 or later): %w", err)
	}
	x.session = true
	return nil
}

// APIGet reads one managed object or class of NX-API REST ("/api/mo/sys/intf.json", "/api/class/ipv4Route.json?rsp-subtree=full").
func (x *nxos) APIGet(ctx context.Context, path string) (any, bool, error) {
	ok := false
	for _, pre := range nxRESTPrefixes {
		ok = ok || strings.HasPrefix(path, pre)
	}
	if !ok {
		return nil, false, fmt.Errorf("path: NX-OS reads /api/mo/<dn>.json and /api/class/<class>.json (the catalog has examples)")
	}
	if err := x.login(ctx); err != nil {
		return nil, false, err
	}
	return apiGet(ctx, x.api, path, nil)
}

// APICatalog: NX-API REST has no index of its classes.  This says how a path is built and lists what is under sys, the root of
// the object model.
func (x *nxos) APICatalog(ctx context.Context) (any, error) {
	out := map[string]any{
		"how": "GET /api/mo/<dn>.json reads one managed object by its distinguished name (/api/mo/sys.json is the system root); GET /api/class/<class>.json reads every object of a class. " +
			"Add ?rsp-subtree=children or =full for what is below, ?query-target=children, ?rsp-prop-include=config-only or naming-only, ?query-target-filter=eq(<class>.<property>,\"<value>\"). " +
			"show commands go through device_show.",
		"examples": []string{"/api/mo/sys/ch.json?rsp-subtree=children", "/api/mo/sys/intf.json?rsp-subtree=children&rsp-prop-include=naming-only",
			"/api/class/ipv4Route.json", "/api/class/ethpmPhysIf.json", "/api/class/topSystem.json"},
	}
	if v, _, err := x.APIGet(ctx, "/api/mo/sys.json?query-target=children&rsp-prop-include=naming-only"); err != nil {
		out["children_of_sys_error"] = err.Error()
	} else if m, ok := v.(map[string]any); ok {
		var classes []string
		for _, e := range rows(m["imdata"]) {
			for k := range e {
				classes = append(classes, k)
			}
		}
		sort.Strings(classes)
		out["children_of_sys"] = classes
	}
	return out, nil
}

func (x *nxos) Close(ctx context.Context) {
	if x.session {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		body := map[string]any{"aaaUser": map[string]any{"attributes": map[string]any{"name": x.user}}}
		_, _ = x.api.do(c, http.MethodPost, "/api/aaaLogout.json", body, nil)
	}
	x.api.close()
}
