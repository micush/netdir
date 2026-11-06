package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cisco IOS-XE (Catalyst 9000 and others) over RESTCONF (RFC 8040), /restconf/data/<YANG model>, HTTP basic
// authentication as a privilege-15 user.  The switch needs:
//
//	ip http secure-server
//	ip http authentication local
//	restconf
//
// Facts, interfaces and neighbors come from Cisco's operational models.  RESTCONF runs no CLI commands, so Show answers
// ErrUnsupported, and Config is the native configuration model as JSON, not the text "show running-config" prints
// (both come with an SSH transport later).

func init() { Register("iosxe", newIOSXE) }

const yangJSON = "application/yang-data+json"

type iosxe struct {
	d   Device
	api *apiClient
}

func newIOSXE(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: RESTCONF needs a username and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(c.Username, c.Password)
	api.hdr.Set("Authorization", req.Header.Get("Authorization"))
	api.hdr.Set("Accept", yangJSON)
	return &iosxe{d: d, api: api}, nil
}

// get reads one RESTCONF resource and returns what is inside its single top-level key
// ({"Cisco-IOS-XE-...:interface": [...]} -> [...]).  A resource that does not exist (404, or 204 for an empty list)
// is nil, no error: a switch with no LLDP neighbors answers that way.
func (x *iosxe) get(ctx context.Context, path string) (any, error) {
	b, err := x.api.do(ctx, http.MethodGet, "/restconf/data/"+path, nil, nil)
	if se, ok := err.(*statusError); ok && se.Code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("RESTCONF %s: the answer is not JSON: %v", path, err)
	}
	for _, v := range m {
		return v, nil
	}
	return nil, nil
}

func (x *iosxe) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Cisco"}
	hn, err := x.get(ctx, "Cisco-IOS-XE-native:native/hostname")
	if err != nil {
		return f, err
	}
	f.Hostname = str(hn)
	hw, err := x.get(ctx, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware")
	if err != nil {
		return f, err
	}
	m, _ := hw.(map[string]any)
	// the first chassis is the switch (the active member of a stack)
	for _, inv := range rows(m["device-inventory"]) {
		if str(inv["hw-type"]) == "hw-type-chassis" {
			f.Model, f.Serial = str(inv["part-number"]), str(inv["serial-number"])
			break
		}
	}
	if sd, ok := m["device-system-data"].(map[string]any); ok {
		f.OSVersion = iosxeVersion(str(sd["software-version"]))
		bt, e1 := time.Parse(time.RFC3339, str(sd["boot-time"]))
		ct, e2 := time.Parse(time.RFC3339, str(sd["current-time"]))
		if e1 == nil && e2 == nil && ct.After(bt) {
			f.UptimeS = int64(ct.Sub(bt).Seconds())
		}
	}
	return f, nil
}

// iosxeVersion takes "17.9.4a" out of the banner the switch reports as its software version
// ("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE ...").
func iosxeVersion(s string) string {
	if i := strings.Index(s, "Version "); i >= 0 {
		v := s[i+len("Version "):]
		if j := strings.IndexAny(v, ", \n"); j >= 0 {
			v = v[:j]
		}
		return v
	}
	return s
}

func (x *iosxe) Interfaces(ctx context.Context) ([]Interface, error) {
	v, err := x.get(ctx, "Cisco-IOS-XE-interfaces-oper:interfaces/interface")
	if err != nil {
		return nil, err
	}
	rs := rows(v)
	out := make([]Interface, 0, len(rs))
	for _, r := range rs {
		i := Interface{Name: str(r["name"]), Description: str(r["description"]), MAC: str(r["phys-address"])}
		if s := str(r["admin-status"]); s != "" {
			i.AdminUp = boolp(s == "if-state-up")
		}
		if s := str(r["oper-status"]); s != "" {
			i.OperUp = boolp(s == "if-oper-state-ready")
		}
		if sp, err := strconv.ParseInt(str(r["speed"]), 10, 64); err == nil && sp > 0 { // bit/s, as a string
			i.SpeedMbps = sp / 1_000_000
		}
		if ip := str(r["ipv4"]); ip != "" && ip != "0.0.0.0" {
			if mask := str(r["ipv4-subnet-mask"]); mask != "" {
				ip += "/" + strconv.Itoa(maskBits(mask))
			}
			i.Addresses = []string{ip}
		}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// maskBits is the prefix length of a dotted mask ("255.255.255.0" -> 24).
func maskBits(m string) int {
	ip := net.ParseIP(m).To4()
	if ip == nil {
		return 0
	}
	n, _ := net.IPMask(ip).Size()
	return n
}

// Neighbors are the LLDP neighbors, and the CDP ones on the ports LLDP has none for (Cisco gear often only speaks CDP).
func (x *iosxe) Neighbors(ctx context.Context) ([]Neighbor, error) {
	v, err := x.get(ctx, "Cisco-IOS-XE-lldp-oper:lldp-entries/lldp-entry")
	if err != nil {
		return nil, err
	}
	var out []Neighbor
	seen := map[string]bool{}
	for _, r := range rows(v) {
		n := Neighbor{LocalPort: str(r["local-interface"]), RemoteName: str(r["device-id"]), RemotePort: str(r["connecting-interface"]),
			Protocol: "lldp", Detail: redactMap(r)}
		out = append(out, n)
		seen[n.LocalPort] = true
	}
	// CDP: kept quiet when the model is missing or CDP is off; LLDP already answered
	if v, err := x.get(ctx, "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details/cdp-neighbor-detail"); err == nil {
		for _, r := range rows(v) {
			lp := str(r["local-intf-name"])
			if seen[lp] {
				continue
			}
			n := Neighbor{LocalPort: lp, RemoteName: str(r["device-name"]), RemotePort: str(r["port-id"]),
				RemoteDesc: str(r["platform-name"]), Protocol: "cdp", Detail: redactMap(r)}
			if ma, ok := r["mgmt-address"].(map[string]any); ok {
				n.RemoteAddr = str(ma["ip-address"])
			}
			if n.RemoteAddr == "" {
				if ip, ok := r["ip-address"].(string); ok {
					n.RemoteAddr = ip
				}
			}
			out = append(out, n)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].LocalPort < out[b].LocalPort })
	return out, nil
}

// Ports are the interfaces with the statistics container and every other property of Cisco-IOS-XE-interfaces-oper.
func (x *iosxe) Ports(ctx context.Context) ([]Port, error) {
	v, err := x.get(ctx, "Cisco-IOS-XE-interfaces-oper:interfaces/interface")
	if err != nil {
		return nil, err
	}
	ifs, err := x.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	byName := map[string]Interface{}
	for _, i := range ifs {
		byName[i.Name] = i
	}
	var out []Port
	for _, r := range rows(v) {
		p := Port{Interface: byName[str(r["name"])], Type: strings.TrimPrefix(str(r["interface-type"]), "iana-iftype:"), MTU: num(r["mtu"])}
		if p.Type == "" {
			p.Type = str(r["type"])
		}
		if es, ok := r["ether-state"].(map[string]any); ok {
			p.Duplex = strings.TrimPrefix(str(es["negotiated-duplex-mode"]), "duplex-")
		}
		props := redactMap(r)
		if st, ok := props["statistics"].(map[string]any); ok {
			p.Counters = countersOf(st)
			delete(props, "statistics")
		}
		p.Properties = props
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// ribModels are the models the routing table is tried from, the first that holds routes wins.
var iosxeRIBModels = []string{"ietf-routing:routing-state", "ietf-routing:routing", "Cisco-IOS-XE-rib-oper:rib-oper-data"}

func (x *iosxe) Routes(ctx context.Context) ([]Route, error) {
	var last error
	for _, m := range iosxeRIBModels {
		v, err := x.get(ctx, m)
		if se, ok := err.(*statusError); ok {
			last = se
			continue
		}
		if err != nil {
			return nil, err
		}
		var rs []Route
		findRoutes(v, "", &rs)
		if len(rs) > 0 {
			return rs, nil
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, nil
}

// Routing reads the operational model of each protocol, and the native configuration of the routers and static routes.
func (x *iosxe) Routing(ctx context.Context) (Routing, error) {
	return gather([]part{
		{"ospf", "Cisco-IOS-XE-ospf-oper:ospf-oper-data"},
		{"ospfv3", "Cisco-IOS-XE-ospfv3-oper:ospfv3-oper-data"},
		{"bgp", "Cisco-IOS-XE-bgp-oper:bgp-state-data"},
		{"eigrp", "Cisco-IOS-XE-eigrp-oper:eigrp-oper-data"},
		{"isis", "Cisco-IOS-XE-isis-oper:isis-oper-data"},
		{"rip", "Cisco-IOS-XE-rip-oper:rip-oper-data"},
		{"bfd", "Cisco-IOS-XE-bfd-oper:bfd-state"},
		{"config_routers", "Cisco-IOS-XE-native:native/router"},
		{"config_static", "Cisco-IOS-XE-native:native/ip/route"},
	}, func(p string) (any, error) { return x.get(ctx, p) })
}

// Firewall: the access lists with the match counter of each entry (operational model), the configured lists, zone-based
// firewall and NAT, and NAT statistics.
func (x *iosxe) Firewall(ctx context.Context) (Firewall, error) {
	return gather([]part{
		{"acl_counters", "Cisco-IOS-XE-acl-oper:access-lists"},
		{"config_acls", "Cisco-IOS-XE-native:native/ip/access-list"},
		{"config_ipv6_acls", "Cisco-IOS-XE-native:native/ipv6/access-list"},
		{"config_zones", "Cisco-IOS-XE-native:native/zone"},
		{"config_zone_pairs", "Cisco-IOS-XE-native:native/zone-pair"},
		{"config_policy_maps", "Cisco-IOS-XE-native:native/policy-map"},
		{"config_class_maps", "Cisco-IOS-XE-native:native/class-map"},
		{"config_nat", "Cisco-IOS-XE-native:native/ip/nat"},
		{"nat_statistics", "Cisco-IOS-XE-nat-oper:nat-data"},
		{"zbfw_statistics", "Cisco-IOS-XE-zone-oper:zbfw-oper-data"},
	}, func(p string) (any, error) { return x.get(ctx, p) })
}

// Resources: CPU (process-cpu-oper), memory pools (memory-oper), file systems and environment sensors (power supplies,
// fans, temperatures), and the hardware inventory whole.
func (x *iosxe) Resources(ctx context.Context) (Resources, error) {
	d, err := gather([]part{
		{"cpu", "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization"},
		{"memory", "Cisco-IOS-XE-memory-oper:memory-statistics/memory-statistic"},
		{"filesystems", "Cisco-IOS-XE-platform-software-oper:cisco-platform-software/q-filesystem"},
		{"sensors", "Cisco-IOS-XE-environment-oper:environment-sensors/environment-sensor"},
		{"hardware_inventory", "Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-inventory"},
	}, func(p string) (any, error) { return x.get(ctx, p) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	if m, ok := d.Protocols["cpu"].(map[string]any); ok {
		out.CPU = &CPU{Now: flt(m["five-seconds"]), OneMin: flt(m["one-minute"]), FiveMin: flt(m["five-minutes"])}
	}
	for _, r := range rows(d.Protocols["memory"]) {
		m := Memory{Name: str(r["name"]), Total: num(r["total-memory"]), Used: num(r["used-memory"]), Free: num(r["free-memory"])}
		m.UsedPercent = pct(m.Used, m.Total)
		out.Memory = append(out.Memory, m)
	}
	for _, r := range rows(d.Protocols["filesystems"]) {
		s := Storage{Name: firstOf(str(r["name"]), str(r["mount-point"])), Size: num(r["size"]), Free: num(r["free"])}
		s.UsedPercent = pct(s.Size-s.Free, s.Size)
		out.Storage = append(out.Storage, s)
	}
	for _, r := range rows(d.Protocols["sensors"]) {
		name := firstOf(str(r["name"]), str(r["location"]))
		s := Sensor{Name: name, State: str(r["state"]), Units: str(r["sensor-units"]), Kind: sensorKind(name+" "+str(r["location"]), str(r["sensor-units"])), Raw: r}
		if v, ok := r["current-reading"]; ok {
			s.Reading = new(float64)
			*s.Reading = flt(v)
		}
		out.Sensors = append(out.Sensors, s)
	}
	return out, nil
}

// VLANs: the operational VLAN list, else the VLANs of the configuration.
func (x *iosxe) VLANs(ctx context.Context) ([]VLAN, error) {
	v, err := x.get(ctx, "Cisco-IOS-XE-vlan-oper:vlans/vlan")
	if se, ok := err.(*statusError); ok {
		v, err = x.get(ctx, "Cisco-IOS-XE-native:native/vlan/vlan-list")
		if se2, ok := err.(*statusError); ok {
			return nil, se2
		}
		_ = se
	}
	if err != nil {
		return nil, err
	}
	var out []VLAN
	for _, r := range rows(v) {
		l := VLAN{ID: num(firstAny(r["id"], r["vlan-id"])), Name: str(r["name"]), Status: str(r["status"]), Raw: redactMap(r)}
		for _, vi := range rows(r["vlan-interfaces"]) {
			if n := str(vi["interface"]); n != "" {
				l.Ports = append(l.Ports, n)
			}
		}
		out = append(out, l)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func firstAny(v ...any) any {
	for _, x := range v {
		if x != nil && x != "" {
			return x
		}
	}
	return nil
}

// APIGet reads any RESTCONF data or capability resource.
func (x *iosxe) APIGet(ctx context.Context, path string) (any, bool, error) {
	if !strings.HasPrefix(path, "/restconf/data") && !strings.HasPrefix(path, "/restconf/yang-library-version") && !strings.HasPrefix(path, "/restconf/tailf/modules") {
		return nil, false, fmt.Errorf("path: IOS-XE reads /restconf/data/... (the catalog lists what is there)")
	}
	return apiGet(ctx, x.api, path, nil)
}

// APICatalog: the top-level nodes of the datastore (depth=1: every model's top container), and the modules the switch
// implements when it will say.
func (x *iosxe) APICatalog(ctx context.Context) (any, error) {
	out := map[string]any{"how": "GET /restconf/data/<module>:<container> with api_get; add ?depth=2 to look a level deeper; /restconf/tailf/modules/<module>/<revision> is a model's YANG source"}
	if v, _, err := apiGet(ctx, x.api, "/restconf/data?depth=1", nil); err == nil && v != nil {
		var names []string
		if m, ok := v.(map[string]any); ok {
			for _, in := range m {
				if mm, ok := in.(map[string]any); ok {
					for k := range mm {
						names = append(names, k)
					}
				} else if l, ok := in.([]any); ok {
					for _, e := range l {
						if mm, ok := e.(map[string]any); ok {
							for k := range mm {
								names = append(names, k)
							}
						}
					}
				}
			}
			if len(names) == 0 {
				for k := range m {
					names = append(names, k)
				}
			}
		}
		sort.Strings(names)
		out["top_level_nodes"] = names
	} else if err != nil {
		out["top_level_nodes_error"] = err.Error()
	}
	if v, _, err := apiGet(ctx, x.api, "/restconf/data/ietf-yang-library:modules-state", nil); err == nil && v != nil {
		out["modules"] = v
	}
	return out, nil
}

func (x *iosxe) Config(ctx context.Context) (string, error) {
	b, err := x.api.do(ctx, http.MethodGet, "/restconf/data/Cisco-IOS-XE-native:native", nil, nil)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (x *iosxe) Show(context.Context, string) (string, error) { return "", ErrUnsupported }

func (x *iosxe) Close(context.Context) { x.api.close() }
