package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The full-detail requests: every counter and property of every port, every field a device reports about its LLDP and
// CDP neighbors, its routing table and the state of every routing protocol.  What a device says is kept as it said it
// (All, Detail, Raw, Protocols) next to a few normalized fields, so nothing a platform offers is lost to the shape that
// is the same for every platform.  Secrets in it (keys, passwords, communities) are replaced by "(hidden)".
//
// A driver offers these by implementing Porter and Router; one that does not answers ErrUnsupported.

// Counters are the traffic statistics of one port.  The named fields are the common ones (0 when the device does not
// report it); All is every statistic the device returned, under its own names.
type Counters struct {
	InOctets        int64          `json:"in_octets,omitempty"`
	InPackets       int64          `json:"in_packets,omitempty"`
	InUnicast       int64          `json:"in_unicast,omitempty"`
	InMulticast     int64          `json:"in_multicast,omitempty"`
	InBroadcast     int64          `json:"in_broadcast,omitempty"`
	InDiscards      int64          `json:"in_discards,omitempty"`
	InErrors        int64          `json:"in_errors,omitempty"`
	InUnknownProtos int64          `json:"in_unknown_protos,omitempty"`
	OutOctets       int64          `json:"out_octets,omitempty"`
	OutPackets      int64          `json:"out_packets,omitempty"`
	OutUnicast      int64          `json:"out_unicast,omitempty"`
	OutMulticast    int64          `json:"out_multicast,omitempty"`
	OutBroadcast    int64          `json:"out_broadcast,omitempty"`
	OutDiscards     int64          `json:"out_discards,omitempty"`
	OutErrors       int64          `json:"out_errors,omitempty"`
	RxPPS           int64          `json:"rx_pps,omitempty"`
	TxPPS           int64          `json:"tx_pps,omitempty"`
	RxKbps          int64          `json:"rx_kbps,omitempty"`
	TxKbps          int64          `json:"tx_kbps,omitempty"`
	Flaps           int64          `json:"flaps,omitempty"`
	All             map[string]any `json:"all,omitempty"`
}

// Port is an Interface with its counters and every property the device holds for it.
type Port struct {
	Interface
	Type       string         `json:"type,omitempty"`
	MTU        int64          `json:"mtu,omitempty"`
	Duplex     string         `json:"duplex,omitempty"`
	Counters   Counters       `json:"counters"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Route is one entry of a routing table.  Raw is the entry as the device reported it.
type Route struct {
	Protocol  string         `json:"protocol,omitempty"`
	Prefix    string         `json:"prefix"`
	NextHop   string         `json:"next_hop,omitempty"`
	Interface string         `json:"interface,omitempty"`
	Metric    int64          `json:"metric,omitempty"`
	Distance  int64          `json:"distance,omitempty"`
	VRF       string         `json:"vrf,omitempty"`
	Raw       map[string]any `json:"raw,omitempty"`
}

// Routing is the state and configuration of the routing protocols, one entry per model or table the device answered
// (OSPF neighbors and areas, BGP neighbors and paths, EIGRP, IS-IS, RIP, BFD, static routes, ...), as the device reports
// it.  Unavailable says why a part is missing: the platform or release has no such model, or the protocol is off.
type Routing struct {
	Protocols   map[string]any    `json:"protocols"`
	Unavailable map[string]string `json:"unavailable,omitempty"`
}

// Firewall is the filtering and translation state of a device, in the same shape as Routing: one entry per part the device
// answered (policies or ACLs with their hit counters, address objects, services, NAT, shapers, ...), as the device reports it.
type Firewall = Routing

// Firewaller is a driver that reads firewall rules and their statistics.
type Firewaller interface {
	Firewall(ctx context.Context) (Firewall, error)
}

// Porter is a driver that reads port counters and properties.
type Porter interface {
	Ports(ctx context.Context) ([]Port, error)
}

// Router is a driver that reads the routing table and the routing protocols.
type Router interface {
	Routes(ctx context.Context) ([]Route, error)
	Routing(ctx context.Context) (Routing, error)
}

// secretWords are what a key's name holds when its value is a secret.
var secretWords = []string{"password", "passwd", "secret", "md5", "psk", "token", "key-string", "key_string",
	"auth-key", "auth_key", "authentication-key", "encrypted", "passphrase",
	// NX-OS's object model ("pwd"), PAN-OS ("phash", "private-key", "pre-shared-key", "snmp-community-string") and API keys
	"pwd", "phash", "private-key", "private_key", "privatekey", "pre-shared", "pre_shared", "api-key", "api_key", "apikey",
	"community-string", "community_string",
	// Observium (a device's SNMP community, and its SNMP authentication and privacy passwords and user name)
	"snmp_community", "snmp-community", "authpass", "cryptopass", "snmp_authname",
	// Infoblox WAPI (zone transfer and DDNS keys: tsig_key, tsig_key_name, ...)
	"tsig_key", "tsig-key",
	// RADIUS and TACACS+ shared keys, SNMPv3 passwords, routing protocol and MC-LAG keys (ArubaOS-CX and others), and the ciphertext of any of them
	"passkey", "pass_key", "pass-key", "auth_pass", "auth-pass", "authpass", "priv_pass", "priv-pass", "privpass", "authentication_key", "keepalive_key", "keepalive-key",
	"ciphertext", "keystring", "shared_key", "shared-key", "sharedkey"}

func secretName(k string) bool {
	k = strings.ToLower(k)
	if k == "key" {
		return true
	}
	for _, w := range secretWords {
		if strings.Contains(k, w) {
			return true
		}
	}
	return holdsExtra(k)
}

// Redact returns v with the value of every key that names a secret replaced by "(hidden)".  Empty values stay empty.
func Redact(v any) any { return redactIn(v, false) }

// redactIn is Redact; snmp says the value lies under a key about SNMP, where every key that names a community holds a
// secret (a BGP community elsewhere is not one).
func redactIn(v any, snmp bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			lk := strings.ToLower(k)
			if x != nil && x != "" && strings.Contains(lk, "community") && (snmp || strings.Contains(lk, "snmp")) {
				out[k] = "(hidden)" // the names of the communities are the secrets, so a list or an object of them goes whole
				continue
			}
			sub := snmp || strings.Contains(lk, "snmp")
			if secretName(k) && x != nil && x != "" {
				switch x.(type) {
				case map[string]any, []any:
					out[k] = redactIn(x, sub) // a container named like a secret: its leaves decide
					if secretLeafless(x) {
						out[k] = "(hidden)"
					}
				default:
					out[k] = "(hidden)"
				}
				continue
			}
			out[k] = redactIn(x, sub)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redactIn(x, snmp)
		}
		return out
	}
	return v
}

// secretLeafless: a container under a secret's name whose contents are plain values is itself the secret.
func secretLeafless(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for _, x := range t {
			switch x.(type) {
			case map[string]any, []any:
				return false
			}
		}
		return true
	}
	return false
}

func redactMap(m map[string]any) map[string]any {
	r, _ := Redact(m).(map[string]any)
	return r
}

// statsOf reads the common counter names out of a map of statistics, under the names of any platform.
func countersOf(m map[string]any) Counters {
	n := func(keys ...string) int64 {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if x := num(v); x != 0 {
					return x
				}
			}
		}
		return 0
	}
	c := Counters{
		InOctets: n("in-octets", "rx_bytes"), InPackets: n("in-pkts", "rx_packets"), InUnicast: n("in-unicast-pkts"),
		InMulticast: n("in-multicast-pkts"), InBroadcast: n("in-broadcast-pkts"), InDiscards: n("in-discards-64", "in-discards"),
		InErrors: n("in-errors-64", "in-errors", "rx_errors"), InUnknownProtos: n("in-unknown-protos-64", "in-unknown-protos"),
		OutOctets: n("out-octets", "tx_bytes"), OutPackets: n("out-pkts", "tx_packets"), OutUnicast: n("out-unicast-pkts"),
		OutMulticast: n("out-multicast-pkts"), OutBroadcast: n("out-broadcast-pkts"), OutDiscards: n("out-discards-64", "out-discards"),
		OutErrors: n("out-errors-64", "out-errors", "tx_errors"),
		RxPPS:     n("rx-pps"), TxPPS: n("tx-pps"), RxKbps: n("rx-kbps"), TxKbps: n("tx-kbps"), Flaps: n("num-flaps"),
		All: m,
	}
	if c.InPackets == 0 {
		c.InPackets = c.InUnicast + c.InMulticast + c.InBroadcast
	}
	if c.OutPackets == 0 {
		c.OutPackets = c.OutUnicast + c.OutMulticast + c.OutBroadcast
	}
	return c
}

// part is one thing to read for Routing: its name in the answer and the platform's path for it.
type part struct{ name, path string }

// gather reads each part with get.  A part the device refuses (an HTTP error: no such model, protocol off) is listed in
// Unavailable; any other error (the device cannot be reached) ends the request.
func gather(parts []part, get func(path string) (any, error)) (Routing, error) {
	r := Routing{Protocols: map[string]any{}, Unavailable: map[string]string{}}
	for _, p := range parts {
		v, err := get(p.path)
		var se *statusError
		switch {
		case errors.As(err, &se):
			r.Unavailable[p.name] = se.Error()
		case err != nil:
			return r, err
		case v == nil:
			r.Unavailable[p.name] = "the device answered nothing (the protocol is off or has no entries)"
		default:
			r.Protocols[p.name] = Redact(v)
		}
	}
	if len(r.Unavailable) == 0 {
		r.Unavailable = nil
	}
	return r, nil
}

// findRoutes walks a routing model's answer and takes every object that has a destination prefix as a route
// (IETF routing: destination-prefix, next-hop{next-hop-address, outgoing-interface}, source-protocol, route-preference).
func findRoutes(v any, vrf string, out *[]Route) {
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			findRoutes(x, vrf, out)
		}
	case map[string]any:
		if n := str(t["name"]); n != "" && (t["ribs"] != nil || t["routing-instance"] != nil) {
			vrf = n
		}
		if p := firstOf(str(t["destination-prefix"]), str(t["ip-prefix"]), str(t["prefix"])); p != "" {
			r := Route{Prefix: p, VRF: vrf, Raw: redactMap(t),
				Protocol: strings.TrimPrefix(firstOf(str(t["source-protocol"]), str(t["route-type"]), str(t["protocol"])), "ietf-routing:"),
				Metric:   num(t["metric"]), Distance: num(t["route-preference"]),
				Interface: firstOf(str(t["outgoing-interface"]), str(t["interface"]))}
			if r.Distance == 0 {
				r.Distance = num(t["distance"])
			}
			r.NextHop = firstOf(str(t["next-hop-address"]), str(t["next-hop"]), str(t["gateway"]))
			if nh, ok := t["next-hop"].(map[string]any); ok {
				r.NextHop = firstOf(str(nh["next-hop-address"]), str(nh["address"]))
				r.Interface = firstOf(str(nh["outgoing-interface"]), r.Interface)
			}
			*out = append(*out, r)
			return
		}
		for _, x := range t {
			findRoutes(x, vrf, out)
		}
	}
}

// CPU is utilization in percent: Now is the newest reading (IOS-XE: the last 5 seconds).
type CPU struct {
	Now     float64 `json:"now_percent"`
	OneMin  float64 `json:"one_min_percent,omitempty"`
	FiveMin float64 `json:"five_min_percent,omitempty"`
}

// Memory is one memory pool.  Total, Used and Free are bytes where the device reports sizes, else 0.
type Memory struct {
	Name        string  `json:"name,omitempty"`
	Total       int64   `json:"total,omitempty"`
	Used        int64   `json:"used,omitempty"`
	Free        int64   `json:"free,omitempty"`
	UsedPercent float64 `json:"used_percent"`
}

// Storage is one file system or disk.  Size and Free are in the unit the device reports (the percentage is not).
type Storage struct {
	Name        string  `json:"name"`
	Size        int64   `json:"size,omitempty"`
	Free        int64   `json:"free,omitempty"`
	UsedPercent float64 `json:"used_percent"`
}

// Sensor is a power supply, fan, temperature sensor or other environment reading.  Kind is psu, fan, temperature or other
// (a guess from the name and unit); State and Reading are what the device says.
type Sensor struct {
	Name    string         `json:"name"`
	Kind    string         `json:"kind"`
	State   string         `json:"state,omitempty"`
	Reading *float64       `json:"reading,omitempty"`
	Units   string         `json:"units,omitempty"`
	Raw     map[string]any `json:"raw,omitempty"`
}

// Resources is what a device says about its own health: CPU, memory, storage and the environment (power supplies, fans,
// temperatures).  A part the device does not answer is left out and named in Details.Unavailable; Details.Protocols
// holds each answer whole.
type Resources struct {
	CPU     *CPU      `json:"cpu,omitempty"`
	Memory  []Memory  `json:"memory,omitempty"`
	Storage []Storage `json:"storage,omitempty"`
	Sensors []Sensor  `json:"sensors,omitempty"`
	Details Routing   `json:"details"`
}

// VLAN is one VLAN of a switch, or one VLAN interface of a firewall.  Ports are the interfaces in it (a firewall: the
// parent interface).
type VLAN struct {
	ID     int64          `json:"id"`
	Name   string         `json:"name,omitempty"`
	Status string         `json:"status,omitempty"`
	Ports  []string       `json:"ports,omitempty"`
	Raw    map[string]any `json:"raw,omitempty"`
}

// Resourcer is a driver that reads CPU, memory, storage and the environment.
type Resourcer interface {
	Resources(ctx context.Context) (Resources, error)
}

// VLANer is a driver that reads VLANs.
type VLANer interface {
	VLANs(ctx context.Context) ([]VLAN, error)
}

func flt(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		var f float64
		if _, err := fmt.Sscan(strings.TrimSpace(t), &f); err == nil {
			return f
		}
	}
	return 0
}

func pct(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(used) * 100 / float64(total)
}

// sensorKind guesses what a reading is from its name and unit.
func sensorKind(name, units string) string {
	n := strings.ToLower(name + " " + units)
	switch {
	case strings.Contains(n, "fan"):
		return "fan"
	case strings.Contains(n, "psu") || strings.Contains(n, "power") || strings.Contains(n, " ps") || strings.HasPrefix(n, "ps"):
		return "psu"
	case strings.Contains(n, "temp") || strings.Contains(n, "celsius"):
		return "temperature"
	}
	return "other"
}

// APIer is a driver that reads any resource of the device's own API, and says what the API offers.  Nothing is picked for
// the caller: whatever the device presents can be asked for by its path.  Only GET is ever sent.
type APIer interface {
	// APIGet reads one path of the device's API.  Text is true when the answer is not JSON (a file, a configuration); such
	// an answer may hold secrets that cannot be found by name, so the caller decides who may have it.
	APIGet(ctx context.Context, path string) (v any, text bool, err error)
	// APICatalog lists what the API offers to be read, as far as the platform can say.
	APICatalog(ctx context.Context) (any, error)
}

// CheckAPIPath refuses a path that is not a plain absolute path on the device: no host, no "..", no spaces or control
// characters.  Each driver then limits it to the parts of its API that only read.
func CheckAPIPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	switch {
	case p == "":
		return "", errors.New("path: the path of the device's API, e.g. /restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces or /api/v2/monitor/system/status")
	case len(p) > 2048:
		return "", errors.New("path: longer than 2048 characters")
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return "", errors.New("path: must start with a single /")
	case strings.Contains(p, "..") || strings.Contains(p, "://") || strings.ContainsAny(p, " \t\r\n\\#") || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "", errors.New("path: a plain path with an optional query (no spaces, .., a host or a fragment)")
	}
	return p, nil
}

// apiGet is the GET every driver's APIGet ends in: the answer as JSON when it is, else as text.
func apiGet(ctx context.Context, c *apiClient, path string, hdr map[string][]string) (any, bool, error) {
	b, err := c.do(ctx, "GET", path, nil, hdr)
	if err != nil {
		return nil, false, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, false, nil
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		return Redact(v), false, nil
	}
	return string(b), true, nil
}
