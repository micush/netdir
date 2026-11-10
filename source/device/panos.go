package device

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Palo Alto Networks PAN-OS firewalls and Panorama over the XML API (/api/), one driver for both:
//
//	panos      a firewall; a Panorama is recognised from "show system info" and answered as one (so a Panorama listed as panos works)
//	panorama   a Panorama, without that check
//
// The login is an API key (Device ▸ Administrators, or "type=keygen"), given as the credential's token, or a user name and a
// password, from which the driver makes a key at the start of each request.  The key is sent in the X-PAN-KEY header, never in
// the URL; the password only in the body of the key request.  An administrator role with the XML API's "operational requests"
// and "configuration" enabled and nothing else (read-only) is enough; reading the logs (type=log) needs "log" enabled too.  Options: "vsys" (default vsys1) names the virtual system
// of a firewall, "device_group" limits a Panorama's rules and objects to one device group.
//
// Every request but the key request is a GET.  PAN-OS answers HTTP 200 with <response status="error"> for a request it refuses,
// and this driver turns that into the same statusError a REST device's HTTP error is.  The XML is read into the same generic
// values (maps and lists) the other drivers return, so keys, passwords and the like are hidden the same way; an <entry> or a
// <member> is always a list element.  Show turns "show system info" into <show><system><info/></system></show>: a word is an
// element, a double-quoted word the text of the element before it (`show interface "all"`), as pan-os-python does; PAN-OS has no
// output filters over the API, so a "|" is refused.

func init() {
	Register("panos", func(d Device, c Credential) (Driver, error) { return newPANOS(d, c, false) })
	Register("panorama", func(d Device, c Credential) (Driver, error) { return newPANOS(d, c, true) })
}

// panDevices is the device entry of the configuration tree: it is always this on a firewall and on a Panorama.
const panDevices = "/config/devices/entry[@name='localhost.localdomain']"

var panNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,30}$`)

type panos struct {
	d          Device
	api        *apiClient
	user, pass string
	key        string
	forced     bool   // platform "panorama"
	vsys       string // a firewall's virtual system
	dg         string // a Panorama's device group, or "" for all
	sys        map[string]any
	sysDone    bool
}

func newPANOS(d Device, c Credential, forcePanorama bool) (Driver, error) {
	if c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: PAN-OS needs an API key (a token) or a username and a password", d.Name)
	}
	p := &panos{d: d, user: c.Username, pass: c.Password, key: c.Token, forced: forcePanorama, vsys: "vsys1", dg: d.Options["device_group"]}
	if v := d.Options["vsys"]; v != "" {
		p.vsys = v
	}
	// the names go into XPath and XML below: only what a PAN-OS name is made of
	if !panNameRE.MatchString(p.vsys) {
		return nil, fmt.Errorf("device %s: option vsys %q is not a virtual system name", d.Name, p.vsys)
	}
	if p.dg != "" && !panNameRE.MatchString(p.dg) {
		return nil, fmt.Errorf("device %s: option device_group %q is not a device group name", d.Name, p.dg)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Accept", "application/xml")
	if p.key != "" {
		api.hdr.Set("X-PAN-KEY", p.key)
	}
	p.api = api
	return p, nil
}

// ---- XML read into generic values ----

type xnode struct {
	name  string
	attrs map[string]string
	kids  []*xnode
	text  strings.Builder
}

// parseXML reads one XML document into a tree.  Entities other than the five predefined are refused by the decoder, a DOCTYPE
// is not followed, and a document nested deeper than 200 levels is refused.
func parseXML(b []byte) (*xnode, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var root *xnode
	var stack []*xnode
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= 200 {
				return nil, errors.New("XML nested deeper than 200 levels")
			}
			n := &xnode{name: t.Name.Local}
			for _, a := range t.Attr {
				if n.attrs == nil {
					n.attrs = map[string]string{}
				}
				n.attrs[a.Name.Local] = a.Value
			}
			switch {
			case len(stack) > 0:
				parent := stack[len(stack)-1]
				parent.kids = append(parent.kids, n)
			case root == nil:
				root = n
			default:
				return nil, errors.New("more than one root element")
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("no XML element")
	}
	return root, nil
}

func (n *xnode) kid(name string) *xnode {
	for _, k := range n.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

// value is the node as a generic value: the text of a leaf; else a map of its attributes (a name that a child also has is
// written "@name") and children.  Children of one name are a list, always for "entry" and "member".
func (n *xnode) value(withAttrs bool) any {
	if len(n.kids) == 0 && (!withAttrs || len(n.attrs) == 0) {
		return strings.TrimSpace(n.text.String())
	}
	m := map[string]any{}
	group := map[string][]any{}
	for _, k := range n.kids {
		group[k.name] = append(group[k.name], k.value(true))
	}
	for name, vs := range group {
		if len(vs) == 1 && name != "entry" && name != "member" {
			m[name] = vs[0]
		} else {
			m[name] = vs
		}
	}
	if withAttrs {
		for k, v := range n.attrs {
			if _, clash := m[k]; clash {
				k = "@" + k
			}
			m[k] = v
		}
	}
	if len(n.kids) == 0 {
		if t := strings.TrimSpace(n.text.String()); t != "" {
			m["#text"] = t
		}
	}
	return m
}

// lines is all the text under a node (the lines of a <msg>), joined.
func (n *xnode) lines() string {
	var parts []string
	var walk func(*xnode)
	walk = func(x *xnode) {
		if t := strings.TrimSpace(x.text.String()); t != "" {
			parts = append(parts, t)
		}
		for _, k := range x.kids {
			walk(k)
		}
	}
	walk(n)
	return strings.Join(parts, "; ")
}

// panError is a refusal by PAN-OS as the statusError a REST device's HTTP error is: 403 for the codes of a bad key or a role
// without the right, 404 for an object that is not there, 400 for the rest (a command it lacks, a bad XPath).
func panError(code, msg string) error {
	c := http.StatusBadRequest
	switch code {
	case "403", "16":
		c = http.StatusForbidden
	case "7":
		c = http.StatusNotFound
	}
	if msg == "" {
		msg = "PAN-OS answered an error (code " + code + ")"
	}
	return &statusError{Code: c, Body: msg}
}

// panResult reads one <response> and gives what is in its <result> (nil when there is nothing).  status="error" is an error.
func panResult(b []byte) (any, error) {
	root, err := parseXML(b)
	if err != nil {
		return nil, fmt.Errorf("PAN-OS: the answer is not the XML expected: %v", err)
	}
	if root.name != "response" {
		return nil, fmt.Errorf("PAN-OS: the answer is not a <response> (it is <%s>)", root.name)
	}
	if root.attrs["status"] == "error" {
		msg := ""
		if m := root.kid("msg"); m != nil {
			msg = m.lines()
		} else if r := root.kid("result"); r != nil {
			msg = r.lines()
		}
		return nil, panError(root.attrs["code"], msg)
	}
	r := root.kid("result")
	if r == nil {
		return nil, nil
	}
	v := r.value(false)
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil, nil
		}
	case map[string]any:
		if len(t) == 0 {
			return nil, nil
		}
	}
	return v, nil
}

// dig follows keys through nested maps; anything that is not a map on the way is nil.
func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// members are the strings of a value that is a text, a list of texts or an object with <member>s.
func members(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, members(e)...)
		}
		return out
	case map[string]any:
		return members(t["member"])
	}
	return nil
}

// ---- requests ----

func panOp(xmlCmd string) url.Values { return url.Values{"type": {"op"}, "cmd": {xmlCmd}} }

func panCfg(xpath string) url.Values {
	return url.Values{"type": {"config"}, "action": {"show"}, "xpath": {xpath}} // show: the running configuration (get: the candidate)
}

// ensureKey makes the API key from the user name and the password when the credential has no key.
func (p *panos) ensureKey(ctx context.Context) error {
	if p.key != "" {
		return nil
	}
	form := url.Values{"user": {p.user}, "password": {p.pass}}
	b, err := p.api.do(ctx, http.MethodPost, "/api/?type=keygen", form.Encode(),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/xml"}})
	if err != nil {
		return err
	}
	v, err := panResult(b)
	if err != nil {
		return err
	}
	key := str(dig(v, "key"))
	if key == "" {
		return errors.New("PAN-OS answered no API key for that user name and password")
	}
	p.key = key
	p.api.hdr.Set("X-PAN-KEY", key)
	return nil
}

// scrubErr takes the API key out of an error text, in case the device echoed it, and keeps the type of a refusal.
func (p *panos) scrubErr(err error) error {
	if err == nil || len(p.key) < 4 {
		return err
	}
	var se *statusError
	if errors.As(err, &se) {
		return &statusError{Code: se.Code, Body: strings.ReplaceAll(se.Body, p.key, "(hidden)")}
	}
	if s := err.Error(); strings.Contains(s, p.key) {
		return errors.New(strings.ReplaceAll(s, p.key, "(hidden)"))
	}
	return err
}

// fetch is one GET of the XML API.
func (p *panos) fetch(ctx context.Context, q url.Values) ([]byte, error) {
	if err := p.ensureKey(ctx); err != nil {
		return nil, p.scrubErr(err)
	}
	b, err := p.api.do(ctx, http.MethodGet, "/api/?"+q.Encode(), nil, http.Header{"Accept": {"application/xml"}})
	return b, p.scrubErr(err)
}

func (p *panos) req(ctx context.Context, q url.Values) (any, error) {
	b, err := p.fetch(ctx, q)
	if err != nil {
		return nil, err
	}
	return panResult(b)
}

// get reads what gather names: an operational command (the XML starts with "<") or a configuration XPath.
func (p *panos) get(ctx context.Context, what string) (any, error) {
	if strings.HasPrefix(what, "<") {
		return p.req(ctx, panOp(what))
	}
	return p.req(ctx, panCfg(what))
}

// ---- what the box is ----

func (p *panos) system(ctx context.Context) (map[string]any, error) {
	if p.sysDone {
		return p.sys, nil
	}
	v, err := p.req(ctx, panOp("<show><system><info></info></system></show>"))
	if err != nil {
		return nil, err
	}
	s, _ := dig(v, "system").(map[string]any)
	if s == nil {
		return nil, errors.New("PAN-OS: show system info answered no <system>")
	}
	p.sys, p.sysDone = s, true
	return s, nil
}

var panoramaModelRE = regexp.MustCompile(`(?i)^(panorama|m-\d+)`)

// panorama says whether this is a Panorama: the platform says so, or the system info does (the model, or the system mode).
func (p *panos) panorama() bool {
	if p.forced {
		return true
	}
	if panoramaModelRE.MatchString(str(p.sys["model"])) {
		return true
	}
	m := strings.ToLower(str(p.sys["system-mode"]))
	return strings.Contains(m, "panorama") || strings.Contains(m, "management") || strings.Contains(m, "log-collector") || strings.Contains(m, "log collector")
}

var panUptimeRE = regexp.MustCompile(`(\d+)\s+days?,\s*(\d+):(\d+):(\d+)`)

func (p *panos) Facts(ctx context.Context) (Facts, error) {
	s, err := p.system(ctx)
	if err != nil {
		return Facts{Vendor: "Palo Alto Networks"}, err
	}
	f := Facts{Vendor: "Palo Alto Networks", Hostname: str(s["hostname"]), Model: str(s["model"]), OSVersion: str(s["sw-version"]), Serial: str(s["serial"])}
	if m := panUptimeRE.FindStringSubmatch(str(s["uptime"])); m != nil { // "12 days, 3:04:05"
		n := func(i int) int64 { v, _ := strconv.ParseInt(m[i], 10, 64); return v }
		f.UptimeS = n(1)*86400 + n(2)*3600 + n(3)*60 + n(4)
	}
	return f, nil
}

// ---- interfaces ----

type panIfaces struct {
	list  []Interface
	ifnet map[string]map[string]any
	hw    map[string]map[string]any
	cfg   map[string]map[string]any
}

// walkNamed calls fn for every object in v that has a text "name" (an <entry name="...">), at any depth.
func walkNamed(v any, fn func(m map[string]any)) {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			walkNamed(e, fn)
		}
	case map[string]any:
		if _, ok := t["name"].(string); ok {
			fn(t)
		}
		for _, e := range t {
			walkNamed(e, fn)
		}
	}
}

func validAddr(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// panAddrs are the addresses of one row of the interface list (the main one, secondary, IPv6 and DHCP-leased ones).
func panAddrs(e map[string]any) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" && validAddr(s) {
			out = append(out, s)
		}
	}
	add(str(e["ip"])) // "N/A" when there is none
	for _, k := range []string{"addr", "addr6", "dyn-addr", "dyn-addr6"} {
		for _, s := range members(e[k]) {
			add(s)
		}
	}
	return out
}

// panSpeed is the speed of a port in Mbit/s: the speed field, else the first part of "1000/full/up".
func panSpeed(h map[string]any) int64 {
	if s := num(h["speed"]); s > 0 {
		return s
	}
	st, _, _ := strings.Cut(str(h["st"]), "/")
	return num(st)
}

func (p *panos) ifaces(ctx context.Context) (*panIfaces, error) {
	sys, err := p.system(ctx)
	if err != nil {
		return nil, err
	}
	res := &panIfaces{ifnet: map[string]map[string]any{}, hw: map[string]map[string]any{}, cfg: map[string]map[string]any{}}
	var names []string
	v, err := p.req(ctx, panOp("<show><interface>all</interface></show>"))
	if err != nil && !(p.panorama() && isDeviceRefusal(err)) { // a Panorama may not list its interfaces this way
		return nil, err
	}
	for _, e := range rows(dig(v, "ifnet", "entry")) {
		n := str(e["name"])
		res.ifnet[n] = e
		names = append(names, n)
	}
	for _, e := range rows(dig(v, "hw", "entry")) {
		n := str(e["name"])
		if _, dup := res.ifnet[n]; !dup {
			names = append(names, n)
		}
		res.hw[n] = e
	}
	if !p.panorama() { // descriptions and the configured link state are configuration
		c, err := p.req(ctx, panCfg(panDevices+"/network/interface"))
		if err != nil && !isDeviceRefusal(err) {
			return nil, err
		}
		walkNamed(c, func(m map[string]any) { res.cfg[str(m["name"])] = m })
	}
	for _, n := range names {
		i := Interface{Name: n, Addresses: panAddrs(res.ifnet[n])}
		if h := res.hw[n]; h != nil {
			i.MAC, i.SpeedMbps = str(h["mac"]), panSpeed(h)
			switch str(h["state"]) {
			case "up":
				i.OperUp = boolp(true)
			case "down":
				i.OperUp = boolp(false)
			}
			if sc := str(h["state_c"]); sc != "" {
				i.AdminUp = boolp(sc != "down")
			}
		}
		if c := res.cfg[n]; c != nil {
			i.Description = str(c["comment"])
			if ls := str(c["link-state"]); ls != "" { // auto, up or down
				i.AdminUp = boolp(ls != "down")
			}
		}
		res.list = append(res.list, i)
	}
	// the management port is not in that list; the system info has its address
	if ip := str(sys["ip-address"]); ip != "" && validAddr(ip) {
		mi := Interface{Name: "management", MAC: str(sys["mac-address"]), Addresses: []string{ip}}
		if bits := maskBits(str(sys["netmask"])); bits > 0 {
			mi.Addresses[0] = ip + "/" + strconv.Itoa(bits)
		}
		if v6 := str(sys["ipv6-address"]); v6 != "" && validAddr(v6) {
			mi.Addresses = append(mi.Addresses, v6)
		}
		res.list = append(res.list, mi)
	}
	sort.Slice(res.list, func(a, b int) bool { return res.list[a].Name < res.list[b].Name })
	return res, nil
}

func (p *panos) Interfaces(ctx context.Context) ([]Interface, error) {
	d, err := p.ifaces(ctx)
	if err != nil {
		return nil, err
	}
	return d.list, nil
}

// flatten lifts the objects one level up into the map, so that a statistic keeps its own name wherever the device nested it.
func flatten(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			for k2, v2 := range sub {
				out[k2] = v2
			}
			continue
		}
		out[k] = v
	}
	return out
}

// panCounters reads the statistics of one port under the names PAN-OS uses at the interface level (ibytes, ipackets, ierrors,
// idrops, ...) and at the hardware level (rx-bytes, tx-unicast, ...); All keeps every statistic as the device named it.
func panCounters(m map[string]any) Counters {
	n := func(keys ...string) int64 {
		for _, k := range keys {
			if x := num(m[k]); x != 0 {
				return x
			}
		}
		return 0
	}
	c := Counters{
		InOctets: n("ibytes", "rx-bytes"), InPackets: n("ipackets", "rx-packets"), InUnicast: n("rx-unicast"), InMulticast: n("rx-multicast"), InBroadcast: n("rx-broadcast"),
		InDiscards: n("idrops", "rx-drops", "rx-discards"), InErrors: n("ierrors", "rx-error", "rx-errors"),
		OutOctets: n("obytes", "tx-bytes"), OutPackets: n("opackets", "tx-packets"), OutUnicast: n("tx-unicast"), OutMulticast: n("tx-multicast"), OutBroadcast: n("tx-broadcast"),
		OutDiscards: n("odrops", "tx-drops", "tx-discards"), OutErrors: n("oerrors", "tx-error", "tx-errors"),
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

// panIfType is the kind of an interface from its name.
func panIfType(name string) string {
	switch {
	case strings.Contains(name, "."):
		return "subinterface"
	case strings.HasPrefix(name, "ethernet"):
		return "ethernet"
	case strings.HasPrefix(name, "ae"):
		return "aggregate"
	}
	if i := strings.IndexAny(name, "0123456789"); i > 0 {
		return name[:i] // loopback, tunnel, vlan
	}
	return name
}

// Ports are the interfaces with their counters ("show counter interface all") and the configuration of each.
func (p *panos) Ports(ctx context.Context) ([]Port, error) {
	d, err := p.ifaces(ctx)
	if err != nil {
		return nil, err
	}
	stats := map[string]map[string]any{}
	cv, err := p.req(ctx, panOp("<show><counter><interface>all</interface></counter></show>"))
	if err != nil && !isDeviceRefusal(err) {
		return nil, err
	}
	for _, sect := range []string{"ifnet", "hw"} {
		for _, e := range rows(dig(cv, sect, "entry")) {
			n := str(e["name"])
			if stats[n] == nil {
				stats[n] = map[string]any{}
			}
			for k, x := range flatten(e) { // the interface level's names win over the hardware level's
				if _, have := stats[n][k]; !have || sect == "ifnet" {
					stats[n][k] = x
				}
			}
		}
	}
	out := make([]Port, 0, len(d.list))
	for _, i := range d.list {
		pt := Port{Interface: i, Type: panIfType(i.Name), Counters: panCounters(redactMap(stats[i.Name]))}
		if h := d.hw[i.Name]; h != nil {
			_, rest, _ := strings.Cut(str(h["st"]), "/") // "1000/full/up"
			pt.Duplex, _, _ = strings.Cut(rest, "/")
			if dp := str(h["duplex"]); dp != "" {
				pt.Duplex = dp
			}
		}
		props := map[string]any{}
		if e := d.ifnet[i.Name]; e != nil {
			props["interface"] = redactMap(e)
		}
		if h := d.hw[i.Name]; h != nil {
			props["hardware"] = redactMap(h)
		}
		if c := d.cfg[i.Name]; c != nil {
			props["config"] = redactMap(c)
			pt.MTU = num(dig(c, "layer3", "mtu"))
		}
		pt.Properties = props
		out = append(out, pt)
	}
	return out, nil
}

// ---- neighbors ----

// panMgmtAddr is the management address a neighbor advertises: the first IP address under a key that names one.
func panMgmtAddr(v any) string {
	var find func(v any, named bool) string
	find = func(v any, named bool) string {
		switch t := v.(type) {
		case string:
			if named && validAddr(t) {
				return t
			}
		case []any:
			for _, e := range t {
				if s := find(e, named); s != "" {
					return s
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				lk := strings.ToLower(k)
				if s := find(t[k], named || strings.Contains(lk, "address") || strings.Contains(lk, "mgmt") || strings.Contains(lk, "management")); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return find(v, false)
}

// Neighbors are the LLDP neighbors of a firewall (LLDP is set up under Network ▸ LLDP).  A Panorama has none.
func (p *panos) Neighbors(ctx context.Context) ([]Neighbor, error) {
	if _, err := p.system(ctx); err != nil {
		return nil, err
	}
	if p.panorama() {
		return nil, nil
	}
	v, err := p.req(ctx, panOp("<show><lldp><neighbors>all</neighbors></lldp></show>"))
	if err != nil {
		if isDeviceRefusal(err) { // LLDP is off
			return nil, nil
		}
		return nil, err
	}
	var out []Neighbor
	for _, e := range rows(dig(v, "entry")) {
		local := str(e["name"])
		ns := rows(dig(e, "neighbors", "entry"))
		if len(ns) == 0 {
			ns = []map[string]any{e}
		}
		for _, n := range ns {
			nb := Neighbor{LocalPort: local, RemoteName: firstOf(str(n["system-name"]), str(n["chassis-id"])), RemotePort: firstOf(str(n["port-id"]), str(n["port-description"])),
				RemoteDesc: str(n["system-description"]), RemoteAddr: panMgmtAddr(n), Protocol: "lldp", Detail: redactMap(n)}
			if nb.RemoteName == "" && nb.RemotePort == "" {
				continue // a port with no neighbor
			}
			out = append(out, nb)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].LocalPort < out[b].LocalPort })
	return out, nil
}

// ---- routing ----

// panRouteProto is the protocol of a route from its flags ("A S", "A C", "A O1", "A B").
func panRouteProto(flags string) string {
	for _, f := range strings.Fields(flags) {
		switch {
		case f == "C":
			return "connected"
		case f == "S":
			return "static"
		case f == "R":
			return "rip"
		case f == "B":
			return "bgp"
		case f == "H":
			return "host"
		case strings.HasPrefix(f, "O"):
			return "ospf"
		}
	}
	return ""
}

func (p *panos) Routes(ctx context.Context) ([]Route, error) {
	if _, err := p.system(ctx); err != nil {
		return nil, err
	}
	if p.panorama() {
		return nil, ErrUnsupported
	}
	v, err := p.req(ctx, panOp("<show><routing><route></route></routing></show>"))
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, r := range rows(dig(v, "entry")) {
		out = append(out, Route{Protocol: panRouteProto(str(r["flags"])), Prefix: str(r["destination"]), NextHop: str(r["nexthop"]), Interface: str(r["interface"]),
			Metric: num(r["metric"]), VRF: str(r["virtual-router"]), Raw: redactMap(r)})
	}
	return out, nil
}

// Routing: the live state of the routing protocols and the routing configuration (virtual routers, and the logical routers of the
// advanced routing engine).  The advanced routing engine's own live commands are not read.
func (p *panos) Routing(ctx context.Context) (Routing, error) {
	if _, err := p.system(ctx); err != nil {
		return Routing{}, err
	}
	if p.panorama() {
		return Routing{}, ErrUnsupported
	}
	return gather([]part{
		{"summary", "<show><routing><summary></summary></routing></show>"},
		{"ospf_neighbors", "<show><routing><protocol><ospf><neighbor></neighbor></ospf></protocol></routing></show>"},
		{"ospf_interfaces", "<show><routing><protocol><ospf><interface></interface></ospf></protocol></routing></show>"},
		{"ospf_areas", "<show><routing><protocol><ospf><area></area></ospf></protocol></routing></show>"},
		{"bgp_summary", "<show><routing><protocol><bgp><summary></summary></bgp></protocol></routing></show>"},
		{"bgp_peers", "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>"},
		{"bgp_loc_rib", "<show><routing><protocol><bgp><loc-rib></loc-rib></bgp></protocol></routing></show>"},
		{"rip_summary", "<show><routing><protocol><rip><summary></summary></rip></protocol></routing></show>"},
		{"bfd", "<show><routing><bfd><summary></summary></bfd></routing></show>"},
		{"config_virtual_routers", panDevices + "/network/virtual-router"},
		{"config_logical_routers", panDevices + "/network/logical-router"},
		{"config_routing_profiles", panDevices + "/network/routing-profile"},
	}, func(w string) (any, error) { return p.get(ctx, w) })
}

// ---- firewall ----

func (p *panos) vsysPath() string { return panDevices + "/vsys/entry[@name='" + p.vsys + "']" }

// hitCount is the rule hit counters of one rule base ("security", "nat", ...) of the virtual system.
func (p *panos) hitCount(base string) string {
	return "<show><rule-hit-count><vsys><vsys-name><entry name='" + p.vsys + "'><rule-base><entry name='" + base +
		"'><rules><all></all></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
}

// Firewall: on a firewall, the rules with their hit counters, the session summary, NAT pool use, and the rules and objects of the
// virtual system from the configuration; on a Panorama, the managed firewalls, device groups and templates, and the shared and
// device group rules and objects.
func (p *panos) Firewall(ctx context.Context) (Firewall, error) {
	if _, err := p.system(ctx); err != nil {
		return Firewall{}, err
	}
	get := func(w string) (any, error) { return p.get(ctx, w) }
	if p.panorama() {
		dg := panDevices + "/device-group"
		if p.dg != "" {
			dg += "/entry[@name='" + p.dg + "']"
		}
		return gather([]part{
			{"managed_devices", "<show><devices><all></all></devices></show>"},
			{"device_groups", "<show><devicegroups></devicegroups></show>"},
			{"templates", "<show><templates></templates></show>"},
			{"shared_pre_rules", "/config/shared/pre-rulebase"},
			{"shared_post_rules", "/config/shared/post-rulebase"},
			{"shared_addresses", "/config/shared/address"},
			{"shared_address_groups", "/config/shared/address-group"},
			{"shared_services", "/config/shared/service"},
			{"shared_service_groups", "/config/shared/service-group"},
			{"shared_tags", "/config/shared/tag"},
			{"device_group_config", dg},
		}, get)
	}
	vs := p.vsysPath()
	return gather([]part{
		{"hit_counts_security", p.hitCount("security")},
		{"hit_counts_nat", p.hitCount("nat")},
		{"hit_counts_pbf", p.hitCount("pbf")},
		{"hit_counts_decryption", p.hitCount("decryption")},
		{"hit_counts_application_override", p.hitCount("application-override")},
		{"session_info", "<show><session><info></info></session></show>"},
		{"nat_pool_utilization", "<show><running><ippool></ippool></running></show>"},
		{"security_rules", vs + "/rulebase/security"},
		{"default_security_rules", vs + "/rulebase/default-security-rules"},
		{"nat_rules", vs + "/rulebase/nat"},
		{"pbf_rules", vs + "/rulebase/pbf"},
		{"decryption_rules", vs + "/rulebase/decryption"},
		{"qos_rules", vs + "/rulebase/qos"},
		{"application_override_rules", vs + "/rulebase/application-override"},
		{"dos_rules", vs + "/rulebase/dos"},
		{"addresses", vs + "/address"},
		{"address_groups", vs + "/address-group"},
		{"services", vs + "/service"},
		{"service_groups", vs + "/service-group"},
		{"applications", vs + "/application"},
		{"application_groups", vs + "/application-group"},
		{"application_filters", vs + "/application-filter"},
		{"tags", vs + "/tag"},
		{"zones", vs + "/zone"},
		{"external_lists", vs + "/external-list"},
		{"schedules", vs + "/schedule"},
		{"security_profiles", vs + "/profiles"},
		{"security_profile_groups", vs + "/profile-group"},
		{"zone_protection_profiles", panDevices + "/network/profiles/zone-protection-profile"},
		{"shared_addresses", "/config/shared/address"},
		{"shared_address_groups", "/config/shared/address-group"},
		{"shared_services", "/config/shared/service"},
		{"shared_service_groups", "/config/shared/service-group"},
	}, get)
}

// ---- resources ----

var (
	topCPURE   = regexp.MustCompile(`(?i)Cpu\(s\):.*?(\d+(?:[.,]\d+)?)\s*%?\s*id\b`) // "96.0 id" (procps-ng) or "96.0%id" (older)
	topMemRE   = regexp.MustCompile(`(?i)([KMG]i?B)\s+(Mem|Swap)\s*:\s*(.*)`)
	topNumRE   = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s+(total|free|used|buff/cache|buffers|cached)`)
	topAvailRE = regexp.MustCompile(`(?i)(\d+(?:[.,]\d+)?)\s+avail\s+Mem`) // printed at the end of the Swap line, but it is the memory's
	dfLineRE   = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S+)\s*$`)
	sizeUnits  = map[byte]float64{'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30, 'T': 1 << 40}
)

func topFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.Replace(s, ",", ".", 1), 64)
	return f
}

// panTop reads the CPU and memory lines of "show system resources", which prints top: "%Cpu(s): ... 96.0 id", "KiB Mem : ... total, ...".
func panTop(text string) (*CPU, []Memory) {
	var cpu *CPU
	var mem []Memory
	if m := topCPURE.FindStringSubmatch(text); m != nil {
		cpu = &CPU{Now: float64(int64((100-topFloat(m[1]))*100+0.5)) / 100}
	}
	for _, m := range topMemRE.FindAllStringSubmatch(text, -1) {
		unit := sizeUnits[strings.ToUpper(m[1])[0]]
		v := map[string]float64{}
		for _, kv := range topNumRE.FindAllStringSubmatch(m[3], -1) {
			v[strings.ToLower(kv[2])] = topFloat(kv[1]) * unit
		}
		total := int64(v["total"])
		if total <= 0 {
			continue
		}
		used := total - int64(v["free"]) - int64(v["buff/cache"])
		if a := topAvailRE.FindStringSubmatch(text); a != nil && strings.EqualFold(m[2], "mem") {
			used = total - int64(topFloat(a[1])*unit)
		}
		if used < 0 {
			used = 0
		}
		mm := Memory{Name: strings.ToLower(m[2]), Total: total, Free: int64(v["free"]), Used: used}
		if mm.Name == "mem" {
			mm.Name = "system"
		}
		mm.UsedPercent = pct(mm.Used, mm.Total)
		mem = append(mem, mm)
	}
	return cpu, mem
}

// panSize reads a size df prints ("7.6G", "512M", "1024") as bytes.
func panSize(s string) int64 {
	if s == "" {
		return 0
	}
	if u, ok := sizeUnits[strings.ToUpper(s[len(s)-1:])[0]]; ok {
		return int64(topFloat(s[:len(s)-1]) * u)
	}
	return int64(topFloat(s))
}

// panDisk reads "show system disk-space" (df).
func panDisk(text string) []Storage {
	var out []Storage
	for _, ln := range strings.Split(text, "\n") {
		m := dfLineRE.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		used, _ := strconv.ParseFloat(m[5], 64)
		out = append(out, Storage{Name: m[6], Size: panSize(m[2]), Free: panSize(m[4]), UsedPercent: used})
	}
	return out
}

// panSensors takes the readings out of an environmentals answer (thermal, fans or power): every object with a description.
func panSensors(kind, units string, key string, v any) []Sensor {
	var out []Sensor
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			if d := str(t["description"]); d != "" {
				s := Sensor{Name: d, Kind: kind, Units: units, Raw: redactMap(t)}
				for k, x := range t {
					switch strings.ToLower(k) {
					case key:
						s.Reading = new(float64)
						*s.Reading = flt(x)
					case "alarm":
						if strings.EqualFold(str(x), "true") {
							s.State = "alarm"
						} else {
							s.State = "ok"
						}
					}
				}
				out = append(out, s)
				return
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

// Resources: CPU and memory of the management plane, the disks, and (on hardware) temperatures, fans and power; session use, the
// data plane's CPU and the HA state are in details.
func (p *panos) Resources(ctx context.Context) (Resources, error) {
	if _, err := p.system(ctx); err != nil {
		return Resources{}, err
	}
	parts := []part{
		{"system_resources", "<show><system><resources></resources></system></show>"},
		{"disk_space", "<show><system><disk-space></disk-space></system></show>"},
	}
	if !p.panorama() {
		parts = append(parts,
			part{"session_info", "<show><session><info></info></session></show>"},
			part{"dataplane_cpu_minute", "<show><running><resource-monitor><minute><last>5</last></minute></resource-monitor></running></show>"})
	}
	parts = append(parts,
		part{"ha_state", "<show><high-availability><state></state></high-availability></show>"},
		part{"thermal", "<show><system><environmentals><thermal></thermal></environmentals></system></show>"},
		part{"fans", "<show><system><environmentals><fans></fans></environmentals></system></show>"},
		part{"power", "<show><system><environmentals><power></power></environmentals></system></show>"})
	d, err := gather(parts, func(w string) (any, error) { return p.get(ctx, w) })
	out := Resources{Details: d}
	if err != nil {
		return out, err
	}
	if t, ok := d.Protocols["system_resources"].(string); ok {
		out.CPU, out.Memory = panTop(t)
	}
	if t, ok := d.Protocols["disk_space"].(string); ok {
		out.Storage = panDisk(t)
	}
	out.Sensors = append(out.Sensors, panSensors("temperature", "celsius", "degreesc", d.Protocols["thermal"])...)
	out.Sensors = append(out.Sensors, panSensors("fan", "rpm", "rpms", d.Protocols["fans"])...)
	out.Sensors = append(out.Sensors, panSensors("psu", "V", "volts", d.Protocols["power"])...)
	return out, nil
}

// VLANs are the tagged subinterfaces of a firewall: the tag is the VLAN ID and the parent interface its port.
func (p *panos) VLANs(ctx context.Context) ([]VLAN, error) {
	if _, err := p.system(ctx); err != nil {
		return nil, err
	}
	if p.panorama() {
		return nil, ErrUnsupported
	}
	d, err := p.ifaces(ctx)
	if err != nil {
		return nil, err
	}
	var out []VLAN
	for _, i := range d.list {
		e := d.ifnet[i.Name]
		tag := num(e["tag"])
		if tag <= 0 {
			continue
		}
		l := VLAN{ID: tag, Name: i.Name, Raw: redactMap(e)}
		if parent, _, ok := strings.Cut(i.Name, "."); ok {
			l.Ports = []string{parent}
		}
		out = append(out, l)
	}
	sort.Slice(out, func(a, b int) bool {
		return out[a].ID < out[b].ID || out[a].ID == out[b].ID && out[a].Name < out[b].Name
	})
	return out, nil
}

// ---- configuration and commands ----

// Config is the running configuration as XML (the whole tree, or a Panorama's own).
func (p *panos) Config(ctx context.Context) (string, error) {
	b, err := p.fetch(ctx, panCfg("/config"))
	if err != nil {
		return "", err
	}
	if bytes.Contains(b[:min(len(b), 300)], []byte(`status="error"`)) {
		_, err := panResult(b)
		return "", err
	}
	var env struct {
		XMLName xml.Name `xml:"response"`
		Result  struct {
			Inner string `xml:",innerxml"`
		} `xml:"result"`
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	if err := d.Decode(&env); err != nil {
		return "", fmt.Errorf("PAN-OS: the configuration answer is not the XML expected: %v", err)
	}
	return strings.TrimSpace(env.Result.Inner), nil
}

var panElementRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// panCLIToXML turns "show system info" into <show><system><info></info></system></show>.  A word is an element; a word in double
// quotes is the text of the element before it; a last word that cannot be an element name (ethernet1/1, 10.0.0.1, 4711) is text too.
func panCLIToXML(cmd string) (string, error) {
	if strings.Contains(cmd, "|") {
		return "", errors.New("PAN-OS runs no output filters over its API: leave out the |")
	}
	type tok struct {
		s      string
		quoted bool
	}
	var toks []tok
	for i := 0; i < len(cmd); {
		switch c := cmd[i]; {
		case c == ' ' || c == '\t':
			i++
		case c == '"':
			j := strings.IndexByte(cmd[i+1:], '"')
			if j < 0 {
				return "", errors.New("a double quote is not closed")
			}
			toks = append(toks, tok{cmd[i+1 : i+1+j], true})
			i += j + 2
		default:
			j := i
			for j < len(cmd) && cmd[j] != ' ' && cmd[j] != '\t' && cmd[j] != '"' {
				j++
			}
			toks = append(toks, tok{cmd[i:j], false})
			i = j
		}
	}
	if len(toks) < 2 || toks[0].quoted || toks[0].s != "show" {
		return "", errors.New("a show command: show followed by its words")
	}
	if len(toks) > 32 {
		return "", errors.New("a command of at most 32 words")
	}
	var open []string
	var sb strings.Builder
	value := ""
	for i, t := range toks {
		last := i == len(toks)-1
		switch {
		case !t.quoted && panElementRE.MatchString(t.s):
			open = append(open, t.s)
			sb.WriteString("<" + t.s + ">")
		case t.quoted && last, !t.quoted && last:
			value = t.s
		default:
			return "", fmt.Errorf("%q is not a word of a command: put a value in double quotes, after the words it belongs to", t.s)
		}
	}
	if value != "" {
		_ = xml.EscapeText(&sb, []byte(value))
	}
	for i := len(open) - 1; i >= 0; i-- {
		sb.WriteString("</" + open[i] + ">")
	}
	return sb.String(), nil
}

// Show runs one show command and returns what PAN-OS answers: the text of a command that prints text, else the answer as indented
// JSON (the XML as the same generic values the other requests return, with keys and passwords hidden).
func (p *panos) Show(ctx context.Context, cmd string) (string, error) {
	cmd, err := CheckShow(cmd)
	if err != nil {
		return "", err
	}
	x, err := panCLIToXML(cmd)
	if err != nil {
		return "", err
	}
	v, err := p.req(ctx, panOp(x))
	switch t := v.(type) {
	case nil:
		return "", err
	case string:
		return t, err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return string(b), err
}

// panShowNames checks that cmd is one well-formed <show> command and returns the names of its elements.  Nothing else: no
// processing instruction, no DOCTYPE, no second element after the first, and the root must be <show>.
func panShowNames(cmd string) ([]string, error) {
	d := xml.NewDecoder(strings.NewReader(cmd))
	var names []string
	depth, ended := 0, false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cmd: not well-formed XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if ended || depth == 0 && t.Name.Local != "show" {
				return nil, errors.New("cmd: one <show>...</show> command is read (nothing that changes or clears anything)")
			}
			names = append(names, t.Name.Local)
			depth++
		case xml.EndElement:
			if depth--; depth == 0 {
				ended = true
			}
		case xml.ProcInst, xml.Directive:
			return nil, errors.New("cmd: no processing instruction or DOCTYPE")
		case xml.CharData:
			if (depth == 0 || ended) && strings.TrimSpace(string(t)) != "" {
				return nil, errors.New("cmd: text outside the <show> command")
			}
		}
	}
	if len(names) == 0 || depth != 0 {
		return nil, errors.New("cmd: one <show>...</show> command, e.g. <show><system><info></info></system></show>")
	}
	return names, nil
}

// panLogTypes are the logs the XML API searches (type=log&log-type=...).
var panLogTypes = map[string]bool{"traffic": true, "threat": true, "url": true, "wildfire": true, "data": true, "config": true, "system": true,
	"hipmatch": true, "globalprotect": true, "userid": true, "auth": true, "tunnel": true, "decryption": true, "gtp": true, "sctp": true,
	"iptag": true, "corr": true, "corr-detail": true, "corr-categ": true}

// PanLogTypeOK says whether t is a log the XML API searches.
func PanLogTypeOK(t string) bool { return panLogTypes[t] }

const panLogMax = 5000 // the most logs PAN-OS gives for one search

// replaceable in tests
var (
	panLogPoll = 500 * time.Millisecond
	panLogWait = 90 * time.Second
)

const panLogSlow = "PAN-OS: the log search did not finish in time; narrow the query or ask for fewer logs"

var panJobRE = regexp.MustCompile(`^[0-9]{1,12}$`)

// logQuery checks the parameters of a log search and returns them as PAN-OS takes them.
func panLogQuery(q url.Values) (url.Values, error) {
	lt := q.Get("log-type")
	if !panLogTypes[lt] {
		return nil, errors.New("path: type=log needs a log-type: traffic, threat, url, wildfire, data, config, system, hipmatch, globalprotect, userid, auth, tunnel, decryption, gtp, sctp, iptag, corr, corr-detail or corr-categ")
	}
	out := url.Values{"type": {"log"}, "log-type": {lt}}
	if f := q.Get("query"); f != "" {
		if len(f) > 2000 || strings.ContainsFunc(f, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, errors.New("path: the query of a log search is one line of at most 2000 characters, e.g. (user.src eq 'acme\\jo')")
		}
		out.Set("query", f)
	}
	for k, max := range map[string]int{"nlogs": panLogMax, "skip": 1 << 30} {
		if v := q.Get(k); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > max || k == "nlogs" && n == 0 {
				return nil, fmt.Errorf("path: %s is a number (nlogs: 1 to %d, 20 when left out)", k, panLogMax)
			}
			out.Set(k, strconv.Itoa(n))
		}
	}
	switch d := q.Get("dir"); d {
	case "":
	case "backward", "forward":
		out.Set("dir", d)
	default:
		return nil, errors.New("path: dir is backward (newest first, the default) or forward")
	}
	return out, nil
}

// logs runs one log search.  PAN-OS answers a search with a job, which is asked for its result until it has finished, and
// is then removed: the three requests are made here, so one read gives the logs.  A search reads; it changes nothing on the
// device but the job, which is its own.
func (p *panos) logs(ctx context.Context, q url.Values) (any, error) {
	v, err := p.req(ctx, q)
	if err != nil {
		return nil, err
	}
	job, _ := dig(v, "job").(string)
	if !panJobRE.MatchString(job) {
		return nil, errors.New("PAN-OS: the log search answered no job")
	}
	defer func() { // the job is removed whatever became of it, also when the caller has gone away
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, _ = p.req(fctx, url.Values{"type": {"log"}, "action": {"finish"}, "job-id": {job}})
	}()
	ctx, cancel := context.WithTimeout(ctx, panLogWait)
	defer cancel()
	for {
		r, err := p.req(ctx, url.Values{"type": {"log"}, "action": {"get"}, "job-id": {job}})
		if err != nil {
			if ctx.Err() != nil {
				return nil, errors.New(panLogSlow)
			}
			return nil, err
		}
		if st, _ := dig(r, "job", "status").(string); st == "FIN" {
			l, _ := dig(r, "log", "logs").(map[string]any)
			if l["entry"] == nil {
				return map[string]any{"entry": []any{}}, nil // nothing matched
			}
			return l, nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New(panLogSlow)
		case <-time.After(panLogPoll):
		}
	}
}

// APIGet reads the XML API: /api/?type=op&cmd=<show>... (a show command), /api/?type=config&action=show&xpath=/config/... (the
// running configuration; action=get is the candidate) or /api/?type=log&log-type=...&query=... (a search of the logs).  The key,
// a target, and every other parameter are refused, and so is everything that is not a show command, a read of the
// configuration or a log search.
func (p *panos) APIGet(ctx context.Context, path string) (any, bool, error) {
	u, err := url.Parse(path)
	if err != nil || u.Path != "/api" && u.Path != "/api/" {
		return nil, false, errors.New("path: PAN-OS reads /api/?type=op&cmd=<show>..., /api/?type=config&action=show&xpath=... and /api/?type=log&log-type=... (the catalog has examples)")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, false, fmt.Errorf("path: the query: %v", err)
	}
	isLog := q.Get("type") == "log"
	for k, vs := range q {
		known := k == "type" || !isLog && (k == "cmd" || k == "xpath" || k == "action") || isLog && (k == "log-type" || k == "query" || k == "nlogs" || k == "skip" || k == "dir")
		if !known || len(vs) != 1 {
			if isLog {
				return nil, false, fmt.Errorf("path: the parameter %q is not read here (a log search takes one each of log-type, query, nlogs, skip and dir)", k)
			}
			return nil, false, fmt.Errorf("path: the parameter %q is not read here (only one each of type, cmd, xpath and action)", k)
		}
	}
	var clean url.Values
	switch q.Get("type") {
	case "op":
		if _, err := panShowNames(q.Get("cmd")); err != nil {
			return nil, false, err
		}
		clean = panOp(q.Get("cmd"))
	case "config":
		if a := q.Get("action"); a != "show" && a != "get" {
			return nil, false, errors.New("path: type=config reads with action=show (the running configuration) or action=get (the candidate)")
		}
		if !strings.HasPrefix(q.Get("xpath"), "/") {
			return nil, false, errors.New("path: type=config needs an xpath that starts with /, e.g. /config/devices/entry[@name='localhost.localdomain']/network")
		}
		clean = url.Values{"type": {"config"}, "action": {q.Get("action")}, "xpath": {q.Get("xpath")}}
	case "log":
		lq, err := panLogQuery(q)
		if err != nil {
			return nil, false, err
		}
		v, err := p.logs(ctx, lq)
		if err != nil {
			return nil, false, err
		}
		return Redact(v), false, nil
	default:
		return nil, false, errors.New("path: type=op (a show command), type=config (a read of the configuration) or type=log (a search of the logs)")
	}
	v, err := p.req(ctx, clean)
	if err != nil {
		return nil, false, err
	}
	switch t := v.(type) {
	case nil:
		return nil, false, nil
	case string:
		return t, true, nil // text
	}
	return Redact(v), false, nil
}

func (p *panos) APICatalog(ctx context.Context) (any, error) {
	out := map[string]any{
		"how": "GET /api/?type=op&cmd=<XML> runs a show command: the CLI words as nested elements, <show><system><info></info></system></show> for \"show system info\". " +
			"GET /api/?type=config&action=show&xpath=<XPath> reads the running configuration (action=get: the candidate). " +
			"GET /api/?type=log&log-type=<type>&query=<filter>&nlogs=<N> searches the logs and answers the entries, newest first (log-type: traffic, threat, url, system, globalprotect, userid, auth, hipmatch, decryption, tunnel, ...; " +
			"query: the filter of the Monitor tab, e.g. (machinename eq 'PC-1') or (addr.src in 10.0.0.5) and (receive_time geq '2026/11/10 08:00:00'); nlogs: 1 to 5000, 20 when left out; skip and dir=forward page through them). " +
			"A space in a query is %20. " +
			"An <entry> or a <member> is always a list. Percent-encode what the URL needs. Nothing that changes, clears or commits anything is sent.",
		"examples": []string{
			"/api/?type=op&cmd=<show><system><info></info></system></show>",
			"/api/?type=op&cmd=<show><interface>all</interface></show>",
			"/api/?type=config&action=show&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security",
			"/api/?type=log&log-type=traffic&nlogs=50&query=(addr.src%20in%2010.0.0.5)",
		},
	}
	if _, err := p.system(ctx); err == nil && p.panorama() {
		out["kind"] = "panorama"
		out["examples"] = []string{
			"/api/?type=op&cmd=<show><devices><all></all></devices></show>",
			"/api/?type=op&cmd=<show><devicegroups></devicegroups></show>",
			"/api/?type=config&action=show&xpath=/config/shared/pre-rulebase/security",
			"/api/?type=log&log-type=globalprotect&nlogs=50&query=(machinename%20eq%20'PC-1')",
		}
	} else if err == nil {
		out["kind"] = "firewall"
	}
	return out, nil
}

func (p *panos) Close(context.Context) { p.api.close() }

// LogSearch is the search of one log for the troubleshooting of a user or a host: the newest n entries that match.
func (p *panos) LogSearch(ctx context.Context, logType, query string, n int) ([]map[string]any, error) {
	q, err := panLogQuery(url.Values{"log-type": {logType}, "query": {query}, "nlogs": {strconv.Itoa(n)}})
	if err != nil {
		return nil, err
	}
	v, err := p.logs(ctx, q)
	if err != nil {
		return nil, err
	}
	m, _ := Redact(v).(map[string]any)
	es, _ := m["entry"].([]any)
	out := make([]map[string]any, 0, len(es))
	for _, e := range es {
		if x, ok := e.(map[string]any); ok {
			out = append(out, x)
		}
	}
	return out, nil
}
