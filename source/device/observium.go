package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Observium (https://docs.observium.org/api), the network monitoring system, through its REST API: https://HOST/api/v0/...
// (enable it with $config['api']['enable'] = TRUE; in config.php; the API is a feature of the Subscription Edition).  The
// credential is an API token (the credential's Token, sent as "Authorization: Bearer TOKEN"; a token made "read only" reads
// only), or a user name and password (HTTP basic authentication against an Observium user).  Neither ever goes into a URL.
// Reads send GET only; a change is RawChange (rawmon.go: POST, PUT, PATCH, DELETE below /api/v0, rw keys only).  Observium must be served over https; the optional "prefix" says where it is below the host
// ("/observium").
//
// Observium is a monitor, not a switch: the "device" here is either
//
//   - the Observium server (no option "device"): its facts (how many devices it monitors), its health (what it says is
//     down, the alerts that have failed), and through Show and APIGet everything it holds (devices, ports, neighbours,
//     sensors, status, storage, memory pools, processors, inventory, alerts, the alert log, groups, ...).  "show device NAME"
//     answers everything it knows about ONE monitored device, as one answer: the device's record, its ports, addresses,
//     neighbours, sensors, status indicators, storage, memory pools, processors, inventory, counters, probes, alerts and its
//     recent alert log; or
//   - one monitored device (option "device": its host name or Observium device ID): its facts, ports with their counters,
//     LLDP/CDP neighbours, CPU, memory, storage and sensors, and "show device" with no name.
//
// The documentation of the API gives the shape of the answer for devices only.  The driver therefore reads an answer without
// assuming its wrapper (the first collection in it, keyed by ID or as a list), looks for a field under the names Observium's
// database uses, and always keeps the whole row next to what it reads from it (Properties, Detail, Raw, Details), so a field
// it does not know is still shown.  /api/v0/openapi.json (read through APIGet) is Observium's own description of every answer.
//
// What an answer holds that is a secret (an SNMP community, an SNMP authentication or privacy password) is hidden (Redact).

func init() { Register("observium", newObservium) }

type observium struct {
	d      Device
	api    *apiClient
	prefix string // where Observium is below the host: "" or "/observium"
	dev    string // option device: a host name or an Observium device ID; "" is the server
	ref    string // the reference the cached row below was found with
	row    map[string]any
}

const obsBase = "/api/v0"

var (
	obsRefRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
	obsPrefixRE = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*$`)
	obsKeyRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	obsValRE    = regexp.MustCompile(`^[A-Za-z0-9._:@/*-]{1,128}$`)
)

// obsWait is how long a 429 (the API throttles) is waited out, once; a variable so tests are quick.
var obsWait = 2 * time.Second

func newObservium(d Device, c Credential) (Driver, error) {
	if c.Token == "" && (c.Username == "" || c.Password == "") {
		return nil, fmt.Errorf("device %s: Observium needs an API token, or a user name and a password", d.Name)
	}
	o := &observium{d: d, dev: strings.TrimSpace(d.Options["device"]), prefix: strings.TrimRight(strings.TrimSpace(d.Options["prefix"]), "/")}
	if o.dev != "" && !obsRefRE.MatchString(o.dev) {
		return nil, fmt.Errorf("device %s: option device is a host name or an Observium device ID", d.Name)
	}
	if o.prefix != "" && (!obsPrefixRE.MatchString(o.prefix) || strings.Contains(o.prefix, "..")) {
		return nil, fmt.Errorf("device %s: option prefix is the path Observium is served below, such as /observium", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		api.hdr.Set("Authorization", "Bearer "+c.Token)
	} else {
		api.hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	}
	api.hdr.Set("User-Agent", "netdir")
	o.api = api
	return o, nil
}

// do sends one GET below /api/v0, waiting out a 429 once.
func (o *observium) do(ctx context.Context, path string) ([]byte, error) {
	for try := 0; ; try++ {
		b, err := o.api.do(ctx, http.MethodGet, o.prefix+obsBase+path, nil, nil)
		var se *statusError
		if err == nil || !errors.As(err, &se) || se.Code != http.StatusTooManyRequests || try >= 1 {
			return b, err
		}
		if err := sleepCtx(ctx, obsWait); err != nil {
			return nil, err
		}
	}
}

// obsFailed turns Observium's own error ({"status": "failed", "message": ...}, which may come with HTTP 200) into a statusError.
func obsFailed(v any) error {
	if m, ok := v.(map[string]any); ok {
		if s := strings.ToLower(str(m["status"])); s == "failed" || s == "error" {
			return &statusError{Code: http.StatusBadRequest, Body: firstOf(str(m["message"]), "the request failed")}
		}
	}
	return nil
}

func (o *observium) get(ctx context.Context, path string) (any, error) {
	b, err := o.do(ctx, path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
	}
	if err := obsFailed(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (o *observium) list(ctx context.Context, path, name string) ([]map[string]any, error) {
	v, err := o.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return obsRows(v, name), nil
}

// obsMeta are the keys of an answer that are not its collection.
var obsMeta = map[string]bool{"status": true, "count": true, "pagesize": true, "pageno": true, "countpage": true, "debug": true, "message": true}

// obsKeys sorts the keys of a collection keyed by ID: numerically when they are numbers.
func obsKeys(m map[string]any) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Slice(k, func(i, j int) bool {
		a, e1 := strconv.ParseInt(k[i], 10, 64)
		b, e2 := strconv.ParseInt(k[j], 10, 64)
		if e1 == nil && e2 == nil {
			return a < b
		}
		return k[i] < k[j]
	})
	return k
}

// obsRows reads the rows of an answer: the collection under name, else the first collection in it, as a list or keyed by ID
// ({"ports": {"12": {...}, "13": {...}}}); a collection whose values are not rows is one row.
func obsRows(v any, name string) []map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return rows(v)
	}
	coll, found := m[name]
	switch coll.(type) {
	case map[string]any, []any:
	default:
		coll, found = nil, false // not a collection: the envelope's "status": "ok" is not the rows of /status/
	}
	if !found {
		for _, k := range obsKeys(m) {
			if obsMeta[k] {
				continue
			}
			switch m[k].(type) {
			case map[string]any, []any:
				coll, found = m[k], true
			}
			if found {
				break
			}
		}
	}
	switch t := coll.(type) {
	case []any:
		return rows(t)
	case map[string]any:
		if len(t) == 0 {
			return nil
		}
		for _, x := range t {
			if _, ok := x.(map[string]any); !ok {
				return []map[string]any{t} // not keyed by ID: the collection is the row
			}
		}
		out := make([]map[string]any, 0, len(t))
		for _, k := range obsKeys(t) {
			out = append(out, t[k].(map[string]any))
		}
		return out
	}
	return nil
}

func obsAny(r []map[string]any) []any {
	out := make([]any, len(r))
	for i := range r {
		out[i] = r[i]
	}
	return out
}

// ---- finding a monitored device ----

// resolve finds the device a host name or an ID names: Observium's own lookup first (the full host name, or the ID), then the
// list of devices, so "ipam2" finds ipam2.example.com when nothing else matches it.  It returns the device's row and its ID.
func (o *observium) resolve(ctx context.Context, ref string) (map[string]any, string, error) {
	ref = strings.TrimSpace(ref)
	if !obsRefRE.MatchString(ref) {
		return nil, "", errors.New("device: a host name or an Observium device ID")
	}
	if o.row != nil && strings.EqualFold(o.ref, ref) {
		return o.row, str(o.row["device_id"]), nil
	}
	remember := func(r map[string]any) (map[string]any, string, error) {
		o.ref, o.row = ref, r
		return r, str(r["device_id"]), nil
	}
	rs, err := o.list(ctx, "/devices/"+url.PathEscape(ref)+"/", "devices")
	var se *statusError
	if err != nil && !(errors.As(err, &se) && (se.Code == http.StatusBadRequest || se.Code == http.StatusNotFound)) {
		return nil, "", err
	}
	if err == nil && len(rs) == 1 && str(rs[0]["device_id"]) != "" {
		return remember(rs[0])
	}
	all, err := o.list(ctx, "/devices/?fields=device_id,hostname,sysName", "devices")
	if err != nil {
		return nil, "", err
	}
	id, err := obsPick(ref, all)
	if err != nil {
		return nil, "", err
	}
	rs, err = o.list(ctx, "/devices/"+url.PathEscape(id)+"/", "devices")
	if err != nil {
		return nil, "", err
	}
	if len(rs) == 0 {
		return nil, "", fmt.Errorf("Observium has no device %s", id)
	}
	return remember(rs[0])
}

// obsPick chooses the device of the list a name means: its host name or ID exactly, else the one host name that starts with the
// name and a dot, else the one that contains it.  Several that fit are an error that names them.
func obsPick(ref string, all []map[string]any) (string, error) {
	lo := strings.ToLower(ref)
	name := func(r map[string]any) (host, sys string) {
		return strings.ToLower(str(r["hostname"])), strings.ToLower(firstOf(str(r["sysName"]), str(r["sysname"])))
	}
	tiers := []func(r map[string]any) bool{
		func(r map[string]any) bool {
			h, s := name(r)
			return h == lo || s == lo || str(r["device_id"]) == ref
		},
		func(r map[string]any) bool {
			h, s := name(r)
			return strings.HasPrefix(h, lo+".") || strings.HasPrefix(s, lo+".")
		},
		func(r map[string]any) bool {
			h, s := name(r)
			return strings.Contains(h, lo) || strings.Contains(s, lo)
		},
	}
	for _, fit := range tiers {
		var hit []map[string]any
		for _, r := range all {
			if fit(r) {
				hit = append(hit, r)
			}
		}
		switch {
		case len(hit) == 1:
			return str(hit[0]["device_id"]), nil
		case len(hit) > 1:
			var n []string
			for i, r := range hit {
				if i == 10 {
					n = append(n, "…")
					break
				}
				n = append(n, firstOf(str(r["hostname"]), str(r["sysName"]))+" (ID "+str(r["device_id"])+")")
			}
			return "", fmt.Errorf("%q fits more than one Observium device: %s", ref, strings.Join(n, ", "))
		}
	}
	return "", fmt.Errorf("Observium has no device that matches %q (show devices lists them)", ref)
}

// target is the device this driver's tools are about: the option device, found.
func (o *observium) target(ctx context.Context) (map[string]any, string, error) {
	if o.dev == "" {
		return nil, "", ErrUnsupported // name a device with the option device
	}
	return o.resolve(ctx, o.dev)
}

// ---- facts, interfaces, neighbours ----

func (o *observium) Facts(ctx context.Context) (Facts, error) {
	if o.dev == "" {
		rs, err := o.list(ctx, "/devices/?fields=device_id", "devices")
		if err != nil {
			return Facts{}, err
		}
		return Facts{Hostname: o.d.Address, Vendor: "Observium", Model: fmt.Sprintf("Network monitoring: %d devices", len(rs))}, nil
	}
	r, _, err := o.resolve(ctx, o.dev)
	if err != nil {
		return Facts{}, err
	}
	return Facts{
		Hostname:  firstOf(str(r["hostname"]), str(r["sysName"]), o.dev),
		Vendor:    firstOf(str(r["vendor"]), str(r["os"]), "unknown"),
		Model:     str(r["hardware"]),
		OSVersion: str(r["version"]),
		Serial:    str(r["serial"]),
		UptimeS:   num(r["uptime"]),
	}, nil
}

// portRows are the ports of the device (not the ones Observium has marked deleted).
func (o *observium) portRows(ctx context.Context, id string) ([]map[string]any, error) {
	rs, err := o.list(ctx, "/ports/?device_id="+url.QueryEscape(id), "ports")
	if err != nil {
		return nil, err
	}
	out := rs[:0:0]
	for _, r := range rs {
		if str(r["deleted"]) != "1" {
			out = append(out, r)
		}
	}
	return out, nil
}

// obsAddrs are the addresses of the device's ports by port ID, "10.0.0.1/24"; a device whose addresses cannot be read has none.
func (o *observium) obsAddrs(ctx context.Context, id string) map[string][]string {
	rs, err := o.list(ctx, "/address/?device_id="+url.QueryEscape(id), "addresses")
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, r := range rs {
		a := firstOf(str(r["ipv4_address"]), str(r["ipv6_address"]), str(r["address"]))
		if a == "" {
			continue
		}
		if p := firstOf(str(r["ipv4_prefixlen"]), str(r["ipv6_prefixlen"]), str(r["prefixlen"])); p != "" {
			a += "/" + p
		}
		pid := str(r["port_id"])
		out[pid] = append(out[pid], a)
	}
	return out
}

// obsMAC writes the 12 hex digits Observium keeps as aa:bb:cc:dd:ee:ff.
func obsMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) == 12 && !strings.ContainsAny(s, ":-. ") {
		return s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]
	}
	return s
}

func obsPortName(r map[string]any) string {
	return firstOf(str(r["ifName"]), str(r["ifDescr"]), str(r["port_label"]), str(r["label"]), "port "+str(r["port_id"]))
}

func obsInterface(r map[string]any, addrs map[string][]string) Interface {
	i := Interface{Name: obsPortName(r), Description: str(r["ifAlias"]), MAC: obsMAC(str(r["ifPhysAddress"])), Addresses: addrs[str(r["port_id"])]}
	if s := str(r["ifAdminStatus"]); s != "" {
		i.AdminUp = boolp(s == "up")
	}
	if s := str(r["ifOperStatus"]); s != "" {
		i.OperUp = boolp(s == "up")
	}
	i.SpeedMbps = num(r["ifSpeed"]) / 1_000_000 // ifSpeed is bits per second
	return i
}

func (o *observium) Interfaces(ctx context.Context) ([]Interface, error) {
	_, id, err := o.target(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := o.portRows(ctx, id)
	if err != nil {
		return nil, err
	}
	addrs := o.obsAddrs(ctx, id)
	out := make([]Interface, 0, len(ps))
	for _, r := range ps {
		out = append(out, obsInterface(r, addrs))
	}
	return out, nil
}

// obsCounters reads the traffic statistics of a port row.  Observium's rates are bytes (or packets) per second.
func obsCounters(r map[string]any) Counters {
	c := Counters{
		InOctets: num(r["ifInOctets"]), OutOctets: num(r["ifOutOctets"]),
		InUnicast: num(r["ifInUcastPkts"]), OutUnicast: num(r["ifOutUcastPkts"]),
		InMulticast: num(r["ifInMulticastPkts"]), OutMulticast: num(r["ifOutMulticastPkts"]),
		InBroadcast: num(r["ifInBroadcastPkts"]), OutBroadcast: num(r["ifOutBroadcastPkts"]),
		InDiscards: num(r["ifInDiscards"]), OutDiscards: num(r["ifOutDiscards"]),
		InErrors: num(r["ifInErrors"]), OutErrors: num(r["ifOutErrors"]),
	}
	c.InPackets = c.InUnicast + c.InMulticast + c.InBroadcast
	c.OutPackets = c.OutUnicast + c.OutMulticast + c.OutBroadcast
	c.RxKbps = int64(flt(r["ifInOctets_rate"]) * 8 / 1000)
	c.TxKbps = int64(flt(r["ifOutOctets_rate"]) * 8 / 1000)
	c.RxPPS = int64(flt(r["ifInUcastPkts_rate"]) + flt(r["ifInMulticastPkts_rate"]) + flt(r["ifInBroadcastPkts_rate"]))
	c.TxPPS = int64(flt(r["ifOutUcastPkts_rate"]) + flt(r["ifOutMulticastPkts_rate"]) + flt(r["ifOutBroadcastPkts_rate"]))
	all := map[string]any{}
	for k, v := range r {
		if strings.HasPrefix(k, "ifIn") || strings.HasPrefix(k, "ifOut") {
			all[k] = v
		}
	}
	if len(all) > 0 {
		c.All = all
	}
	return c
}

func (o *observium) Ports(ctx context.Context) ([]Port, error) {
	_, id, err := o.target(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := o.portRows(ctx, id)
	if err != nil {
		return nil, err
	}
	addrs := o.obsAddrs(ctx, id)
	out := make([]Port, 0, len(ps))
	for _, r := range ps {
		out = append(out, Port{Interface: obsInterface(r, addrs), Type: str(r["ifType"]), MTU: num(r["ifMtu"]), Duplex: str(r["ifDuplex"]),
			Counters: obsCounters(r), Properties: redactMap(r)})
	}
	return out, nil
}

func (o *observium) Neighbors(ctx context.Context) ([]Neighbor, error) {
	_, id, err := o.target(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := o.portRows(ctx, id)
	if err != nil {
		return nil, err
	}
	local := map[string]string{}
	for _, p := range ps {
		local[str(p["port_id"])] = obsPortName(p)
	}
	rs, err := o.list(ctx, "/neighbours/?device_id="+url.QueryEscape(id), "neighbours")
	if err != nil {
		return nil, err
	}
	out := make([]Neighbor, 0, len(rs))
	for _, r := range rs {
		if str(r["active"]) == "0" {
			continue
		}
		pid := str(r["port_id"])
		out = append(out, Neighbor{
			LocalPort: firstOf(local[pid], "port "+pid), RemoteName: str(r["remote_hostname"]), RemotePort: str(r["remote_port"]),
			RemoteAddr: str(r["remote_address"]), RemoteDesc: firstOf(str(r["remote_version"]), str(r["remote_platform"])),
			Protocol: strings.ToLower(str(r["protocol"])), Detail: redactMap(r)})
	}
	return out, nil
}

func (o *observium) Config(context.Context) (string, error) { return "", ErrUnsupported }

// ---- resources ----

var obsUnits = map[string]string{"temperature": "C", "fanspeed": "rpm", "voltage": "V", "current": "A", "power": "W", "humidity": "%", "frequency": "Hz"}

func obsKind(class, descr string) string {
	c, d := strings.ToLower(class), strings.ToLower(descr)
	switch {
	case strings.Contains(c, "fan") || strings.Contains(d, "fan"):
		return "fan"
	case strings.Contains(c, "temp"):
		return "temperature"
	case strings.Contains(d, "power supply") || strings.Contains(d, "psu"):
		return "psu"
	}
	return "other"
}

func (o *observium) Resources(ctx context.Context) (Resources, error) {
	if o.dev == "" { // the server: what it says is wrong with what it monitors
		d, err := gather([]part{
			{"alerts_failed", "/alerts/?status=failed"},
			{"devices", "/devices/?fields=device_id,hostname,sysName,status,status_type,uptime,disabled,ignore"},
		}, func(p string) (any, error) { return o.get(ctx, p) })
		return Resources{Details: d}, err
	}
	_, id, err := o.target(ctx)
	if err != nil {
		return Resources{}, err
	}
	q := "?device_id=" + url.QueryEscape(id)
	res := Resources{Details: Routing{Protocols: map[string]any{}, Unavailable: map[string]string{}}}
	got := map[string][]map[string]any{}
	for _, p := range []part{{"processors", "/processors/" + q}, {"mempools", "/mempools/" + q}, {"storage", "/storage/" + q}, {"sensors", "/sensors/" + q}, {"status", "/status/" + q}} {
		rs, err := o.list(ctx, p.path, p.name)
		var se *statusError
		switch {
		case errors.As(err, &se):
			res.Details.Unavailable[p.name] = se.Error()
		case err != nil:
			return res, err
		default:
			got[p.name] = rs
			res.Details.Protocols[p.name] = Redact(obsAny(rs))
		}
	}
	if len(res.Details.Unavailable) == 0 {
		res.Details.Unavailable = nil
	}
	if ps := got["processors"]; len(ps) > 0 {
		var sum float64
		for _, p := range ps {
			sum += flt(p["processor_usage"])
		}
		res.CPU = &CPU{Now: sum / float64(len(ps))}
	}
	for _, m := range got["mempools"] {
		pct := flt(m["mempool_perc"])
		res.Memory = append(res.Memory, Memory{Name: str(m["mempool_descr"]), Total: num(m["mempool_total"]), Used: num(m["mempool_used"]), Free: num(m["mempool_free"]), UsedPercent: pct})
	}
	for _, s := range got["storage"] {
		pct := flt(s["storage_perc"])
		if size := num(s["storage_size"]); pct == 0 && size > 0 {
			pct = float64(num(s["storage_used"])) * 100 / float64(size)
		}
		res.Storage = append(res.Storage, Storage{Name: str(s["storage_descr"]), Size: num(s["storage_size"]), Free: num(s["storage_free"]), UsedPercent: pct})
	}
	for _, s := range got["sensors"] {
		class := str(s["sensor_class"])
		se := Sensor{Name: firstOf(str(s["sensor_descr"]), str(s["sensor_id"])), Kind: obsKind(class, str(s["sensor_descr"])), State: str(s["sensor_event"]),
			Units: firstOf(str(s["sensor_unit"]), obsUnits[strings.ToLower(class)]), Raw: redactMap(s)}
		if s["sensor_value"] != nil && str(s["sensor_value"]) != "" {
			v := flt(s["sensor_value"])
			se.Reading = &v
		}
		res.Sensors = append(res.Sensors, se)
	}
	return res, nil
}

// ---- show ----

// obsShow are the lists "show NAME" reads.
var obsShow = map[string]string{
	"devices": "/devices/", "ports": "/ports/", "neighbours": "/neighbours/", "neighbors": "/neighbours/", "sensors": "/sensors/", "status": "/status/",
	"storage": "/storage/", "mempools": "/mempools/", "processors": "/processors/", "inventory": "/inventory/", "counters": "/counters/",
	"probes": "/probes/", "alerts": "/alerts/", "alert_log": "/alert_log/", "alert_checks": "/alert_checks/", "address": "/address/",
	"groups": "/groups/", "maintenance": "/maintenance/", "vlans": "/vlans/", "printersupplies": "/printersupplies/",
}

// obsScoped are the lists that take a device_id: with a device named they answer that device's rows.
var obsScoped = map[string]bool{"ports": true, "neighbours": true, "neighbors": true, "sensors": true, "status": true, "storage": true, "mempools": true,
	"processors": true, "inventory": true, "counters": true, "probes": true, "alerts": true, "alert_log": true, "address": true, "printersupplies": true}

// obsDeniedParams are never sent for a caller: the credential is the driver's own.
var obsDeniedParams = map[string]bool{"api_token": true, "token": true, "password": true, "username": true, "user": true, "pass": true}

func obsShowNames() string {
	n := []string{"device"}
	for k := range obsShow {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

const obsUsage = "show device NAME (everything Observium knows about one device), or show NAME [device=NAME] [filter=value ...], e.g. show ports device=ipam2, show alerts status=failed; names: "

// deviceAll is everything Observium holds about one monitored device, as one answer.
func (o *observium) deviceAll(ctx context.Context, ref string) (map[string]any, error) {
	row, id, err := o.resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	q := "?device_id=" + url.QueryEscape(id)
	out := map[string]any{"device": Redact(row)}
	counts, unavailable := map[string]int{}, map[string]string{}
	for _, p := range []part{
		{"ports", "/ports/" + q}, {"addresses", "/address/" + q}, {"neighbours", "/neighbours/" + q}, {"sensors", "/sensors/" + q},
		{"status", "/status/" + q}, {"storage", "/storage/" + q}, {"mempools", "/mempools/" + q}, {"processors", "/processors/" + q},
		{"inventory", "/inventory/" + q}, {"counters", "/counters/" + q}, {"probes", "/probes/" + q},
		{"alerts", "/alerts/" + q + "&status=all"}, {"alert_log", "/alert_log/" + q + "&pagesize=50"},
	} {
		rs, err := o.list(ctx, p.path, p.name)
		var se *statusError
		switch {
		case errors.As(err, &se):
			unavailable[p.name] = se.Error()
		case err != nil:
			return nil, err
		default:
			counts[p.name] = len(rs)
			out[p.name] = Redact(obsAny(rs))
		}
	}
	out["counts"] = counts
	if len(unavailable) > 0 {
		out["unavailable"] = unavailable
	}
	return out, nil
}

// Show takes "show device NAME", or "show NAME [device=NAME] [filter=value ...]" (see obsUsage).
func (o *observium) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(obsUsage + obsShowNames())
	}
	name := strings.ToLower(f[1])
	ref := ""
	q := url.Values{}
	for _, a := range f[2:] {
		k, v, ok := strings.Cut(a, "=")
		switch {
		case !ok && name == "device" && ref == "" && obsRefRE.MatchString(a):
			ref = a
		case !ok:
			return "", fmt.Errorf("%q: use key=value (device=NAME, status=failed, ...)", a)
		case k == "device" && obsRefRE.MatchString(v):
			ref = v
		case obsKeyRE.MatchString(k) && !obsDeniedParams[k] && k != "device" && obsValRE.MatchString(v):
			q.Set(k, v)
		default:
			return "", fmt.Errorf("%q: a filter is name=value, the name in lower case letters, digits and _, the value letters, digits and . _ : @ / * -", a)
		}
	}
	if name == "device" {
		if ref == "" {
			ref = o.dev
		}
		if ref == "" {
			return "", errors.New("show device NAME: which device? (show devices lists them)")
		}
		all, err := o.deviceAll(ctx, ref)
		if err != nil {
			return "", err
		}
		return obsText(all), nil
	}
	path, ok := obsShow[name]
	if !ok {
		return "", fmt.Errorf("show %s: not a read the Observium driver has; names: %s", f[1], obsShowNames())
	}
	if ref == "" && obsScoped[name] {
		ref = o.dev
	}
	if ref != "" {
		if !obsScoped[name] && name != "devices" {
			return "", fmt.Errorf("show %s has no device filter", name)
		}
		_, id, err := o.resolve(ctx, ref)
		if err != nil {
			return "", err
		}
		if name == "devices" {
			path = "/devices/" + url.PathEscape(id) + "/"
		} else {
			q.Set("device_id", id)
		}
	}
	if q.Get("pagesize") == "" && (ref == "" || name == "alert_log") {
		// a whole server's ports are many: the answer says how many there are (count); the alert log is always paginated
		q.Set("pagesize", map[bool]string{true: "100", false: "500"}[name == "alert_log"])
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	v, err := o.get(ctx, path)
	if err != nil {
		return "", err
	}
	return obsText(v), nil
}

// obsScrub runs the text redactor over each string of an answer, one at a time: over the printed JSON it would take the rest of a line
// ("snmp_authpass": "(hidden)",) and leave a document that is not JSON.
func obsScrub(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = obsScrub(x)
		}
	case []any:
		for i, x := range t {
			t[i] = obsScrub(x)
		}
	case string:
		return RedactText(t)
	}
	return v
}

// obsText is an answer as indented JSON, with the secrets in it hidden by name (Redact) and in text (RedactText).
func obsText(v any) string {
	b, _ := json.MarshalIndent(obsScrub(Redact(v)), "", "  ")
	return string(b)
}

// ---- reading through the API ----

// obsReadable are the first words of the paths of the API that are read.  Observium's users and tokens are not among them.
var obsReadable = map[string]bool{"alerts": true, "alert_checks": true, "alert_log": true, "address": true, "counters": true, "devices": true, "entity": true,
	"groups": true, "inventory": true, "mempools": true, "neighbours": true, "ports": true, "printersupplies": true, "probes": true, "processors": true,
	"sensors": true, "status": true, "storage": true, "vlans": true, "maintenance": true, "openapi.json": true}

// obsRead accepts a path of the API, with or without /api/v0: /devices/..., /ports/..., /openapi.json.
func (o *observium) obsRead(path string) (string, error) {
	p := strings.TrimPrefix(path, o.prefix)
	p = strings.TrimPrefix(p, obsBase)
	pp, qs, _ := strings.Cut(p, "?")
	q, err := url.ParseQuery(qs)
	if err != nil {
		return "", errors.New("path: the query is not valid")
	}
	for k := range q {
		if obsDeniedParams[strings.ToLower(k)] {
			return "", fmt.Errorf("path: the parameter %q is sent by the driver, not by the caller", k)
		}
	}
	if strings.Contains(pp, "..") || strings.ContainsAny(pp, "\r\n\x00 ") || !strings.HasPrefix(pp, "/") {
		return "", errors.New("path: not a path of the Observium API")
	}
	if first := strings.SplitN(strings.TrimPrefix(pp, "/"), "/", 2)[0]; !obsReadable[first] {
		return "", errors.New("path: Observium is read at /devices/, /ports/, /neighbours/, /sensors/, /status/, /storage/, /mempools/, /processors/, /alerts/, ... (see device_api_catalog)")
	}
	return p, nil
}

func (o *observium) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := o.obsRead(path)
	if err != nil {
		return nil, false, err
	}
	b, err := o.do(ctx, p)
	if err != nil {
		return nil, false, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, false, nil
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		if err := obsFailed(v); err != nil {
			return nil, false, err
		}
		return Redact(v), false, nil
	}
	return string(b), true, nil
}

func (o *observium) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET /<entity>/<id>?<filters> below /api/v0: /devices/ (and /devices/<host name or ID>/, /devices/<ID>/entities), /ports/, /address/, /neighbours/, /sensors/, /status/, /storage/, " +
			"/mempools/, /processors/, /inventory/, /counters/, /probes/, /alerts/, /alert_checks/, /alert_log/, /groups/, /maintenance/, /vlans/ and /entity/<type>/<id>. " +
			"Most lists take device_id=N (or device=NAME on /devices/), and every list takes fields=a,b,c, pagesize=N and pageno=N; the answer's count says how many there are. " +
			"/openapi.json is Observium's own description of every answer. Reading sends only GET (changes are device_change_raw); the token or password is the driver's, never a parameter. SNMP communities and passwords are hidden.",
		"examples": []string{"/devices/", "/devices/ipam2.example.com/", "/ports/?device_id=12", "/neighbours/?device_id=12", "/sensors/?device_id=12", "/alerts/?status=failed",
			"/alert_log/?device_id=12&pagesize=50", "/devices/?os=ios&fields=device_id,hostname,hardware,version", "/openapi.json"},
		"tip": "show device NAME (device_show) answers everything about one monitored device in one call.",
	}, nil
}

func (o *observium) Close(context.Context) { o.api.close() }

// reuse forgets the row of the monitored device that was looked up last (its status and uptime are in it), which is kept for
// the length of one request only.
func (o *observium) reuse() { o.ref, o.row = "", nil }
