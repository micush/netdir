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
	"strconv"
	"strings"
	"time"
)

// Cisco Meraki, through the Dashboard API (https://developer.cisco.com/meraki/api-v1/): REST at https://api.meraki.com/api/v1 with
// an API key (the credential's Token, sent as a Bearer token; a key made by a read-only dashboard administrator reads only).
// Meraki is a cloud: the "device" here is either
//
//   - an organization (no option "serial"; option "org" is its ID, and may be left out when the key sees only one): its facts,
//     its MX uplinks as interfaces, and through Show and APIGet everything the dashboard holds (networks, devices, statuses,
//     clients, SSIDs, VLANs, firewall rules, the change log); or
//   - one Meraki device (option "serial", e.g. Q2XX-XXXX-XXXX): its facts, a switch's ports, its LLDP/CDP neighbors, and typed
//     port changes (description = the port's name, shut down = enabled false).
//
// The API answers 308 to a regional shard (nNNN.meraki.com): it is followed only to a meraki host over https, with the key
// (Go's client would drop it).  A 429 waits for Retry-After and tries again twice.  Lists are asked with perPage=1000 and the
// following pages are not fetched.

func init() { Register("meraki", newMeraki) }

type meraki struct {
	d      Device
	api    *apiClient
	org    string
	serial string
	ckey   string // names this device and its key in the lookup cache
}

var (
	merakiOrgRE      = regexp.MustCompile(`^[0-9]{1,20}$`)
	merakiSerialRE   = regexp.MustCompile(`^(?i)[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$`)
	merakiClientIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	merakiNetRE      = regexp.MustCompile(`^[LNEHT]_?[0-9]{1,24}$`)
	merakiHostRE     = regexp.MustCompile(`^(?i)([a-z0-9-]+\.)*meraki\.(com|cn|ca|in)$`)
)

func newMeraki(d Device, c Credential) (Driver, error) {
	key := firstOf(c.Token, c.Password)
	if key == "" {
		return nil, fmt.Errorf("device %s: Meraki needs the dashboard API key as the credential's token", d.Name)
	}
	m := &meraki{d: d, org: strings.TrimSpace(d.Options["org"]), serial: strings.ToUpper(strings.TrimSpace(d.Options["serial"]))}
	if m.org != "" && !merakiOrgRE.MatchString(m.org) {
		return nil, fmt.Errorf("device %s: option org is the organization's ID, digits only", d.Name)
	}
	if m.serial != "" && !merakiSerialRE.MatchString(m.serial) {
		return nil, fmt.Errorf("device %s: option serial is a Meraki serial such as Q2XX-XXXX-XXXX", d.Name)
	}
	if d.Address == "" {
		d.Address = "api.meraki.com"
		m.d = d
	}
	m.ckey = idKey("meraki", d.Address, strconv.Itoa(d.Port), m.org, key)
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+key)
	api.hdr.Set("User-Agent", "netdir")
	api.hc.CheckRedirect = merakiRedirect
	m.api = api
	return m, nil
}

// merakiRedirect follows a redirect to another Meraki host over https and sends the key there; any other redirect is not followed.
func merakiRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || req.URL.Scheme != "https" || !merakiHostRE.MatchString(req.URL.Hostname()) {
		return http.ErrUseLastResponse
	}
	for _, k := range []string{"Authorization", "User-Agent", "Accept", "Content-Type"} {
		if v := via[0].Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}
	return nil
}

const merakiBase = "/api/v1"

// do sends one request below /api/v1, waiting out a 429 twice.
func (m *meraki) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	for try := 0; ; try++ {
		b, err := m.api.do(ctx, method, merakiBase+path, body, nil)
		var se *statusError
		if err == nil || !errors.As(err, &se) || se.Code != http.StatusTooManyRequests || try >= 2 {
			return b, err
		}
		if err := sleepCtx(ctx, merakiWait); err != nil {
			return nil, err
		}
	}
}

// merakiWait is how long a 429 is waited out (the API's Retry-After is a second or so); a variable so tests are quick.
var merakiWait = 2 * time.Second

func (m *meraki) get(ctx context.Context, path string) (any, error) {
	b, err := m.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var v any
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
	}
	return v, nil
}

// orgID is the organization: the option, else the one the key sees.
func (m *meraki) orgID(ctx context.Context) (string, error) {
	if m.org != "" {
		return m.org, nil
	}
	v, err := m.get(ctx, "/organizations")
	if err != nil {
		return "", err
	}
	os := rows(v)
	switch len(os) {
	case 0:
		return "", errors.New("the key sees no organization")
	case 1:
		m.org = str(os[0]["id"])
		return m.org, nil
	}
	var l []string
	for _, o := range os {
		l = append(l, str(o["id"])+" "+str(o["name"]))
	}
	sort.Strings(l)
	if len(l) > 10 {
		l = append(l[:10], "…")
	}
	return "", fmt.Errorf("the key sees several organizations; set the device's option org to one of: %s", strings.Join(l, "; "))
}

func (m *meraki) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Cisco Meraki"}
	if m.serial != "" {
		v, err := m.get(ctx, "/devices/"+m.serial)
		if err != nil {
			return f, err
		}
		o, _ := v.(map[string]any)
		f.Hostname, f.Model, f.Serial, f.OSVersion = firstOf(str(o["name"]), m.serial), str(o["model"]), firstOf(str(o["serial"]), m.serial), str(o["firmware"])
		return f, nil
	}
	org, err := m.orgID(ctx)
	if err != nil {
		return f, err
	}
	v, err := m.get(ctx, "/organizations/"+org)
	if err != nil {
		return f, err
	}
	o, _ := v.(map[string]any)
	f.Hostname = firstOf(str(o["name"]), org)
	f.Model = "Meraki organization " + org
	if st, err := m.get(ctx, "/organizations/"+org+"/devices/statuses?perPage=1000"); err == nil {
		on := 0
		l := rows(st)
		for _, d := range l {
			if str(d["status"]) == "online" {
				on++
			}
		}
		f.Model = fmt.Sprintf("Meraki organization %s, %d devices (%d online)", org, len(l), on)
	}
	return f, nil
}

func (m *meraki) Interfaces(ctx context.Context) ([]Interface, error) {
	if m.serial != "" {
		ports, err := m.switchPorts(ctx)
		if err == nil {
			out := make([]Interface, len(ports))
			for i, p := range ports {
				out[i] = p.Interface
			}
			return out, nil
		}
		var se *statusError
		if !errors.As(err, &se) || (se.Code != 400 && se.Code != 404) { // not a switch
			return nil, err
		}
		v, err := m.get(ctx, "/devices/"+m.serial)
		if err != nil {
			return nil, err
		}
		o, _ := v.(map[string]any)
		i := Interface{Name: "management", MAC: str(o["mac"])}
		if ip := str(o["lanIp"]); ip != "" {
			i.Addresses = []string{ip}
		}
		return []Interface{i}, nil
	}
	org, err := m.orgID(ctx)
	if err != nil {
		return nil, err
	}
	v, err := m.get(ctx, "/organizations/"+org+"/appliance/uplink/statuses?perPage=1000")
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, a := range rows(v) {
		for _, u := range rows(a["uplinks"]) {
			st := str(u["status"])
			up := st == "active" || st == "ready" || st == "connecting"
			i := Interface{Name: str(a["serial"]) + " " + str(u["interface"]), Description: str(a["networkId"]), OperUp: &up}
			if ip := str(u["ip"]); ip != "" {
				i.Addresses = []string{ip}
			}
			out = append(out, i)
		}
	}
	return out, nil
}

// switchPorts reads a switch's ports: their configuration and their live status.
func (m *meraki) switchPorts(ctx context.Context) ([]Port, error) {
	cfg, err := m.get(ctx, "/devices/"+m.serial+"/switch/ports")
	if err != nil {
		return nil, err
	}
	st := map[string]map[string]any{}
	if v, err := m.get(ctx, "/devices/"+m.serial+"/switch/ports/statuses"); err == nil {
		for _, s := range rows(v) {
			st[str(s["portId"])] = s
		}
	}
	var out []Port
	for _, c := range rows(cfg) {
		id := str(c["portId"])
		s := st[id]
		i := Interface{Name: id, Description: strings.TrimSpace(str(c["name"]))}
		if en, ok := c["enabled"].(bool); ok {
			i.AdminUp = boolp(en)
		}
		if s != nil {
			i.OperUp = boolp(str(s["status"]) == "Connected")
			i.SpeedMbps = merakiSpeed(str(s["speed"]))
		}
		p := Port{Interface: i, Type: str(c["type"]), Properties: map[string]any{}}
		if s != nil {
			p.Duplex = strings.ToLower(str(s["duplex"]))
			for _, k := range []string{"isUplink", "errors", "warnings", "poe", "vlan"} {
				if x, ok := s[k]; ok {
					p.Properties[k] = x
				}
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return portLess(out[i].Name, out[j].Name) })
	return out, nil
}

func portLess(a, b string) bool {
	x, ea := strconv.Atoi(a)
	y, eb := strconv.Atoi(b)
	if ea == nil && eb == nil {
		return x < y
	}
	return a < b
}

// merakiSpeed reads "1 Gbps", "100 Mbps", "10 Gbps".
func merakiSpeed(s string) int64 {
	f := strings.Fields(s)
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	switch strings.ToLower(f[1]) {
	case "gbps":
		return int64(n * 1000)
	case "mbps":
		return int64(n)
	}
	return 0
}

func (m *meraki) Ports(ctx context.Context) ([]Port, error) {
	if m.serial == "" {
		return nil, ErrUnsupported // name a device with the option serial
	}
	return m.switchPorts(ctx)
}

func (m *meraki) Neighbors(ctx context.Context) ([]Neighbor, error) {
	if m.serial == "" {
		return nil, ErrUnsupported
	}
	v, err := m.get(ctx, "/devices/"+m.serial+"/lldpCdp")
	if err != nil {
		return nil, err
	}
	o, _ := v.(map[string]any)
	ports, _ := o["ports"].(map[string]any)
	var out []Neighbor
	for id, p := range ports {
		pm, _ := p.(map[string]any)
		if l, ok := pm["lldp"].(map[string]any); ok {
			out = append(out, Neighbor{LocalPort: id, RemoteName: str(l["systemName"]), RemotePort: str(l["portId"]), RemoteAddr: str(l["managementAddress"]),
				RemoteDesc: str(l["systemDescription"]), Protocol: "lldp", Detail: redactMap(l)})
		}
		if c, ok := pm["cdp"].(map[string]any); ok {
			out = append(out, Neighbor{LocalPort: id, RemoteName: str(c["deviceId"]), RemotePort: str(c["portId"]), RemoteAddr: str(c["address"]), Protocol: "cdp", Detail: redactMap(c)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LocalPort != out[j].LocalPort {
			return portLess(out[i].LocalPort, out[j].LocalPort)
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out, nil
}

func (m *meraki) Config(context.Context) (string, error) { return "", ErrUnsupported }

// ---- show NAME [network=ID] [serial=S] ----

var merakiShow = map[string]string{
	"networks":    "/organizations/{org}/networks?perPage=1000",
	"devices":     "/organizations/{org}/devices?perPage=1000",
	"statuses":    "/organizations/{org}/devices/statuses?perPage=1000",
	"uplinks":     "/organizations/{org}/appliance/uplink/statuses?perPage=1000",
	"inventory":   "/organizations/{org}/inventory/devices?perPage=1000",
	"changes":     "/organizations/{org}/configurationChanges?perPage=50",
	"clients":     "/networks/{network}/clients?perPage=100&timespan=3600",
	"ssids":       "/networks/{network}/wireless/ssids",
	"vlans":       "/networks/{network}/appliance/vlans",
	"firewall":    "/networks/{network}/appliance/firewall/l3FirewallRules",
	"device":      "/devices/{serial}",
	"switchports": "/devices/{serial}/switch/ports",
	"portstatus":  "/devices/{serial}/switch/ports/statuses",
	"lldp":        "/devices/{serial}/lldpCdp",
}

func merakiShowNames() string {
	var n []string
	for k := range merakiShow {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// Show takes "show NAME [network=ID] [serial=SERIAL]": the dashboard reads above (org is the device's).
func (m *meraki) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New("show NAME [network=ID] [serial=SERIAL], e.g. show networks; names: " + merakiShowNames())
	}
	p, ok := merakiShow[strings.ToLower(f[1])]
	if !ok {
		return "", fmt.Errorf("show %s: not a read the Meraki driver has; names: %s", f[1], merakiShowNames())
	}
	net, serial := "", m.serial
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case ok && k == "network" && merakiNetRE.MatchString(v):
			net = v
		case ok && k == "serial" && merakiSerialRE.MatchString(v):
			serial = strings.ToUpper(v)
		default:
			return "", fmt.Errorf("%q: use network=ID (L_… or N_…) or serial=Q2XX-XXXX-XXXX", kv)
		}
	}
	if strings.Contains(p, "{org}") {
		org, err := m.orgID(ctx)
		if err != nil {
			return "", err
		}
		p = strings.ReplaceAll(p, "{org}", org)
	}
	if strings.Contains(p, "{network}") {
		if net == "" {
			return "", fmt.Errorf("show %s needs network=ID (show networks lists them)", f[1])
		}
		p = strings.ReplaceAll(p, "{network}", net)
	}
	if strings.Contains(p, "{serial}") {
		if serial == "" {
			return "", fmt.Errorf("show %s needs serial=SERIAL (show devices lists them)", f[1])
		}
		p = strings.ReplaceAll(p, "{serial}", serial)
	}
	v, err := m.get(ctx, p)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

// ---- reading through the API ----

// merakiRead accepts a path of the dashboard API, with or without /api/v1: /organizations/…, /networks/… or /devices/….
func merakiRead(path string) (string, error) {
	p := strings.TrimPrefix(path, merakiBase)
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	if strings.Contains(pp, "..") || strings.ContainsAny(pp, "\r\n\x00 ") {
		return "", errors.New("path: not a path of the Meraki API")
	}
	first := strings.SplitN(strings.TrimPrefix(pp, "/"), "/", 2)[0]
	if !strings.HasPrefix(pp, "/") || first != "organizations" && first != "networks" && first != "devices" {
		return "", errors.New("path: Meraki is read at /organizations/…, /networks/… or /devices/… (see device_api_catalog)")
	}
	return p, nil
}

func (m *meraki) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := merakiRead(path)
	if err != nil {
		return nil, false, err
	}
	b, err := m.do(ctx, http.MethodGet, p, nil)
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

func (m *meraki) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET /organizations, /organizations/{id}/networks, /organizations/{id}/devices, /organizations/{id}/devices/statuses, /organizations/{id}/appliance/uplink/statuses, " +
			"/organizations/{id}/configurationChanges (what was changed, by whom), /networks/{id}/clients, /networks/{id}/wireless/ssids, /networks/{id}/appliance/vlans, " +
			"/devices/{serial}, /devices/{serial}/switch/ports, /devices/{serial}/lldpCdp. ?perPage=N (up to 1000 for most lists) and ?timespan=SECONDS narrow an answer; further pages are not fetched. " +
			"Only GET is sent. Administrators, SAML, SNMP, VPN and license paths are not read over MCP.",
		"examples": []string{"/organizations", "/organizations/{id}/networks", "/organizations/{id}/devices/statuses?perPage=1000", "/networks/{networkId}/clients?timespan=3600&perPage=100",
			"/devices/{serial}/switch/ports/statuses", "/networks/{networkId}/appliance/firewall/l3FirewallRules"},
	}, nil
}

func (m *meraki) Close(context.Context) { m.api.close() }
