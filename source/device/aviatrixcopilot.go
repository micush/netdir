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
)

// Aviatrix CoPilot (platform "aviatrixcopilot"): the Aviatrix monitoring and visibility product, through its Network Insights API
// (the metrics and status APIs, over HTTPS on port 443, the CoPilot's own address).  The Aviatrix Controller, the other half of the
// platform, is the platform "aviatrix".
//
// The credential is the API key, in the credential's token field (CoPilot ▸ Settings ▸ Configuration ▸ General ▸ Features ▸ Network
// Insights API makes it; "Authorization: Bearer KEY"); a user name and password are not used.  The key is never put in a URL.
// The API only reads:
//
//	GET /status-api/v1/           gateways, tunnels (peering and site-to-cloud) and BGP neighbors: up, down or degraded
//	GET /metrics-api/v1/gateways  per gateway CPU, memory and vCPU use, and per interface rates and drops
//
// Both answer Prometheus text by default (the documented, stable form, read here) and JSON with ?format=json (passed through by the
// API read).  There is nothing to change: RawChange refuses.  It is not a network device: no neighbors, ports, routes or firewall.

func init() { Register("aviatrixcopilot", newAviatrixCoPilot) }

const (
	avcStatus  = "/status-api/v1/"
	avcMetrics = "/metrics-api/v1/gateways"
)

type avCoPilot struct {
	d   Device
	api *apiClient
}

func newAviatrixCoPilot(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: Aviatrix CoPilot needs the Network Insights API key as the credential's token (CoPilot ▸ Settings ▸ Configuration ▸ General ▸ Features)", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	api.hdr.Set("User-Agent", "netdir")
	return &avCoPilot{d: d, api: api}, nil
}

func (a *avCoPilot) Close(context.Context) { a.api.close() }

// get reads one path as text.
func (a *avCoPilot) get(ctx context.Context, path string) ([]byte, error) {
	b, err := a.api.do(ctx, http.MethodGet, path, nil, http.Header{"Accept": {"text/plain, application/json"}})
	if err != nil {
		var se *statusError
		if errors.As(err, &se) {
			switch se.Code {
			case http.StatusForbidden, http.StatusUnauthorized:
				return nil, fmt.Errorf("CoPilot refused the API key (HTTP %d): the key is wrong or has expired; make a new one under Settings ▸ Configuration ▸ General ▸ Features", se.Code)
			case http.StatusNotFound:
				return nil, errors.New("CoPilot has no Network Insights API at this address (HTTP 404): the API is off, or this is not a CoPilot (or it is too old)")
			}
		}
		return nil, err
	}
	return b, nil
}

// avcSample is one line of Prometheus text: name{labels} value [timestamp].
type avcSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

var (
	avcLineRE  = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+-?\d+)?$`)
	avcLabelRE = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"`)
)

func avcParse(b []byte) ([]avcSample, error) {
	var out []avcSample
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		m := avcLineRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		s := avcSample{Name: m[1], Value: v, Labels: map[string]string{}}
		for _, lm := range avcLabelRE.FindAllStringSubmatch(m[2], -1) {
			s.Labels[lm[1]] = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n").Replace(lm[2])
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("the answer holds no Prometheus samples: this is not the CoPilot Network Insights API (or it has nothing to report yet)")
	}
	return out, nil
}

// avcState is what a status value means: 1 up, 0 down, -1 degraded.
func avcState(v float64) string {
	switch {
	case v > 0:
		return "up"
	case v < 0:
		return "degraded"
	}
	return "down"
}

// avcStatusView is the status API, sorted: gateways and tunnels by name, BGP neighbors by gateway.
type avcStatusView struct {
	Gateways []avcItem `json:"gateways"`
	Tunnels  []avcItem `json:"tunnels"`
	BGP      []avcItem `json:"bgp"`
}

type avcItem struct {
	Name     string `json:"name"`
	Neighbor string `json:"neighbor,omitempty"`
	State    string `json:"state"`
}

func (a *avCoPilot) status(ctx context.Context) (*avcStatusView, error) {
	b, err := a.get(ctx, avcStatus)
	if err != nil {
		return nil, err
	}
	ss, err := avcParse(b)
	if err != nil {
		return nil, err
	}
	v := &avcStatusView{Gateways: []avcItem{}, Tunnels: []avcItem{}, BGP: []avcItem{}}
	for _, s := range ss {
		switch {
		case s.Name == "status" && s.Labels["gateway"] != "":
			v.Gateways = append(v.Gateways, avcItem{Name: s.Labels["gateway"], State: avcState(s.Value)})
		case s.Name == "status" && s.Labels["tunnel"] != "":
			v.Tunnels = append(v.Tunnels, avcItem{Name: s.Labels["tunnel"], State: avcState(s.Value)})
		case s.Name == "bgp_status":
			st := "not established"
			if s.Value > 0 {
				st = "established"
			}
			v.BGP = append(v.BGP, avcItem{Name: s.Labels["gateway"], Neighbor: s.Labels["bgp_neighbor"], State: st})
		}
	}
	for _, l := range [][]avcItem{v.Gateways, v.Tunnels, v.BGP} {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Name != l[j].Name {
				return l[i].Name < l[j].Name
			}
			return l[i].Neighbor < l[j].Neighbor
		})
	}
	return v, nil
}

func avcCount(l []avcItem, state string) (n int) {
	for _, x := range l {
		if x.State == state {
			n++
		}
	}
	return n
}

func (a *avCoPilot) Facts(ctx context.Context) (Facts, error) {
	v, err := a.status(ctx)
	if err != nil {
		return Facts{}, err
	}
	m := fmt.Sprintf("CoPilot: %d gateways (%d up, %d down, %d degraded), %d tunnels (%d up), %d BGP neighbors (%d established)",
		len(v.Gateways), avcCount(v.Gateways, "up"), avcCount(v.Gateways, "down"), avcCount(v.Gateways, "degraded"),
		len(v.Tunnels), avcCount(v.Tunnels, "up"), len(v.BGP), avcCount(v.BGP, "established"))
	return Facts{Hostname: a.d.Address, Vendor: "Aviatrix", Model: m}, nil
}

// Interfaces are the gateways, with the state CoPilot reports.
func (a *avCoPilot) Interfaces(ctx context.Context) ([]Interface, error) {
	v, err := a.status(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(v.Gateways))
	for _, g := range v.Gateways {
		out = append(out, Interface{Name: g.Name, Description: "gateway, " + g.State, OperUp: boolp(g.State == "up"), AdminUp: boolp(true)})
	}
	return out, nil
}

func (a *avCoPilot) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (a *avCoPilot) Config(context.Context) (string, error)        { return "", ErrUnsupported }

const avcUsage = "show status | gateways | tunnels | bgp | metrics [gateway=NAME] | gateway NAME"

// avcMetricsView is the metrics API grouped by gateway: its CPU and memory numbers and, per interface, its rates.
func (a *avCoPilot) metrics(ctx context.Context, only string) (map[string]any, error) {
	b, err := a.get(ctx, avcMetrics)
	if err != nil {
		return nil, err
	}
	ss, err := avcParse(b)
	if err != nil {
		return nil, err
	}
	gws := map[string]map[string]any{}
	get := func(g string) map[string]any {
		if gws[g] == nil {
			gws[g] = map[string]any{}
		}
		return gws[g]
	}
	for _, s := range ss {
		g := s.Labels["gateway"]
		if g == "" || (only != "" && !strings.EqualFold(g, only)) {
			continue
		}
		m := get(g)
		switch {
		case s.Labels["interface"] != "":
			im, _ := m["interfaces"].(map[string]map[string]float64)
			if im == nil {
				im = map[string]map[string]float64{}
				m["interfaces"] = im
			}
			if im[s.Labels["interface"]] == nil {
				im[s.Labels["interface"]] = map[string]float64{}
			}
			im[s.Labels["interface"]][s.Name] = s.Value
		case s.Labels["vcpu_name"] != "":
			vm, _ := m["vcpus"].(map[string]map[string]float64)
			if vm == nil {
				vm = map[string]map[string]float64{}
				m["vcpus"] = vm
			}
			if vm[s.Labels["vcpu_name"]] == nil {
				vm[s.Labels["vcpu_name"]] = map[string]float64{}
			}
			vm[s.Labels["vcpu_name"]][s.Name] = s.Value
		default:
			m[s.Name] = s.Value
		}
	}
	out := map[string]any{}
	for g, m := range gws {
		out[g] = m
	}
	return out, nil
}

func avcText(v any) string {
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return string(b)
}

func (a *avCoPilot) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(avcUsage)
	}
	name := strings.ToLower(f[1])
	switch name {
	case "status", "gateways", "tunnels", "bgp":
		v, err := a.status(ctx)
		if err != nil {
			return "", err
		}
		switch name {
		case "gateways":
			return avcText(v.Gateways), nil
		case "tunnels":
			return avcText(v.Tunnels), nil
		case "bgp":
			return avcText(v.BGP), nil
		}
		return avcText(v), nil
	case "metrics":
		only := ""
		for _, w := range f[2:] {
			k, val, ok := strings.Cut(w, "=")
			if !ok || k != "gateway" || !avcNameRE.MatchString(val) {
				return "", errors.New("show metrics [gateway=NAME]")
			}
			only = val
		}
		m, err := a.metrics(ctx, only)
		if err != nil {
			return "", err
		}
		if only != "" && len(m) == 0 {
			return "", fmt.Errorf("CoPilot has no metrics for a gateway called %q (show gateways lists them)", only)
		}
		return avcText(m), nil
	case "gateway":
		if len(f) != 3 || !avcNameRE.MatchString(f[2]) {
			return "", errors.New("show gateway NAME: the gateway's name (show gateways lists them)")
		}
		v, err := a.status(ctx)
		if err != nil {
			return "", err
		}
		out := map[string]any{"name": f[2]}
		found := false
		for _, g := range v.Gateways {
			if strings.EqualFold(g.Name, f[2]) {
				out["name"], out["state"], found = g.Name, g.State, true
			}
		}
		if !found {
			return "", fmt.Errorf("CoPilot has no gateway called %q (show gateways lists them)", f[2])
		}
		var tun, bgp []avcItem
		for _, t := range v.Tunnels {
			if strings.Contains(strings.ToLower(t.Name), strings.ToLower(f[2])) {
				tun = append(tun, t)
			}
		}
		for _, x := range v.BGP {
			if strings.EqualFold(x.Name, f[2]) {
				bgp = append(bgp, x)
			}
		}
		out["tunnels"], out["bgp"] = tun, bgp
		if m, err := a.metrics(ctx, f[2]); err == nil {
			out["metrics"] = m[out["name"].(string)]
		}
		return avcText(out), nil
	}
	return "", errors.New(avcUsage)
}

var avcNameRE = regexp.MustCompile(`^[A-Za-z0-9._:@/+-]{1,200}$`)

// APIGet reads the two paths of the API.  Without a query the answer is read as Prometheus text and given as JSON (the status:
// gateways, tunnels, bgp; the metrics: per gateway); with ?format=json CoPilot's own JSON is passed through.
func (a *avCoPilot) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	if pp == strings.TrimSuffix(avcStatus, "/") {
		pp = avcStatus
	}
	if pp != avcStatus && pp != avcMetrics {
		return nil, false, errors.New("path: /status-api/v1/ or /metrics-api/v1/gateways (see device_api_catalog); add ?format=json for CoPilot's own JSON")
	}
	q, err := url.ParseQuery(qs)
	if err != nil {
		return nil, false, errors.New("path: the query is not valid")
	}
	for k, vs := range q {
		if k != "format" || len(vs) != 1 || vs[0] != "json" {
			return nil, false, errors.New("path: the only parameter is format=json")
		}
	}
	if q.Get("format") == "json" {
		b, err := a.get(ctx, pp+"?format=json")
		if err != nil {
			return nil, false, err
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, false, fmt.Errorf("GET %s: the answer is not JSON: %v", pp, err)
		}
		return Redact(v), false, nil
	}
	if pp == avcStatus {
		v, err := a.status(ctx)
		if err != nil {
			return nil, false, err
		}
		return v, false, nil
	}
	m, err := a.metrics(ctx, "")
	if err != nil {
		return nil, false, err
	}
	return m, false, nil
}

func (a *avCoPilot) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "Two reads: /status-api/v1/ (gateways, tunnels and BGP neighbors: up, down, degraded) and /metrics-api/v1/gateways (CPU, memory, vCPU and interface rates per gateway). " +
			"They are given as JSON read from CoPilot's Prometheus text; add ?format=json for CoPilot's own JSON. Nothing can be changed.",
		"examples": []string{"/status-api/v1/", "/metrics-api/v1/gateways", "/status-api/v1/?format=json"},
		"tip":      "device_show: show status, show gateways, show tunnels, show bgp, show metrics gateway=NAME, show gateway NAME.",
	}, nil
}

func (a *avCoPilot) RawChange(_ context.Context, r Raw, dry bool) (RawResult, error) {
	return RawResult{DryRun: dry}, errors.New("Aviatrix CoPilot's API only reads (metrics and status); change the Aviatrix Controller instead (platform aviatrix)")
}
