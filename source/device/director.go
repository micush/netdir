package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The sibling products and other Network Directors, reached through their own MCP endpoint (POST /mcp on the GUI port, JSON answers):
//
//	dnsdir   AnyName DNS Director: DNS proxy gateways served by a cluster of nodes (GUI and MCP port 53853)
//	ntpdir   NTP Director: the same for NTP (port 12380)
//	netdir   MCP Network Director: another one of these (port 22161); the devices it reaches are reachable here too (downstream.go)
//
// The credential is an MCP key as the token ("Authorization: Bearer KEY", made under Configure ▸ Monitoring ▸ MCP ▸ Keys of
// that director); the key's ro or rw is the access, as everywhere here (an address of this gateway in the director's mcp_acl
// gives the higher of the two).  The driver only calls the director's tools: the named read tools
// (Facts from list_nodes, Neighbors from get_lldp, Resources from get_host_stats, "show <name>" for the rest), api_get and
// list_api for the API, get_config for the configuration, and for changes api_request and edit_config.  Each director hides its
// own secrets in every answer, so none passes through here.  A cluster answers for all its nodes: the option "node" names the node
// (an address or host name from list_nodes) that tools should ask about; without it the node serving the endpoint is asked.

func init() {
	Register("dnsdir", func(d Device, c Credential) (Driver, error) { return newDirector(d, c, "dns") })
	Register("ntpdir", func(d Device, c Credential) (Driver, error) { return newDirector(d, c, "ntp") })
	Register("netdir", func(d Device, c Credential) (Driver, error) { return newDirector(d, c, "net") })
}

type director struct {
	d    Device
	api  *apiClient
	kind string // dns, ntp or net
	node string
}

var directorNodeRE = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]{1,100}$`)

func newDirector(d Device, c Credential, kind string) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: a director needs an MCP key as the credential's token (Configure ▸ Monitoring ▸ MCP ▸ Keys on the director)", d.Name)
	}
	port := map[string]int{"dns": 53853, "ntp": 12380, "net": 22161}[kind]
	api, err := newAPIClient(d, port)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	n := strings.TrimSpace(d.Options["node"])
	if n != "" && !directorNodeRE.MatchString(n) {
		return nil, fmt.Errorf("device %s: option node %q is not an address or host name", d.Name, n)
	}
	return &director{d: d, api: api, kind: kind, node: n}, nil
}

func (m *director) product() (vendor, model string) {
	switch m.kind {
	case "ntp":
		return "NTP Director", "NTP gateway cluster"
	case "net":
		return "MCP Network Director", "gateway cluster"
	}
	return "AnyName", "DNS Director"
}

// call runs one tool and returns what its text answer holds as JSON.  The director says isError with a text for a refusal.
func (m *director) call(ctx context.Context, tool string, args map[string]any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	if m.node != "" {
		if _, ok := args["node"]; !ok {
			args["node"] = m.node
		}
	}
	return m.callPlain(ctx, tool, args)
}

// callPlain is call without the node option: the device tools of a Network Director take no node.
func (m *director) callPlain(ctx context.Context, tool string, args map[string]any) (any, error) {
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}}
	b, err := m.api.do(ctx, http.MethodPost, "/mcp", req, http.Header{"Accept": {"application/json, text/event-stream"}})
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: the answer is not MCP JSON: %v", tool, err)
	}
	if r.Error != nil {
		return nil, &statusError{Code: http.StatusBadRequest, Body: r.Error.Message}
	}
	text := ""
	if len(r.Result.Content) > 0 {
		text = r.Result.Content[0].Text
	}
	if r.Result.IsError {
		code := http.StatusBadRequest
		if strings.Contains(text, "read-only") {
			code = http.StatusForbidden
		}
		return nil, &statusError{Code: code, Body: text}
	}
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil, fmt.Errorf("%s: the answer is cut or not JSON (ask for less): %.80q", tool, text)
	}
	return v, nil
}

func (m *director) Facts(ctx context.Context) (Facts, error) {
	v, err := m.call(ctx, "list_nodes", nil)
	if err != nil {
		return Facts{}, err
	}
	vendor, model := m.product()
	f := Facts{Vendor: vendor, Model: model}
	nodes := rows(v)
	pick := map[string]any(nil)
	for _, n := range nodes {
		if m.node != "" && (str(n["name"]) == m.node || strings.HasPrefix(str(n["addr"]), m.node+":")) {
			pick = n
		}
	}
	for _, n := range nodes {
		if pick == nil && boolv(n["this_node"]) {
			pick = n
		}
	}
	if pick != nil {
		f.Hostname = str(pick["name"])
		if ver := str(pick["version"]); ver != "" {
			f.OSVersion = "v" + ver
		}
	}
	f.Model = fmt.Sprintf("%s, %d node(s)", model, len(nodes))
	return f, nil
}

func boolv(v any) bool { b, _ := v.(bool); return b }

func (m *director) hostNow(ctx context.Context) (map[string]any, error) {
	v, err := m.call(ctx, "get_host_stats", map[string]any{"range": "15m"})
	if err != nil {
		return nil, err
	}
	h, _ := v.(map[string]any)
	now, _ := h["now"].(map[string]any)
	if now == nil {
		return nil, errors.New("get_host_stats: no current reading")
	}
	return now, nil
}

func (m *director) Interfaces(ctx context.Context) ([]Interface, error) {
	now, err := m.hostNow(ctx)
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, r := range rows(now["ifaces"]) {
		i := Interface{Name: str(r["name"]), SpeedMbps: int64(num(r["speed_mbps"]))}
		if up, ok := r["up"].(bool); ok {
			i.OperUp = boolp(up)
		}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func (m *director) Neighbors(ctx context.Context) ([]Neighbor, error) {
	v, err := m.call(ctx, "get_lldp", nil)
	if err != nil {
		return nil, err
	}
	l, _ := v.(map[string]any)
	var out []Neighbor
	for _, r := range rows(l["neighbors"]) {
		n := Neighbor{LocalPort: str(r["interface"]), RemoteName: str(r["system_name"]), RemotePort: firstOf(str(r["port_descr"]), str(r["port_id"])),
			RemoteDesc: str(r["system_descr"]), Protocol: strings.ToLower(firstOf(str(r["protocol"]), "lldp")), Detail: redactMap(r)}
		if ips, ok := r["mgmt_ips"].([]any); ok {
			for _, ip := range ips {
				if s := str(ip); s != "" && !strings.HasPrefix(strings.ToLower(s), "fe80:") {
					n.RemoteAddr = s
					break
				}
			}
		}
		out = append(out, n)
	}
	return out, nil
}

func (m *director) Resources(ctx context.Context) (Resources, error) {
	now, err := m.hostNow(ctx)
	if err != nil {
		return Resources{}, err
	}
	r := Resources{CPU: &CPU{Now: flt(now["cpu_pct"])}}
	if l, ok := now["load"].([]any); ok && len(l) >= 2 {
		r.CPU.OneMin, r.CPU.FiveMin = flt(l[0]), flt(l[1])
	}
	total, used := int64(num(now["mem_total"])), int64(num(now["mem_used"]))
	r.Memory = []Memory{{Name: "memory", Total: total, Used: used, Free: total - used, UsedPercent: flt(now["mem_pct"])}}
	if st := int64(num(now["swap_total"])); st > 0 {
		su := int64(num(now["swap_used"]))
		r.Memory = append(r.Memory, Memory{Name: "swap", Total: st, Used: su, Free: st - su, UsedPercent: float64(su) * 100 / float64(st)})
	}
	for _, f := range rows(now["fs"]) {
		t, u := int64(num(f["total"])), int64(num(f["used"]))
		r.Storage = append(r.Storage, Storage{Name: str(f["mount"]), Size: t, Free: t - u, UsedPercent: flt(f["pct"])})
	}
	r.Details = Routing{Protocols: map[string]any{"cores": now["cores"], "load": now["load"], "io_percent": now["io_pct"],
		"rx_bps": now["rx_bps"], "tx_bps": now["tx_bps"], "net_util_percent": now["net_util_pct"]}}
	return r, nil
}

// ---- show <name>: the director's read tools ----

var directorShow = map[string]string{
	"nodes": "list_nodes", "topology": "get_topology", "gateways": "get_gateways", "alerts": "get_alerts", "log": "get_log",
	"query-stats": "get_query_stats", "host-stats": "get_host_stats", "server-stats": "get_server_stats", "schedule": "get_schedule",
	"updates": "get_updates", "node-status": "get_node_status", "lldp": "get_lldp",
	"dns": "get_dns", "ntp": "get_ntp", "time": "get_time", "devices": "list_devices",
}

// hasTool says whether a director of this kind has the read tool: the DNS and NTP products each have their own, and only a
// Network Director has devices and no query or server statistics.
func hasTool(kind, tool string) bool {
	switch tool {
	case "get_dns":
		return kind == "dns"
	case "get_ntp", "get_time":
		return kind == "ntp"
	case "get_query_stats", "get_server_stats":
		return kind != "net"
	case "list_devices":
		return kind == "net"
	}
	return true
}

var directorShowArgs = map[string]string{"node": "s", "range": "s", "top": "i", "gateway": "i", "transport": "s", "lines": "i", "level": "s"}

// Show takes "show NAME [key=value ...]": NAME is one of the director's read tools without its get_ (show nodes, show topology,
// show gateways, show alerts, show log, show query-stats, show host-stats, show server-stats, show schedule, show updates,
// show node-status, show lldp, and show dns, show time, show ntp or show devices for the product that has them), and the keys node, range,
// top, gateway, transport, lines and level are the tool's arguments.
func (m *director) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(`show NAME [node=… range=… top=… gateway=… transport=…], e.g. show topology; names: ` + strings.Join(m.showNames(), ", "))
	}
	tool, ok := directorShow[strings.ToLower(f[1])]
	if !ok || !hasTool(m.kind, tool) {
		return "", fmt.Errorf("show %s: not a read this director has; names: %s", f[1], strings.Join(m.showNames(), ", "))
	}
	args := map[string]any{}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		typ := directorShowArgs[k]
		if !ok || typ == "" || !directorNodeRE.MatchString(v) {
			return "", fmt.Errorf("%q: use key=value with a key of node, range, top, gateway, transport, lines or level", kv)
		}
		if typ == "i" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 100000 {
				return "", fmt.Errorf("%s=%s: a number", k, v)
			}
			args[k] = n
		} else {
			args[k] = v
		}
	}
	v, err := m.call(ctx, tool, args)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

func (m *director) showNames() []string {
	var n []string
	for k, t := range directorShow {
		if !hasTool(m.kind, t) {
			continue
		}
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Config is the director's whole configuration as get_config answers it (its secrets are hidden by the director).
func (m *director) Config(ctx context.Context) (string, error) {
	v, err := m.call(ctx, "get_config", nil)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

// ---- the API ----

func checkDirectorPath(p string) error {
	if !strings.HasPrefix(p, "/api/") || len(p) > 2000 || strings.Contains(p, "..") || ctlRE.MatchString(p) || strings.Contains(p, "#") {
		return errors.New("path: a path of the director's GUI API that starts with /api/ (the catalog lists them)")
	}
	return nil
}

func (m *director) APIGet(ctx context.Context, path string) (any, bool, error) {
	if err := checkDirectorPath(path); err != nil {
		return nil, false, err
	}
	v, err := m.call(ctx, "api_get", map[string]any{"path": path})
	if err != nil {
		return nil, false, err
	}
	return v, false, nil
}

func (m *director) APICatalog(ctx context.Context) (any, error) {
	return m.call(ctx, "list_api", nil)
}

func (m *director) Close(context.Context) { m.api.close() }

// ---- changes ----

// RawChange: Method SET changes settings with edit_config (Body is the JSON object merged into the configuration, e.g.
// {"dns": {"cache_entries": 200000}}; objects merge key by key, a list or a value replaces what is there, null removes), a dry run
// asks the director to check it without saving.  Method POST or PUT calls a route of the GUI's API with api_request (Path
// /api/…, Body its JSON).  A dry run of those reads the route first (when it can be read) and sends nothing that changes.
// The director keeps every configuration change in its configuration history, which is the way back; it is not put back here.
func (m *director) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if len(r.Lines) > 0 {
		return res, errors.New("lines: a director is changed with SET (settings) or POST and PUT (API routes)")
	}
	if len(r.Body) > rawMaxBody {
		return res, errors.New("body: larger than 256 KB")
	}
	var body any
	if strings.TrimSpace(r.Body) != "" {
		if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
			return res, errors.New("body: not valid JSON")
		}
	}
	switch method {
	case "SET":
		set, ok := body.(map[string]any)
		if !ok || len(set) == 0 {
			return res, errors.New("body: a JSON object with the settings to change, e.g. {\"dns\": {\"cache_entries\": 200000}}")
		}
		args := map[string]any{"set": set, "dry_run": dry, "note": "netdir"}
		v, err := m.call(ctx, "edit_config", args)
		if err != nil {
			return res, fmt.Errorf("edit_config: %w", err)
		}
		j, _ := json.Marshal(Redact(v))
		if dry {
			res.Before = rawTrunc(j)
			res.Note = "the director checked the change and answers the configuration as it would be saved; nothing was saved"
			return res, nil
		}
		res.Applied, res.Answer = true, rawTrunc(j)
		res.Note = "kept in the director's configuration history, where an earlier version can be restored"
		return res, nil
	case http.MethodPost, http.MethodPut:
		if err := checkDirectorPath(r.Path); err != nil {
			return res, err
		}
		if hasSeg(r.Path, "login", "logout", "session", "sso") {
			return res, errors.New("path: login, logout and sign-in routes are not called here")
		}
		if dry {
			if v, err := m.call(ctx, "api_get", map[string]any{"path": r.Path}); err == nil {
				j, _ := json.Marshal(Redact(v))
				res.Before = rawTrunc(j)
			}
			res.Note = fmt.Sprintf("would call %s %s on the director; nothing was changed", method, r.Path)
			return res, nil
		}
		args := map[string]any{"method": method, "path": r.Path}
		if body != nil {
			args["body"] = body
		}
		v, err := m.call(ctx, "api_request", args)
		if err != nil {
			return res, fmt.Errorf("%s %s: %w", method, r.Path, err)
		}
		j, _ := json.Marshal(Redact(v))
		res.Applied, res.Answer = true, rawTrunc(j)
		res.Note = "the director does not undo an API call by itself"
		return res, nil
	}
	return res, fmt.Errorf("method %q: SET (settings), POST or PUT (a route of the GUI's API)", r.Method)
}
