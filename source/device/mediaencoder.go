package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// multi-media[encoder] (platform "mediaencoder"): the NVENC HEVC re-encoding daemon, reached through its own MCP endpoint
// (POST /mcp on its web port, 8765, JSON answers; Settings ▸ General ▸ MCP Server on the encoder makes the token).
//
// The credential is that token ("Authorization: Bearer TOKEN"), in the token field; a password is not used.  The encoder has
// one kind of access: whoever holds the token may also change it, so give netdir a token of its own (Revoke ends it on the
// encoder at once).  The driver only calls the encoder's tools:
//
//	reads    get_status, get_live_session, get_queue, get_log, list_history, get_history_log, get_metrics, get_cluster,
//	         check_cluster, list_schedules, get_quarantine, get_config, scan_library (what a job would encode: reads and
//	         probes files, changes nothing)
//	changes  set_config (method SET), and method CALL with one of start_job, stop_job, stop_cluster_jobs, drain_node,
//	         create_schedule, update_schedule, toggle_schedule, run_schedule, delete_schedule, clear_queue,
//	         purge_quarantine, clear_log, clear_history, clean_temp_files
//
// The encoder has no certificate, token or secret tool, and hides cluster_secret, plex_token and mcp_token itself, so none
// passes through here.  It is not a network device: no interfaces, neighbors, ports, routes or firewall (ErrUnsupported).

func init() { Register("mediaencoder", newMediaEncoder) }

type mediaencoder struct {
	d    Device
	api  *apiClient
	ver  string // the release the encoder said in initialize, kept for the length of one request
	seen bool
}

func newMediaEncoder(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: an encoder needs its MCP token as the credential's token (Settings ▸ General ▸ MCP Server ▸ Generate token on the encoder)", d.Name)
	}
	api, err := newAPIClient(d, 8765)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	return &mediaencoder{d: d, api: api}, nil
}

func (m *mediaencoder) reuse() { m.ver, m.seen = "", false }

func (m *mediaencoder) Close(context.Context) { m.api.close() }

// rpc sends one JSON-RPC request and returns its result.
func (m *mediaencoder) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, err := m.api.do(ctx, http.MethodPost, "/mcp", req, http.Header{"Accept": {"application/json, text/event-stream"}})
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return nil, errors.New("the encoder's MCP endpoint is off (HTTP 404): Settings ▸ General ▸ MCP Server ▸ Generate token on the encoder")
		}
		return nil, err
	}
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: the answer is not MCP JSON: %v", method, err)
	}
	if r.Error != nil {
		return nil, &statusError{Code: http.StatusBadRequest, Body: r.Error.Message}
	}
	return r.Result, nil
}

// call runs one tool and returns what its text answer holds as JSON.  The encoder says isError with a text for a refusal.
func (m *mediaencoder) call(ctx context.Context, tool string, args map[string]any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	res, err := m.rpc(ctx, "tools/call", map[string]any{"name": tool, "arguments": args})
	if err != nil {
		return nil, err
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, fmt.Errorf("%s: the answer is not an MCP tool result: %v", tool, err)
	}
	text := ""
	if len(r.Content) > 0 {
		text = r.Content[0].Text
	}
	if r.IsError {
		return nil, &statusError{Code: http.StatusBadRequest, Body: text}
	}
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil, fmt.Errorf("%s: the answer is not JSON: %.80q", tool, text)
	}
	return v, nil
}

func (m *mediaencoder) version(ctx context.Context) (string, error) {
	if m.seen {
		return m.ver, nil
	}
	res, err := m.rpc(ctx, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "netdir", "version": "1"}})
	if err != nil {
		return "", err
	}
	var r struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(res, &r); err != nil || r.ServerInfo.Name != "multi-mediaencoder" {
		return "", errors.New("this is not a multi-media[encoder] (its MCP server did not say so in initialize)")
	}
	m.ver, m.seen = r.ServerInfo.Version, true
	return m.ver, nil
}

func lastRow(v any) map[string]any {
	l, _ := v.([]any)
	if len(l) == 0 {
		return nil
	}
	r, _ := l[len(l)-1].(map[string]any)
	return r
}

func (m *mediaencoder) Facts(ctx context.Context) (Facts, error) {
	ver, err := m.version(ctx)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Vendor: "multi-mediaencoder", Model: "NVENC HEVC encoder"}
	if ver != "" {
		f.OSVersion = "v" + ver
	}
	if v, err := m.call(ctx, "get_cluster", nil); err == nil {
		if c, _ := v.(map[string]any); boolv(c["enabled"]) {
			f.Hostname = str(c["name"])
			f.Model = fmt.Sprintf("NVENC HEVC encoder, %d node(s)", len(rows(c["nodes"])))
		}
	}
	if v, err := m.call(ctx, "get_metrics", nil); err == nil {
		if mm, _ := v.(map[string]any); mm != nil {
			if g, _ := mm["gpu"].(map[string]any); g != nil && str(g["name"]) != "" {
				f.Model += ", " + str(g["name"])
			}
		}
	}
	return f, nil
}

func (m *mediaencoder) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (m *mediaencoder) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }

const mib = 1 << 20

// meNoSample is what is said when the encoder has no reading: it samples its host and its GPU every 2 s, but only while a browser
// has its page open (version 23), and the GPU only where nvidia-smi answers; an unwatched encoder has none to give.
const meNoSample = "the encoder has no sample: it takes them only while a browser is on its page (the GPU's also needs nvidia-smi)"

// Resources: the newest sample of the encoder's host (CPU, load, memory, swap) and of its GPU (utilisation, NVENC/NVDEC, memory,
// temperature, power, fan), as get_metrics answers them.  The encoder samples only while a browser has its page open, so an
// unwatched one has none: that part is named in Details.Unavailable.
func (m *mediaencoder) Resources(ctx context.Context) (Resources, error) {
	v, err := m.call(ctx, "get_metrics", nil)
	if err != nil {
		return Resources{}, err
	}
	mm, _ := v.(map[string]any)
	r := Resources{Details: Routing{Protocols: map[string]any{}, Unavailable: map[string]string{}}}
	sys, _ := mm["system"].(map[string]any)
	if s := lastRow(sys["history"]); s != nil && boolv(sys["available"]) {
		if cpu := flt(s["cpu"]); cpu >= 0 {
			r.CPU = &CPU{Now: cpu}
		}
		tot, used := int64(flt(s["mem_total"])*mib), int64(flt(s["mem_used"])*mib)
		r.Memory = append(r.Memory, Memory{Name: "memory", Total: tot, Used: used, Free: tot - used, UsedPercent: pct(used, tot)})
		if st := int64(flt(s["swap_total"]) * mib); st > 0 {
			su := int64(flt(s["swap_used"]) * mib)
			r.Memory = append(r.Memory, Memory{Name: "swap", Total: st, Used: su, Free: st - su, UsedPercent: pct(su, st)})
		}
		r.Details.Protocols["host"] = map[string]any{"cores": sys["ncpu"], "load": []any{s["load1"], s["load5"], s["load15"]}}
	} else {
		r.Details.Unavailable["host"] = meNoSample
	}
	gpu, _ := mm["gpu"].(map[string]any)
	if s := lastRow(gpu["history"]); s != nil && boolv(gpu["available"]) {
		tot, used := int64(flt(s["mem_total"])*mib), int64(flt(s["mem_used"])*mib)
		r.Memory = append(r.Memory, Memory{Name: "gpu memory", Total: tot, Used: used, Free: tot - used, UsedPercent: pct(used, tot)})
		reading := func(name, kind, units string, v float64) {
			if v >= 0 && !math.IsNaN(v) {
				x := v
				r.Sensors = append(r.Sensors, Sensor{Name: name, Kind: kind, Units: units, Reading: &x})
			}
		}
		reading("GPU temperature", "temperature", "C", flt(s["temp"]))
		reading("GPU power", "psu", "W", flt(s["power"]))
		reading("GPU fan", "fan", "%", flt(s["fan"]))
		r.Details.Protocols["gpu"] = map[string]any{"name": gpu["name"], "util_percent": s["util"], "nvenc_percent": s["enc"], "nvdec_percent": s["dec"],
			"power_limit_w": s["power_limit"], "clock_sm_mhz": s["clk_sm"], "clock_mem_mhz": s["clk_mem"], "processes": len(rows(gpu["procs"]))}
	} else {
		r.Details.Unavailable["gpu"] = meNoSample
	}
	if len(r.Details.Unavailable) == 0 {
		r.Details.Unavailable = nil
	}
	return r, nil
}

// ---- the reads: show NAME, and the encoder's own routes as an API ----

type meRead struct {
	tool string
	arg  string // the argument "key=value" may carry: "lines" (a number) or "id" (a session id), "" for none
}

var meShow = map[string]meRead{
	"status": {"get_status", ""}, "live-session": {"get_live_session", ""}, "queue": {"get_queue", ""}, "log": {"get_log", "lines"},
	"history": {"list_history", ""}, "history-log": {"get_history_log", "id"}, "metrics": {"get_metrics", ""},
	"cluster": {"get_cluster", ""}, "quarantine": {"get_quarantine", ""}, "cluster-check": {"check_cluster", ""}, "schedules": {"list_schedules", ""}, "config": {"get_config", ""},
	"scan": {"scan_library", "target"},
}

var meIDRE = regexp.MustCompile(`^[a-f0-9]{1,64}$`)

func meNames() []string {
	n := make([]string, 0, len(meShow))
	for k := range meShow {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func meJSON(v any) string {
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b))
}

// Show takes "show NAME [lines=N] [id=ID]": NAME is one of status, live-session, queue, log (lines=1..2000), history,
// history-log (id=SESSION from show history), metrics, cluster, cluster-check, schedules, quarantine, config and
// scan (target=movies|tv|/absolute/dir: reports what a job would encode; encodes and renames nothing, may take a while).
func (m *mediaencoder) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(`show NAME [lines=N] [id=ID], e.g. show status; names: ` + strings.Join(meNames(), ", "))
	}
	rd, ok := meShow[strings.ToLower(f[1])]
	if !ok {
		return "", fmt.Errorf("show %s: not a read this encoder has; names: %s", f[1], strings.Join(meNames(), ", "))
	}
	args := map[string]any{}
	if rd.arg == "target" {
		// the path may hold spaces: everything after "target=" is the target
		_, rest, ok := strings.Cut(cmd, "target=")
		rest = strings.TrimSpace(rest)
		if !ok || rest == "" || len(rest) > 1024 || strings.ContainsAny(rest, "\x00\n\r") {
			return "", errors.New("show scan needs target=movies, target=tv or target=/absolute/directory (a scan only: nothing is encoded or changed)")
		}
		if rest != "movies" && rest != "tv" && !strings.HasPrefix(rest, "/") {
			return "", errors.New("target: movies, tv or an absolute directory path")
		}
		args["target"] = rest
		f = f[:2]
	}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" || k != rd.arg {
			return "", fmt.Errorf("%q: show %s takes %s", kv, strings.ToLower(f[1]), argHelp(rd.arg))
		}
		switch k {
		case "lines":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 2000 {
				return "", errors.New("lines=N: a number from 1 to 2000")
			}
			args[k] = n
		case "id":
			if !meIDRE.MatchString(v) {
				return "", errors.New("id=ID: the session id show history lists (lower-case hex)")
			}
			args[k] = v
		}
	}
	if rd.arg == "id" && args["id"] == nil {
		return "", errors.New("show history-log needs id=ID (the ids are in show history)")
	}
	v, err := m.call(ctx, rd.tool, args)
	if err != nil {
		return "", err
	}
	return meJSON(v), nil
}

func argHelp(a string) string {
	if a == "" {
		return "no arguments"
	}
	return a + "=…"
}

// Config is the encoder's settings as get_config answers them (its three secrets are not in the answer).
func (m *mediaencoder) Config(ctx context.Context) (string, error) {
	v, err := m.call(ctx, "get_config", nil)
	if err != nil {
		return "", err
	}
	return meJSON(v), nil
}

// The encoder's web API, by path, answered by the matching read tool.  Only these are read: the rest of the web API has no
// tool, and the encoder serves it to a signed-in browser only.
var meAPI = []struct{ path, tool, pick string }{
	{"/api/status", "get_status", ""}, {"/api/live-session", "get_live_session", ""}, {"/api/queue", "get_queue", ""},
	{"/api/log", "get_log", ""}, {"/api/sessions", "list_history", ""}, {"/api/sys", "get_metrics", "system"}, {"/api/gpu", "get_metrics", "gpu"},
	{"/api/cluster", "get_cluster", ""}, {"/api/quarantine", "get_quarantine", ""}, {"/api/cluster/check", "check_cluster", ""}, {"/api/schedules", "list_schedules", ""}, {"/api/config", "get_config", ""},
}

var meSessLinesRE = regexp.MustCompile(`^/api/sessions/([a-f0-9]{1,64})/lines$`)

func (m *mediaencoder) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := CheckAPIPath(path)
	if err != nil {
		return nil, false, err
	}
	u, err := url.Parse(p)
	if err != nil {
		return nil, false, errors.New("path: not a valid path")
	}
	if sm := meSessLinesRE.FindStringSubmatch(u.Path); sm != nil {
		v, err := m.call(ctx, "get_history_log", map[string]any{"id": sm[1]})
		if err != nil {
			return nil, false, err
		}
		return Redact(v), false, nil
	}
	for _, e := range meAPI {
		if u.Path != e.path {
			continue
		}
		args := map[string]any{}
		if e.tool == "get_log" {
			if n := u.Query().Get("n"); n != "" {
				c, err := strconv.Atoi(n)
				if err != nil || c < 1 || c > 2000 {
					return nil, false, errors.New("n: a number from 1 to 2000")
				}
				args["lines"] = c
			}
		}
		v, err := m.call(ctx, e.tool, args)
		if err != nil {
			return nil, false, err
		}
		if e.pick != "" {
			if mm, ok := v.(map[string]any); ok {
				v = mm[e.pick]
			}
		}
		return Redact(v), false, nil
	}
	return nil, false, fmt.Errorf("path %s: not a route the encoder has a read tool for (the catalog lists them)", u.Path)
}

func (m *mediaencoder) APICatalog(context.Context) (any, error) {
	var out []any
	for _, e := range meAPI {
		out = append(out, map[string]any{"method": "GET", "path": e.path, "tool": e.tool})
	}
	out = append(out, map[string]any{"method": "GET", "path": "/api/sessions/ID/lines", "tool": "get_history_log"})
	return out, nil
}

// ---- changes ----

// meWrite is what method CALL may run, and what a dry run reads first to show how things stand.
var meWrite = map[string]string{
	"start_job": "get_status", "stop_job": "get_status", "stop_cluster_jobs": "get_cluster", "drain_node": "get_cluster",
	"create_schedule": "list_schedules", "update_schedule": "list_schedules", "toggle_schedule": "list_schedules",
	"run_schedule": "list_schedules", "delete_schedule": "list_schedules", "clear_queue": "get_queue", "purge_quarantine": "get_quarantine",
	"clear_log": "get_status", "clear_history": "list_history", "clean_temp_files": "get_status",
}

// meGuarded are the calls and settings the guard lists (NETDIR_DEVICE_GUARDS=1) refuse: what erases records, and what decides who
// may sign in to the encoder or where it listens.
var (
	meGuardedCalls = map[string]bool{"clear_log": true, "clear_history": true, "clean_temp_files": true, "purge_quarantine": true}
	meGuardedKeys  = map[string]bool{"allowed_groups": true, "session_hours": true, "port": true}
)

// RawChange: method SET changes settings with set_config (Body is a JSON object of the settings to change, e.g.
// {"encode_preset": "slow"}; only the keys given change).  Method CALL runs one action: Path is the tool (start_job, stop_job,
// stop_cluster_jobs, drain_node, create_schedule, update_schedule, toggle_schedule, run_schedule, delete_schedule, clear_queue and,
// with the guards off, clear_log, clear_history, clean_temp_files) and Body is its arguments as a JSON object.  The encoder has no
// dry run: a dry run checks the request here and reads how things stand now (the settings it would change, the status, the
// schedules), and sends nothing that changes.  The encoder checks the values itself when the change is made, as its Settings page
// does, and a refusal comes back as the error; it does not put a setting back, and the result's Before is the copy to put back by hand.
func (m *mediaencoder) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if len(r.Lines) > 0 {
		return res, errors.New("lines: an encoder is changed with SET (settings) or CALL (an action)")
	}
	if len(r.Body) > rawMaxBody || strings.ContainsRune(r.Body, 0) {
		return res, errors.New("body: larger than 256 KB, or not text")
	}
	var obj map[string]any
	if strings.TrimSpace(r.Body) != "" {
		if err := json.Unmarshal([]byte(r.Body), &obj); err != nil {
			return res, errors.New("body: a JSON object")
		}
	}
	switch method {
	case "SET":
		if len(obj) == 0 {
			return res, errors.New(`body: a JSON object with the settings to change, e.g. {"encode_preset": "slow"}`)
		}
		var bad []string
		for k := range obj {
			if k == "cluster_secret" || k == "plex_token" || k == "mcp_token" || (guardsOn && meGuardedKeys[k]) {
				bad = append(bad, k)
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			return res, fmt.Errorf("settings %s: not changed from here", strings.Join(bad, ", "))
		}
		cur, err := m.call(ctx, "get_config", nil)
		if err != nil {
			return res, fmt.Errorf("get_config: %w", err)
		}
		before := map[string]any{}
		if c, ok := cur.(map[string]any); ok {
			for k := range obj {
				if v, ok := c[k]; ok {
					before[k] = v
				}
			}
		}
		bj, _ := json.Marshal(Redact(before))
		res.Before = rawTrunc(bj)
		if dry {
			res.Note = "the encoder has no dry run: the settings above are what would be replaced; nothing was changed"
			return res, nil
		}
		v, err := m.call(ctx, "set_config", map[string]any{"settings": obj})
		if err != nil {
			return res, fmt.Errorf("set_config: %w", err)
		}
		j, _ := json.Marshal(Redact(v))
		res.Applied, res.Answer = true, rawTrunc(j)
		res.Note = "the encoder does not undo a setting by itself; Before holds what was replaced"
		return res, nil
	case "CALL":
		tool := strings.TrimSpace(r.Path)
		read, ok := meWrite[tool]
		if !ok {
			return res, fmt.Errorf("path %q: the action to run: %s", r.Path, strings.Join(meWriteNames(), ", "))
		}
		if tool == "purge_quarantine" {
			return m.purgeQuarantine(ctx, obj, dry)
		}
		if guardsOn && meGuardedCalls[tool] {
			return res, fmt.Errorf("%s: refused while the guard lists are on (NETDIR_DEVICE_GUARDS=1): it erases records on the encoder", tool)
		}
		if id, has := obj["id"]; has {
			if s, ok := id.(string); !ok || !meIDRE.MatchString(s) {
				return res, errors.New("body: id is a schedule id, as show schedules lists them")
			}
		}
		if obj == nil {
			obj = map[string]any{}
		}
		if v, err := m.call(ctx, read, nil); err == nil {
			j, _ := json.Marshal(Redact(v))
			res.Before = rawTrunc(j)
		} else if dry {
			return res, fmt.Errorf("%s: %w", read, err)
		}
		if dry {
			res.Note = fmt.Sprintf("would run %s on the encoder; nothing was changed. The encoder checks the arguments when it runs it", tool)
			return res, nil
		}
		v, err := m.call(ctx, tool, obj)
		if err != nil {
			return res, fmt.Errorf("%s: %w", tool, err)
		}
		j, _ := json.Marshal(Redact(v))
		res.Applied, res.Answer = true, rawTrunc(j)
		res.Note = "the encoder does not undo an action by itself"
		return res, nil
	}
	return res, fmt.Errorf("method %q: SET (settings) or CALL (an action)", r.Method)
}

func meWriteNames() []string {
	n := make([]string, 0, len(meWrite))
	for k := range meWrite {
		if guardsOn && meGuardedCalls[k] {
			continue
		}
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// purgeQuarantine deletes the files in the encoder's quarantine (the originals kept after an encode).  Body: {"older_than_days": N}
// to delete only the files older than N days; without it every file goes (the encoder holds back one that arrived in the last two
// minutes).  The encoder has a real dry run for this one, so a dry run here (or "dry_run": true in the body) asks it what would be
// deleted and deletes nothing; Before is its answer.  The encoder only ever deletes regular files inside the quarantine folders it
// made itself (the ones with its marker file).  With NETDIR_DEVICE_GUARDS=1 only a dry run is accepted.
func (m *mediaencoder) purgeQuarantine(ctx context.Context, body map[string]any, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	args := map[string]any{}
	for k, v := range body {
		switch k {
		case "older_than_days":
			n, ok := v.(float64)
			if v != nil && (!ok || n < 0 || n > 3650) {
				return res, errors.New("older_than_days: a number of days from 0 to 3650, or leave it out to delete every file in quarantine")
			}
			if v != nil {
				args[k] = n
			}
		case "dry_run":
			b, ok := v.(bool)
			if !ok {
				return res, errors.New("dry_run: true or false")
			}
			dry = dry || b
		default:
			return res, fmt.Errorf("body: purge_quarantine takes older_than_days and dry_run, not %q", k)
		}
	}
	res.DryRun = dry
	if guardsOn && !dry {
		return res, errors.New("purge_quarantine: only a dry run is accepted while the guard lists are on (NETDIR_DEVICE_GUARDS=1): it deletes the originals of past encodes")
	}
	args["dry_run"] = dry
	v, err := m.call(ctx, "purge_quarantine", args)
	if err != nil {
		return res, fmt.Errorf("purge_quarantine: %w", err)
	}
	j, _ := json.Marshal(Redact(v))
	if dry {
		res.Before = rawTrunc(j)
		res.Note = "the encoder's own dry run: Before says what would be deleted; nothing was deleted"
		return res, nil
	}
	res.Applied, res.Answer = true, rawTrunc(j)
	res.Note = "the files are gone: the encoder does not keep a copy. The answer says how many were deleted and the space freed"
	return res, nil
}
