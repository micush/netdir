package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// What the MCP endpoint is used for: every tool call is counted by who made it (the key, or the address when there was none), the
// address it came from, the tool and the target it asked about, in hourly buckets kept for eight days (the file mcpusage.json in
// the state directory, written at most every 30 seconds and when the web server stops), and the last 200 calls are kept in memory.
// The numbers are this node's: a caller reaches the node that holds its connection, and the Node menu picks another.  Nothing the
// caller sent or was answered is kept, only the tool, the target (a device name, a tag, ...) and sizes and times.

const (
	mcpUsageKeep    = 8 * 24 * time.Hour
	mcpUsageRows    = 1000 // rows in one hourly bucket; more are counted as "(other)"
	mcpUsageRecent  = 200
	mcpUsageFlushIn = 30 * time.Second
)

type mcpUseVal struct {
	Calls   int64 `json:"n"`
	Errors  int64 `json:"e,omitempty"`
	Writes  int64 `json:"w,omitempty"`
	Refused int64 `json:"r,omitempty"`
	Bytes   int64 `json:"b,omitempty"`
	Ms      int64 `json:"ms,omitempty"`
	Last    int64 `json:"last"`
}

type mcpUseKey struct{ Caller, Addr, Tool, Target string }

type mcpUseCall struct {
	Time   time.Time `json:"time"`
	Caller string    `json:"caller"`
	Addr   string    `json:"addr"`
	Tool   string    `json:"tool"`
	Target string    `json:"target,omitempty"`
	Ms     int64     `json:"ms"`
	Bytes  int       `json:"bytes"`
	Result string    `json:"result"` // ok, error, refused
	Write  bool      `json:"write,omitempty"`
}

type mcpUsage struct {
	mu     sync.Mutex
	path   string
	hours  map[int64]map[mcpUseKey]*mcpUseVal // by the start of the hour (Unix)
	recent []mcpUseCall
	dirty  bool
	flush  time.Time
	now    func() time.Time
}

func newMCPUsage(stateDir string) *mcpUsage {
	u := &mcpUsage{hours: map[int64]map[mcpUseKey]*mcpUseVal{}, now: time.Now}
	if stateDir != "" {
		u.path = filepath.Join(stateDir, "mcpusage.json")
		u.load()
	}
	return u
}

type mcpUseRow struct {
	Hour   int64  `json:"h"`
	Caller string `json:"c"`
	Addr   string `json:"a"`
	Tool   string `json:"t"`
	Target string `json:"g,omitempty"`
	mcpUseVal
}

func (u *mcpUsage) load() {
	b, err := os.ReadFile(u.path)
	if err != nil {
		return
	}
	var rows []mcpUseRow
	if json.Unmarshal(b, &rows) != nil {
		return
	}
	cut := u.now().Add(-mcpUsageKeep).Unix()
	for _, r := range rows {
		if r.Hour < cut {
			continue
		}
		m := u.hours[r.Hour]
		if m == nil {
			m = map[mcpUseKey]*mcpUseVal{}
			u.hours[r.Hour] = m
		}
		v := r.mcpUseVal
		m[mcpUseKey{r.Caller, r.Addr, r.Tool, r.Target}] = &v
	}
}

// save writes the buckets; the caller holds u.mu.
func (u *mcpUsage) save() {
	if u.path == "" {
		return
	}
	var rows []mcpUseRow
	for h, m := range u.hours {
		for k, v := range m {
			rows = append(rows, mcpUseRow{h, k.Caller, k.Addr, k.Tool, k.Target, *v})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hour < rows[j].Hour })
	b, err := json.Marshal(rows)
	if err != nil {
		return
	}
	tmp := u.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, u.path) == nil {
		u.dirty = false
		u.flush = u.now()
	}
}

// Flush writes the buckets now (the web server is stopping).
func (u *mcpUsage) Flush() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dirty {
		u.save()
	}
}

// callerOf splits the name a call is logged under: KEYNAME@ADDRESS, or just the address.
func mcpCallerOf(who, from string) string {
	if who == from {
		return "(address list)"
	}
	return strings.TrimSuffix(who, "@"+from)
}

// mcpTarget is what a call asked about: the devices of a device tool, as it was written.
func mcpTarget(args map[string]any) string {
	t, _ := args["target"].(string)
	t = strings.TrimSpace(t)
	if len(t) > 120 {
		t = t[:120] + "…"
	}
	return t
}

// Record counts one call.
func (u *mcpUsage) Record(c mcpUseCall) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	hr := c.Time.Truncate(time.Hour).Unix()
	m := u.hours[hr]
	if m == nil {
		m = map[mcpUseKey]*mcpUseVal{}
		u.hours[hr] = m
		cut := now.Add(-mcpUsageKeep).Unix()
		for h := range u.hours {
			if h < cut {
				delete(u.hours, h)
			}
		}
	}
	k := mcpUseKey{c.Caller, c.Addr, c.Tool, c.Target}
	v := m[k]
	if v == nil {
		if len(m) >= mcpUsageRows {
			k = mcpUseKey{c.Caller, c.Addr, c.Tool, "(other)"}
			v = m[k]
		}
		if v == nil {
			v = &mcpUseVal{}
			m[k] = v
		}
	}
	v.Calls++
	v.Bytes += int64(c.Bytes)
	v.Ms += c.Ms
	v.Last = c.Time.Unix()
	switch c.Result {
	case "error":
		v.Errors++
	case "refused":
		v.Refused++
	}
	if c.Write && c.Result == "ok" {
		v.Writes++
	}
	u.recent = append(u.recent, c)
	if len(u.recent) > mcpUsageRecent {
		u.recent = append(u.recent[:0], u.recent[len(u.recent)-mcpUsageRecent:]...)
	}
	u.dirty = true
	if now.Sub(u.flush) >= mcpUsageFlushIn {
		u.save()
	}
}

type mcpUseSum struct {
	Name    string `json:"name"`
	Calls   int64  `json:"calls"`
	Errors  int64  `json:"errors"`
	Writes  int64  `json:"writes"`
	Refused int64  `json:"refused"`
	Bytes   int64  `json:"bytes"`
	AvgMs   int64  `json:"avg_ms"`
	Last    int64  `json:"last"`
	ms      int64
}

func (s *mcpUseSum) add(v *mcpUseVal) {
	s.Calls += v.Calls
	s.Errors += v.Errors
	s.Writes += v.Writes
	s.Refused += v.Refused
	s.Bytes += v.Bytes
	s.ms += v.Ms
	if v.Last > s.Last {
		s.Last = v.Last
	}
}

func mcpSums(m map[string]*mcpUseSum) []mcpUseSum {
	out := make([]mcpUseSum, 0, len(m))
	for _, s := range m {
		if s.Calls > 0 {
			s.AvgMs = s.ms / s.Calls
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type mcpUseHour struct {
	T      int64 `json:"t"`
	Calls  int64 `json:"calls"`
	Errors int64 `json:"errors"`
	Bytes  int64 `json:"bytes"`
}

// Report adds the buckets of the last window up, by key, source address, tool and target, and by hour.
func (u *mcpUsage) Report(window time.Duration) map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	from := now.Add(-window).Truncate(time.Hour).Unix()
	tot := &mcpUseSum{Name: "all"}
	by := map[string]map[string]*mcpUseSum{"key": {}, "source": {}, "tool": {}, "target": {}}
	bump := func(dim, name string, v *mcpUseVal) {
		s := by[dim][name]
		if s == nil {
			s = &mcpUseSum{Name: name}
			by[dim][name] = s
		}
		s.add(v)
	}
	hours := map[int64]*mcpUseHour{}
	for h := now.Truncate(time.Hour).Unix(); h >= from; h -= 3600 {
		hours[h] = &mcpUseHour{T: h}
	}
	for h, m := range u.hours {
		if h < from {
			continue
		}
		for k, v := range m {
			tot.add(v)
			bump("key", k.Caller, v)
			bump("source", k.Addr, v)
			bump("tool", k.Tool, v)
			if k.Target == "" {
				bump("target", "(none)", v)
			}
			for _, t := range strings.Split(k.Target, ",") {
				if t = strings.TrimSpace(t); t != "" {
					bump("target", t, v)
				}
			}
			if hh := hours[h]; hh != nil {
				hh.Calls += v.Calls
				hh.Errors += v.Errors
				hh.Bytes += v.Bytes
			}
		}
	}
	if tot.Calls > 0 {
		tot.AvgMs = tot.ms / tot.Calls
	}
	var hs []mcpUseHour
	for _, h := range hours {
		hs = append(hs, *h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].T < hs[j].T })
	recent := make([]mcpUseCall, len(u.recent))
	for i, c := range u.recent {
		recent[len(u.recent)-1-i] = c // newest first
	}
	return map[string]any{
		"window_hours": int(window / time.Hour), "now": now.Unix(), "totals": *tot,
		"by_key": mcpSums(by["key"]), "by_source": mcpSums(by["source"]), "by_tool": mcpSums(by["tool"]), "by_target": mcpSums(by["target"]),
		"hours": hs, "recent": recent,
		"note": "This node's calls only (the Node menu picks another). Counted from the hourly buckets kept for 8 days; the 200 newest calls are kept in memory and start again when the daemon restarts.",
	}
}

// handleMCPUsage: GET /api/mcpusage?window=24h|7d
func (w *WebServer) handleMCPUsage(rw http.ResponseWriter, r *http.Request, s *session) {
	win := 24 * time.Hour
	switch r.URL.Query().Get("window") {
	case "", "24h":
	case "1h":
		win = time.Hour
	case "7d":
		win = 7 * 24 * time.Hour
	default:
		jsonError(rw, http.StatusBadRequest, "window: 1h, 24h or 7d")
		return
	}
	if w.usage == nil {
		w.usage = newMCPUsage("")
	}
	writeJSON(rw, http.StatusOK, w.usage.Report(win))
}
