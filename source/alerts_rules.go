package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The rules of the alerts (see alerts.go) and what they read.

var alertDefs = []alertDef{
	{ID: "listener_down", Title: "MCP listener down", Subject: "gateway", Kind: "updown", Sev: "critical", On: true, Go: "gateways"},
	{ID: "device_down", Title: "Device not answering", Subject: "device", Kind: "updown", Sev: "warning", On: true, DefMode: "minutes", DefAfter: 3, Go: "devices"},
	{ID: "no_active_gateway", Title: "No active gateway", Subject: "gateway", Kind: "updown", Sev: "critical", On: true, Go: "gateways"},
	{ID: "certificate_expiring", Title: "Certificate about to expire", Subject: "certificate", Kind: "value", Sev: "warning", On: true, Unit: "days left", Below: true, Thresh: 14, ForMin: 0, Go: "cfg_web"},
	{ID: "backup_failed", Title: "Backup failed", Subject: "", Kind: "updown", Sev: "warning", On: true, DefMode: "minutes", DefAfter: 30, Go: "cfg_backup"},
	{ID: "cpu_high", Title: "CPU busy", Subject: "", Kind: "value", Sev: "warning", On: true, Unit: "% CPU", Thresh: 90, ForMin: 15, Go: "host"},
	{ID: "memory_high", Title: "Memory nearly full", Subject: "", Kind: "value", Sev: "warning", On: true, Unit: "% memory", Thresh: 90, ForMin: 15, Go: "host"},
	{ID: "disk_full", Title: "Disk nearly full", Subject: "filesystem", Kind: "value", Sev: "warning", On: true, Unit: "% full", Thresh: 90, ForMin: 10, Go: "host"},
}

func alertDefByID(id string) (alertDef, bool) {
	for _, d := range alertDefs {
		if d.ID == id {
			return d, true
		}
	}
	return alertDef{}, false
}

// cntPoint is kept for the engine's per-key counter history.
type cntPoint struct {
	at   time.Time
	q, f uint64
}

// sampleNode reads everything the rules look at, on this node.
func (e *AlertEngine) sampleNode(now time.Time) []alertSample {
	st := e.st
	if st == nil {
		return nil
	}
	var out []alertSample
	type gk struct {
		gid int
		af  string
	}
	active, local, serving, up := map[gk]bool{}, map[gk]bool{}, map[gk]bool{}, map[gk]bool{}
	for _, r := range st.snapshot() {
		k := gk{r.GroupID, r.AF}
		if r.State == "active" {
			active[k] = true
		}
		if r.Local {
			local[k] = true
			if r.State == "active" || r.State == "forward" {
				serving[k] = true
				up[k] = r.ServiceUp
			}
		}
	}
	for k := range local {
		subj := fmt.Sprintf("group %d %s", k.gid, k.af)
		out = append(out, alertSample{Rule: "no_active_gateway", Subject: subj, Bad: !active[k], Message: "no node is the active gateway of " + subj})
		if serving[k] {
			out = append(out, alertSample{Rule: "listener_down", Subject: subj, Bad: !up[k], Message: "this node serves " + subj + " but its MCP and web listener is not serving"})
		}
	}
	for name, h := range deviceHealth(false) {
		switch h.Status {
		case "bad", "warn":
			out = append(out, alertSample{Rule: "device_down", Subject: name, Bad: true, Message: name + ": " + h.Detail})
		case "ok":
			out = append(out, alertSample{Rule: "device_down", Subject: name, Bad: false, Message: name + " answers"})
		}
	}
	if e.mg != nil && e.mg.certs != nil {
		if lc, err := e.mg.certs.current(false); err == nil && lc != nil && !lc.info.NotAfter.IsZero() {
			days := time.Until(lc.info.NotAfter).Hours() / 24
			out = append(out, alertSample{Rule: "certificate_expiring", Subject: "web", Value: days, Bad: days < e.threshold("certificate_expiring"),
				Message: fmt.Sprintf("the web certificate runs out on %s (%.0f days)", lc.info.NotAfter.Format("2006-01-02"), days)})
		}
	}
	if e.mg != nil && e.mg.backup != nil {
		if failing, enabled, msg := e.mg.backup.Failing(); enabled {
			out = append(out, alertSample{Rule: "backup_failed", Bad: failing, Message: "the last backup failed: " + msg})
		}
	}
	if h := hoststats.lastNow(); h.At != 0 {
		out = append(out, alertSample{Rule: "cpu_high", Value: h.CPU, Bad: h.CPU > e.threshold("cpu_high"), Message: fmt.Sprintf("CPU is at %.0f%%", h.CPU)})
		out = append(out, alertSample{Rule: "memory_high", Value: h.MemPct, Bad: h.MemPct > e.threshold("memory_high"), Message: fmt.Sprintf("memory is %.0f%% in use", h.MemPct)})
		for _, f := range h.FS {
			out = append(out, alertSample{Rule: "disk_full", Subject: f.Mount, Value: f.Pct, Bad: f.Pct > e.threshold("disk_full"), Message: fmt.Sprintf("%s is %.0f%% full", f.Mount, f.Pct)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// threshold is the rule's threshold in force.
func (e *AlertEngine) threshold(id string) float64 {
	d, _ := alertDefByID(id)
	return e.cfg().rule(d).Threshold
}

// ── the Fix menu ─────────────────────────────────────────────────────────────

var alertFixes = map[string]string{}

func (e *AlertEngine) fix(action, actor string) (string, error) {
	if e.st == nil {
		return "", errors.New("not available")
	}
	return "", errors.New("unknown action")
}

// ── the operations behind /api/alerts ────────────────────────────────────────

func (m *Mgmt) alertsOp(cmd string, raw json.RawMessage, actor string) (any, error) {
	e := m.alerts
	if e == nil {
		return nil, errors.New("alerts are not available on this node")
	}
	var a struct {
		ID      string `json:"id"`
		Ack     bool   `json:"ack"`
		Minutes int    `json:"minutes"`
		Action  string `json:"action"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
	}
	ok := map[string]any{"ok": true}
	switch cmd {
	case "alerts.list":
		return e.View(), nil
	case "alerts.ack":
		return ok, e.Ack(a.ID, a.Ack, actor)
	case "alerts.silence":
		return ok, e.Silence(a.ID, a.Minutes, actor)
	case "alerts.resolve":
		return ok, e.Resolve(a.ID, actor)
	case "alerts.test":
		if err := e.Test(actor); err != nil {
			return nil, err
		}
		return ok, nil
	case "alerts.fix":
		view := e.View()
		var allowed bool
		for _, al := range view.Alerts {
			if al.ID == a.ID {
				d, _ := alertDefByID(al.Rule)
				allowed = containsStr(d.Fix, a.Action)
			}
		}
		if !allowed {
			return nil, errors.New("that action does not go with that alert")
		}
		msg, err := e.fix(a.Action, actor)
		if err != nil {
			return nil, err
		}
		warnf("alerts: %q ran %q for an alert", actor, alertFixes[a.Action])
		return map[string]any{"ok": true, "message": msg}, nil
	}
	return nil, fmt.Errorf("unknown command %q", cmd)
}

var _ = strings.TrimSpace
