package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netdir/internal/core"
)

// Alerts (Configure ▸ Alerts, Monitor ▸ Alerts).  Every node checks itself every alertTick against a fixed list of rules
// (alertDefs).  A rule makes an alert after its condition has held for as long as the rule says (a number of checks in a row,
// a number of minutes, M of the last N checks, or a value over a threshold for some minutes), and ends it after the condition
// has been good for the "clear after" time.  An alert is open, acknowledged (someone is on it), silenced (nobody wants to
// hear about it for a while) or closed.  Opening and closing go to the log (so to syslog) and to a webhook.  The settings are
// shared by the cluster (Settings.Alerts); the alerts, acknowledgements and silences are each node's own, kept in
// alerts.json in the state directory.

const alertTick = 15 * time.Second

const alertFlapWindow = time.Hour

const alertKeepDays = 30

const alertKeepMax = 1000

type alertSample struct {
	Rule, Subject, Message string
	Bad                    bool
	Value                  float64
}

type alertTrack struct {
	hist                []bool
	badRun, goodRun     int
	badSince, goodSince time.Time
	value               float64
	message             string
}

// AlertEngine keeps the alerts of this node.
type AlertEngine struct {
	mu       sync.Mutex
	path     string
	node     string
	cfg      func() *core.AlertsConfig
	sample   func(now time.Time) []alertSample
	now      func() time.Time
	alerts   map[string]*core.Alert // by ID
	tracks   map[string]*alertTrack
	silences []core.Silence
	opened   uint64 // alerts opened, ever (an alert that comes back counts again)
	send     func(url string, body []byte) error
	lastErr  time.Time
	st       *StatusServer // what the rules read
	mg       *Mgmt
	cnt      map[string][]cntPoint
}

func NewAlertEngine(stateDir, node string, cfg func() *core.AlertsConfig) *AlertEngine {
	e := &AlertEngine{path: filepath.Join(stateDir, "alerts.json"), node: node, cfg: cfg, now: time.Now,
		alerts: map[string]*core.Alert{}, tracks: map[string]*alertTrack{}, send: postWebhook}
	e.load()
	return e
}

func (e *AlertEngine) load() {
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var st struct {
		Alerts   []*core.Alert  `json:"alerts"`
		Silences []core.Silence `json:"silences"`
		Opened   uint64         `json:"opened_total"`
	}
	if json.Unmarshal(b, &st) != nil {
		return
	}
	for _, a := range st.Alerts {
		if a != nil && a.ID != "" {
			e.alerts[a.ID] = a
		}
	}
	e.silences, e.opened = st.Silences, st.Opened
}

// saveLocked writes the state; the caller holds e.mu.
func (e *AlertEngine) saveLocked() {
	var st struct {
		Alerts   []*core.Alert  `json:"alerts"`
		Silences []core.Silence `json:"silences"`
		Opened   uint64         `json:"opened_total"`
	}
	st.Opened = e.opened
	for _, a := range e.alerts {
		st.Alerts = append(st.Alerts, a)
	}
	sort.Slice(st.Alerts, func(i, j int) bool { return st.Alerts[i].Opened < st.Alerts[j].Opened })
	st.Silences = e.silences
	b, err := json.Marshal(st)
	if err == nil {
		err = core.WriteAtomic(e.path, b, 0o600)
	}
	if err != nil && time.Since(e.lastErr) > time.Hour {
		e.lastErr = time.Now()
		core.Warnf("alerts: could not save %s: %v", e.path, err)
	}
}

func newAlertID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run checks every alertTick until ctx ends.
func (e *AlertEngine) Run(ctx context.Context) {
	t := time.NewTicker(alertTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Tick()
		}
	}
}

// Tick makes one round of checks.
func (e *AlertEngine) Tick() {
	now := e.now()
	var samples []alertSample
	if e.sample != nil {
		samples = e.sample(now)
	}
	e.apply(now, samples)
}

type alertNote struct {
	event string
	a     core.Alert
}

// apply feeds one round of samples through the rules.
func (e *AlertEngine) apply(now time.Time, samples []alertSample) {
	cfg := e.cfg()
	var notes []alertNote
	e.mu.Lock()
	seen := map[string]bool{}
	for _, s := range samples {
		def, ok := core.AlertDefByID(s.Rule)
		if !ok {
			continue
		}
		r := cfg.Rule(def)
		if !r.Enabled {
			continue
		}
		key := s.Rule + "|" + s.Subject
		seen[key] = true
		notes = e.feedLocked(now, key, s, r, notes)
	}
	// a subject that was not reported this round (a server taken away, a rule turned off) counts as good
	for key := range e.tracks {
		if seen[key] {
			continue
		}
		rule, subject, _ := strings.Cut(key, "|")
		def, ok := core.AlertDefByID(rule)
		r := cfg.Rule(def)
		if !ok || !r.Enabled {
			notes = e.closeKeyLocked(now, key, "rule off", "", notes)
			delete(e.tracks, key)
			continue
		}
		notes = e.feedLocked(now, key, alertSample{Rule: rule, Subject: subject}, r, notes)
	}
	// alerts of a rule that was switched off, or that are open without a track (after a restart): close the first kind
	for _, a := range e.alerts {
		if a.Closed != 0 {
			continue
		}
		def, ok := core.AlertDefByID(a.Rule)
		if !ok || !cfg.Rule(def).Enabled {
			notes = e.closeAlertLocked(now, a, "rule off", "", notes)
		}
	}
	// tell again
	if cfg != nil && cfg.RepeatHours > 0 {
		for _, a := range e.alerts {
			if a.Closed == 0 && !a.Acked && !e.silencedLocked(a, now) && now.Unix()-a.Notified >= int64(cfg.RepeatHours)*3600 {
				a.Notified = now.Unix()
				notes = append(notes, alertNote{"repeat", *a})
			}
		}
	}
	e.trimLocked(now)
	e.saveLocked()
	e.mu.Unlock()
	e.notify(cfg, notes)
}

func (e *AlertEngine) silencedLocked(a *core.Alert, now time.Time) bool {
	for _, s := range e.silences {
		if s.Until > now.Unix() && s.Matches(a) {
			return true
		}
	}
	return false
}

// feedLocked adds one sample to the key's track and opens or closes its alert when the rule says so.
func (e *AlertEngine) feedLocked(now time.Time, key string, s alertSample, r core.RuleView, notes []alertNote) []alertNote {
	t := e.tracks[key]
	if t == nil {
		t = &alertTrack{}
		e.tracks[key] = t
	}
	t.hist = append(t.hist, s.Bad)
	if len(t.hist) > core.AlertHistLen {
		t.hist = t.hist[len(t.hist)-core.AlertHistLen:]
	}
	if s.Bad {
		if t.badRun == 0 {
			t.badSince = now
		}
		t.badRun++
		t.goodRun, t.goodSince = 0, time.Time{}
		t.value, t.message = s.Value, s.Message
	} else {
		if t.goodRun == 0 {
			t.goodSince = now
		}
		t.goodRun++
		t.badRun, t.badSince = 0, time.Time{}
	}
	open := e.openAlertLocked(key)
	if open == nil {
		if s.Bad && alertTriggered(r, t, now) {
			notes = e.openLocked(now, key, s, r, notes)
		} else if !s.Bad && t.goodRun > core.AlertHistLen {
			delete(e.tracks, key) // nothing to follow: a subject that has been fine for a long while
		}
		return notes
	}
	open.Value = t.value
	if s.Bad {
		open.Recovering = false
		if s.Message != "" {
			open.Message = s.Message
		}
		open.Severity = r.Severity
		return notes
	}
	if alertCleared(r, t, now) {
		return e.closeAlertLocked(now, open, "cleared", "", notes)
	}
	open.Recovering = true
	return notes
}

func (e *AlertEngine) openAlertLocked(key string) *core.Alert {
	rule, subject, _ := strings.Cut(key, "|")
	for _, a := range e.alerts {
		if a.Closed == 0 && a.Rule == rule && a.Subject == subject {
			return a
		}
	}
	return nil
}

func alertTriggered(r core.RuleView, t *alertTrack, now time.Time) bool {
	if r.Kind != "updown" {
		return t.badRun > 0 && now.Sub(t.badSince) >= time.Duration(r.ForMinNow)*time.Minute
	}
	switch r.Mode {
	case "minutes":
		return t.badRun > 0 && now.Sub(t.badSince) >= time.Duration(r.After)*time.Minute
	case "m_of_n":
		last := t.hist
		if len(last) > r.Of {
			last = last[len(last)-r.Of:]
		}
		n := 0
		for _, b := range last {
			if b {
				n++
			}
		}
		return t.badRun > 0 && n >= r.After
	}
	return t.badRun >= r.After
}

func alertCleared(r core.RuleView, t *alertTrack, now time.Time) bool {
	if r.ClearMode == "minutes" {
		return t.goodRun > 0 && now.Sub(t.goodSince) >= time.Duration(r.Clear)*time.Minute
	}
	return t.goodRun >= r.Clear
}

func (e *AlertEngine) openLocked(now time.Time, key string, s alertSample, r core.RuleView, notes []alertNote) []alertNote {
	var a *core.Alert
	for _, c := range e.alerts { // back within the hour: the same alert again
		if c.Closed != 0 && c.Rule == s.Rule && c.Subject == s.Subject && now.Unix()-c.Closed < int64(alertFlapWindow/time.Second) {
			a = c
			break
		}
	}
	if a == nil {
		a = &core.Alert{ID: newAlertID(), Rule: s.Rule, Title: r.Title, Subject: s.Subject, Node: e.node}
		e.alerts[a.ID] = a
	}
	a.Count++
	e.opened++
	a.Opened, a.Closed = now.Unix(), 0
	a.Severity, a.Message, a.Value = r.Severity, s.Message, s.Value
	a.Recovering, a.Acked, a.AckedBy, a.AckedAt, a.Resolution, a.ResolvedBy = false, false, "", 0, "", ""
	if !e.silencedLocked(a, now) {
		a.Notified = now.Unix()
		notes = append(notes, alertNote{"open", *a})
	}
	return notes
}

func (e *AlertEngine) closeKeyLocked(now time.Time, key, how, by string, notes []alertNote) []alertNote {
	if a := e.openAlertLocked(key); a != nil {
		return e.closeAlertLocked(now, a, how, by, notes)
	}
	return notes
}

func (e *AlertEngine) closeAlertLocked(now time.Time, a *core.Alert, how, by string, notes []alertNote) []alertNote {
	a.Closed, a.Recovering, a.Resolution, a.ResolvedBy = now.Unix(), false, how, by
	if !e.silencedLocked(a, now) {
		notes = append(notes, alertNote{"resolved", *a})
	}
	if t := e.tracks[a.Rule+"|"+a.Subject]; t != nil && how == "manual" {
		t.badRun, t.hist = 0, nil // a manual close starts the count again, so it reopens only if the condition goes on
	}
	return notes
}

func (e *AlertEngine) trimLocked(now time.Time) {
	cut := now.Add(-alertKeepDays * 24 * time.Hour).Unix()
	var closed []*core.Alert
	for id, a := range e.alerts {
		if a.Closed != 0 {
			if a.Closed < cut {
				delete(e.alerts, id)
				continue
			}
			closed = append(closed, a)
		}
	}
	if len(closed) > alertKeepMax {
		sort.Slice(closed, func(i, j int) bool { return closed[i].Closed < closed[j].Closed })
		for _, a := range closed[:len(closed)-alertKeepMax] {
			delete(e.alerts, a.ID)
		}
	}
	live := e.silences[:0]
	for _, s := range e.silences {
		if s.Until > now.Unix()-3600 { // kept for an hour after it ran out, so the list can say so
			live = append(live, s)
		}
	}
	e.silences = live
}

// ── telling people ───────────────────────────────────────────────────────────

func (e *AlertEngine) notify(cfg *core.AlertsConfig, notes []alertNote) {
	for _, n := range notes {
		a := n.a
		line := fmt.Sprintf("alert %s: [%s] %s — %s (%s)", n.event, a.Severity, a.Title, a.Message, e.node)
		switch {
		case n.event == "resolved":
			core.Infof("%s", line)
		case a.Severity == "info":
			core.Infof("%s", line)
		default:
			core.Warnf("%s", line)
		}
		if cfg == nil || cfg.Webhook == "" {
			continue
		}
		body := alertWebhookBody(n.event, a, e.node)
		go func(u string) {
			if err := e.send(u, body); err != nil && time.Since(e.lastErrAt()) > time.Minute {
				e.setLastErr()
				core.Warnf("alerts: the webhook did not take the message: %v", err)
			}
		}(cfg.Webhook)
	}
}

func (e *AlertEngine) lastErrAt() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.lastErr }
func (e *AlertEngine) setLastErr()          { e.mu.Lock(); e.lastErr = time.Now(); e.mu.Unlock() }

func alertWebhookBody(event string, a core.Alert, node string) []byte {
	text := fmt.Sprintf("[%s] %s — %s (%s)", a.Severity, a.Title, a.Message, node)
	switch event {
	case "resolved":
		text = "RESOLVED " + text
	case "repeat":
		text = "STILL OPEN " + text
	}
	m := map[string]any{"event": event, "text": text, "content": text, "node": node, "severity": a.Severity, "rule": a.Rule,
		"title": a.Title, "subject": a.Subject, "message": a.Message, "opened": a.Opened, "count": a.Count}
	if a.Closed != 0 {
		m["closed"] = a.Closed
		m["duration_seconds"] = a.Closed - a.Opened
		m["resolution"] = a.Resolution
	}
	b, _ := json.Marshal(m)
	return b
}

func postWebhook(u string, body []byte) error {
	req, err := newJSONPost(u, body)
	if err != nil {
		return err
	}
	resp, err := core.Ipv4FirstClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return nil
}

// ── what the pages ask for ───────────────────────────────────────────────────

// alertBefore is the order of the Alerts page: newest first, and alerts opened in the same second by
// node, rule, subject and ID, so that the list comes out the same on every poll (e.alerts is a map).
func alertBefore(a, b core.Alert) bool {
	if a.Opened != b.Opened {
		return a.Opened > b.Opened
	}
	if a.Node != b.Node {
		return a.Node < b.Node
	}
	if a.Rule != b.Rule {
		return a.Rule < b.Rule
	}
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	return a.ID < b.ID
}

func (e *AlertEngine) View() core.AlertView {
	now := e.now()
	cfg := e.cfg()
	e.mu.Lock()
	defer e.mu.Unlock()
	v := core.AlertView{Node: e.node, Now: now.Unix(), Alerts: []core.Alert{}, Silences: []core.Silence{}}
	for _, a := range e.alerts {
		c := *a
		if c.Closed == 0 {
			for _, s := range e.silences {
				if s.Until > now.Unix() && s.Matches(a) && s.Until > c.Silenced {
					c.Silenced = s.Until
				}
			}
		}
		v.Alerts = append(v.Alerts, c)
	}
	sort.Slice(v.Alerts, func(i, j int) bool { return alertBefore(v.Alerts[i], v.Alerts[j]) })
	for _, s := range e.silences {
		if s.Until > now.Unix() {
			v.Silences = append(v.Silences, s)
		}
	}
	for _, d := range core.AlertDefs {
		v.Rules = append(v.Rules, cfg.Rule(d))
	}
	return v
}

// counts is the number of open alerts that are not silenced, and of those that someone has acknowledged, by severity.
func (e *AlertEngine) counts() (active, acked map[string]int, opened uint64) {
	now := e.now()
	active, acked = map[string]int{}, map[string]int{}
	e.mu.Lock()
	defer e.mu.Unlock()
	opened = e.opened
	for _, a := range e.alerts {
		if a.Closed != 0 || e.silencedLocked(a, now) {
			continue
		}
		if a.Acked {
			acked[a.Severity]++
		} else {
			active[a.Severity]++
		}
	}
	return
}

func (e *AlertEngine) find(id string) *core.Alert {
	if a := e.alerts[id]; a != nil {
		return a
	}
	return nil
}

// Ack sets or clears the acknowledgement of an open alert.
func (e *AlertEngine) Ack(id string, ack bool, by string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.find(id)
	if a == nil || a.Closed != 0 {
		return errors.New("that alert is not open any more")
	}
	a.Acked = ack
	if ack {
		a.AckedBy, a.AckedAt = by, e.now().Unix()
	} else {
		a.AckedBy, a.AckedAt = "", 0
	}
	core.Infof("alerts: %q %s %q (%s)", by, map[bool]string{true: "acknowledged", false: "took back the acknowledgement of"}[ack], a.Title, a.Subject)
	e.saveLocked()
	return nil
}

// Silence keeps the alerts of this alert's rule and subject quiet for the given minutes (0 ends it).
func (e *AlertEngine) Silence(id string, minutes int, by string) error {
	if minutes < 0 || minutes > 60*24*90 {
		return errors.New("a silence lasts up to 90 days")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.find(id)
	if a == nil {
		return errors.New("there is no such alert")
	}
	now := e.now().Unix()
	keep := e.silences[:0]
	for _, s := range e.silences {
		if !(s.Rule == a.Rule && s.Subject == a.Subject) {
			keep = append(keep, s)
		}
	}
	e.silences = keep
	if minutes > 0 {
		e.silences = append(e.silences, core.Silence{ID: newAlertID(), Rule: a.Rule, Subject: a.Subject, Until: now + int64(minutes)*60, By: by, Created: now})
		core.Infof("alerts: %q silenced %q (%s) for %d minutes", by, a.Title, a.Subject, minutes)
	} else {
		core.Infof("alerts: %q ended the silence of %q (%s)", by, a.Title, a.Subject)
	}
	e.saveLocked()
	return nil
}

// Resolve closes an alert by hand.  It opens again when the condition is still there and holds long enough again.
func (e *AlertEngine) Resolve(id, by string) error {
	e.mu.Lock()
	a := e.find(id)
	if a == nil || a.Closed != 0 {
		e.mu.Unlock()
		return errors.New("that alert is not open any more")
	}
	notes := e.closeAlertLocked(e.now(), a, "manual", by, nil)
	core.Infof("alerts: %q marked %q (%s) resolved", by, a.Title, a.Subject)
	e.saveLocked()
	cfg := e.cfg()
	e.mu.Unlock()
	e.notify(cfg, notes)
	return nil
}

// Test sends a message to the webhook so the setting can be tried.
func (e *AlertEngine) Test(by string) error {
	cfg := e.cfg()
	if cfg == nil || cfg.Webhook == "" {
		return errors.New("there is no webhook address to try")
	}
	a := core.Alert{Rule: "test", Title: "Test alert", Message: "This is a test from " + by, Severity: "info", Opened: e.now().Unix(), Count: 1}
	return e.send(cfg.Webhook, alertWebhookBody("test", a, e.node))
}

func newJSONPost(u string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netdir")
	return req, nil
}
