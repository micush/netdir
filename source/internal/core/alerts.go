package core

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
)

const AlertHistLen = 100

// AlertsConfig is the "alerts" block of the shared settings.
type AlertsConfig struct {
	Webhook     string               `json:"webhook,omitempty"`      // URL that gets a JSON POST for every opened and resolved alert
	RepeatHours int                  `json:"repeat_hours,omitempty"` // tell again this often while an alert stays open and unacknowledged; 0 = never
	Rules       map[string]AlertRule `json:"rules,omitempty"`        // by rule id; a rule that is not here, or a field left out, has its default
}

// AlertRule is one rule's settings.  Fields left out take the rule's default.
type AlertRule struct {
	Enabled   *bool   `json:"enabled,omitempty"`
	Severity  string  `json:"severity,omitempty"`    // info, warning, critical
	Mode      string  `json:"mode,omitempty"`        // up/down rules: in_a_row, minutes or m_of_n
	After     int     `json:"after,omitempty"`       // in_a_row: checks; minutes: minutes; m_of_n: the M
	Of        int     `json:"of,omitempty"`          // m_of_n: the N
	Threshold float64 `json:"threshold,omitempty"`   // value rules
	ForMin    *int    `json:"for_minutes,omitempty"` // value rules: how long past the threshold
	ClearMode string  `json:"clear_mode,omitempty"`  // checks (good checks in a row) or minutes
	Clear     int     `json:"clear,omitempty"`
}

// alertDef is a rule of the catalog.
type alertDef struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Subject  string   `json:"subject"` // what one alert is about: "upstream server", "certificate", ...
	Kind     string   `json:"kind"`    // updown or value
	Sev      string   `json:"severity"`
	On       bool     `json:"on"`              // enabled by default
	Unit     string   `json:"unit"`            // value rules: the unit of the threshold
	Below    bool     `json:"below,omitempty"` // value rules: bad when under the threshold
	Thresh   float64  `json:"threshold,omitempty"`
	ForMin   int      `json:"for_minutes,omitempty"`
	DefMode  string   `json:"-"`             // up/down rules: the counting the rule starts with (default in_a_row)
	DefAfter int      `json:"-"`             // and its number (default 3)
	Fix      []string `json:"fix,omitempty"` // the actions of the Fix menu
	Go       string   `json:"go,omitempty"`  // the page "Go to" opens
}

// ruleView is a rule with every default filled in, for the form and for the checks.
type RuleView struct {
	alertDef
	Enabled   bool    `json:"enabled"`
	Severity  string  `json:"severity_now"`
	Mode      string  `json:"mode"`
	After     int     `json:"after"`
	Of        int     `json:"of"`
	Threshold float64 `json:"threshold_now"`
	ForMinNow int     `json:"for_minutes_now"`
	ClearMode string  `json:"clear_mode"`
	Clear     int     `json:"clear"`
}

var AlertSeverities = []string{"info", "warning", "critical"}

func (c *AlertsConfig) Rule(d alertDef) RuleView {
	r := AlertRule{}
	if c != nil {
		r = c.Rules[d.ID]
	}
	v := RuleView{alertDef: d, Enabled: d.On, Severity: d.Sev, Threshold: d.Thresh, ForMinNow: d.ForMin}
	if r.Enabled != nil {
		v.Enabled = *r.Enabled
	}
	if r.Severity != "" {
		v.Severity = r.Severity
	}
	if d.Kind == "updown" {
		v.Mode, v.After, v.Of = "in_a_row", 3, 5
		if d.DefMode != "" {
			v.Mode, v.After = d.DefMode, d.DefAfter
		}
		if r.Mode != "" {
			v.Mode = r.Mode
		}
		if r.After > 0 {
			v.After = r.After
		}
		if r.Of > 0 {
			v.Of = r.Of
		}
		v.ClearMode, v.Clear = "checks", 2
	} else {
		if r.Threshold != 0 {
			v.Threshold = r.Threshold
		}
		if r.ForMin != nil {
			v.ForMinNow = *r.ForMin
		}
		v.ClearMode, v.Clear = "minutes", 5
	}
	if r.ClearMode != "" {
		v.ClearMode = r.ClearMode
	}
	if r.Clear > 0 {
		v.Clear = r.Clear
	}
	return v
}

// Validate checks the block and tidies it.
func (c *AlertsConfig) Validate() error {
	c.Webhook = strings.TrimSpace(c.Webhook)
	if c.Webhook != "" {
		u, err := url.Parse(c.Webhook)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("alerts: the webhook must be an http:// or https:// address")
		}
		if len(c.Webhook) > 2000 {
			return errors.New("alerts: the webhook address is too long")
		}
	}
	if c.RepeatHours < 0 || c.RepeatHours > 24*30 {
		return errors.New("alerts: repeat_hours is 0 (never) to 720")
	}
	for id, r := range c.Rules {
		def, ok := AlertDefByID(id)
		if !ok {
			return fmt.Errorf("alerts: there is no rule %q", id)
		}
		if r.Severity != "" && !ContainsStr(AlertSeverities, r.Severity) {
			return fmt.Errorf("alerts: %s: severity is info, warning or critical", id)
		}
		if r.Mode != "" && r.Mode != "in_a_row" && r.Mode != "minutes" && r.Mode != "m_of_n" {
			return fmt.Errorf("alerts: %s: mode is in_a_row, minutes or m_of_n", id)
		}
		if r.ClearMode != "" && r.ClearMode != "checks" && r.ClearMode != "minutes" {
			return fmt.Errorf("alerts: %s: clear_mode is checks or minutes", id)
		}
		if r.After < 0 || r.After > 100000 || r.Of < 0 || r.Of > AlertHistLen || r.Clear < 0 || r.Clear > 100000 {
			return fmt.Errorf("alerts: %s: a count is out of range (of is at most %d)", id, AlertHistLen)
		}
		if r.Mode == "m_of_n" {
			v := c.Rule(def)
			if v.After > v.Of {
				return fmt.Errorf("alerts: %s: %d failures out of the last %d checks is not possible", id, v.After, v.Of)
			}
		}
		if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Threshold < 0 {
			return fmt.Errorf("alerts: %s: the threshold is a number of 0 or more", id)
		}
		if r.ForMin != nil && (*r.ForMin < 0 || *r.ForMin > 10080) {
			return fmt.Errorf("alerts: %s: for_minutes is 0 to 10080", id)
		}
	}
	if len(c.Rules) == 0 {
		c.Rules = nil
	}
	return nil
}

func (c *AlertsConfig) clone() *AlertsConfig {
	if c == nil {
		return nil
	}
	n := *c
	if c.Rules != nil {
		n.Rules = make(map[string]AlertRule, len(c.Rules))
		for k, v := range c.Rules {
			n.Rules[k] = v
		}
	}
	return &n
}

// ── alerts and silences ──────────────────────────────────────────────────────

// Alert is one alert.  Times are unix seconds; 0 = not yet / never.
type Alert struct {
	ID         string  `json:"id"`
	Rule       string  `json:"rule"`
	Title      string  `json:"title"`
	Subject    string  `json:"subject"`
	Node       string  `json:"node"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
	Value      float64 `json:"value,omitempty"`
	Opened     int64   `json:"opened"`
	Closed     int64   `json:"closed,omitempty"`
	Count      int     `json:"count"`                // how many times it has opened (it comes back within an hour: the same alert)
	Recovering bool    `json:"recovering,omitempty"` // the condition is good, the clear time has not passed yet
	Acked      bool    `json:"acked,omitempty"`
	AckedBy    string  `json:"acked_by,omitempty"`
	AckedAt    int64   `json:"acked_at,omitempty"`
	Resolution string  `json:"resolution,omitempty"` // cleared, manual, rule off, auto fix
	ResolvedBy string  `json:"resolved_by,omitempty"`
	Notified   int64   `json:"notified,omitempty"` // when somebody was last told (webhook)
	Silenced   int64   `json:"silenced_until,omitempty"`
}

// Silence keeps the alerts that match quiet until it runs out.  An empty Rule or Subject matches any.
type Silence struct {
	ID      string `json:"id"`
	Rule    string `json:"rule,omitempty"`
	Subject string `json:"subject,omitempty"`
	Until   int64  `json:"until"`
	By      string `json:"by,omitempty"`
	Created int64  `json:"created"`
}

func (s Silence) Matches(a *Alert) bool {
	return (s.Rule == "" || s.Rule == a.Rule) && (s.Subject == "" || s.Subject == a.Subject)
}

// AlertView is the Monitor ▸ Alerts page's data.
type AlertView struct {
	Node     string     `json:"node"`
	Now      int64      `json:"now"`
	Alerts   []Alert    `json:"alerts"`
	Silences []Silence  `json:"silences"`
	Rules    []RuleView `json:"rules"`
}
