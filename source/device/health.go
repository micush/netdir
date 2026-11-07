package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Health is how a device stands as the gateway last saw it, for the colour of its square on the Topology page and for
// the alerts.  Reach is a TCP connection to the API port, often (cheap, no session on the device); the facts are a real
// request through the driver, now and then (it logs in, so it proves the login works and says what the device is).
//
//	ok    the API port answers and the last facts request worked
//	warn  the API port answers, but the facts request failed (a wrong password or token, an API switched off, a
//	      certificate that is not trusted)
//	bad   the API port does not answer
//	idle  not checked yet
//	paused  the device is disabled
type Health struct {
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Facts    *Facts `json:"facts,omitempty"`     // the last facts the device gave, kept while it is down
	LastOK   int64  `json:"last_ok,omitempty"`   // unix time it last answered a facts request
	Checked  int64  `json:"checked,omitempty"`   // unix time of the last reach check
	FactsAt  int64  `json:"facts_at,omitempty"`  // unix time of the last facts request, good or bad
	FactsErr string `json:"facts_err,omitempty"` // why the last facts request failed
}

// dialFn opens the TCP connection of a reach check (replaceable in tests).
var dialFn = func(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// Monitor keeps the health of every device.  Run calls Check on a timer; the GUI and the alerts read Snapshot.
type Monitor struct {
	mu    sync.Mutex
	state map[string]Health

	ReachEvery time.Duration // how often the API port is tried while someone is looking (default 30 s)
	FactsEvery time.Duration // how often the facts are asked while someone is looking (default 5 min); also at once when a device comes back
	Timeout    time.Duration // the time a reach check may take (default 4 s); a facts request gets 5 times that
	Parallel   int           // devices checked at once (default 16)

	// While nobody is looking (no GUI page of the devices or the topology, no MCP device request for WatchFor) the checks are
	// slower: IdleReach and IdleFacts (0 is the same as ReachEvery and FactsEvery).  Tune, when set, gives all four from the settings.
	IdleReach    time.Duration
	IdleFacts    time.Duration
	WatchFor     time.Duration
	Tune         func() Tuning // the settings; 0 in a field is the default of that one
	Active       func() bool   // false: this node does not do the checks now (it is not the cluster's primary); nil is always
	InactiveWait time.Duration // how long an inactive node waits before it asks again (default 15 s)

	seen atomic.Int64 // unix time of the last Touch
	wake chan struct{}
}

func NewMonitor() *Monitor {
	return &Monitor{state: map[string]Health{}, ReachEvery: 30 * time.Second, FactsEvery: 5 * time.Minute, Timeout: 4 * time.Second, Parallel: 16,
		IdleReach: DefaultIdleReach, IdleFacts: DefaultIdleFacts, WatchFor: 10 * time.Minute, wake: make(chan struct{}, 1)}
}

// What the checks do while nobody is looking: a TCP connect to each device every 3 minutes and its facts every 6 hours (and the
// facts at once when a device is first seen or answers again).  Someone looking is the GUI's Devices or Topology page, or a device
// request through MCP: Touch.
const (
	DefaultIdleReach = 3 * time.Minute
	DefaultIdleFacts = 6 * time.Hour
)

// Tuning is the four intervals the settings can change; 0 keeps the default of that one.
type Tuning struct {
	Reach, Facts         time.Duration // while nobody is looking
	LiveReach, LiveFacts time.Duration // while someone is
}

// Touch says that someone is looking at the devices.  The first look after a quiet time checks at once.
func (m *Monitor) Touch() {
	was := m.seen.Swap(time.Now().Unix())
	if m.wake != nil && time.Since(time.Unix(was, 0)) > m.watchFor() {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
}

func (m *Monitor) watchFor() time.Duration {
	if m.WatchFor > 0 {
		return m.WatchFor
	}
	return 10 * time.Minute
}

func (m *Monitor) watched(now time.Time) bool {
	return now.Sub(time.Unix(m.seen.Load(), 0)) <= m.watchFor()
}

// intervals are how often the reach and the facts checks are due at this moment.
func (m *Monitor) intervals(now time.Time) (reach, facts time.Duration) {
	var t Tuning
	if m.Tune != nil {
		t = m.Tune()
	}
	reach, facts = m.ReachEvery, m.FactsEvery
	if t.LiveReach > 0 {
		reach = t.LiveReach
	}
	if t.LiveFacts > 0 {
		facts = t.LiveFacts
	}
	if m.watched(now) {
		return
	}
	ir, ifa := m.IdleReach, m.IdleFacts
	if t.Reach > 0 {
		ir = t.Reach
	}
	if t.Facts > 0 {
		ifa = t.Facts
	}
	if ir > reach { // never quicker than while someone is looking
		reach = ir
	}
	if ifa > facts {
		facts = ifa
	}
	return
}

// Snapshot is the health of every device checked so far, by name.
func (m *Monitor) Snapshot() map[string]Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Health, len(m.state))
	for k, v := range m.state {
		out[k] = v
	}
	return out
}

// Check looks at every device once: a reach check for each, and a facts request for those whose facts are due (or that
// were down and answer again).  Devices no longer in the list are forgotten.
func (m *Monitor) Check(ctx context.Context, devs []Device, creds []Credential, now time.Time) {
	cred := map[string]Credential{}
	for _, c := range creds {
		cred[c.Name] = c
	}
	m.mu.Lock()
	keep := map[string]bool{}
	for _, d := range devs {
		keep[d.Name] = true
	}
	for k := range m.state {
		if !keep[k] {
			delete(m.state, k)
		}
	}
	prev := make(map[string]Health, len(m.state))
	for k, v := range m.state {
		prev[k] = v
	}
	m.mu.Unlock()
	m.checkList(ctx, devs, cred, prev, now)
}

// checkList checks the devices in devs (all of them, or the few that changed) and stores each one's health.
func (m *Monitor) checkList(ctx context.Context, devs []Device, cred map[string]Credential, prev map[string]Health, now time.Time) {
	sem := make(chan struct{}, max(1, m.Parallel))
	var wg sync.WaitGroup
	for _, d := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			h := m.checkOne(ctx, d, cred[d.Credential], prev[d.Name], now)
			m.mu.Lock()
			m.state[d.Name] = h
			m.mu.Unlock()
		}()
	}
	wg.Wait()
}

func (m *Monitor) checkOne(ctx context.Context, d Device, c Credential, h Health, now time.Time) (out Health) {
	defer func() {
		if p := recover(); p != nil { // a driver bug costs that device's check, not the loop
			out = Health{Status: "warn", Detail: "the check failed inside the driver", Facts: h.Facts, LastOK: h.LastOK, Checked: now.Unix()}
		}
	}()
	if d.Disabled {
		return Health{Status: "paused", Detail: "disabled: never contacted", Facts: h.Facts, LastOK: h.LastOK}
	}
	h.Checked = now.Unix()
	rctx, cancel := context.WithTimeout(ctx, m.Timeout)
	conn, err := dialFn(rctx, hostPort(d, DefaultPort(d.Platform)))
	cancel()
	if err != nil {
		h.Status, h.Detail = "bad", "the API port does not answer: "+shortErr(err)
		return h
	}
	conn.Close()
	wasDown := h.Status != "ok" && h.Status != "warn"
	_, factsEvery := m.intervals(now)
	if wasDown || h.FactsAt == 0 || now.Sub(time.Unix(h.FactsAt, 0)) >= factsEvery {
		h.FactsAt = now.Unix()
		f, err := m.facts(ctx, d, c)
		if err != nil {
			h.FactsErr = scrub(err.Error(), c)
		} else {
			h.Facts, h.FactsErr, h.LastOK = &f, "", now.Unix()
		}
	}
	if h.FactsErr != "" {
		h.Status, h.Detail = "warn", "the API port answers, but the device refused or failed a request: "+h.FactsErr
		return h
	}
	h.Status, h.Detail = "ok", "answering"
	return h
}

func (m *Monitor) facts(ctx context.Context, d Device, c Credential) (Facts, error) {
	if c.Name == "" {
		return Facts{}, errors.New("its credential " + d.Credential + " is not in the list")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*m.Timeout)
	defer cancel()
	drv, err := Open(d, c)
	if err != nil {
		return Facts{}, err
	}
	defer drv.Close(context.WithoutCancel(ctx))
	return drv.Facts(ctx)
}

// changeEvery is how often Run looks at the inventory for a device that was added, enabled, disabled or edited, and checks
// that device at once (enabling a device would otherwise show "paused" until the next round, minutes away when nobody looks).
var changeEvery = 3 * time.Second

// fingerprint is what a check of the device depends on.
func fingerprint(d Device, creds []Credential) string {
	f := fmt.Sprint(d.Platform, "|", d.Address, "|", d.Port, "|", d.Credential, "|", d.Disabled, "|", d.Insecure, "|", d.Options)
	for _, c := range creds {
		if c.Name == d.Credential {
			f += fmt.Sprint("|", c.Username, "|", len(c.Password), "|", len(c.Token))
		}
	}
	return f
}

// Run checks the devices until ctx ends, as often as intervals says; list gives the inventory as it is at that moment.  Between
// rounds it looks at the inventory every changeEvery, and checks a device that changed at once.
func (m *Monitor) Run(ctx context.Context, list func() ([]Device, []Credential)) {
	seen := map[string]string{}
	remember := func(devs []Device, creds []Credential) {
		seen = make(map[string]string, len(devs))
		for _, d := range devs {
			seen[d.Name] = fingerprint(d, creds)
		}
	}
	for {
		wait := m.InactiveWait
		if wait <= 0 {
			wait = 15 * time.Second
		}
		active := m.Active == nil || m.Active()
		if active {
			devs, creds := list()
			m.Check(ctx, devs, creds, time.Now())
			remember(devs, creds)
			wait, _ = m.intervals(time.Now())
		}
		until := time.Now().Add(wait)
	sleep:
		for {
			step := time.Until(until)
			if active && step > changeEvery {
				step = changeEvery
			}
			if step <= 0 {
				break
			}
			t := time.NewTimer(step)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				if !active || !time.Now().Before(until) {
					break sleep
				}
				devs, creds := list()
				var changed []Device
				for _, d := range devs {
					if seen[d.Name] != fingerprint(d, creds) {
						changed = append(changed, d)
					}
				}
				if len(changed) > 0 {
					cred := map[string]Credential{}
					for _, c := range creds {
						cred[c.Name] = c
					}
					m.mu.Lock()
					prev := make(map[string]Health, len(m.state))
					for k, v := range m.state {
						prev[k] = v
					}
					m.mu.Unlock()
					m.checkList(ctx, changed, cred, prev, time.Now())
					remember(devs, creds)
				}
			case <-m.wake: // someone began to look after a quiet time
				t.Stop()
				break sleep
			}
		}
	}
}

// shortErr keeps the end of a dial error, which says what happened ("connection refused", "i/o timeout").
func shortErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "no answer in time"
	}
	return err.Error()
}
