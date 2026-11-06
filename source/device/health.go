package device

import (
	"context"
	"errors"
	"net"
	"sync"
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

	ReachEvery time.Duration // how often the API port is tried (default 30 s)
	FactsEvery time.Duration // how often the facts are asked (default 5 min); also at once when a device comes back
	Timeout    time.Duration // the time a reach check may take (default 4 s); a facts request gets 5 times that
	Parallel   int           // devices checked at once (default 16)
}

func NewMonitor() *Monitor {
	return &Monitor{state: map[string]Health{}, ReachEvery: 30 * time.Second, FactsEvery: 5 * time.Minute, Timeout: 4 * time.Second, Parallel: 16}
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
	conn, err := dialFn(rctx, hostPort(d, 443))
	cancel()
	if err != nil {
		h.Status, h.Detail = "bad", "the API port does not answer: "+shortErr(err)
		return h
	}
	conn.Close()
	wasDown := h.Status != "ok" && h.Status != "warn"
	if wasDown || h.FactsAt == 0 || now.Sub(time.Unix(h.FactsAt, 0)) >= m.FactsEvery {
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

// Run checks the devices every ReachEvery until ctx ends; list gives the inventory as it is at that moment.
func (m *Monitor) Run(ctx context.Context, list func() ([]Device, []Credential)) {
	t := time.NewTicker(m.ReachEvery)
	defer t.Stop()
	for {
		devs, creds := list()
		m.Check(ctx, devs, creds, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
