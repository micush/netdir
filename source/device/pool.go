package device

// Drivers kept open between requests.
//
// A request to a device used to cost a TLS handshake and, on most platforms, a login, before the question was asked, and a
// logout after it.  FanoutReuse keeps the driver a read used (its connections and its login) for the next read of the same
// device: for a couple of minutes of idleness, and never longer than ten minutes in all.  What the device answers is asked
// anew every time; only the way in is kept.
//
//   - One request at a time uses a driver.  Two reads of one device at once use two drivers (two logins), as before.
//   - A driver that failed in any way is closed, not kept.
//   - A kept driver whose session the device has ended, or whose connection has gone, fails the first request it is used
//     for: that request is then made once more with a new driver.  Only reads come this way (Fanout, which changes and
//     captures use, always opens a new driver), so asking twice does no harm.
//   - The key of a kept driver is everything it was opened with, the login included: a changed address, option, password
//     or token opens a new one, and PoolFlush (called when the configuration is loaded) closes those that are idle.
//   - NETDIR_DEVICE_REUSE=0 in the daemon's environment switches it off: FanoutReuse is then Fanout.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// reuser is a driver that remembers something the device said for the length of one request (PAN-OS: its system info):
// reuse forgets it, before the driver is used for another request.
type reuser interface{ reuse() }

type pooledDriver struct {
	drv  Driver
	born time.Time
	idle time.Time // when it was put back
}

type driverPool struct {
	mu        sync.Mutex
	idle      map[string][]*pooledDriver
	sweeping  bool
	IdleFor   time.Duration // an unused driver is closed after this
	MaxAge    time.Duration // and any driver this long after it was opened
	PerDevice int           // idle drivers kept for one device
	Max       int           // idle drivers kept in all
	now       func() time.Time
}

var pool = &driverPool{idle: map[string][]*pooledDriver{}, IdleFor: 2 * time.Minute, MaxAge: 10 * time.Minute, PerDevice: 2, Max: 512, now: time.Now}

// ReuseDrivers says whether drivers are kept between reads (NETDIR_DEVICE_REUSE=0 switches it off).
var ReuseDrivers = os.Getenv("NETDIR_DEVICE_REUSE") != "0"

func poolKey(d Device, c Credential) string {
	b, _ := json.Marshal(struct {
		D Device
		C Credential
	}{d, c})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func closeDriver(drv Driver) {
	defer func() { _ = recover() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	drv.Close(ctx)
}

func (p *driverPool) expired(x *pooledDriver, now time.Time) bool {
	return now.Sub(x.idle) > p.IdleFor || now.Sub(x.born) > p.MaxAge
}

// get takes the driver put back last, if one is still good.
func (p *driverPool) get(key string) *pooledDriver {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	l := p.idle[key]
	for len(l) > 0 {
		x := l[len(l)-1]
		l = l[:len(l)-1]
		if p.expired(x, now) {
			go closeDriver(x.drv)
			continue
		}
		p.setLocked(key, l)
		return x
	}
	p.setLocked(key, l)
	return nil
}

func (p *driverPool) setLocked(key string, l []*pooledDriver) {
	if len(l) == 0 {
		delete(p.idle, key)
	} else {
		p.idle[key] = l
	}
}

func (p *driverPool) countLocked() int {
	n := 0
	for _, l := range p.idle {
		n += len(l)
	}
	return n
}

// put keeps a driver for the next request, or closes it when there is no room or it is too old.
func (p *driverPool) put(key string, x *pooledDriver) {
	p.mu.Lock()
	now := p.now()
	x.idle = now
	if now.Sub(x.born) > p.MaxAge || len(p.idle[key]) >= p.PerDevice || p.countLocked() >= p.Max {
		p.mu.Unlock()
		closeDriver(x.drv)
		return
	}
	p.idle[key] = append(p.idle[key], x)
	if !p.sweeping {
		p.sweeping = true
		go p.sweep()
	}
	p.mu.Unlock()
}

// sweep closes the drivers nobody came back for, and ends when none is left (put starts it again).
func (p *driverPool) sweep() {
	for {
		time.Sleep(20 * time.Second)
		var gone []*pooledDriver
		p.mu.Lock()
		now := p.now()
		for k, l := range p.idle {
			keep := l[:0]
			for _, x := range l {
				if p.expired(x, now) {
					gone = append(gone, x)
				} else {
					keep = append(keep, x)
				}
			}
			p.setLocked(k, keep)
		}
		done := len(p.idle) == 0
		if done {
			p.sweeping = false
		}
		p.mu.Unlock()
		for _, x := range gone {
			closeDriver(x.drv)
		}
		if done {
			return
		}
	}
}

// PoolFlush closes every idle driver (their sessions are logged out): when the configuration has changed, and when the
// daemon stops.  It returns how many there were.
func PoolFlush() int {
	pool.mu.Lock()
	var all []*pooledDriver
	for _, l := range pool.idle {
		all = append(all, l...)
	}
	pool.idle = map[string][]*pooledDriver{}
	pool.mu.Unlock()
	var wg sync.WaitGroup
	for _, x := range all {
		wg.Add(1)
		go func() { defer wg.Done(); closeDriver(x.drv) }()
	}
	wg.Wait()
	return len(all)
}

// PoolIdle is how many drivers are kept at this moment.
func PoolIdle() int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.countLocked()
}

// sessionGone says whether an error of a kept driver means that what was kept is no longer good, so that the request is
// worth making again with a new driver: the device no longer knows the session (401, 403), or the connection that was
// kept has gone.  An answer of the device about the request itself (404, 400, 500) is not.
func sessionGone(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.Code == 401 || se.Code == 403
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var ue *url.Error
	var ne net.Error
	if errors.As(err, &ue) || errors.As(err, &ne) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// a driver may have made the error a text of its own
	m := err.Error()
	for _, w := range []string{"HTTP 401", "HTTP 403", "EOF", "connection reset", "broken pipe", "closed network connection", "server closed idle connection", "session", "not logged in", "unauthorized", "Unauthorized"} {
		if strings.Contains(m, w) {
			return true
		}
	}
	return false
}

// FanoutReuse is Fanout for reads: the driver of a device is taken from those kept open, if there is one, and kept open
// afterwards.  Result.Reused says that the answer came over a kept driver.
func FanoutReuse(ctx context.Context, devs []Device, creds []Credential, par int, each time.Duration, fn func(context.Context, Driver) (any, error)) []Result {
	if !ReuseDrivers {
		return Fanout(ctx, devs, creds, par, each, fn)
	}
	return fanout(ctx, devs, creds, par, each, fn, oneReuse)
}

func oneReuse(ctx context.Context, d Device, cred map[string]Credential, each time.Duration, fn func(context.Context, Driver) (any, error)) (r Result) {
	start := time.Now()
	r = Result{Device: d.Name, Platform: d.Platform}
	var cur *pooledDriver // the driver in use, which a failure of the driver must not leave in the pool
	defer func() {
		if p := recover(); p != nil { // a driver bug costs that device's answer, not the gateway
			r.OK, r.Data, r.Reused, r.Error = false, nil, false, fmt.Sprintf("driver failure: %v", p)
			if cur != nil {
				go closeDriver(cur.drv)
			}
		}
		r.MS = time.Since(start).Milliseconds()
	}()
	c, ok := cred[d.Credential]
	if d.Platform == "tools" {
		ok = true // no login
	}
	if !ok {
		r.Error = fmt.Sprintf("credential %q is not in the credentials list", d.Credential)
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, each)
	defer cancel()
	key := poolKey(d, c)
	open := func() error {
		drv, err := Open(d, c)
		if err != nil {
			return err
		}
		cur = &pooledDriver{drv: drv, born: pool.now()}
		return nil
	}
	reused := false
	if cur = pool.get(key); cur != nil {
		reused = true
		if ru, ok := cur.drv.(reuser); ok {
			ru.reuse()
		}
	} else if err := open(); err != nil {
		r.Error = err.Error()
		return r
	}
	v, err := fn(ctx, cur.drv)
	if err != nil && reused && ctx.Err() == nil && sessionGone(err) {
		// what was kept is no longer good: once more, the way a request was always made
		closeDriver(cur.drv)
		cur, reused = nil, false
		if err = open(); err != nil {
			r.Error = err.Error()
			return r
		}
		v, err = fn(ctx, cur.drv)
	}
	if err != nil {
		x := cur
		cur = nil
		closeDriver(x.drv)
		r.Error = scrub(err.Error(), c)
		return r
	}
	x := cur
	cur = nil
	pool.put(key, x)
	r.OK, r.Data, r.Reused = true, v, reused
	return r
}
