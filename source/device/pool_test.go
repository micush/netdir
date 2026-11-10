package device

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// poolFake is a driver that counts: how often one was opened (a login) and closed (a logout), and what each is asked.
type poolFake struct {
	Driver
	id     int32
	st     *poolFakeState
	forgot int
}

type poolFakeState struct {
	mu            sync.Mutex
	opens, closes atomic.Int32
	failNext      error // the next request of a driver that is not new fails with this
	inUse         map[int32]bool
	overlap       bool
}

func (f *poolFake) Close(context.Context) { f.st.closes.Add(1) }
func (f *poolFake) reuse()                { f.forgot++ }

// poolRig registers a platform of fakes and returns its device, its login and the state; the pool is empty before and after.
func poolRig(t *testing.T) (Device, []Credential, *poolFakeState) {
	t.Helper()
	st := &poolFakeState{inUse: map[int32]bool{}}
	plat := fmt.Sprintf("poolfake%d", time.Now().UnixNano())
	Register(plat, func(d Device, c Credential) (Driver, error) {
		if c.Password == "wrong" {
			return nil, errors.New("no login")
		}
		return &poolFake{id: st.opens.Add(1), st: st}, nil
	})
	PoolFlush()
	idleFor, maxAge, per, max, now, was := pool.IdleFor, pool.MaxAge, pool.PerDevice, pool.Max, pool.now, ReuseDrivers
	ReuseDrivers = true
	t.Cleanup(func() {
		PoolFlush()
		pool.mu.Lock()
		pool.IdleFor, pool.MaxAge, pool.PerDevice, pool.Max, pool.now = idleFor, maxAge, per, max, now
		pool.mu.Unlock()
		ReuseDrivers = was
	})
	return Device{Name: "d1", Platform: plat, Address: "192.0.2.1", Credential: "c"}, []Credential{{Name: "c", Username: "u", Password: "p"}}, st
}

// ask is one read: it returns the number of the driver that answered.
func poolAsk(d Device, creds []Credential, st *poolFakeState) Result {
	return FanoutReuse(context.Background(), []Device{d}, creds, 1, time.Second, func(ctx context.Context, drv Driver) (any, error) {
		f := drv.(*poolFake)
		st.mu.Lock()
		if st.inUse[f.id] {
			st.overlap = true
		}
		st.inUse[f.id] = true
		fail := st.failNext
		if fail != nil && f.forgot > 0 {
			st.failNext = nil
		} else {
			fail = nil
		}
		st.mu.Unlock()
		defer func() { st.mu.Lock(); delete(st.inUse, f.id); st.mu.Unlock() }()
		if fail != nil {
			return nil, fail
		}
		return f.id, nil
	})[0]
}

func TestPoolKeepsADriverBetweenReads(t *testing.T) {
	d, creds, st := poolRig(t)
	r1 := poolAsk(d, creds, st)
	r2 := poolAsk(d, creds, st)
	r3 := poolAsk(d, creds, st)
	if !r1.OK || r1.Reused || !r2.OK || !r2.Reused || !r3.Reused || r1.Data != r2.Data || r2.Data != r3.Data {
		t.Fatalf("three reads: %+v %+v %+v", r1, r2, r3)
	}
	if st.opens.Load() != 1 || st.closes.Load() != 0 || PoolIdle() != 1 {
		t.Errorf("one login for three reads and no logout yet: %d opened, %d closed, %d kept", st.opens.Load(), st.closes.Load(), PoolIdle())
	}
	// Fanout, which changes use, never takes a kept driver and never leaves one
	r := Fanout(context.Background(), []Device{d}, creds, 1, time.Second, func(ctx context.Context, drv Driver) (any, error) { return drv.(*poolFake).id, nil })[0]
	if !r.OK || r.Reused || r.Data == r1.Data || st.opens.Load() != 2 || st.closes.Load() != 1 || PoolIdle() != 1 {
		t.Errorf("a change has a driver of its own: %+v, %d opened, %d closed", r, st.opens.Load(), st.closes.Load())
	}
	// another login, or another address, is another driver
	other := []Credential{{Name: "c", Username: "u", Password: "p2"}}
	if r := poolAsk(d, other, st); r.Reused || st.opens.Load() != 3 {
		t.Errorf("a changed password took the kept driver: %+v", r)
	}
	d2 := d
	d2.Address = "192.0.2.2"
	if r := poolAsk(d2, creds, st); r.Reused || st.opens.Load() != 4 {
		t.Errorf("a changed address took the kept driver: %+v", r)
	}
	if n := PoolFlush(); n != 3 || st.closes.Load() != 4 || PoolIdle() != 0 {
		t.Errorf("flush: %d closed now, %d in all, %d kept", n, st.closes.Load(), PoolIdle())
	}
	if r := poolAsk(d, []Credential{{Name: "c", Password: "wrong"}}, st); r.OK || r.Error != "no login" || PoolIdle() != 0 {
		t.Errorf("a driver that cannot be opened: %+v", r)
	}
}

func TestPoolIdleAndAge(t *testing.T) {
	d, creds, st := poolRig(t)
	var clk sync.Mutex
	now := time.Now()
	pool.mu.Lock()
	pool.now = func() time.Time { clk.Lock(); defer clk.Unlock(); return now }
	pool.mu.Unlock()
	step := func(d time.Duration) { clk.Lock(); now = now.Add(d); clk.Unlock() }
	poolAsk(d, creds, st)
	step(pool.IdleFor - time.Second)
	if r := poolAsk(d, creds, st); !r.Reused {
		t.Fatal("not kept for the idle time")
	}
	step(pool.IdleFor + time.Second)
	if r := poolAsk(d, creds, st); r.Reused || st.opens.Load() != 2 {
		t.Fatalf("kept beyond the idle time: %+v", r)
	}
	// used again and again it is still closed when it is too old
	for i := 0; i < 20 && st.opens.Load() == 2; i++ {
		step(pool.IdleFor / 2)
		poolAsk(d, creds, st)
	}
	if st.opens.Load() != 3 {
		t.Errorf("a driver in steady use was never replaced: %d opened", st.opens.Load())
	}
	deadline := time.Now().Add(2 * time.Second)
	for st.closes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st.closes.Load() != 2 {
		t.Errorf("the drivers that were too old were not closed: %d", st.closes.Load())
	}
}

func TestPoolAsksAgainWhenTheSessionHasGone(t *testing.T) {
	d, creds, st := poolRig(t)
	poolAsk(d, creds, st)
	// the device has ended the session: the read is made once more with a new driver, and the caller sees no error
	st.failNext = &statusError{Code: 401, Body: "session expired"}
	r := poolAsk(d, creds, st)
	if !r.OK || r.Reused || r.Data != int32(2) || st.opens.Load() != 2 || st.closes.Load() != 1 {
		t.Fatalf("after a 401 on a kept driver: %+v, %d opened, %d closed", r, st.opens.Load(), st.closes.Load())
	}
	// an answer about the request itself is the answer: nothing is asked twice, and the driver is not kept
	st.failNext = &statusError{Code: 404, Body: "no such thing"}
	r = poolAsk(d, creds, st)
	if r.OK || st.opens.Load() != 2 || st.closes.Load() != 2 || PoolIdle() != 0 {
		t.Fatalf("after a 404: %+v, %d opened, %d closed, %d kept", r, st.opens.Load(), st.closes.Load(), PoolIdle())
	}
	for err, again := range map[error]bool{
		&statusError{Code: 403}: true, errors.New("unexpected EOF"): true, errors.New("read: connection reset by peer"): true,
		&statusError{Code: 500}: false, &statusError{Code: 400}: false, context.DeadlineExceeded: false, errors.New("path: no such table"): false,
	} {
		if sessionGone(err) != again {
			t.Errorf("sessionGone(%v) = %v", err, !again)
		}
	}
}

func TestPoolOneRequestPerDriver(t *testing.T) {
	d, creds, st := poolRig(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := poolAsk(d, creds, st); !r.OK {
				t.Errorf("%+v", r)
			}
		}()
	}
	wg.Wait()
	if st.overlap {
		t.Error("two requests used one driver at the same time")
	}
	if PoolIdle() > pool.PerDevice {
		t.Errorf("%d drivers kept for one device (at most %d)", PoolIdle(), pool.PerDevice)
	}
	if got := st.opens.Load() - st.closes.Load(); int(got) != PoolIdle() {
		t.Errorf("%d drivers open and %d kept: one was lost", got, PoolIdle())
	}
	// a driver that panics is closed, and the answer says so
	r := FanoutReuse(context.Background(), []Device{d}, creds, 1, time.Second, func(context.Context, Driver) (any, error) { panic("boom") })[0]
	if r.OK || r.Error != "driver failure: boom" {
		t.Errorf("a panic: %+v", r)
	}
	// switched off, every read has a driver of its own
	PoolFlush()
	ReuseDrivers = false
	poolAsk(d, creds, st)
	if r := poolAsk(d, creds, st); r.Reused || PoolIdle() != 0 {
		t.Errorf("switched off: %+v, %d kept", r, PoolIdle())
	}
}
