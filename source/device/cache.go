package device

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"time"
)

// A small cache with a lifetime for each entry, for answers that are slow to get and change slowly: the list of Meraki networks, where a
// machine was last seen, who a directory says a name is.  The keys start with a hash of the device's identity and login, so two
// devices never share an entry.  NETDIR_DEVICE_CACHE=0 switches it off (it also switches off the answer cache of the gateway).
var CacheOn = os.Getenv("NETDIR_DEVICE_CACHE") != "0"

type cacheEntry struct {
	v    any
	at   time.Time
	life time.Duration
}

type ttlCache struct {
	mu  sync.Mutex
	m   map[string]cacheEntry
	max int
	now func() time.Time
}

var lookups = &ttlCache{m: map[string]cacheEntry{}, max: 2000, now: time.Now}

// Get returns the entry and how old it is.
func (c *ttlCache) Get(key string) (any, time.Duration, bool) {
	if !CacheOn {
		return nil, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, 0, false
	}
	age := c.now().Sub(e.at)
	if age > e.life {
		delete(c.m, key)
		return nil, 0, false
	}
	return e.v, age, true
}

func (c *ttlCache) Put(key string, v any, life time.Duration) {
	if !CacheOn || life <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max { // full: drop what has expired, and if that is not enough, everything
		for k, e := range c.m {
			if now.Sub(e.at) > e.life {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.max {
			c.m = map[string]cacheEntry{}
		}
	}
	c.m[key] = cacheEntry{v: v, at: now, life: life}
}

func (c *ttlCache) Drop(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if strings.HasPrefix(k, prefix) {
			delete(c.m, k)
		}
	}
}

// CacheFlush forgets everything (a new configuration may hold other logins).
func CacheFlush() {
	lookups.mu.Lock()
	lookups.m = map[string]cacheEntry{}
	lookups.mu.Unlock()
}

func idKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// AnswerCache keeps what a device answered to a read for a short while, for callers that ask the same thing twice (see
// Supervisor handleDeviceQuery).  Only what the caller marks as safe is put in; the age comes back with the hit.
type AnswerCache struct{ c *ttlCache }

var Answers = &AnswerCache{c: &ttlCache{m: map[string]cacheEntry{}, max: 500, now: time.Now}}

// Key is the identity of one question to one device.
func AnswerKey(d Device, c Credential, mode, op, arg string) string {
	return poolKey(d, c) + "|" + mode + "|" + op + "|" + arg
}

func (a *AnswerCache) Get(key string) (Result, time.Duration, bool) {
	v, age, ok := a.c.Get(key)
	if !ok {
		return Result{}, 0, false
	}
	return v.(Result), age, true
}

func (a *AnswerCache) Put(key string, r Result, life time.Duration) {
	if r.OK {
		a.c.Put(key, r, life)
	}
}

func (a *AnswerCache) Flush() {
	a.c.mu.Lock()
	a.c.m = map[string]cacheEntry{}
	a.c.mu.Unlock()
}

// copyAny copies maps and lists (the shapes the drivers answer with) so a caller that changes an answer cannot change the cache's.
func copyAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = copyAny(e)
		}
		return m
	case []map[string]any:
		if x == nil {
			return x
		}
		l := make([]map[string]any, len(x))
		for i, e := range x {
			l[i] = copyAny(e).(map[string]any)
		}
		return l
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = copyAny(e)
		}
		return l
	case []string:
		return append([]string(nil), x...)
	}
	return v
}
