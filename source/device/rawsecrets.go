package device

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
)

// A caller whose privacy level is "none" is given what a device answers as the device says it: configurations, show output and API
// answers keep the secrets the filters (Redact, RedactText, RedactConfig, dnsHide) would take out.  (netdir's own logins and keys are
// not part of what a device answers and stay hidden: see leak capture in Open and mcpRedact.)
//
// The drivers filter inside their own methods, so the mark travels with the goroutine that runs the request instead of through every
// call: RunRaw marks the running goroutine, Unfiltered asks.  A goroutine a driver starts itself is not marked, so what it reads stays
// filtered: the failure is on the safe side.

var (
	rawActive atomic.Int32
	rawG      sync.Map // goroutine id -> true
)

func goid() uint64 {
	var buf [32]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	if i := bytes.IndexByte(b, ' '); i > 0 {
		b = b[:i]
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// RunRaw runs f; while it runs, filters called from this goroutine leave what a device said as it is, when on.
func RunRaw(on bool, f func()) {
	if !on {
		f()
		return
	}
	id := goid()
	rawActive.Add(1)
	rawG.Store(id, true)
	defer func() { rawG.Delete(id); rawActive.Add(-1) }()
	f()
}

// Unfiltered says whether the calling goroutine runs under RunRaw(true, ...).
func Unfiltered() bool {
	if rawActive.Load() == 0 {
		return false
	}
	_, ok := rawG.Load(goid())
	return ok
}
