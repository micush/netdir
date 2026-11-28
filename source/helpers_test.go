package main

import (
	"bytes"
	"sync"

	"netdir/internal/core"
)

// pauseTestConfig is a one-gateway configuration, for the pause tests.
func pauseTestConfig() *core.DaemonConfig {
	dc := core.NewDaemonConfig()
	dc.Groups = []core.GroupConfig{core.DefaultGroup()}
	if err := dc.Validate(); err != nil {
		panic(err)
	}
	return dc
}

// lockedBuf is a log sink several goroutines may write to.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
func (l *lockedBuf) Reset()         { l.mu.Lock(); defer l.mu.Unlock(); l.b.Reset() }
