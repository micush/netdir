package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pauseTestConfig is a one-gateway configuration, for the pause tests.
func pauseTestConfig() *DaemonConfig {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{defaultGroup()}
	if err := dc.Validate(); err != nil {
		panic(err)
	}
	return dc
}

func fmtN(i int) string { return strconv.Itoa(i) }

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
