package main

import (
	"encoding/json"
	"testing"
	"time"
)

func jsonMarshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

// A stopping controller tells the group and goes quiet; waitUntilSafe holds a
// finished update back until it is safe to go down.
func TestWaitUntilSafe(t *testing.T) {
	n := 0
	var reasons []string
	waitUntilSafe(func() (bool, string) {
		n++
		return n >= 3, "the other member is still recovering"
	}, false, time.Millisecond, func(s string) { reasons = append(reasons, s) })
	if n != 3 {
		t.Fatalf("asked %d times", n)
	}
	if len(reasons) != 3 || reasons[0] == "" || reasons[1] == "" || reasons[2] != "" {
		t.Fatalf("waiting reasons: %q", reasons)
	}
	called := false
	waitUntilSafe(func() (bool, string) { called = true; return false, "x" }, true, time.Millisecond, func(string) {})
	if called {
		t.Fatal("force must not wait")
	}
}
