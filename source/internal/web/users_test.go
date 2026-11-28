package web

import (
	"strings"
	"testing"
)

func TestValidUserName(t *testing.T) {
	for _, n := range []string{"alice", "_svc", "a-b_c9", strings.Repeat("a", 32)} {
		if !ValidUserName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "Alice", "-a", "9a", "a:b", "a b", "a;b", "a/b", "a\nb", "root:x", strings.Repeat("a", 33), "é"} {
		if ValidUserName(n) {
			t.Errorf("%q should be refused", n)
		}
	}
}
