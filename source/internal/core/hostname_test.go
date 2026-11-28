package core

import (
	"strings"
	"testing"
)

func TestValidNodeName(t *testing.T) {
	for _, ok := range []string{"ntp01", "NTP-02", "a", "ntp.example.com", "a-b.c-d"} {
		if _, err := ValidNodeName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " ", "-a", "a-", "a_b", "a b", "a;rm -rf /", "$(x)", "a..b", "a.b.c.d.e", strings.Repeat("a", 64), "ünï", "a\nb", "../x"} {
		if _, err := ValidNodeName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n, _ := ValidNodeName("  NTP01 "); n != "ntp01" {
		t.Errorf("not trimmed and lower-cased: %q", n)
	}
}

func TestRewriteHosts(t *testing.T) {
	in := "127.0.0.1\tlocalhost\n127.0.1.1\told.example.com old\n10.0.0.5 other old # keep this\n::1 ip6-localhost\n# old stays in comments\n"
	got := RewriteHosts(in, "old.example.com", "new.example.com")
	want := "127.0.0.1\tlocalhost\n127.0.1.1\tnew.example.com\tnew\n10.0.0.5\tother\tnew # keep this\n::1 ip6-localhost\n# old stays in comments\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// no line names the old host: a 127.0.1.1 line is added
	got = RewriteHosts("127.0.0.1 localhost\n", "old", "new")
	if got != "127.0.0.1 localhost\n127.0.1.1\tnew\n" {
		t.Fatalf("added line: %q", got)
	}
	// a file with no final newline, and an empty one
	if got := RewriteHosts("127.0.0.1 localhost", "old", "new"); got != "127.0.0.1 localhost\n127.0.1.1\tnew\n" {
		t.Fatalf("no final newline: %q", got)
	}
	if got := RewriteHosts("", "old", "a.b"); got != "127.0.1.1\ta.b\ta\n" {
		t.Fatalf("empty file: %q", got)
	}
}
