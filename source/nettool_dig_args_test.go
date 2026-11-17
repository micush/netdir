package main

import (
	"strings"
	"testing"
)

// Some dig builds answer "Invalid option: --", so the name goes on the command line bare.
func TestDigArgsHaveNoDoubleDash(t *testing.T) {
	args, name, qtype, err := digArgs("Example.COM.", "mx", "10.250.250.250")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args, " "); got != "+time=3 +tries=1 @10.250.250.250 Example.COM MX" || name != "Example.COM" || qtype != "MX" {
		t.Fatalf("args %q name %q type %q", got, name, qtype)
	}
	args, _, qtype, err = digArgs("192.0.2.7", "", "")
	if err != nil || strings.Join(args, " ") != "+time=3 +tries=1 -x 192.0.2.7" || qtype != "PTR" {
		t.Fatalf("reverse: %v %v %q", args, err, qtype)
	}
	for _, bad := range []string{"-x", "-f/etc/passwd", "a.-b", "+short", "a b", ""} { // nothing that looks like an option gets through
		if _, _, _, err := digArgs(bad, "A", ""); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
