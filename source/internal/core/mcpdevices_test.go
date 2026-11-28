package core

import (
	"strings"
	"testing"
)

func TestNormDevices(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"all":                    "",
		"sw1,sw2":                "sw1,sw2",
		"SW1, sw1 ,tag:site=dc1": "SW1,tag:site=dc1",
		"sw1,none":               "none",
		"sw1,all":                "",
		"none":                   "none",
	} {
		got, err := NormDevices(strings.Split(in, ","))
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%q: %v %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"sw 1", "tag:", "a/b", "tag:a b", `x"y`} {
		if _, err := NormDevices([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestMCPACLDevices(t *testing.T) {
	got, err := NormMCPACL([]string{"10.1.1.50 rw strict devices=sw1,tag:site=dc1", "10.1.0.0/24", "10.2.0.0/24 devices=none", "10.3.0.1 devices=a", "10.3.0.1 devices=b", "10.4.0.1 rw devices=x disabled"})
	if err != nil {
		t.Fatal(err)
	}
	want := "10.1.1.50 rw strict devices=sw1,tag:site=dc1|10.1.0.0/24|10.2.0.0/24 devices=none|10.3.0.1 devices=a,b|10.4.0.1 rw devices=x disabled"
	if strings.Join(got, "|") != want {
		t.Fatalf("%q\nwant %q", strings.Join(got, "|"), want)
	}
	for _, bad := range []string{"10.1.1.50 devices=a b!", "10.1.1.50 devices=tag:", "10.1.1.50 rw strict devices=a extra"} {
		if _, err := NormMCPACL([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
