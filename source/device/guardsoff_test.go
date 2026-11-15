package device

import (
	"regexp"
	"strings"
	"testing"
)

func TestGuardsOffByDefaultPassThrough(t *testing.T) {
	SetGuards(false)
	defer SetGuards(true)
	// a CLI line the lists refuse is checked for form only
	lines, err := checkLines(Raw{Lines: []string{"username bob secret x", "no ip routing"}}, regexp.MustCompile(`^username |^no ip routing`))
	if err != nil || len(lines) != 2 {
		t.Fatalf("lines refused with guards off: %v %v", lines, err)
	}
	if err := pathOK("/rest/v1/x"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"//evil", "http://x/y", "/a b", "rest", "/a#b"} {
		if pathOK(bad) == nil {
			t.Errorf("path %q allowed", bad)
		}
	}
	if err := pveBodyCheck(Raw{Method: "POST", Body: `{"password":"x"}`}); err != nil {
		t.Errorf("pve body refused with guards off: %v", err)
	}
	if !strings.Contains("on", "o") || GuardsOn() {
		t.Fatal("guards should be off")
	}
}
