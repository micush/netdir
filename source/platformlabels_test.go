package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"netdir/device"
)

// Every platform a driver registers has a name in the GUI's list (PLATFORM_LABEL in app.js), and the list names none that is not there.
func TestGUIPlatformLabelsMatchTheDrivers(t *testing.T) {
	b, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "const PLATFORM_LABEL = {")
	if i < 0 {
		t.Fatal("PLATFORM_LABEL not found")
	}
	blk := s[i : i+strings.Index(s[i:], "};")]
	got := map[string]bool{}
	for _, m := range regexp.MustCompile(`(\w+): "[^"]+"`).FindAllStringSubmatch(blk, -1) {
		got[m[1]] = true
	}
	for _, p := range device.Platforms() {
		if !got[p] {
			t.Errorf("platform %s has no name in PLATFORM_LABEL", p)
		}
		delete(got, p)
	}
	for p := range got {
		t.Errorf("PLATFORM_LABEL names %s, which no driver registers", p)
	}
}
