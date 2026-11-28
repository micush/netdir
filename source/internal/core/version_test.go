package core

import (
	"regexp"
	"testing"
)

func TestVersionIsPlainInteger(t *testing.T) {
	if !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(Version()) {
		t.Fatalf("VERSION must be a plain positive integer, got %q", Version())
	}
}
