package core

import (
	"strings"
	"testing"
)

func TestGatewayNameValidation(t *testing.T) {
	g := DefaultGroup()
	for _, ok := range []string{"", "Office DNS", strings.Repeat("é", maxGatewayName)} {
		g.Name = ok
		if err := g.Validate(); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{strings.Repeat("x", maxGatewayName+1), "a\nb", "tab\there"} {
		g.Name = bad
		if g.Validate() == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
