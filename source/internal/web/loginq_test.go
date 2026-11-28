package web

import (
	"reflect"
	"testing"
)

func TestSplitGroups(t *testing.T) {
	for in, want := range map[string][]string{
		"a":            {"a"},
		"a,b":          {"a", "b"},
		" a , b ,a,,c": {"a", "b", "c"},
		"a b":          {"a", "b"},
		"":             nil,
	} {
		if got := SplitGroups(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitGroups(%q) = %q, want %q", in, got, want)
		}
	}
}
