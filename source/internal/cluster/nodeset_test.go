package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"netdir/internal/core"
)

// The list is shared, sorted, de-duplicated, checked, and absent from the file (and the hash) when empty.
func TestExcludedNodesAreSharedAndTidy(t *testing.T) {
	dc := core.NewDaemonConfig()
	b0, _ := json.Marshal(dc.Groups[0])
	if strings.Contains(string(b0), "excluded_nodes") {
		t.Fatalf("an empty list is written: %s", b0)
	}
	h0 := core.SharedOf(dc).Hash()
	dc.Groups[0].ExcludedNodes = []string{"bb", "aa", "bb"}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dc.Groups[0].ExcludedNodes, ","); got != "aa,bb" {
		t.Fatalf("the list is %q, want sorted and without duplicates", got)
	}
	if core.SharedOf(dc).Hash() == h0 {
		t.Fatal("removing a node does not change what the cluster shares")
	}
	other := core.NewDaemonConfig()
	changed, err := MergeShared(other, core.SharedOf(dc), nil)
	if err != nil || !changed || strings.Join(other.Groups[0].ExcludedNodes, ",") != "aa,bb" {
		t.Fatalf("a replica did not take the list: %v %v %v", changed, err, other.Groups[0].ExcludedNodes)
	}
	// bringing everyone back empties it and the key goes away
	dc.Groups[0].ExcludedNodes = nil
	if core.SharedOf(dc).Hash() != h0 {
		t.Fatal("an empty list changes the hash")
	}
	for _, bad := range []string{"", "not hex!", strings.Repeat("a", 65)} {
		dc.Groups[0].ExcludedNodes = []string{bad}
		if err := dc.Validate(); err == nil {
			t.Errorf("node ID %q accepted", bad)
		}
	}
}
