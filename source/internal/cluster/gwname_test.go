package cluster

import (
	"strings"
	"testing"

	"netdir/internal/core"
)

// A name is shared across the cluster; an unnamed cluster hashes exactly as before.
func TestGatewayNameIsSharedAndHashStable(t *testing.T) {
	a := core.NewDaemonConfig()
	before := core.SharedOf(a).Hash()
	if strings.Contains(string(mustJSON(t, core.SharedOf(a))), `"name"`) {
		t.Fatal("empty name must be omitted from the shared document")
	}
	a.Groups[0].Name = "Office DNS"
	if core.SharedOf(a).Hash() == before {
		t.Fatal("renaming did not change the shared hash")
	}
	b := core.NewDaemonConfig()
	if _, err := MergeShared(b, core.SharedOf(a), SeedsOf(b)); err != nil {
		t.Fatal(err)
	}
	if b.Groups[0].Name != "Office DNS" {
		t.Fatalf("replica did not get the name: %q", b.Groups[0].Name)
	}
}
