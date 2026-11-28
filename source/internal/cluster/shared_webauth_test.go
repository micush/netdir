package cluster

import (
	"testing"

	"netdir/internal/core"
)

func TestWebAuthIsShared(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups = nil
	plain := core.SharedOf(dc)
	if plain.WebAuth != nil {
		t.Fatalf("the defaults stay out of the document (hash unchanged for a rolling update): %+v", plain.WebAuth)
	}
	h0 := plain.Hash()
	dc.Web.LockoutMinutes = 30
	dc.Web.MinPasswordLength = 14
	sh := core.SharedOf(dc)
	if sh.WebAuth == nil || sh.WebAuth.LockoutMinutes != 30 || sh.WebAuth.MinPasswordLength != 14 || sh.Hash() == h0 {
		t.Fatalf("changed rules are shared: %+v", sh.WebAuth)
	}
	if err := sh.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rep := core.NewDaemonConfig()
	rep.Groups = nil
	changed, err := MergeShared(rep, sh, nil)
	if err != nil || !changed || rep.Web.LockoutMinutes != 30 || rep.Web.MinPasswordLength != 14 || rep.Web.MaxFailedLogins != 3 {
		t.Fatalf("merge: %v %v %+v", changed, err, rep.Web)
	}
	if changed, _ = MergeShared(rep, sh, nil); changed {
		t.Fatal("merging the same document again changes nothing")
	}
	if _, err := MergeShared(rep, plain, nil); err != nil || rep.Web.LockoutMinutes != 30 {
		t.Fatalf("no value from the primary keeps the node's own: %v %+v", err, rep.Web)
	}
	// 0 and the default length are the same rule
	dc2 := core.NewDaemonConfig()
	dc2.Groups = nil
	dc2.Web.MinPasswordLength = core.DefaultMinPassword
	if core.SharedOf(dc2).WebAuth != nil {
		t.Fatal("the default length, written out, is still the default")
	}
}
