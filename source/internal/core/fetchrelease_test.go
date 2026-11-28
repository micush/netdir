package core

import (
	"testing"
)

// The repository is part of the shared update settings: set on the primary, kept in the intent, used by the fetch.
func TestUpdateRepoSetting(t *testing.T) {
	u, err := NewUpdater(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if u.Repo() != GhRepo {
		t.Fatalf("default repo = %q", u.Repo())
	}
	u.SetRepo("someone/fork", "tester", "n1")
	if u.Repo() != "someone/fork" || u.Intent().Repo != "someone/fork" {
		t.Fatalf("repo not set: %q", u.Repo())
	}
	u.SetRepo("", "tester", "n1")
	if u.Repo() != GhRepo {
		t.Fatalf("empty must go back to the default: %q", u.Repo())
	}
}
