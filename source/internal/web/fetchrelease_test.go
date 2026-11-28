package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"netdir/internal/core"
)

func TestNumericTagLess(t *testing.T) {
	if !numericTagLess("v215", "v1000") || numericTagLess("v1000", "v215") || !numericTagLess("1.2", "1.10") || numericTagLess("v5", "v5") {
		t.Fatal("tags are not ordered by number")
	}
}

// fakeGitHub serves the two places fetchRelease asks: the API (release/tag lists) and the archive.
func fakeGitHub(t *testing.T, release string, tags string, archives map[string][]byte) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch {
		case r.URL.Path == "/repos/micush/netdir/releases/latest":
			if release == "" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`{"tag_name":"` + release + `"}`))
		case r.URL.Path == "/repos/micush/netdir/tags":
			w.Write([]byte(tags))
		case strings.HasPrefix(r.URL.Path, "/micush/netdir/archive/refs/tags/"):
			tag := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/micush/netdir/archive/refs/tags/"), ".tar.gz")
			if b, ok := archives[tag]; ok {
				w.Write(b)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	oa, oh := GhAPI, GhHost
	GhAPI, GhHost = srv.URL, srv.URL
	t.Cleanup(func() { srv.Close(); GhAPI, GhHost = oa, oh })
	return &n
}

func TestLatestTag(t *testing.T) {
	fakeGitHub(t, "v300", `[]`, nil)
	if tag, err := LatestTag(context.Background(), core.GhRepo); err != nil || tag != "v300" {
		t.Fatalf("release: %q %v", tag, err)
	}
	fakeGitHub(t, "", `[{"name":"v99"},{"name":"v1000"},{"name":"nightly"},{"name":"v215"}]`, nil)
	if tag, err := LatestTag(context.Background(), core.GhRepo); err != nil || tag != "v1000" {
		t.Fatalf("tags: %q %v", tag, err)
	}
	fakeGitHub(t, "", `[{"name":"nightly"}]`, nil)
	if _, err := LatestTag(context.Background(), core.GhRepo); err == nil {
		t.Fatal("no usable tag was accepted")
	}
}

func TestNormalizeRepo(t *testing.T) {
	good := map[string]string{
		"":                                       "",
		"default":                                "",
		"https://github.com/micush/netdir":       "", // the default is stored as empty
		"https://github.com/micush/netdir/":      "",
		"github.com/micush/netdir.git":           "",
		"micush/netdir":                          "",
		"https://github.com/someone/netdir-fork": "someone/netdir-fork",
		"  https://www.github.com/a.b/c_d.git ":  "a.b/c_d",
		"someone/fork":                           "someone/fork",
	}
	for in, want := range good {
		got, err := NormalizeRepo(in)
		if err != nil || got != want {
			t.Errorf("normalizeRepo(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"https://gitlab.com/a/b", "https://example.com/a/b", "a", "a/b/c", "https://github.com/a", "https://github.com/a/b/c",
		"https://github.com/../b", "a/..", "a b/c", "https://github.com/a/b?x=1", "-a/b", "git@github.com:a/b",
	} {
		if got, err := NormalizeRepo(in); err == nil {
			t.Errorf("normalizeRepo(%q) = %q, want an error", in, got)
		}
	}
}
