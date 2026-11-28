package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A read-only caller may start the look jobs, here or through /api/proxy on another node, and nothing else.
func TestReadOnlyJob(t *testing.T) {
	req := func(method, target string) *http.Request { return httptest.NewRequest(method, target, nil) }
	for target, want := range map[string]bool{
		"/api/nettool": true, "/api/scan": true,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fnettool": true,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fscan":    true,
		"/api/wake": false, "/api/proxy?node=10.0.0.2&path=%2Fapi%2Fwake": false,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fconfig":                false,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fdevices%2Fchange":      false,
		"/api/proxy?node=10.0.0.2&path=%2Fapi%2Fnettool%2F..%2Fconfig": false,
		"/api/devices/change": false,
	} {
		if got := readOnlyJob(req("POST", target)); got != want {
			t.Errorf("POST %s: %v, want %v", target, got, want)
		}
	}
	body := func(target, b string) *http.Request { return httptest.NewRequest("POST", target, strings.NewReader(b)) }
	for b, want := range map[string]bool{
		`{"target":"depot","tool":""}`: true, `{"target":"depot","tool":"files_list","args":{"folder":"/"},"write":false}`: true,
		`{"target":"depot","tool":"files_delete","write":true}`: false, `{"target":"depot","write":1}`: false, `not json`: false,
	} {
		for _, target := range []string{"/api/devices/mcp", "/api/proxy?node=10.0.0.2&path=%2Fapi%2Fdevices%2Fmcp"} {
			r := body(target, b)
			if got := readOnlyJob(r); got != want {
				t.Errorf("POST %s %s: %v, want %v", target, b, got, want)
			}
			if rest, _ := io.ReadAll(r.Body); string(rest) != b {
				t.Errorf("the body was not put back: %q", rest)
			}
		}
	}
	if readOnlyJob(req("PUT", "/api/nettool")) {
		t.Error("a PUT was let through")
	}
}
