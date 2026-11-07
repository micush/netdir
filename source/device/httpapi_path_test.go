package device

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A request goes to the device's own address whatever the path says.
func TestAPIClientPathCannotChangeTheHost(t *testing.T) {
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.EscapedPath()+"?"+r.URL.RawQuery)
		io.WriteString(w, "{}")
	}))
	defer srv.Close()
	c, err := newAPIClient(Device{Name: "x", Insecure: true, Address: strings.TrimPrefix(srv.URL, "https://")}, 443)
	if err != nil {
		t.Fatal(err)
	}
	c.base = srv.URL
	ctx := context.Background()
	for _, bad := range []string{"@other.example/x", ".other.example/x", ":9/x", "x"} {
		if _, err := c.do(ctx, http.MethodGet, bad, nil, nil); err == nil {
			t.Errorf("accepted the path %q", bad)
		}
	}
	for path, want := range map[string]string{
		"/a/b?x=1&y=%2F":    "/a/b?x=1&y=%2F",
		"/a%2Fb/c%20d":      "/a%2Fb/c%20d?",
		"//other.example/x": "//other.example/x?",
		"/p#frag":           "/p?",
		"/@other.example/x": "/@other.example/x?",
	} {
		got = nil
		if _, err := c.do(ctx, http.MethodGet, path, nil, nil); err != nil {
			t.Errorf("%q: %v", path, err)
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q reached the device as %v, want %q", path, got, want)
		}
	}
}
