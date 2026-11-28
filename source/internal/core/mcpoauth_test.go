package core

import (
	"net/http"
	"strings"
	"testing"
)

func TestMCPOAuthHelpers(t *testing.T) {
	for s, want := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true, "http://localhost:8080/cb": true, "http://127.0.0.1/cb": true, "http://[::1]:1/cb": true,
		"com.example.app:/cb": true, "http://example.com/cb": false, "myapp://x": false, "javascript:alert(1)": false, "file:///etc/passwd": false,
		"https://a/b#f": false, "https://u:p@a/b": false, "": false, "/relative": false, "https://a/b c": false,
		"https://" + strings.Repeat("a", 400) + "/cb": false,
	} {
		if OauthRedirectOK(s) != want {
			t.Errorf("oauthRedirectOK(%q) = %v", s, !want)
		}
	}
	if !OauthRedirectMatches([]string{"http://localhost:1/cb"}, "http://localhost:2/cb") || OauthRedirectMatches([]string{"http://localhost:1/cb"}, "http://127.0.0.1:1/cb") ||
		OauthRedirectMatches([]string{"https://a.example/cb"}, "https://a.example:444/cb") || !OauthRedirectMatches([]string{"https://a.example/cb"}, "https://a.example/cb") {
		t.Error("oauthRedirectMatches")
	}
	if got := OauthCleanName("  <script>x</script>\x00" + strings.Repeat("é", 100)); strings.ContainsAny(got, "<>\x00") || len([]rune(got)) != 60 {
		t.Errorf("oauthCleanName: %q", got)
	}
	if OauthCleanName(" \x01 ") != "an MCP client" {
		t.Error("empty name")
	}
	if OauthBase(&http.Request{Host: "a.example:443"}) != "https://a.example:443" || OauthBase(&http.Request{Host: "a/b"}) != "" || OauthBase(&http.Request{}) != "" {
		t.Error("oauthBase")
	}
}
