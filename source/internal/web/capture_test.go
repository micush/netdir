package web

import (
	"strings"
	"testing"
)

// What a node relays must be allowed, and what asks the other nodes itself must not be.
func TestCaptureRelayRules(t *testing.T) {
	for _, p := range []string{"/api/capture/interfaces", "/api/capture/start", "/api/capture/packets?since=3", "/api/capture/download", "/api/capture/job", "/api/capture/job?id=x"} {
		m := "GET"
		if strings.HasSuffix(p, "start") || p == "/api/capture/job" {
			m = "POST"
		}
		if err := ProxyAllowed(m, p); err != nil {
			t.Errorf("%s cannot be relayed: %v", p, err)
		}
	}
	for _, p := range []string{"/api/clustercapture/start", "/api/clustercapture/status", "/api/clustercapture/download"} {
		if ProxyAllowed("GET", p) == nil || ProxyAllowed("POST", p) == nil {
			t.Errorf("%s can be relayed", p)
		}
	}
}
