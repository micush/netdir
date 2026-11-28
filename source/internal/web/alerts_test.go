package web

import (
	"testing"
)

// The alerts of any node can be seen and handled from the GUI of another one.
func TestAlertsCanBeRelayedToAnotherNode(t *testing.T) {
	for _, c := range [][2]string{{"GET", "/api/alerts"}, {"POST", "/api/alerts/ack"}, {"POST", "/api/alerts/silence"}, {"POST", "/api/alerts/resolve"}, {"POST", "/api/alerts/fix"}, {"POST", "/api/alerts/test"}} {
		if err := ProxyAllowed(c[0], c[1]); err != nil {
			t.Errorf("%s %s: %v", c[0], c[1], err)
		}
	}
}
