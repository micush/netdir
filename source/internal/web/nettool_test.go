package web

import (
	"testing"
)

func TestNetToolRelayable(t *testing.T) {
	if err := ProxyAllowed("POST", "/api/nettool"); err != nil {
		t.Errorf("not relayable: %v", err)
	}
}
