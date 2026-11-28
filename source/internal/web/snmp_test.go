package web

import (
	"testing"
)

func TestSNMPStatusCanBeReadOnAnotherNode(t *testing.T) {
	if err := ProxyAllowed("GET", "/api/snmp"); err != nil {
		t.Fatalf("the SNMP status must be relayable to the node picked in the top bar: %v", err)
	}
}
