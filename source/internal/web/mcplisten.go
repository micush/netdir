package web

import (
	"net/netip"

	"netdir/internal/core"
)

// isGatewayAddr says whether a is an address of any gateway in the running configuration.
func (w *WebServer) isGatewayAddr(a netip.Addr) bool {
	for _, g := range core.GatewayAddrs(w.Status.Sup().Config(), false) {
		if g == a {
			return true
		}
	}
	return false
}
