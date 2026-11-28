package core

import (
	"net/netip"
	"strings"
	"time"
)

// /metrics: this node's counters in the Prometheus text format, on the web GUI port (Configure ▸ Monitoring ▸ Metrics).
// It is always there, but only the sources in MetricsACL may read it (an empty list is nobody, and the list is empty until
// it is filled in); there is no login, Prometheus cannot fill in a form.  The source is the address of the connection, never a header.
// Only counts and states are written, no client or domain names.

// metricsAllowed says whether a request from this address may read /metrics.
func (s *Supervisor) MetricsAllowed(from netip.Addr) bool {
	s.Mu.Lock()
	var acl []string
	if s.Dc != nil {
		acl = s.Dc.Settings.MetricsACL
	}
	s.Mu.Unlock()
	return inNets(s.metricsNets(acl), from.Unmap())
}

// metricsNets is the list as networks.  Host names in it are looked up again after a minute, not for every request.
func (s *Supervisor) metricsNets(acl []string) []netip.Prefix {
	key := strings.Join(acl, ",")
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	if s.metricsKey == key && time.Since(s.metricsAt) < time.Minute {
		return s.metricsCache
	}
	s.metricsKey, s.metricsAt, s.metricsCache = key, time.Now(), expandACL(acl)
	return s.metricsCache
}
