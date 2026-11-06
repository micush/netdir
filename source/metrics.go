package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// /metrics: this node's counters in the Prometheus text format, on the web GUI port (Configure ▸ Monitoring ▸ Metrics).
// It is always there, but only the sources in MetricsACL may read it (an empty list is nobody, and the list is empty until
// it is filled in); there is no login, Prometheus cannot fill in a form.  The source is the address of the connection, never a header.
// Only counts and states are written, no client or domain names.

// metricsAllowed says whether a request from this address may read /metrics.
func (s *Supervisor) metricsAllowed(from netip.Addr) bool {
	s.mu.Lock()
	var acl []string
	if s.dc != nil {
		acl = s.dc.Settings.MetricsACL
	}
	s.mu.Unlock()
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

func (w *WebServer) handleMetrics(rw http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	if !w.status.sup.metricsAllowed(ap.Addr()) {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = rw.Write([]byte(w.status.metricsText()))
}

type metricsOut struct {
	b    strings.Builder
	seen map[string]bool
}

func (m *metricsOut) add(name, kind, help string, labels string, v float64) {
	if !m.seen[name] {
		m.seen[name] = true
		fmt.Fprintf(&m.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	if labels != "" {
		labels = "{" + labels + "}"
	}
	fmt.Fprintf(&m.b, "%s%s %g\n", name, labels, v)
}

// cert writes when a certificate runs out: as a time (for dashboards) and as seconds left (for alerts; negative once it has).
func (m *metricsOut) cert(notAfterName, leftName, which string, cm *CertManager) {
	if cm == nil {
		return
	}
	lc, err := cm.current(false)
	if err != nil || lc == nil || lc.info.NotAfter.IsZero() {
		return
	}
	l := promLabel("certificate", which)
	m.add(notAfterName, "gauge", "When the certificate runs out (unix time).", l, float64(lc.info.NotAfter.Unix()))
	m.add(leftName, "gauge", "Seconds until the certificate runs out (negative once it has).", l, time.Until(lc.info.NotAfter).Seconds())
}

func promLabel(k, v string) string {
	v = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
	return k + `="` + v + `"`
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metricsText is the page: the gateways, the managed devices and the host, per node.
func (s *StatusServer) metricsText() string {
	m := &metricsOut{seen: map[string]bool{}}
	m.add("netdir_info", "gauge", "The version this node runs.", promLabel("version", version()), 1)
	devs, _ := s.sup.deviceInventory()
	m.add("netdir_devices", "gauge", "Managed devices in the inventory.", "", float64(len(devs)))
	if s.mg != nil {
		m.cert("netdir_certificate_not_after_timestamp_seconds", "netdir_certificate_expires_in_seconds", "web", s.mg.certs)
	}
	if h := hoststats.lastNow(); h.At != 0 {
		m.add("netdir_host_cpu_percent", "gauge", "CPU in use, all cores.", "", h.CPU)
		m.add("netdir_host_cpu_cores", "gauge", "CPU cores.", "", float64(h.Cores))
		for i, n := range []string{"1", "5", "15"} {
			m.add("netdir_host_load", "gauge", "Load average.", promLabel("minutes", n), h.Load[i])
		}
		m.add("netdir_host_memory_total_bytes", "gauge", "Memory installed.", "", float64(h.MemTotal))
		m.add("netdir_host_memory_used_bytes", "gauge", "Memory in use.", "", float64(h.MemUsed))
		m.add("netdir_host_swap_total_bytes", "gauge", "Swap space.", "", float64(h.SwapTotal))
		m.add("netdir_host_swap_used_bytes", "gauge", "Swap space in use.", "", float64(h.SwapUsed))
		m.add("netdir_host_disk_io_percent", "gauge", "Time the busiest disk spent on I/O.", "", h.IO)
		for _, f := range h.FS {
			l := promLabel("mount", f.Mount)
			m.add("netdir_host_filesystem_total_bytes", "gauge", "Size of the filesystem.", l, float64(f.Total))
			m.add("netdir_host_filesystem_used_bytes", "gauge", "Space used on the filesystem.", l, float64(f.Used))
			m.add("netdir_host_filesystem_used_percent", "gauge", "Percent of the filesystem in use.", l, f.Pct)
		}
		for _, i := range h.Ifaces {
			l := promLabel("interface", i.Name)
			m.add("netdir_host_interface_up", "gauge", "1 when the interface is up.", l, b2f(i.Up))
			m.add("netdir_host_interface_receive_bits_per_second", "gauge", "Receive rate over the last sample.", l, i.Rx)
			m.add("netdir_host_interface_transmit_bits_per_second", "gauge", "Transmit rate over the last sample.", l, i.Tx)
			if i.UtilPct >= 0 {
				m.add("netdir_host_interface_utilization_percent", "gauge", "The busier direction as a percent of the link speed.", l, i.UtilPct)
			}
		}
	}
	if s.alerts != nil {
		active, acked, opened := s.alerts.counts()
		for _, sev := range alertSeverities {
			l := promLabel("severity", sev)
			m.add("netdir_alerts_active", "gauge", "Open alerts that nobody has acknowledged or silenced.", l, float64(active[sev]))
			m.add("netdir_alerts_acknowledged", "gauge", "Open alerts that someone has acknowledged (not silenced).", l, float64(acked[sev]))
		}
		m.add("netdir_alerts_opened_total", "counter", "Alerts opened since the history began (an alert that comes back is counted again).", "", float64(opened))
	}
	for _, r := range s.snapshot() {
		if !r.Local {
			continue
		}
		l := promLabel("group", itoa(r.GroupID)) + "," + promLabel("af", r.AF)
		m.add("netdir_gateway_active", "gauge", "1 when this node is the active gateway of the group.", l, b2f(r.State == "active"))
		m.add("netdir_gateway_service_up", "gauge", "1 when this node's MCP and web listener is serving the gateway.", l, b2f(r.ServiceUp))
	}
	return m.b.String()
}

// The example Grafana dashboard and Prometheus alert rules (webui/), as downloads for a signed-in user (the links under the
// Allowed sources list of Configure ▸ Monitoring ▸ Metrics).  They are behind the sign-in, not the metrics access list:
// that list names the Prometheus server, not the browser.
func (w *WebServer) handleMetricsFile(file, ctype, download string) func(http.ResponseWriter, *http.Request, *session) {
	return func(rw http.ResponseWriter, r *http.Request, s *session) {
		b, err := webFS.ReadFile("webui/" + file)
		if err != nil {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", ctype)
		rw.Header().Set("Content-Disposition", `attachment; filename="`+download+`"`)
		_, _ = rw.Write(b)
	}
}
