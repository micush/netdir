package web

import (
	"io/fs"
	"net/http"
	"net/netip"

	"netdir/internal/core"
)

func (w *WebServer) HandleMetrics(rw http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	if !w.Status.Sup().MetricsAllowed(ap.Addr()) {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = rw.Write([]byte(w.Status.MetricsText()))
}

// The example Grafana dashboard and Prometheus alert rules (webui/), as downloads for a signed-in user (the links under the
// Allowed sources list of Configure ▸ Monitoring ▸ Metrics).  They are behind the sign-in, not the metrics access list:
// that list names the Prometheus server, not the browser.
func (w *WebServer) handleMetricsFile(file, ctype, download string) func(http.ResponseWriter, *http.Request, *core.Session) {
	return func(rw http.ResponseWriter, r *http.Request, s *core.Session) {
		b, err := fs.ReadFile(WebFS, "webui/"+file)
		if err != nil {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", ctype)
		rw.Header().Set("Content-Disposition", `attachment; filename="`+download+`"`)
		_, _ = rw.Write(b)
	}
}
