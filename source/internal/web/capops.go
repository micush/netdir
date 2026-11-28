package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"time"

	"netdir/internal/core"
)

// ── the web side ─────────────────────────────────────────────────────────────

func (w *WebServer) registerCapture(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/capture/interfaces", w.authed(w.op("capture.interfaces", nil)))
	mux.HandleFunc("POST /api/capture/start", w.authed(w.op("capture.start", nil)))
	mux.HandleFunc("POST /api/capture/stop", w.authed(w.op("capture.stop", nil)))
	mux.HandleFunc("POST /api/capture/clear", w.authed(w.op("capture.clear", nil)))
	mux.HandleFunc("GET /api/capture/packets", w.authed(w.op("capture.packets", []string{"since"})))
	// a timed capture in a buffer of its own, started and then asked for (each request is quick: the peer channel
	// gives a slow request only a few seconds per address before it tries the next one)
	mux.HandleFunc("POST /api/capture/job", w.authed(w.op("capture.job.start", nil)))
	mux.HandleFunc("GET /api/capture/job", w.authed(w.op("capture.job.get", []string{"id"})))
	mux.HandleFunc("GET /api/capture/download", w.authed(w.handleCaptureDownload))
	// every node at once: the node asked asks the others itself, so none of these can be relayed
	mux.HandleFunc("POST /api/clustercapture/start", w.authed(w.op("capture.cluster.start", nil)))
	mux.HandleFunc("GET /api/clustercapture/status", w.authed(w.op("capture.cluster.status", nil)))
	mux.HandleFunc("GET /api/clustercapture/download", w.authed(w.handleClusterCaptureDownload))
	w.registerTshoot(mux)
}

// handleCaptureDownload sends the buffer of this node's Capture page as a .tgz holding one .pcap.  Reached through another
// node it is the newest packets that fit the peer channel.
func (w *WebServer) handleCaptureDownload(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	limit := 0
	if _, relayed := r.Context().Value(ProxyCtxKey{}).(*core.Session); relayed {
		limit = core.CapRelayBytes
	}
	iface, pcap := w.Mg.CapturePcap(limit)
	if iface == "" {
		iface = "capture"
	}
	host, _ := core.HostnameShort()
	now := time.Now()
	base := fmt.Sprintf("netdir-%s-%s-%s", host, core.CapNameRe.ReplaceAllString(iface, "_"), now.Format("20060102-150405"))
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	if tw.WriteHeader(&tar.Header{Name: base + ".pcap", Mode: 0o644, Size: int64(len(pcap)), ModTime: now}) == nil {
		tw.Write(pcap)
	}
	tw.Close()
	gz.Close()
	rw.Header().Set("Content-Type", "application/gzip")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".tgz"))
	rw.Write(out.Bytes())
}

func (w *WebServer) handleClusterCaptureDownload(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	b, err := w.Mg.CaptureClusterBundle()
	if err != nil {
		core.JsonError(rw, http.StatusConflict, err.Error())
		return
	}
	rw.Header().Set("Content-Type", "application/gzip")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "netdir-cluster-capture-"+time.Now().Format("20060102-150405")+".tgz"))
	rw.Write(b)
}
