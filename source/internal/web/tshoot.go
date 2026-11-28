package web

import (
	"fmt"
	"net/http"
	"time"

	"netdir/internal/core"
)

// ── the web side ─────────────────────────────────────────────────────────────

func (w *WebServer) registerTshoot(mux *http.ServeMux) {
	// this node's own bundle (what the cluster-wide one asks of every other node)
	mux.HandleFunc("POST /api/tshoot/node", w.authed(w.op("tshoot.node", nil)))
	// the bundle of every node, asked of the node you are logged in to: it asks the others itself
	mux.HandleFunc("GET /api/tshoot/download", w.authed(w.handleTshootDownload))
}

func (w *WebServer) handleTshootDownload(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	capture := r.URL.Query().Get("capture") != "0" // the capture is always part of it unless a caller asks otherwise
	var b []byte
	var err error
	if r.URL.Query().Get("all") == "0" {
		b, err = w.Mg.TshootNode(capture, s.User)
	} else {
		b, err = w.Mg.TshootCluster(capture, s.User)
	}
	if err != nil {
		core.JsonError(rw, http.StatusInternalServerError, err.Error())
		return
	}
	host, _ := core.HostnameShort()
	rw.Header().Set("Content-Type", "application/gzip")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "netdir-tshoot-"+host+"-"+time.Now().Format("20060102-150405")+".tgz"))
	rw.Write(b)
}
