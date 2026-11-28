package web

import (
	"net/http"
	"time"

	"netdir/internal/core"
)

// handleMCPUsage: GET /api/mcpusage?window=24h|7d
func (w *WebServer) handleMCPUsage(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	win := 24 * time.Hour
	switch r.URL.Query().Get("window") {
	case "", "24h":
	case "1h":
		win = time.Hour
	case "7d":
		win = 7 * 24 * time.Hour
	default:
		core.JsonError(rw, http.StatusBadRequest, "window: 1h, 24h or 7d")
		return
	}
	if w.Usage == nil {
		w.Usage = core.NewMCPUsage("")
	}
	core.WriteJSON(rw, http.StatusOK, w.Usage.Report(win))
}
