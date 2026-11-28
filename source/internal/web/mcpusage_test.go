package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"netdir/internal/core"
)

func TestMCPUsageHandler(t *testing.T) {
	w := &WebServer{Usage: core.NewMCPUsage("")}
	w.Usage.Record(core.McpUseCall{Time: time.Now(), Caller: "k", Addr: "a", Tool: "t", Result: "ok"})
	for _, win := range []string{"", "1h", "24h", "7d"} {
		rw := httptest.NewRecorder()
		w.handleMCPUsage(rw, httptest.NewRequest("GET", "/api/mcpusage?window="+win, nil), nil)
		var out map[string]any
		if rw.Code != 200 || json.Unmarshal(rw.Body.Bytes(), &out) != nil || out["by_tool"] == nil {
			t.Errorf("window %q: %d %s", win, rw.Code, rw.Body.String())
		}
	}
	rw := httptest.NewRecorder()
	w.handleMCPUsage(rw, httptest.NewRequest("GET", "/api/mcpusage?window=9y", nil), nil)
	if rw.Code != 400 {
		t.Errorf("a bad window: %d", rw.Code)
	}
}
