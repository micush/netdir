package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"netdir/internal/core"
	"netdir/internal/mcp"
	"netdir/internal/web"
)

// guiEditConfig changes the configuration the way the GUI does (get it, merge set into it, put it back): MCP cannot,
// so a test that needs a changed configuration makes the change here.
func guiEditConfig(t *testing.T, e *webEnv, set string) {
	t.Helper()
	h := e.ws.Handler()
	do := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), web.ProxyCtxKey{}, &core.Session{User: "gui", Created: time.Now()}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := do("GET", "/api/config", nil)
	var cur struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cur); err != nil || cur.Config == nil {
		t.Fatalf("read config: %v %s", err, rec.Body.String())
	}
	var s map[string]any
	if err := json.Unmarshal([]byte(set), &s); err != nil {
		t.Fatal(err)
	}
	mcp.MergeJSON(cur.Config, s)
	b, _ := json.Marshal(map[string]any{"config": cur.Config, "base": "force"})
	if rec := do("PUT", "/api/config", b); rec.Code != 200 {
		t.Fatalf("save config: %d %s", rec.Code, rec.Body.String())
	}
}
