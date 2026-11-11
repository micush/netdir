package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// guiEditConfig changes the configuration the way the GUI does (get it, merge set into it, put it back): MCP cannot,
// so a test that needs a changed configuration makes the change here.
func guiEditConfig(t *testing.T, e *webEnv, set string) {
	t.Helper()
	h := e.ws.Handler()
	do := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), proxyCtxKey{}, &session{user: "gui", created: time.Now()}))
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
	mergeJSON(cur.Config, s)
	b, _ := json.Marshal(map[string]any{"config": cur.Config, "base": "force"})
	if rec := do("PUT", "/api/config", b); rec.Code != 200 {
		t.Fatalf("save config: %d %s", rec.Code, rec.Body.String())
	}
}

// A request that changes anything but a device is refused over MCP, at every route.
func TestMCPWriteGuard(t *testing.T) {
	for _, c := range []struct {
		m, p string
		ok   bool
	}{
		{"GET", "/api/config", true}, {"PUT", "/api/config", false}, {"POST", "/api/canvas/edit", false},
		{"POST", "/api/devices/change", true}, {"POST", "/api/devices/raw", true}, {"POST", "/api/devices/capture", true},
		{"POST", "/api/proxy?node=x&path=/api/devices/change", true}, {"POST", "/api/proxy?node=x&path=/api/config", false},
		{"DELETE", "/api/devices/change", false}, {"POST", "/api/nodepause", false}, {"POST", "/api/schedule", false},
	} {
		if err := mcpWriteGuard(c.m, c.p); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.m, c.p, err)
		}
	}
}
