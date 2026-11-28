package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A read-only MCP caller reaches device_mcp (the tool list and the tools a device marks read-only): the shared gate used to
// refuse its POST /api/devices/mcp, so the tool never ran.  device_mcp_write stays an rw tool.
func TestDeviceMCPReadOnlyCaller(t *testing.T) {
	_, post := mcpEnv(t, "127.0.0.0/8")
	_, m := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	names := " " + strings.Join(toolNames(t, m), " ") + " "
	if !strings.Contains(names, " device_mcp ") || strings.Contains(names, " device_mcp_write ") {
		t.Fatalf("read-only tools: %s", names)
	}
	_, m = post(mcpCall("device_mcp", `{"target":"nosuchdevice"}`))
	if txt, _ := toolResult(t, m); strings.Contains(txt, readOnlyMsg) || strings.Contains(txt, "read-only") {
		t.Fatalf("device_mcp was refused at the gate: %s", txt)
	}
	_, m = post(mcpCall("device_mcp_write", `{"target":"nosuchdevice","tool":"files_delete"}`))
	if txt, isErr := toolResult(t, m); !isErr {
		t.Fatalf("device_mcp_write ran for a read-only caller: %s", txt)
	}
}

// The route itself, as an in-process read-only session: a read passes the gate, a write does not.
func TestDeviceMCPRouteReadOnlySession(t *testing.T) {
	e := newWebEnv(t)
	for body, want := range map[string]int{
		`{"target":"nosuchdevice","tool":""}`:                          http.StatusOK,
		`{"target":"nosuchdevice","tool":"files_delete","write":true}`: http.StatusForbidden,
	} {
		req := httptest.NewRequest("POST", "/api/devices/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), proxyCtxKey{}, &session{user: "u", readOnly: true, created: time.Now()})
		rec := httptest.NewRecorder()
		e.ws.Handler().ServeHTTP(rec, req.WithContext(ctx))
		refused := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), readOnlyMsg)
		if refused != (want == http.StatusForbidden) {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
}
