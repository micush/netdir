package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestHandleDeviceHealth(t *testing.T) {
	core.HealthCl = nil
	w := &WebServer{}
	rec := httptest.NewRecorder()
	w.handleDeviceHealth(rec, httptest.NewRequest(http.MethodGet, "/api/devices/health?look=1", nil), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"health"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// A read-only account may not ask (the one gate refuses every POST): the route is not an exception.
func TestRecheckIsAPostRefusedToReadOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/devices/recheck", nil)
	if !readOnlyDenied(r) {
		t.Fatal("a read-only account can ask a device again")
	}
}
