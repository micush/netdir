package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeviceHealthStandaloneChecksHere(t *testing.T) {
	healthMg = nil
	if !checksHere() {
		t.Fatal("a node without a cluster must do its own checks")
	}
	if deviceHealth(true) == nil {
		t.Fatal("deviceHealth returned nil")
	}
	lookAtDevices()
}

func TestHandleDeviceHealth(t *testing.T) {
	healthMg = nil
	w := &WebServer{}
	rec := httptest.NewRecorder()
	w.handleDeviceHealth(rec, httptest.NewRequest(http.MethodGet, "/api/devices/health?look=1", nil), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"health"`) || !strings.Contains(rec.Body.String(), `"checks_here":true`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
