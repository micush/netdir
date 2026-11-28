package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netdir/internal/core"
	"netdir/internal/web"
)

func TestMetricsIsForTheACLOnly(t *testing.T) {
	dc := core.NewDaemonConfig()
	dc.Groups = nil
	s := core.NewSupervisor(context.Background(), dc)
	w := &web.WebServer{Status: &StatusServer{sup: s}}
	set := func(acl ...string) {
		d := core.NewDaemonConfig()
		d.Groups = nil
		d.Settings.MetricsACL = acl
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
		s.Mu.Lock()
		s.Dc = d.Effective()
		s.Mu.Unlock()
	}
	get := func(from string) (int, string) {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.RemoteAddr = from
		rw := httptest.NewRecorder()
		w.HandleMetrics(rw, r)
		return rw.Code, rw.Body.String()
	}
	set() // nobody listed: nobody may read it
	if c, _ := get("192.0.2.7:5000"); c != http.StatusForbidden {
		t.Fatalf("empty list: %d, want 403", c)
	}
	set("192.0.2.7", "10.1.0.0/24", "2001:db8::/32")
	for from, want := range map[string]int{"192.0.2.7:1": 200, "10.1.0.99:1": 200, "[2001:db8::5]:1": 200, "[::ffff:192.0.2.7]:1": 200, "192.0.2.8:1": 403, "10.2.0.1:1": 403, "[2001:db9::1]:1": 403} {
		if c, _ := get(from); c != want {
			t.Errorf("%s: %d, want %d", from, c, want)
		}
	}
	_, body := get("192.0.2.7:1")
	if !strings.Contains(body, "# TYPE netdir_info gauge") || !strings.Contains(body, `netdir_info{version="`) {
		t.Fatalf("no info line in:\n%s", body)
	}
}

func TestMetricsTextHasNoBlankLinesAndEscapes(t *testing.T) {
	if got := promLabel("a", "x\"y\\z\n"); got != `a="x\"y\\z\n"` {
		t.Fatal(got)
	}
	dc := core.NewDaemonConfig()
	dc.Groups = nil
	s := &StatusServer{sup: core.NewSupervisor(context.Background(), dc)}
	for _, l := range strings.Split(strings.TrimSpace(s.MetricsText()), "\n") {
		if l == "" {
			t.Fatal("blank line in the page")
		}
	}
}

func TestMetricsCertificateExpiry(t *testing.T) {
	cm, _ := newTestCertMgr(t)
	m := &metricsOut{seen: map[string]bool{}}
	m.cert("x_not_after", "x_left", "web", cm)
	m.cert("x_not_after", "x_left", "none", nil) // no manager: nothing written
	out := m.b.String()
	if !strings.Contains(out, `x_not_after{certificate="web"} `) || !strings.Contains(out, `x_left{certificate="web"} `) || strings.Contains(out, "none") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, `x_left{`) {
			var v float64
			if _, err := fmt.Sscanf(l[strings.LastIndex(l, " ")+1:], "%g", &v); err != nil || v < 86400 {
				t.Fatalf("a new certificate should have days left: %q", l)
			}
		}
	}
}
