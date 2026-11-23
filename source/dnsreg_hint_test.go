package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSRegNoNameserverHint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("search example.lan\n"), 0o644)
	r := &dnsReg{port: "1", resolvPath: p} // nothing listens on port 1
	_, err := r.findZone(&DNSRegConfig{}, "example.lan")
	if err == nil || !strings.Contains(err.Error(), "lists no nameserver") {
		t.Fatalf("want the hint, got %v", err)
	}
	os.WriteFile(p, []byte("nameserver 127.0.0.1\n"), 0o644)
	if _, err = r.findZone(&DNSRegConfig{}, "example.lan"); err == nil || strings.Contains(err.Error(), "lists no nameserver") {
		t.Fatalf("no hint expected when a nameserver is listed, got %v", err)
	}
}
