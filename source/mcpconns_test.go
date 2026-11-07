package main

import (
	"net"
	"net/http"
	"testing"
)

type fakeConn struct {
	net.Conn
	l, r string
}

func (f *fakeConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.ParseIP(f.l), Port: 443} }
func (f *fakeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP(f.r), Port: 50000} }

func TestMCPClientsCountsDifferentAddresses(t *testing.T) {
	tr := &mcpConnTracker{conns: map[net.Conn]mcpConnKey{}, n: map[mcpConnKey]int{}}
	a1, a2, b := &fakeConn{l: "10.0.0.1", r: "10.0.0.50"}, &fakeConn{l: "10.0.0.1", r: "10.0.0.50"}, &fakeConn{l: "10.0.0.1", r: "10.0.0.51"}
	self, lo, other := &fakeConn{l: "10.0.0.1", r: "10.0.0.1"}, &fakeConn{l: "10.0.0.1", r: "127.0.0.1"}, &fakeConn{l: "10.0.0.9", r: "10.0.0.60"}
	for _, c := range []*fakeConn{a1, a2, b, self, lo, other} {
		tr.hook(c, http.StateNew)
		tr.hook(c, http.StateNew) // a repeated state is not counted twice
	}
	if n := tr.clients("10.0.0.1/24", ""); n != 2 {
		t.Fatalf("clients = %d, want 2 (two connections from one address count once; the node itself and loopback do not count)", n)
	}
	if n := tr.clients("10.0.0.1", "10.0.0.9"); n != 3 {
		t.Fatalf("clients across two addresses = %d, want 3", n)
	}
	tr.hook(a1, http.StateClosed)
	if n := tr.clients("10.0.0.1"); n != 2 {
		t.Fatalf("one of two connections closed: %d, want 2", n)
	}
	tr.hook(a2, http.StateClosed)
	tr.hook(a2, http.StateClosed)
	if n := tr.clients("10.0.0.1"); n != 1 {
		t.Fatalf("after both closed: %d, want 1", n)
	}
	if len(tr.conns) != 4 {
		t.Fatalf("%d connections kept, want 4", len(tr.conns))
	}
}
