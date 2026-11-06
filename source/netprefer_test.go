package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestIPv4First(t *testing.T) {
	got := ipv4First([]string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2", "not an ip"})
	want := []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2", "not an ip"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
	in := []string{"2001:db8::1", "192.0.2.1"}
	ipv4First(in)
	if in[0] != "2001:db8::1" {
		t.Fatal("the caller's slice was reordered")
	}
	if len(ipv4First(nil)) != 0 {
		t.Fatal("nil in, something out")
	}
}

func acceptAndClose(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}

// listen6 gives a listener on the IPv6 loopback, or skips the test on a host that has none.
func listen6(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback here:", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestDialPrefer4(t *testing.T) {
	d := &net.Dialer{Timeout: 2 * time.Second}
	// an IPv4 target is reached
	l4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l4.Close()
	go acceptAndClose(l4)
	c, err := dialPrefer4(context.Background(), d, "tcp", l4.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().(*net.TCPAddr).IP.To4() == nil {
		t.Fatalf("not IPv4: %v", c.RemoteAddr())
	}
	c.Close()
	// a target that only has IPv6 is still reached: IPv4 first, then the network as given
	t.Run("IPv6 only", func(t *testing.T) {
		l6 := listen6(t)
		go acceptAndClose(l6)
		c, err := dialPrefer4(context.Background(), d, "tcp", l6.Addr().String())
		if err != nil {
			t.Fatalf("IPv6-only target: %v", err)
		}
		c.Close()
	})
	// a name that has both: the IPv4 listener is the one that answers, even though ::1 is listening too
	t.Run("both families", func(t *testing.T) {
		_, port, _ := net.SplitHostPort(l4.Addr().String())
		l, err := net.Listen("tcp6", "[::1]:"+port)
		if err != nil {
			t.Skip("no IPv6 loopback, or its port is taken:", err)
		}
		defer l.Close()
		go acceptAndClose(l)
		c, err := dialPrefer4(context.Background(), d, "tcp", "localhost:"+port)
		if err != nil {
			t.Fatal(err)
		}
		if c.RemoteAddr().(*net.TCPAddr).IP.To4() == nil {
			t.Fatalf("localhost went to %v, not IPv4", c.RemoteAddr())
		}
		c.Close()
	})
	// a cancelled context is not retried on the other family
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialPrefer4(ctx, d, "tcp", l4.Addr().String()); err == nil {
		t.Fatal("dialled with a cancelled context")
	}
	// a network other than tcp or udp goes straight through
	if _, err := dialPrefer4(context.Background(), d, "unix", "/nonexistent/socket"); err == nil {
		t.Fatal("unix dial to nowhere worked")
	}
}

func TestIPv4FirstClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	cl := ipv4FirstClient(5 * time.Second)
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	// an IPv6-only server answers too
	t.Run("IPv6 only", func(t *testing.T) {
		l6 := listen6(t)
		s6 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok6")) }))
		s6.Listener.Close()
		s6.Listener = l6
		s6.Start()
		defer s6.Close()
		resp, err := cl.Get(s6.URL)
		if err != nil {
			t.Fatalf("IPv6-only server: %v", err)
		}
		resp.Body.Close()
	})
	if cl.Timeout != 5*time.Second {
		t.Fatalf("timeout %v", cl.Timeout)
	}
}
