package device

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type xeWriteState struct {
	mu      sync.Mutex
	ports   map[string]portState // "GigabitEthernet1/0/1"
	reqs    []string             // "PATCH /restconf/..." and "DELETE ..."
	bodies  []string
	deletes int
	failDel int    // the n-th DELETE (1-based) answers 500
	ignore  bool   // PATCH answers 204 and changes nothing
	mgmt    string // the port that holds the address the gateway uses (127.0.0.1)
}

// xeWriteStub is an IOS-XE RESTCONF server on loopback that holds the native interface container and accepts only: GET of
// that container, PATCH of that container, DELETE of the description or shutdown leaf of one interface.  Anything else fails
// the test.
func xeWriteStub(t *testing.T, ports map[string]portState) (Device, *xeWriteState) {
	t.Helper()
	st := &xeWriteState{ports: ports}
	const base = "/restconf/data/Cisco-IOS-XE-native:native/interface"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		ep := r.URL.EscapedPath()
		switch {
		case r.Method == http.MethodGet && ep == base:
			byType := map[string][]any{}
			names := make([]string, 0, len(st.ports))
			for n := range st.ports {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				typ, nm, _ := iosxeSplit(n)
				e := J{"name": nm}
				if st.ports[n].Description != "" {
					e["description"] = st.ports[n].Description
				}
				if st.ports[n].Down {
					e["shutdown"] = []any{nil}
				}
				byType[typ] = append(byType[typ], e)
			}
			w.Header().Set("Content-Type", yangJSON)
			_ = json.NewEncoder(w).Encode(J{"Cisco-IOS-XE-native:interface": byType})
		case r.Method == http.MethodGet && ep == "/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface":
			var l []any
			for n := range st.ports {
				e := J{"name": n}
				if n == st.mgmt {
					e["ipv4"], e["ipv4-subnet-mask"] = "127.0.0.1", "255.255.255.0"
				}
				l = append(l, e)
			}
			w.Header().Set("Content-Type", yangJSON)
			_ = json.NewEncoder(w).Encode(J{"Cisco-IOS-XE-interfaces-oper:interface": l})
		case r.Method == http.MethodPatch && ep == base:
			b, _ := io.ReadAll(r.Body)
			st.reqs = append(st.reqs, "PATCH "+ep)
			st.bodies = append(st.bodies, string(b))
			if r.Header.Get("Content-Type") != yangJSON {
				t.Errorf("PATCH content type %q", r.Header.Get("Content-Type"))
			}
			var body struct {
				I map[string][]map[string]any `json:"Cisco-IOS-XE-native:interface"`
			}
			if err := json.Unmarshal(b, &body); err != nil || len(body.I) == 0 {
				t.Errorf("PATCH body: %v %s", err, b)
			}
			for typ, list := range body.I {
				for _, e := range list {
					key := typ + str(e["name"])
					if _, ok := st.ports[key]; !ok {
						t.Errorf("PATCH of a port that does not exist: %s", key)
					}
					for k := range e {
						if k != "name" && k != "description" && k != "shutdown" {
							t.Errorf("PATCH sets %q", k)
						}
					}
					if st.ignore {
						continue
					}
					s := st.ports[key]
					if d, ok := e["description"]; ok {
						s.Description = str(d)
					}
					if _, ok := e["shutdown"]; ok {
						s.Down = true
					}
					st.ports[key] = s
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(ep, base+"/"):
			st.reqs = append(st.reqs, "DELETE "+ep)
			st.deletes++
			if st.failDel == st.deletes {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			rest := strings.TrimPrefix(ep, base+"/")
			parts := strings.Split(rest, "/") // Type=1%2F0%2F2, leaf
			if len(parts) != 2 || (parts[1] != "description" && parts[1] != "shutdown") {
				t.Errorf("DELETE of %s", ep)
				http.NotFound(w, r)
				return
			}
			typ, name, _ := strings.Cut(parts[0], "=")
			un := strings.ReplaceAll(name, "%2F", "/")
			s := st.ports[typ+un]
			if parts[1] == "description" {
				s.Description = ""
			} else {
				s.Down = false
			}
			st.ports[typ+un] = s
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("a request a change never sends: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "sw1", Platform: "iosxe", Address: host, Port: pn, Insecure: true}, st
}

func xePorts() map[string]portState {
	return map[string]portState{
		"GigabitEthernet1/0/1": {Description: "old"}, "GigabitEthernet1/0/2": {Description: "devices"}, "GigabitEthernet1/0/3": {Down: true},
		"TenGigabitEthernet1/1/1": {}, "Port-channel1": {Description: "uplink"},
	}
}

func TestIOSXEChange(t *testing.T) {
	ctx := context.Background()
	d, st := xeWriteStub(t, xePorts())
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"})
	ch, ok := drv.(Changer)
	if !ok {
		t.Fatal("not a Changer")
	}
	ports, _ := ParsePorts("gi1/0/1-3 te1/1/1")
	// dry run writes nothing
	r, err := ch.Change(ctx, Change{ActDescription, ports, "devices"}, true)
	if err != nil || len(st.reqs) != 0 || len(r.Changes) != 3 || len(r.Unchanged) != 1 {
		t.Fatalf("dry: %v %+v %v", err, r, st.reqs)
	}
	// set: one PATCH, every port in it
	r, err = ch.Change(ctx, Change{ActDescription, ports, "devices"}, false)
	if err != nil || !r.Applied || len(st.reqs) != 1 || st.reqs[0] != "PATCH /restconf/data/Cisco-IOS-XE-native:native/interface" {
		t.Fatalf("set: %v %+v %v", err, r, st.reqs)
	}
	var body struct {
		I map[string][]map[string]any `json:"Cisco-IOS-XE-native:interface"`
	}
	_ = json.Unmarshal([]byte(st.bodies[0]), &body)
	if len(body.I["GigabitEthernet"]) != 2 || len(body.I["TenGigabitEthernet"]) != 1 || body.I["GigabitEthernet"][0]["description"] != "devices" {
		t.Errorf("body: %s", st.bodies[0])
	}
	if st.ports["GigabitEthernet1/0/1"].Description != "devices" || st.ports["GigabitEthernet1/0/3"].Description != "devices" || st.ports["Port-channel1"].Description != "uplink" {
		t.Errorf("state: %+v", st.ports)
	}
	// the port the gateway reaches the switch on is never shut down, and nothing else is either in that request
	st.mgmt = "GigabitEthernet1/0/2"
	st.reqs = nil
	if _, err = ch.Change(ctx, Change{ActShutdown, ports[:3], ""}, false); err == nil || !strings.Contains(err.Error(), "cut the gateway off") || len(st.reqs) != 0 {
		t.Errorf("management port: %v %v", err, st.reqs)
	}
	st.mgmt = ""
	// shutdown merges [null]; no shutdown deletes the leaf, the name escaped
	st.reqs, st.bodies = nil, nil
	if r, err = ch.Change(ctx, Change{ActShutdown, ports[:2], ""}, false); err != nil || !r.Applied || !strings.Contains(st.bodies[0], `"shutdown":[null]`) || !st.ports["GigabitEthernet1/0/1"].Down {
		t.Fatalf("shutdown: %v %+v %v", err, r, st.bodies)
	}
	st.reqs = nil
	if r, err = ch.Change(ctx, Change{ActNoShutdown, ports[:3], ""}, false); err != nil || !r.Applied || len(st.reqs) != 3 {
		t.Fatalf("no shutdown: %v %+v %v", err, r, st.reqs)
	}
	want := "DELETE /restconf/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet=1%2F0%2F1/shutdown"
	if st.reqs[0] != want {
		t.Errorf("delete path: %s", st.reqs[0])
	}
	for n, s := range st.ports {
		if s.Down {
			t.Errorf("%s still down", n)
		}
	}
	// clear
	st.reqs = nil
	if r, err = ch.Change(ctx, Change{ActClearDescription, []string{"Port-channel1", "GigabitEthernet1/0/1"}, ""}, false); err != nil || !r.Applied || len(st.reqs) != 2 || st.ports["Port-channel1"].Description != "" {
		t.Fatalf("clear: %v %+v %v", err, r, st.reqs)
	}
	// a port the switch lacks: nothing is sent
	st.reqs = nil
	if _, err = ch.Change(ctx, Change{ActDescription, []string{"GigabitEthernet1/0/1", "GigabitEthernet9/9/9"}, "x"}, false); err == nil || len(st.reqs) != 0 {
		t.Errorf("missing port: %v %v", err, st.reqs)
	}
	// a refusal half way through the deletes: the old values come back
	d2, st2 := xeWriteStub(t, xePorts())
	st2.failDel = 2
	ch2 := open(t, d2, Credential{Username: "admin", Password: "s3cret"}).(Changer)
	p2, _ := ParsePorts("gi1/0/1 gi1/0/2 po1")
	r, err = ch2.Change(ctx, Change{ActClearDescription, p2, ""}, false)
	if err == nil || !r.RolledBack || !strings.Contains(err.Error(), "the old values are back") {
		t.Fatalf("rollback: %v %+v", err, r)
	}
	if !reflect.DeepEqual(st2.ports, xePorts()) {
		t.Errorf("not as before: %+v", st2.ports)
	}
	// a PATCH the switch accepts and does not apply
	d3, st3 := xeWriteStub(t, xePorts())
	st3.ignore = true
	ch3 := open(t, d3, Credential{Username: "admin", Password: "s3cret"}).(Changer)
	if _, err = ch3.Change(ctx, Change{ActDescription, ports[:1], "new"}, false); err == nil || !strings.Contains(err.Error(), "holds the description") {
		t.Errorf("silent: %v", err)
	}
	// the name checks
	for _, bad := range []string{"GigabitEthernet", "1/0/1", "Gi/1", "Gi1/0/1/../x", "Gi1 0 1"} {
		if _, _, err := iosxeSplit(bad); err == nil {
			t.Errorf("%q split", bad)
		}
	}
}
