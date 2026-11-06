package device

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type eosWState struct {
	mu       sync.Mutex
	ports    map[string]portState
	requests [][]string
	sessions map[string]bool // pending sessions
	refuse   string          // a line that is refused
	ignore   bool            // the commit changes nothing
	mgmt     string          // the port that holds the address the gateway uses (127.0.0.1)
}

// eosWriteStub is an EOS eAPI on loopback with config sessions: show interfaces description answers from the state; a request
// that starts with "configure session X" builds up the session and applies it at "commit"; a refused line stops the request with
// an error and leaves the session pending until "abort".  The test fails on a line outside the forms a change sends.
func eosWriteStub(t *testing.T, ports map[string]portState) (Device, *eosWState) {
	t.Helper()
	st := &eosWState{ports: ports, sessions: map[string]bool{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			ID     string `json:"id"`
			Params struct {
				Cmds   []string `json:"cmds"`
				Format string   `json:"format"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		st.mu.Lock()
		defer st.mu.Unlock()
		st.requests = append(st.requests, req.Params.Cmds)
		reply := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		cmds := req.Params.Cmds
		if len(cmds) == 1 && cmds[0] == "show interfaces description" {
			d := J{}
			for n, p := range st.ports {
				status := "up"
				if p.Down {
					status = "adminDown"
				}
				d[n] = J{"description": p.Description, "interfaceStatus": status, "lineProtocolStatus": "up"}
			}
			reply(J{"jsonrpc": "2.0", "id": req.ID, "result": []any{J{"interfaceDescriptions": d}}})
			return
		}
		if len(cmds) == 1 && cmds[0] == "show interfaces" {
			im := J{}
			for n := range st.ports {
				o := J{"name": n}
				if n == st.mgmt {
					o["interfaceAddress"] = []any{J{"primaryIp": J{"address": "127.0.0.1", "maskLen": 24}}}
				}
				im[n] = o
			}
			reply(J{"jsonrpc": "2.0", "id": req.ID, "result": []any{J{"interfaces": im}}})
			return
		}
		if !strings.HasPrefix(cmds[0], "configure session netdir") {
			t.Errorf("a request that is neither the read nor a session: %q", cmds)
		}
		sess := strings.TrimPrefix(cmds[0], "configure session ")
		pending := map[string]portState{}
		cur := ""
		results := []any{}
		for i, c := range cmds {
			if !eosCfgRE.MatchString(c) {
				t.Errorf("a line a change never sends: %q", c)
			}
			if c == st.refuse {
				st.sessions[sess] = true
				reply(J{"jsonrpc": "2.0", "id": req.ID, "error": J{"code": 1002, "message": "CLI command " + strconv.Itoa(i+1) + " of " + strconv.Itoa(len(cmds)) + " '" + c + "' failed: invalid command"}})
				return
			}
			switch {
			case strings.HasPrefix(c, "interface "):
				cur = strings.TrimPrefix(c, "interface ")
				if _, ok := st.ports[cur]; !ok {
					t.Errorf("interface %s does not exist", cur)
				}
				if _, ok := pending[cur]; !ok {
					pending[cur] = st.ports[cur]
				}
			case strings.HasPrefix(c, "description "):
				s := pending[cur]
				s.Description = strings.TrimPrefix(c, "description ")
				pending[cur] = s
			case c == "no description":
				s := pending[cur]
				s.Description = ""
				pending[cur] = s
			case c == "shutdown" || c == "no shutdown":
				s := pending[cur]
				s.Down = c == "shutdown"
				pending[cur] = s
			case c == "commit":
				if !st.ignore {
					for n, s := range pending {
						st.ports[n] = s
					}
				}
				delete(st.sessions, sess)
			case c == "abort":
				delete(st.sessions, sess)
			}
			results = append(results, J{})
		}
		reply(J{"jsonrpc": "2.0", "id": req.ID, "result": results})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "eos1", Platform: "eos", Address: host, Port: pn, Insecure: true}, st
}

func eosPorts() map[string]portState {
	return map[string]portState{"Ethernet1": {Description: "old"}, "Ethernet2": {}, "Ethernet3": {Down: true}, "Port-Channel1": {Description: "uplink"}}
}

func TestEOSChange(t *testing.T) {
	ctx := context.Background()
	d, st := eosWriteStub(t, eosPorts())
	ch := open(t, d, Credential{Username: "admin", Password: "s3cret"}).(Changer)
	ports, _ := ParsePorts("et1-3 po1")
	// dry: only the read
	r, err := ch.Change(ctx, Change{ActDescription, ports, "devices"}, true)
	if err != nil || len(st.requests) != 1 || len(r.Changes) != 4 {
		t.Fatalf("dry: %v %+v %v", err, r, st.requests)
	}
	// one session request: read, then configure ... commit, then the read-back
	st.requests = nil
	r, err = ch.Change(ctx, Change{ActDescription, ports, "devices"}, false)
	if err != nil || !r.Applied || len(st.requests) != 3 {
		t.Fatalf("set: %v %+v %v", err, r, st.requests)
	}
	w := st.requests[1]
	if !strings.HasPrefix(w[0], "configure session netdir") || w[len(w)-1] != "commit" || w[1] != "interface Ethernet1" || w[2] != "description devices" || len(w) != 1+2*4+1 {
		t.Errorf("session: %q", w)
	}
	if st.ports["Ethernet2"].Description != "devices" || st.ports["Port-Channel1"].Description != "devices" || len(st.sessions) != 0 {
		t.Errorf("state: %+v %v", st.ports, st.sessions)
	}
	// the port the gateway reaches the switch on is never shut down
	st.mgmt = "Ethernet2"
	st.requests = nil
	if _, err = ch.Change(ctx, Change{ActShutdown, ports[:3], ""}, false); err == nil || !strings.Contains(err.Error(), "cut the gateway off") {
		t.Errorf("management port: %v", err)
	}
	for _, q := range st.requests {
		if strings.HasPrefix(q[0], "configure") {
			t.Errorf("a session was opened: %q", q)
		}
	}
	st.mgmt = ""
	// admin states and clear
	if r, err = ch.Change(ctx, Change{ActShutdown, ports[:2], ""}, false); err != nil || !st.ports["Ethernet1"].Down || !st.ports["Ethernet2"].Down {
		t.Fatalf("shutdown: %v %+v", err, r)
	}
	if r, err = ch.Change(ctx, Change{ActNoShutdown, ports[:3], ""}, false); err != nil || st.ports["Ethernet1"].Down || st.ports["Ethernet3"].Down {
		t.Fatalf("no shutdown: %v %+v", err, r)
	}
	if r, err = ch.Change(ctx, Change{ActClearDescription, ports[:2], ""}, false); err != nil || st.ports["Ethernet1"].Description != "" {
		t.Fatalf("clear: %v %+v", err, r)
	}
	// a port that does not exist (Port-channel and Port-Channel are one): no session at all
	st.requests = nil
	if _, err = ch.Change(ctx, Change{ActDescription, []string{"port-channel1", "Ethernet99"}, "x"}, false); err == nil || len(st.requests) != 1 {
		t.Errorf("missing: %v %v", err, st.requests)
	}
	// a line the switch refuses: nothing applied, the pending session aborted
	d2, st2 := eosWriteStub(t, eosPorts())
	st2.refuse = "description devices"
	ch2 := open(t, d2, Credential{Username: "admin", Password: "s3cret"}).(Changer)
	r, err = ch2.Change(ctx, Change{ActDescription, ports, "devices"}, false)
	if err == nil || r.Applied || !strings.Contains(err.Error(), "invalid command") {
		t.Fatalf("refused: %v %+v", err, r)
	}
	if len(st2.sessions) != 0 || !reflect.DeepEqual(st2.ports, eosPorts()) {
		t.Errorf("left behind: %v %+v", st2.sessions, st2.ports)
	}
	aborted := false
	for _, q := range st2.requests {
		if len(q) == 2 && q[1] == "abort" {
			aborted = true
		}
	}
	if !aborted {
		t.Errorf("no abort: %q", st2.requests)
	}
	// a commit that changes nothing is caught by the read-back
	d3, st3 := eosWriteStub(t, eosPorts())
	st3.ignore = true
	ch3 := open(t, d3, Credential{Username: "admin", Password: "s3cret"}).(Changer)
	if _, err = ch3.Change(ctx, Change{ActDescription, ports[:1], "x"}, false); err == nil || !strings.Contains(err.Error(), "holds the description") {
		t.Errorf("silent: %v", err)
	}
	// the gate: a line that is not one of the forms is never sent
	e := &eos{}
	for _, bad := range []string{"reload", "write erase", "description a\nreload", "interface Ethernet1; reload", "configure terminal", "username x secret y", "description " + string([]byte{0x01}), ""} {
		if err := e.cfg(ctx, []string{bad}); err == nil || !strings.Contains(err.Error(), "not a line a change sends") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
