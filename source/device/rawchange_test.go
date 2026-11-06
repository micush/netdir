package device

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type rawSrv struct {
	mu   sync.Mutex
	reqs []string // "METHOD uri"
	body map[string]string
}

func (s *rawSrv) log(r *http.Request, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r.Method+" "+r.URL.RequestURI())
	if s.body == nil {
		s.body = map[string]string{}
	}
	s.body[r.Method+" "+r.URL.Path] = body
}

func (s *rawSrv) count(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.reqs {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func rawStub(t *testing.T, platform string, h func(w http.ResponseWriter, r *http.Request, body string)) (Device, *rawSrv) {
	t.Helper()
	st := &rawSrv{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		st.log(r, string(b))
		h(w, r, string(b))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "x1", Platform: platform, Address: host, Port: pn, Insecure: true}, st
}

var rawAny = Credential{Username: "admin", Password: "s3cret", Token: ""}

// A change a guard refuses never reaches the device.
func TestRawGuards(t *testing.T) {
	cases := []struct {
		plat string
		cred Credential
		raw  Raw
		want string
	}{
		{"iosxe", rawAny, Raw{Method: "POST", Path: "/restconf/operations/cisco-ia:save-config"}, "restconf/data"},
		{"iosxe", rawAny, Raw{Method: "GET", Path: "/restconf/data/x"}, "method"},
		{"iosxe", rawAny, Raw{Method: "PATCH", Path: "/restconf/data/../x", Body: "{}"}, "path"},
		{"iosxe", rawAny, Raw{Method: "PATCH", Path: "/restconf/data/x", Body: "not json"}, "JSON"},
		{"iosxe", rawAny, Raw{Method: "PATCH", Path: "/restconf/data/x", Lines: []string{"x"}}, "lines"},
		{"aoscx", rawAny, Raw{Method: "POST", Path: "/rest/v10.09/login"}, "login"},
		{"fortios", Credential{Token: "T"}, Raw{Method: "PUT", Path: "/api/v2/cmdb/system/admin/admin", Body: "{}"}, "administrators"},
		{"fortios", Credential{Token: "T"}, Raw{Method: "POST", Path: "/api/v2/monitor/system/reboot"}, "cmdb"},
		{"nios", rawAny, Raw{Method: "POST", Path: "/wapi/v2.12/fileop?_function=restartservices"}, "file operations"},
		{"bigip", rawAny, Raw{Method: "POST", Path: "/mgmt/tm/sys/ucs", Body: "{}"}, "not touched"},
		{"bigip", rawAny, Raw{Method: "POST", Path: "/mgmt/tm/sys", Body: `{"command":"halt"}`}, "halt"},
		{"technitium", Credential{Token: "T"}, Raw{Method: "POST", Path: "/api/user/create"}, "users"},
		{"panos", Credential{Token: "KEYKEYKEY"}, Raw{Method: "set", Path: "/config/mgt-config/users", Body: "<entry/>"}, "mgt-config"},
		{"panos", Credential{Token: "KEYKEYKEY"}, Raw{Method: "set", Path: "/config/devices", Body: "no xml"}, "XML"},
		{"eos", rawAny, Raw{Lines: []string{"interface Ethernet1", "reload"}}, "not sent"},
		{"eos", rawAny, Raw{Lines: []string{"commit"}}, "not sent"},
		{"eos", rawAny, Raw{Lines: []string{"interface Management1", "shutdown"}}, "not sent"},
		{"nxos", rawAny, Raw{Lines: []string{"copy running-config startup-config"}}, "not sent"},
		{"nxos", rawAny, Raw{Lines: []string{"no feature nxapi"}}, "not sent"},
		{"nxos", rawAny, Raw{Lines: []string{"a\x00b"}}, "control"},
		{"nxos", rawAny, Raw{Lines: []string{"  ", "! comment"}}, "nothing"},
	}
	for _, c := range cases {
		d, st := rawStub(t, c.plat, func(w http.ResponseWriter, r *http.Request, b string) {
			t.Errorf("%s: a request reached the device: %s %s", c.plat, r.Method, r.URL)
			w.WriteHeader(500)
		})
		drv := open(t, d, c.cred)
		rc, ok := drv.(RawChanger)
		if !ok {
			t.Fatalf("%s is not a RawChanger", c.plat)
		}
		_, err := rc.RawChange(context.Background(), c.raw, false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %+v: %v (want %q)", c.plat, c.raw, err, c.want)
		}
		if len(st.reqs) != 0 {
			t.Errorf("%s: requests %v", c.plat, st.reqs)
		}
	}
}

type xeRaw struct {
	mu                    sync.Mutex
	val                   string
	failPatch, breakAfter bool
}

func TestRawRESTChange(t *testing.T) {
	x := &xeRaw{val: `{"Cisco-IOS-XE-native:ntp":{"server":"1.1.1.1"}}`}
	d, st := rawStub(t, "iosxe", func(w http.ResponseWriter, r *http.Request, body string) {
		x.mu.Lock()
		defer x.mu.Unlock()
		w.Header().Set("Content-Type", yangJSON)
		switch {
		case r.URL.Path == "/restconf/data/Cisco-IOS-XE-native:native/hostname":
			if x.breakAfter && x.val != `{"Cisco-IOS-XE-native:ntp":{"server":"1.1.1.1"}}` {
				w.WriteHeader(500)
				return
			}
			_, _ = io.WriteString(w, `{"Cisco-IOS-XE-native:hostname":"sw"}`)
		case r.URL.Path == "/restconf/data/Cisco-IOS-XE-native:native/ntp" && r.Method == "GET":
			_, _ = io.WriteString(w, x.val)
		case r.URL.Path == "/restconf/data/Cisco-IOS-XE-native:native/ntp" && (r.Method == "PATCH" || r.Method == "PUT"):
			if r.Method == "PATCH" && x.failPatch {
				x.val = `{"half":"applied"}`
				w.WriteHeader(500)
				return
			}
			if r.Method == "PATCH" && strings.Contains(body, "refuse") {
				w.WriteHeader(400)
				return
			}
			x.val = body
			w.WriteHeader(204)
		case r.URL.Path == "/restconf/operations/cisco-ia:save-config":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	})
	drv := open(t, d, rawAny).(RawChanger)
	ctx := context.Background()
	const p = "/restconf/data/Cisco-IOS-XE-native:native/ntp"
	const old = `{"Cisco-IOS-XE-native:ntp":{"server":"1.1.1.1"}}`
	nw := `{"Cisco-IOS-XE-native:ntp":{"server":"2.2.2.2"}}`

	// dry run: the old state is shown, nothing is written
	r, err := drv.RawChange(ctx, Raw{Method: "patch", Path: p, Body: nw}, true)
	if err != nil || !r.DryRun || r.Applied || !strings.Contains(r.Before, "1.1.1.1") || x.val != old || st.count("PATCH") != 0 {
		t.Fatalf("dry: %v %+v %s", err, r, x.val)
	}
	// apply, and save
	r, err = drv.RawChange(ctx, Raw{Method: "PATCH", Path: p, Body: nw, Save: true}, false)
	if err != nil || !r.Applied || !r.Saved || x.val != nw || r.RolledBack {
		t.Fatalf("apply: %v %+v", err, r)
	}
	// a refusal (400) changed nothing and puts nothing back
	x.val = old
	puts := st.count("PUT")
	r, err = drv.RawChange(ctx, Raw{Method: "PATCH", Path: p, Body: `{"refuse":1}`}, false)
	if err == nil || r.Applied || r.RolledBack || st.count("PUT") != puts || x.val != old {
		t.Fatalf("refused: %v %+v", err, r)
	}
	// a 500 may have half applied: the old state is put back
	x.failPatch = true
	r, err = drv.RawChange(ctx, Raw{Method: "PATCH", Path: p, Body: nw}, false)
	if err == nil || r.Applied || !r.RolledBack || x.val != old {
		t.Fatalf("500: %v %+v %s", err, r, x.val)
	}
	// the device stops answering after the change: put back
	x.failPatch, x.breakAfter = false, true
	r, err = drv.RawChange(ctx, Raw{Method: "PATCH", Path: p, Body: nw}, false)
	if err == nil || !strings.Contains(err.Error(), "did not answer") || !r.Applied || !r.RolledBack {
		t.Fatalf("alive: %v %+v", err, r)
	}
}

func TestRawFortiOSPutsBackTheFirstResult(t *testing.T) {
	cur := `{"status":"success","results":[{"name":"a","subnet":"10.0.0.0 255.0.0.0"}]}`
	var put string
	d, _ := rawStub(t, "fortios", func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "GET":
			if strings.Contains(r.URL.Path, "monitor") {
				_, _ = io.WriteString(w, `{"status":"success","results":{}}`)
				return
			}
			_, _ = io.WriteString(w, cur)
		case "PUT":
			put = body
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"status":"success"}`)
		}
	})
	drv := open(t, d, Credential{Token: "T"}).(RawChanger)
	// the device stops answering after the change
	d2, _ := rawStub(t, "fortios", func(w http.ResponseWriter, r *http.Request, body string) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "monitor"):
			w.WriteHeader(500)
		case r.Method == "GET":
			_, _ = io.WriteString(w, cur)
		case r.Method == "PUT" && !strings.Contains(body, "10.0.0.0"):
			_, _ = io.WriteString(w, `{"status":"success"}`)
		default:
			put = body
			_, _ = io.WriteString(w, `{"status":"success"}`)
		}
	})
	_ = drv
	r, err := open(t, d2, Credential{Token: "T"}).(RawChanger).RawChange(context.Background(),
		Raw{Method: "PUT", Path: "/api/v2/cmdb/firewall/address/a", Body: `{"subnet":"192.168.0.0 255.255.0.0"}`}, false)
	if err == nil || !r.Applied || !r.RolledBack {
		t.Fatalf("%v %+v", err, r)
	}
	var m map[string]any
	if json.Unmarshal([]byte(put), &m) != nil || m["name"] != "a" || m["results"] != nil {
		t.Errorf("restored body: %s", put)
	}
}

func TestRawTechnitium(t *testing.T) {
	d, st := rawStub(t, "technitium", func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","response":{"added":true}}`)
	})
	drv := open(t, d, Credential{Token: "APITOKEN"}).(RawChanger)
	raw := Raw{Method: "POST", Path: "/api/zones/records/add", Body: "zone=example.com&domain=a.example.com&type=A&ipAddress=1.2.3.4"}
	r, err := drv.RawChange(context.Background(), raw, true)
	if err != nil || r.Applied || len(st.reqs) != 0 {
		t.Fatalf("dry: %v %+v %v", err, r, st.reqs)
	}
	r, err = drv.RawChange(context.Background(), raw, false)
	if err != nil || !r.Applied || !strings.Contains(st.body["POST /api/zones/records/add"], "ipAddress=1.2.3.4") || !strings.Contains(r.Answer, "added") {
		t.Fatalf("apply: %v %+v %v", err, r, st.body)
	}
}

func TestRawPANOS(t *testing.T) {
	d, st := rawStub(t, "panos", func(w http.ResponseWriter, r *http.Request, body string) {
		if r.Header.Get("X-PAN-KEY") != "KEYKEYKEY" {
			w.WriteHeader(403)
			return
		}
		q := r.URL.Query()
		w.Header().Set("Content-Type", "application/xml")
		if q.Get("action") == "get" {
			_, _ = io.WriteString(w, `<response status="success"><result total-count="1"><entry name="a"><ip-netmask>10.0.0.1</ip-netmask></entry></result></response>`)
			return
		}
		_, _ = io.WriteString(w, `<response status="success" code="20"><msg>command succeeded</msg></response>`)
	})
	drv := open(t, d, Credential{Token: "KEYKEYKEY"}).(RawChanger)
	x := "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='a']"
	r, err := drv.RawChange(context.Background(), Raw{Method: "edit", Path: x, Body: "<entry name='a'><ip-netmask>10.0.0.2</ip-netmask></entry>"}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "10.0.0.1") || st.count("GET /api/?action=edit") != 0 {
		t.Fatalf("dry: %v %+v %v", err, r, st.reqs)
	}
	r, err = drv.RawChange(context.Background(), Raw{Method: "edit", Path: x, Body: "<entry name='a'><ip-netmask>10.0.0.2</ip-netmask></entry>", Save: true}, false)
	if err != nil || !r.Applied || !r.Saved || st.count("GET /api/?cmd=%3Ccommit") != 1 {
		t.Fatalf("apply: %v %+v %v", err, r, st.reqs)
	}
}

func eosRawStub(t *testing.T, failLine string) (Device, *[][]string) {
	var mu sync.Mutex
	var reqs [][]string
	d, _ := rawStub(t, "eos", func(w http.ResponseWriter, r *http.Request, body string) {
		var req struct {
			Params struct{ Cmds []string }
		}
		_ = json.Unmarshal([]byte(body), &req)
		mu.Lock()
		reqs = append(reqs, req.Params.Cmds)
		mu.Unlock()
		res := make([]any, len(req.Params.Cmds))
		for i, c := range req.Params.Cmds {
			res[i] = J{}
			if c == failLine {
				_ = json.NewEncoder(w).Encode(J{"error": J{"code": 1002, "message": "invalid command"}})
				return
			}
			if c == "show session-config diffs" {
				res[i] = J{"output": "+ interface Ethernet1\n+   description x\n"}
			}
		}
		_ = json.NewEncoder(w).Encode(J{"jsonrpc": "2.0", "id": "netdir", "result": res})
	})
	return d, &reqs
}

func TestRawEOS(t *testing.T) {
	d, reqs := eosRawStub(t, "")
	drv := open(t, d, rawAny).(RawChanger)
	ctx := context.Background()
	lines := []string{"interface Ethernet1", "description x"}
	r, err := drv.RawChange(ctx, Raw{Lines: lines}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "description x") {
		t.Fatalf("dry: %v %+v", err, r)
	}
	if last := (*reqs)[len(*reqs)-1]; last[len(last)-1] != "abort" {
		t.Errorf("dry run did not abort: %v", last)
	}
	*reqs = nil
	r, err = drv.RawChange(ctx, Raw{Lines: lines, Save: true}, false)
	if err != nil || !r.Applied || !r.Saved {
		t.Fatalf("apply: %v %+v", err, r)
	}
	var flat []string
	for _, q := range *reqs {
		flat = append(flat, strings.Join(q, " | "))
	}
	j := strings.Join(flat, "\n")
	for _, want := range []string{"description x | commit timer 00:03:00", "show version", "commit\n", "write memory"} {
		if !strings.Contains(j+"\n", want) {
			t.Errorf("missing %q in\n%s", want, j)
		}
	}
	// a refused line aborts the session and says nothing was committed
	d2, reqs2 := eosRawStub(t, "bogus")
	_, err = open(t, d2, rawAny).(RawChanger).RawChange(ctx, Raw{Lines: []string{"bogus"}}, false)
	if err == nil || !strings.Contains(err.Error(), "nothing was committed") {
		t.Fatalf("refused: %v", err)
	}
	if last := (*reqs2)[len(*reqs2)-1]; last[len(last)-1] != "abort" {
		t.Errorf("no abort: %v", last)
	}
}

func TestRawNXOS(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	fail := ""
	d, _ := rawStub(t, "nxos", func(w http.ResponseWriter, r *http.Request, body string) {
		var req struct {
			Ins map[string]any `json:"ins_api"`
		}
		_ = json.Unmarshal([]byte(body), &req)
		typ, _ := req.Ins["type"].(string)
		in, _ := req.Ins["input"].(string)
		mu.Lock()
		seen = append(seen, typ+" "+in)
		mu.Unlock()
		out := J{"input": in, "msg": "Success", "code": "200"}
		if fail != "" && strings.Contains(in, fail) {
			out["code"], out["msg"] = "400", "Invalid command"
		}
		if typ == "cli_show" {
			out["body"] = J{"host_name": "n9k"}
		}
		_ = json.NewEncoder(w).Encode(J{"ins_api": J{"outputs": J{"output": out}}})
	})
	drv := open(t, d, rawAny).(RawChanger)
	ctx := context.Background()
	r, err := drv.RawChange(ctx, Raw{Lines: []string{"vlan 10", "name x"}, Save: true}, false)
	if err != nil || !r.Applied || !r.Saved || r.RolledBack {
		t.Fatalf("apply: %v %+v", err, r)
	}
	j := strings.Join(seen, "\n")
	for _, want := range []string{"cli_conf vlan 10 ;name x", "cli_show_ascii checkpoint netdir", "cli_show_ascii no checkpoint netdir", "copy running-config startup-config"} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in\n%s", want, j)
		}
	}
	seen, fail = nil, "name bad"
	r, err = drv.RawChange(ctx, Raw{Lines: []string{"vlan 11", "name bad"}}, false)
	if err == nil || r.Applied || !r.RolledBack || !strings.Contains(strings.Join(seen, "\n"), "rollback running-config checkpoint netdir") {
		t.Fatalf("refused: %v %+v\n%v", err, r, seen)
	}
}
