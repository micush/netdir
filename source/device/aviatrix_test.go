package device

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type avxState struct {
	mu      sync.Mutex
	actions []string
	forms   []url.Values
	expire  atomic.Int32
	logins  atomic.Int32
}

func (s *avxState) joined() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.actions, ",")
}

// avxStub is an Aviatrix controller: /v2/api takes forms, get_api_token then login (X-Access-Key) give the session C<n>.
func avxStub(t *testing.T, st *avxState) Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.Path != "/v2/api" {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		b, _ := io.ReadAll(r.Body)
		f, _ := url.ParseQuery(string(b))
		st.mu.Lock()
		st.actions = append(st.actions, f.Get("action"))
		st.forms = append(st.forms, f)
		st.mu.Unlock()
		send := func(ok bool, results any, reason string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(J{"return": ok, "results": results, "reason": reason})
		}
		switch f.Get("action") {
		case "get_api_token":
			send(true, J{"api_token": "APITOK"}, "")
			return
		case "login":
			if r.Header.Get("X-Access-Key") != "APITOK" || f.Get("username") != "admin" || f.Get("password") != "pw" {
				send(false, "", "Invalid username or password")
				return
			}
			n := st.logins.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(J{"return": true, "results": "ok", "CID": "C" + strconv.Itoa(int(n))})
			return
		}
		if f.Get("CID") != "C"+strconv.Itoa(int(st.logins.Load())) || st.expire.Add(-1) >= 0 {
			send(false, "", "CID is invalid or expired.")
			return
		}
		switch f.Get("action") {
		case "list_vpcs_summary":
			gw := J{"vpc_name": "transit1", "vpc_id": "vpc-1", "cloud_type": "1", "account_name": "aws1", "vpc_region": "us-east-1", "vpc_size": "c5.xlarge",
				"public_ip": "8.8.4.4", "private_ip": "10.0.0.5", "inst_state": "running"}
			if n := f.Get("gateway_name"); n != "" && n != "transit1" {
				send(true, []J{}, "")
				return
			}
			send(true, []J{gw, {"vpc_name": "spoke1", "inst_state": "stopped", "private_ip": "10.1.0.5"}}, "")
		case "get_gateway_info":
			send(true, J{"vpc_name": "transit1", "bgp_enabled": true, "snmp_community": "SECRETCOMM"}, "")
		case "list_inter_transit_gateway_peering":
			send(true, [][]J{{{"site1": "transit1", "site2": "transit2"}}, {{"site1": "x", "site2": "y"}}}, "")
		case "list_version_info":
			send(true, J{"current_version": "7.1-1234"}, "")
		case "edit_gw_config":
			send(true, J{"request_id": "r1"}, "")
		case "list_users":
			t.Error("a denied read reached the controller")
		default:
			send(false, "", "unknown action "+f.Get("action"))
		}
	}))
	t.Cleanup(srv.Close)
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "avx", Platform: "aviatrix", Address: h, Port: pn, Insecure: true}
}

func TestAviatrix(t *testing.T) {
	st := &avxState{}
	d := avxStub(t, st)
	ctx := context.Background()
	drv := open(t, d, Credential{Username: "admin", Password: "pw"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Aviatrix" || !strings.Contains(f.Model, "2 gateways") || f.OSVersion != "7.1-1234" {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[0].OperUp == nil || !*ifs[0].OperUp || *ifs[1].OperUp {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	// the session expires once: the driver signs in again and the call goes through
	st.expire.Store(1)
	out, err := drv.Show(ctx, "show gateways")
	if err != nil || !strings.Contains(out, "transit1") || st.logins.Load() != 2 {
		t.Fatalf("expired session: %v logins %d\n%s", err, st.logins.Load(), out)
	}
	out, err = drv.Show(ctx, "show gateway transit1")
	if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "bgp_enabled") || !strings.Contains(out, "transit2") || strings.Contains(out, `"x"`) || strings.Contains(out, "SECRETCOMM") {
		t.Fatalf("show gateway: %v\n%s", err, out)
	}
	if _, err := drv.Show(ctx, "show gateway nope"); err == nil || !strings.Contains(err.Error(), "no gateway") {
		t.Errorf("unknown gateway: %v", err)
	}
	if out, err := drv.Show(ctx, "show transit"); err != nil || !strings.Contains(out, "transit1") {
		t.Errorf("transit %v", err)
	}
	if out, err := drv.Show(ctx, "show get_gateway_info gateway_name=transit1"); err != nil || !strings.Contains(out, "bgp_enabled") {
		t.Errorf("raw read %v", err)
	}
	for _, bad := range []string{"show", "show list_users", "show get_api_token", "show list_admin_accounts", "show edit_gw_config", "show login", "show get_gateway_info password=x",
		"show list_vpcs_summary CID=x", "show list_vpcs_summary a", "show gateways | include x"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	v, text, err := drv.(APIer).APIGet(ctx, "/get_gateway_info?gateway_name=transit1")
	if err != nil || text || strings.Contains(toJSON(v), "SECRETCOMM") {
		t.Fatalf("apiget %v %v", err, v)
	}
	for _, bad := range []string{"/list_users", "/a/b", "/", "/edit_gw_config"} {
		if _, _, err := drv.(APIer).APIGet(ctx, bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	for _, f := range st.forms {
		if f.Get("action") != "get_api_token" && f.Get("action") != "login" && f.Get("CID") == "" {
			t.Errorf("a call without a session ID: %v", f)
		}
	}
}

func TestAviatrixChangeAndLogin(t *testing.T) {
	st := &avxState{}
	d := avxStub(t, st)
	ctx := context.Background()
	bad, _ := Open(d, Credential{Username: "admin", Password: "wrong"})
	if _, err := bad.Facts(ctx); err == nil || !strings.Contains(err.Error(), "sign-in failed") {
		t.Errorf("bad login: %v", err)
	}
	if _, err := Open(d, Credential{Token: "x"}); err == nil {
		t.Error("a token alone was accepted")
	}
	rc := open(t, d, Credential{Username: "admin", Password: "pw"}).(RawChanger)
	r, err := rc.RawChange(ctx, Raw{Method: "POST", Body: `{"action":"edit_gw_config","gateway_name":"transit1","size":"c5.2xlarge"}`}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "bgp_enabled") || strings.Contains(r.Before, "SECRETCOMM") || strings.Contains(st.joined(), "edit_gw_config") {
		t.Fatalf("dry %+v %v", r, err)
	}
	r, err = rc.RawChange(ctx, Raw{Method: "post", Body: "action=edit_gw_config&gateway_name=transit1&CID=evil"}, false)
	if err != nil || !r.Applied || !strings.Contains(r.Answer, "r1") {
		t.Fatalf("change %+v %v", r, err)
	}
	last := st.forms[len(st.forms)-1]
	if last.Get("action") != "edit_gw_config" || last.Get("CID") == "evil" || last.Get("CID") == "" {
		t.Errorf("sent %v", last)
	}
	for _, b := range []Raw{
		{Method: "GET", Body: `{"action":"edit_gw_config"}`},
		{Method: "POST", Body: `{"action":"login","username":"a","password":"b"}`},
		{Method: "POST", Body: `{"action":"add_admin_user"}`},
		{Method: "POST", Body: `{"action":"delete_container","gateway_name":"x"}`},
		{Method: "POST", Body: `{"action":"edit_gw_config","password":"x"}`},
		{Method: "POST", Body: `{"action":"list_vpcs_summary"}`},
		{Method: "POST", Body: `{"gateway_name":"x"}`},
		{Method: "POST", Path: "/other", Body: `{"action":"edit_gw_config"}`},
		{Method: "POST", Body: `{bad`},
		{Lines: []string{"x"}, Method: "POST"},
	} {
		if _, err := rc.RawChange(ctx, b, false); err == nil {
			t.Errorf("%+v accepted", b)
		}
	}
	if strings.Count(st.joined(), "edit_gw_config") != 1 {
		t.Errorf("refused changes were sent: %s", st.joined())
	}
	if _, err := Open(Device{Name: "x", Platform: "aviatrix", Address: "h", Options: map[string]string{"api_path": "/x"}}, Credential{Username: "a", Password: "b"}); err == nil {
		t.Error("bad api_path accepted")
	}
}
