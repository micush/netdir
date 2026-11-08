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
	"testing"
)

const pbsUPID = "UPID:pbs1:0000A1:0000B2:5F000001:garbage_collection:backup1:root@pam!nd:"

type pxState struct {
	mu      sync.Mutex
	prefix  string // PBSAPIToken or PDMAPIToken
	cookie  string
	secret  string
	gets    []string
	writes  []string
	logins  int
	polls   int
	product string
}

func pxStub(t *testing.T, st *pxState) Device {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		out := func(code int, data any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		}
		b, _ := io.ReadAll(r.Body)
		p := strings.TrimPrefix(r.URL.Path, "/api2/json")
		if p == "/access/ticket" {
			f, _ := url.ParseQuery(string(b))
			if f.Get("username") != "admin@pbs" || f.Get("password") != "S3CRET" {
				out(401, nil)
				return
			}
			st.logins++
			out(200, map[string]any{"ticket": "PBS:admin@pbs:T" + strconv.Itoa(st.logins), "CSRFPreventionToken": "C" + strconv.Itoa(st.logins)})
			return
		}
		if st.secret != "" {
			if r.Header.Get("Authorization") != st.prefix+"=root@pam!nd:"+st.secret {
				out(401, nil)
				return
			}
		} else {
			c, err := r.Cookie(st.cookie)
			if v, _ := url.QueryUnescape(c.Value); err != nil || !strings.HasPrefix(v, "PBS:admin@pbs:T") { // the ticket travels percent-encoded
				out(401, nil)
				return
			}
			if r.Method != "GET" && r.Header.Get("CSRFPreventionToken") != "C"+strconv.Itoa(st.logins) {
				out(403, nil)
				return
			}
		}
		if r.Method != "GET" {
			st.writes = append(st.writes, r.Method+" "+p)
		} else {
			st.gets = append(st.gets, r.URL.RequestURI()[len("/api2/json"):])
		}
		switch {
		case p == "/version":
			out(200, map[string]any{"version": "3.2", "release": "6", "repoid": "x"})
		case p == "/nodes/localhost/status":
			out(200, map[string]any{"uptime": 1234, "info": map[string]any{"fingerprint": "aa:bb"}})
		case p == "/status/datastore-usage":
			out(200, []map[string]any{{"store": "backup1", "total": 100, "used": 40}, {"store": "backup2", "total": 10, "used": 1}})
		case p == "/nodes/localhost/network":
			out(200, []map[string]any{{"iface": "vmbr0", "type": "bridge", "active": 1, "cidr": "10.0.0.5/24"}})
		case p == "/admin/datastore/backup1/snapshots":
			out(200, []map[string]any{{"backup-id": "100", "backup-type": "vm", "password": "hunter2hunter2"}})
		case p == "/remotes/remote":
			out(200, []map[string]any{{"id": "prod", "type": "pve"}, {"id": "bk", "type": "pbs"}})
		case p == "/pve/remotes/prod/qemu":
			out(200, []map[string]any{{"vmid": 100, "name": "web"}})
		case p == "/admin/datastore/backup1/gc" && r.Method == "POST":
			out(200, pbsUPID)
		case strings.HasSuffix(p, "/tasks/"+pbsUPID+"/status"), strings.HasSuffix(p, "/tasks/"+url.PathEscape(pbsUPID)+"/status"):
			st.polls++
			if st.polls < 2 {
				out(200, map[string]any{"status": "running"})
			} else {
				out(200, map[string]any{"status": "stopped", "exitstatus": "OK"})
			}
		case p == "/config/sync/job1" && r.Method == "PUT":
			out(200, nil)
		case p == "/config/sync/job1":
			out(200, map[string]any{"id": "job1", "schedule": "daily"})
		case p == "/pve/remotes/prod/qemu/100/start" && r.Method == "POST":
			out(200, "prod!"+pbsUPID)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			out(404, nil)
		}
	}))
	t.Cleanup(srv.Close)
	pxTaskNow = 1
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "x", Platform: st.product, Address: h, Port: pn, Insecure: true}
}

func openPx(t *testing.T, platform string, st *pxState, c Credential) Driver {
	t.Helper()
	st.product = platform
	d := pxStub(t, st)
	drv, err := Open(d, c)
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestPBSRead(t *testing.T) {
	st := &pxState{prefix: "PBSAPIToken", secret: "SEC"}
	drv := openPx(t, "pbs", st, Credential{Name: "a", Token: "root@pam!nd:SEC"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.OSVersion != "3.2-6" || f.UptimeS != 1234 || !strings.Contains(f.Model, "2 datastore") {
		t.Fatalf("facts: %+v %v", f, err)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 1 || ifs[0].Name != "vmbr0" || ifs[0].Addresses[0] != "10.0.0.5/24" {
		t.Fatalf("interfaces: %+v %v", ifs, err)
	}
	out, err := drv.Show(ctx, "show snapshots store=backup1")
	if err != nil || !strings.Contains(out, "backup-id") || strings.Contains(out, "hunter2") {
		t.Fatalf("show: %q %v", out, err)
	}
	for _, bad := range []string{"show snapshots", "show snapshots store=a/b", "show nothing", "show version x=1", "version"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// the user name and token ID as the user name, the secret as the token
	st2 := &pxState{prefix: "PBSAPIToken", secret: "SEC"}
	d2 := openPx(t, "pbs", st2, Credential{Name: "b", Username: "root@pam!nd", Token: "SEC"})
	if _, err := d2.Facts(ctx); err != nil {
		t.Fatalf("token as user name and secret: %v", err)
	}
	if _, err := Open(Device{Name: "x", Platform: "pbs", Address: "127.0.0.1"}, Credential{Name: "c"}); err == nil {
		t.Fatal("no login accepted")
	}
}

func TestPBSTicketLogin(t *testing.T) {
	st := &pxState{cookie: "PBSAuthCookie"}
	drv := openPx(t, "pbs", st, Credential{Name: "a", Username: "admin@pbs", Password: "S3CRET"})
	if _, err := drv.Facts(context.Background()); err != nil || st.logins != 1 {
		t.Fatalf("ticket login: %v (%d logins)", err, st.logins)
	}
	if rc, _ := drv.(RawChanger); rc != nil {
		if _, err := rc.RawChange(context.Background(), Raw{Method: "POST", Path: "/admin/datastore/backup1/gc", Body: `{}`}, false); err != nil {
			t.Fatalf("a write with a ticket needs the CSRF token: %v", err)
		}
	}
}

func TestPBSAPIGet(t *testing.T) {
	st := &pxState{prefix: "PBSAPIToken", secret: "SEC"}
	a := openPx(t, "pbs", st, Credential{Name: "a", Token: "root@pam!nd:SEC"}).(APIer)
	ctx := context.Background()
	for _, ok := range []string{"/version", "/api2/json/version", "/status/datastore-usage", "/admin/datastore/backup1/snapshots"} {
		if _, _, err := a.APIGet(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	before := len(st.gets)
	for _, bad := range []string{"/access/users", "/access/ticket", "/nodes/localhost/termproxy", "/admin/datastore/b/pxar-file-download", "/admin/datastore/b/download", "/config/tape-encryption-keys",
		"/../access", "version", "/nodes/a b", "/version?%zz"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s read", bad)
		}
	}
	if len(st.gets) != before {
		t.Errorf("a refused path reached PBS: %v", st.gets[before:])
	}
}

func TestPBSChange(t *testing.T) {
	st := &pxState{prefix: "PBSAPIToken", secret: "SEC"}
	rc := openPx(t, "pbs", st, Credential{Name: "a", Token: "root@pam!nd:SEC"}).(RawChanger)
	ctx := context.Background()
	for _, bad := range []Raw{
		{Method: "POST", Path: "/access/users", Body: `{}`},
		{Method: "PUT", Path: "/access/acl", Body: `{}`},
		{Method: "POST", Path: "/nodes/localhost/status", Body: `{"command":"shutdown"}`},
		{Method: "POST", Path: "/nodes/localhost/services/proxmox-backup-proxy/stop", Body: `{}`},
		{Method: "POST", Path: "/nodes/localhost/certificates/custom", Body: `{}`},
		{Method: "POST", Path: "/nodes/localhost/disks/wipedisk", Body: `{}`},
		{Method: "DELETE", Path: "/admin/datastore/backup1/snapshots"},
		{Method: "DELETE", Path: "/admin/datastore/backup1/groups"},
		{Method: "DELETE", Path: "/config/datastore/backup1"},
		{Method: "POST", Path: "/admin/datastore/backup1/prune-datastore", Body: `{"keep-last":1}`},
		{Method: "POST", Path: "/admin/prune/job1/run", Body: `{}`},
		{Method: "POST", Path: "/admin/sync/job1/run", Body: `{"remove-vanished":true}`},
		{Method: "POST", Path: "/version", Body: `{}`},
		{Method: "PUT", Path: "/config/sync/job1?x=1", Body: `{}`},
		{Method: "PUT", Path: "/config/sync/job1", Body: `{bad`},
		{Method: "PUT", Path: "/config/sync/job1"},
		{Method: "GET", Path: "/version"},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if len(st.writes) != 0 {
		t.Fatalf("a refused change was sent: %v", st.writes)
	}
	r, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "/config/sync/job1", Body: `{"schedule":"hourly"}`}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "daily") || len(st.writes) != 0 {
		t.Fatalf("dry run: %+v %v %v", r, err, st.writes)
	}
	if r, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/api2/json/config/sync/job1", Body: `{"schedule":"hourly"}`}, false); err != nil || !r.Applied {
		t.Fatalf("put: %+v %v", r, err)
	}
	r, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/admin/datastore/backup1/gc", Body: `{}`}, false)
	if err != nil || !r.Applied || !strings.Contains(r.Answer, "ended: OK") || st.polls < 2 {
		t.Fatalf("task: %+v %v (%d polls)", r, err, st.polls)
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/admin/datastore/backup1/prune-datastore", Body: `{"dry-run": true, "keep-last":1}`}, true); err != nil {
		t.Errorf("a dry-run prune: %v", err)
	}
}

func TestPDMReadAndChange(t *testing.T) {
	st := &pxState{prefix: "PDMAPIToken", secret: "SEC"}
	drv := openPx(t, "pdm", st, Credential{Name: "a", Token: "root@pam!nd:SEC"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.OSVersion != "3.2-6" || !strings.Contains(f.Model, "2 remote") {
		t.Fatalf("facts: %+v %v", f, err)
	}
	out, err := drv.Show(ctx, "show pve-qemu remote=prod")
	if err != nil || !strings.Contains(out, "web") {
		t.Fatalf("show: %q %v", out, err)
	}
	if _, err := drv.Show(ctx, "show pve-qemu"); err == nil {
		t.Error("a per-remote read without remote= accepted")
	}
	a := drv.(APIer)
	if _, _, err := a.APIGet(ctx, "/remotes/remote"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.APIGet(ctx, "/access/users"); err == nil {
		t.Error("/access read")
	}
	rc := drv.(RawChanger)
	for _, bad := range []Raw{
		{Method: "DELETE", Path: "/remotes/remote/prod"},
		{Method: "DELETE", Path: "/pve/remotes/prod/qemu/100"},
		{Method: "POST", Path: "/pve/remotes/prod/qemu/100/remote-migrate", Body: `{}`},
		{Method: "POST", Path: "/pve/remotes/prod/qemu/100/snapshot/s1/rollback", Body: `{}`},
		{Method: "POST", Path: "/access/users", Body: `{}`},
		{Method: "POST", Path: "/nodes/localhost/status", Body: `{}`},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	r, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/pve/remotes/prod/qemu/100/start", Body: `{}`}, false)
	if err != nil || !r.Applied || !strings.Contains(r.Note, "task was started") {
		t.Fatalf("start: %+v %v", r, err)
	}
}

func TestPxmxDefaultPorts(t *testing.T) {
	if DefaultPort("pbs") != 8007 || DefaultPort("pdm") != 8443 {
		t.Fatal("ports")
	}
}

// Backup Server's /admin tree and a datastore called "backup" are read over MCP and by the driver; the places of accounts, consoles and the
// backup protocol are not.
func TestPBSPathsAndDatastoreNames(t *testing.T) {
	for _, plat := range []string{"pbs", "pdm", "proxmox"} {
		if err := CheckAPIPathMCPFor(plat, "/admin/datastore/backup/snapshots"); err != nil {
			t.Errorf("%s: the MCP check refuses a datastore tree: %v", plat, err)
		}
	}
	for _, p := range []string{"/admin/datastore", "/admin/datastore/backup/status", "/admin/gc", "/config/key"} {
		if err := CheckAPIPathMCP(p); err == nil {
			t.Errorf("another platform's path %s is no longer refused over MCP", p)
		}
		if err := CheckAPIPathMCPFor("iosxe", p); err == nil {
			t.Errorf("iosxe %s is no longer refused over MCP", p)
		}
	}
	p := &pxmx{spec: pbsSpec}
	for _, ok := range []string{"/admin/datastore", "/admin/datastore/backup/status", "/admin/datastore/backup/snapshots", "/config/datastore/backup",
		"/admin/gc", "/admin/sync", "/status/datastore-usage", "/nodes/localhost/tasks?errors=1", "/config/remote/access"} {
		if _, err := p.read(ok); err != nil {
			t.Errorf("read %s: %v", ok, err)
		}
	}
	for _, no := range []string{"/access/users", "/backup", "/admin/datastore/s1/download", "/nodes/localhost/termproxy", "/admin/datastore/s1/pxar-file-download", "/tfa"} {
		if _, err := p.read(no); err == nil {
			t.Errorf("read %s is allowed", no)
		}
	}
	// a change: a datastore called backup is changed like any other, the backup protocol and downloads are not
	if err := p.rawGuard("POST", "/admin/datastore/backup/gc"); err != nil {
		t.Errorf("a datastore called backup: %v", err)
	}
	for _, no := range []string{"/access/users", "/backup", "/admin/datastore/s1/download"} {
		if err := p.rawGuard("POST", no); err == nil {
			t.Errorf("change %s is allowed", no)
		}
	}
}
