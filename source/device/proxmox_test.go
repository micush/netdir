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
	"time"
)

type pveState struct {
	mu      sync.Mutex
	logins  int
	expire  bool // the next authenticated call answers 401 once (ticket mode)
	gets    []string
	writes  []string
	csrfOK  bool
	polls   map[string]int
	bodyOf  map[string]string
	ticket  string
	secret  string
	hasAuth bool
}

const (
	pveUPIDOK   = "UPID:pve2:0000A1:0000B2:5F000001:qmstart:100:root@pam!nd:"
	pveUPIDFail = "UPID:pve2:0000A1:0000B3:5F000002:qmstart:101:root@pam!nd:"
)

func pveStub(t *testing.T, st *pveState) Device {
	t.Helper()
	st.polls, st.bodyOf = map[string]int{}, map[string]string{}
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
			if f.Get("username") != "root@pam" || f.Get("password") != "S3CRET" {
				out(401, nil)
				return
			}
			st.logins++
			st.ticket = "T" + strconv.Itoa(st.logins)
			out(200, map[string]any{"ticket": st.ticket, "CSRFPreventionToken": "C" + strconv.Itoa(st.logins), "username": "root@pam"})
			return
		}
		if st.secret != "" { // token mode
			if r.Header.Get("Authorization") != "PVEAPIToken=root@pam!nd="+st.secret {
				out(401, nil)
				return
			}
		} else {
			if r.Header.Get("Cookie") != "PVEAuthCookie="+st.ticket || st.expire {
				st.expire = false
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
			st.bodyOf[r.Method+" "+p] = string(b)
		} else {
			st.gets = append(st.gets, r.URL.RequestURI()[len("/api2/json"):])
		}
		task := func(upid, exit string) {
			st.polls[upid]++
			if st.polls[upid] < 2 {
				out(200, map[string]any{"status": "running"})
				return
			}
			out(200, map[string]any{"status": "stopped", "exitstatus": exit})
		}
		switch {
		case p == "/version" && r.Method == "GET":
			out(200, map[string]any{"version": "8.2.4", "release": "8.2", "repoid": "x"})
		case p == "/cluster/status":
			out(200, []map[string]any{{"type": "cluster", "name": "prod", "nodes": 2, "quorate": 1}, {"type": "node", "name": "pve1", "local": 1, "online": 1}, {"type": "node", "name": "pve2", "local": 0, "online": 0}})
		case p == "/nodes":
			out(200, []map[string]any{{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"}})
		case p == "/cluster/resources" && r.URL.Query().Get("type") == "storage":
			out(200, []map[string]any{{"type": "storage", "storage": "local", "status": "available"}, {"type": "storage", "storage": "nfs1", "status": "unknown"}})
		case p == "/cluster/resources":
			out(200, []map[string]any{{"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve2", "name": "web"}, {"id": "lxc/200", "type": "lxc", "vmid": 200, "node": "pve1", "name": "ct"}})
		case p == "/nodes/pve1/network":
			out(200, []map[string]any{{"iface": "vmbr0", "type": "bridge", "active": 1, "cidr": "10.0.0.2/24", "comments": "lan"}, {"iface": "eno1", "type": "eth", "active": 0}})
		case p == "/nodes/pve2/qemu/100/config" && r.Method == "GET":
			out(200, map[string]any{"name": "web", "memory": 1024, "cipassword": "hunter2hunter2", "digest": "abc"})
		case r.Method == "GET" && (p == "/nodes/pve2/qemu/100/resize" || p == "/nodes/pve2/qemu/100" || p == "/nodes/pve1/lxc/200"): // the read before a change
			out(200, map[string]any{})
		case strings.HasPrefix(p, "/access/users/") && r.Method == "GET", p == "/nodes/pve2/qemu/100/unlink" && r.Method == "GET":
			out(501, nil)
		case strings.HasPrefix(p, "/access/users/") && r.Method == "PUT", p == "/nodes/pve2/qemu/100/unlink" && r.Method == "PUT":
			out(200, nil)
		case p == "/nodes/pve1/lxc/200/resize" && r.Method == "GET": // an action: Proxmox answers a read of it with "not implemented"
			out(501, nil)
		case p == "/nodes/pve2/qemu/100/status/current":
			out(200, map[string]any{"status": "stopped", "vmid": 100})
		case p == "/nodes/pve2/qemu/100/config" && r.Method == "PUT", p == "/nodes/pve2/qemu/100/resize" && r.Method == "PUT", p == "/nodes/pve1/lxc/200/resize" && r.Method == "PUT",
			p == "/nodes/pve1/qemu" && r.Method == "POST", p == "/nodes/pve1/lxc" && r.Method == "POST",
			p == "/nodes/pve2/qemu/100" && r.Method == "DELETE", p == "/nodes/pve1/lxc/200" && r.Method == "DELETE":
			out(200, nil)
		case p == "/nodes/pve2/qemu/100/status/start" && r.Method == "POST":
			out(200, pveUPIDOK)
		case p == "/nodes/pve2/qemu/101/status/start" && r.Method == "POST":
			out(200, pveUPIDFail)
		case strings.HasSuffix(p, "/tasks/"+pveUPIDOK+"/status"), strings.HasSuffix(p, "/tasks/"+url.PathEscape(pveUPIDOK)+"/status"):
			task(pveUPIDOK, "OK")
		case strings.HasSuffix(p, "/tasks/"+pveUPIDFail+"/status"):
			task(pveUPIDFail, "start failed: exit code 255")
		case strings.HasSuffix(p, "/tasks/"+pveUPIDFail+"/log"):
			out(200, []map[string]any{{"n": 1, "t": "kvm: cannot allocate memory"}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			out(404, nil)
		}
	}))
	t.Cleanup(srv.Close)
	proxmoxPoll = time.Millisecond
	h, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "pve", Platform: "proxmox", Address: h, Port: pn, Insecure: true}
}

func openPVE(t *testing.T, d Device, c Credential) Driver {
	t.Helper()
	drv, err := Open(d, c)
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestProxmoxRead(t *testing.T) {
	st := &pveState{secret: "SEC"}
	d := pveStub(t, st)
	ctx := context.Background()
	for _, c := range []Credential{{Name: "a", Token: "root@pam!nd=SEC"}, {Name: "b", Username: "root@pam!nd", Token: "SEC"}} {
		drv := openPVE(t, d, c)
		f, err := drv.Facts(ctx)
		if err != nil || f.Hostname != "prod" || f.Vendor != "Proxmox" || f.OSVersion != "8.2.4-8.2" || !strings.Contains(f.Model, "2 node(s)") {
			t.Fatalf("facts %+v %v", f, err)
		}
		ifs, err := drv.Interfaces(ctx)
		if err != nil || len(ifs) != 2 || ifs[0].Name != "vmbr0" || ifs[0].Addresses[0] != "10.0.0.2/24" || ifs[0].OperUp == nil || !*ifs[0].OperUp || *ifs[1].OperUp {
			t.Fatalf("interfaces %+v %v", ifs, err)
		}
		if _, err := drv.Neighbors(ctx); err != ErrUnsupported {
			t.Errorf("neighbors: %v", err)
		}
	}
	drv := openPVE(t, d, Credential{Name: "a", Token: "root@pam!nd=SEC"})
	out, err := drv.Show(ctx, "show vm-config vmid=100")
	if err != nil || !strings.Contains(out, `"memory": 1024`) || strings.Contains(out, "hunter2") {
		t.Fatalf("vm-config: %q %v", out, err)
	}
	found := false
	for _, g := range st.gets {
		found = found || g == "/nodes/pve2/qemu/100/config" // the node came from the vmid
	}
	if !found {
		t.Errorf("the guest's node was not found from its vmid: %v", st.gets)
	}
	if out, err = drv.Show(ctx, "show vms"); err != nil || !strings.Contains(out, "web") {
		t.Errorf("vms: %q %v", out, err)
	}
	before := len(st.gets)
	for _, bad := range []string{"show", "show nothing", "show vm-config", "show vm-config vmid=1", "show vms node=a/b", "show vms |x", "show node-status node=", "show vm-config vmid=999"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(st.gets) > before+1 { // show vm-config vmid=999 asks for the list of guests
		t.Errorf("a refused command reached Proxmox: %v", st.gets[before:])
	}
}

func TestProxmoxTicketLogin(t *testing.T) {
	st := &pveState{}
	d := pveStub(t, st)
	ctx := context.Background()
	drv := openPVE(t, d, Credential{Name: "a", Username: "root@pam", Password: "S3CRET"})
	if _, err := drv.Facts(ctx); err != nil || st.logins != 1 {
		t.Fatalf("facts: %v, %d logins", err, st.logins)
	}
	st.expire = true
	if _, err := drv.Facts(ctx); err != nil || st.logins != 2 {
		t.Fatalf("a refused ticket: %v, %d logins", err, st.logins)
	}
	rc := drv.(RawChanger)
	if r, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "/nodes/pve2/qemu/100/config", Body: `{"memory":2048}`}, false); err != nil || !r.Applied {
		t.Fatalf("a write needs the CSRF token: %+v %v", r, err)
	}
	_, err := openPVE(t, d, Credential{Name: "a", Username: "root@pam", Password: "WRONG!!"}).Facts(ctx)
	if err == nil || strings.Contains(err.Error(), "WRONG!!") {
		t.Errorf("wrong password: %v", err)
	}
	for _, c := range []Credential{{Name: "x"}, {Name: "x", Username: "root@pam"}, {Name: "x", Token: "plain-secret"}} {
		if _, err := Open(d, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestProxmoxAPIGet(t *testing.T) {
	st := &pveState{secret: "SEC"}
	d := pveStub(t, st)
	a := openPVE(t, d, Credential{Name: "a", Token: "root@pam!nd=SEC"}).(APIer)
	ctx := context.Background()
	for _, ok := range []string{"/version", "/api2/json/version", "/cluster/resources?type=vm", "/nodes/pve2/qemu/100/config", "/nodes/pve2/qemu/100/status/current"} {
		if _, _, err := a.APIGet(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	before := len(st.gets)
	for _, bad := range []string{"/access/users", "/access/ticket", "/nodes/pve2/qemu/100/vncproxy", "/nodes/pve2/qemu/100/agent/file-read?file=/etc/shadow", "/nodes/pve2/qemu/100/agent/exec",
		"/cluster/config/join", "/cluster/acme/account", "/nodes/pve2/termproxy", "/../access", "version", "/storage/../access", "/other", "/nodes/a b", "/version?%zz"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s read", bad)
		}
	}
	if len(st.gets) != before {
		t.Errorf("a refused path reached Proxmox: %v", st.gets[before:])
	}
}

func TestProxmoxChange(t *testing.T) {
	st := &pveState{secret: "SEC"}
	d := pveStub(t, st)
	drv := openPVE(t, d, Credential{Name: "a", Token: "root@pam!nd=SEC"})
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("no RawChanger")
	}
	ctx := context.Background()
	for _, bad := range []Raw{
		{Method: "POST", Path: "/access/users", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve1/status", Body: `{"command":"shutdown"}`},
		{Method: "POST", Path: "/nodes/pve1/stopall", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve1/services/pveproxy/stop", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve1/termproxy", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve1/vncshell", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve1/certificates/custom", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve1/disks/wipedisk", Body: `{}`},
		{Method: "DELETE", Path: "/storage/local"},
		{Method: "DELETE", Path: "/nodes/pve1/storage/local"},
		{Method: "DELETE", Path: "/nodes/pve1/storage/local/content/local:iso%2Fx.iso"},
		{Method: "POST", Path: "/nodes/pve1/qemu", Body: `{"vmid":100,"archive":"local:backup/vzdump.vma.zst","force":1}`},
		{Method: "POST", Path: "/nodes/pve2/qemu/100/snapshot/s1/rollback", Body: `{}`},
		{Method: "POST", Path: "/nodes/pve2/qemu/100/unlink", Body: `{"idlist":"scsi0","force":1}`},
		{Method: "POST", Path: "/nodes/pve2/qemu/100/agent/exec", Body: `{"command":"id"}`},
		{Method: "POST", Path: "/cluster/config/nodes/pve2", Body: `{}`},
		{Method: "POST", Path: "/cluster/config", Body: `{}`},
		{Method: "PUT", Path: "/version", Body: `{}`},
		{Method: "PUT", Path: "/nodes/pve2/qemu/100/config?memory=1", Body: `{}`},
		{Method: "PUT", Path: "/nodes/pve2/qemu/100/config", Body: `{bad`},
		{Method: "PUT", Path: "/nodes/pve2/qemu/100/config"},
		{Method: "GET", Path: "/version"},
		{Method: "POST", Path: "/nodes/pve2/qemu/100/status/start", Body: `{"purge":1}`},
		{Method: "DELETE", Path: "/nodes/pve2/qemu/100/config", Body: `{"purge":1}`},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if len(st.writes) != 0 {
		t.Fatalf("a refused change was sent: %v", st.writes)
	}
	// a dry run reads what is there and sends nothing
	r, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "/nodes/pve2/qemu/100/config", Body: `{"memory":2048}`}, true)
	if err != nil || r.Applied || !strings.Contains(r.Before, "web") || strings.Contains(r.Before, "hunter2") || len(st.writes) != 0 {
		t.Fatalf("dry run: %+v %v %v", r, err, st.writes)
	}
	// an applied change, and a change that starts a task: waited for
	if r, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/api2/json/nodes/pve2/qemu/100/config", Body: `{"memory":2048}`}, false); err != nil || !r.Applied || st.bodyOf["PUT /nodes/pve2/qemu/100/config"] != `{"memory":2048}` {
		t.Fatalf("put: %+v %v", r, err)
	}
	r, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/nodes/pve2/qemu/100/status/start", Body: `{}`}, false)
	if err != nil || !r.Applied || !strings.Contains(r.Answer, "ended: OK") || st.polls[pveUPIDOK] < 2 {
		t.Fatalf("task: %+v %v (%d polls)", r, err, st.polls[pveUPIDOK])
	}
	r, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/nodes/pve2/qemu/101/status/start"}, false)
	if err == nil || !strings.Contains(err.Error(), "start failed") || !strings.Contains(err.Error(), "cannot allocate memory") || !r.Applied {
		t.Fatalf("failed task: %+v %v", r, err)
	}
}

// An rw caller creates, resizes and deletes VMs and containers.
func TestProxmoxGuestLifecycle(t *testing.T) {
	ctx := context.Background()
	st := &pveState{secret: "SEC"}
	d := pveStub(t, st)
	rc := openPVE(t, d, Credential{Name: "a", Token: "root@pam!nd=SEC"}).(RawChanger)
	for _, ok := range []Raw{
		{Method: "POST", Path: "/nodes/pve1/qemu", Body: `{"vmid":300,"name":"new","memory":2048,"cores":2,"scsi0":"local-lvm:32"}`},
		{Method: "POST", Path: "/nodes/pve1/lxc", Body: `{"vmid":301,"ostemplate":"local:vztmpl/debian-12.tar.zst","memory":512,"cores":1,"rootfs":"local-lvm:8"}`},
		{Method: "PUT", Path: "/nodes/pve2/qemu/100/config", Body: `{"cores":4,"memory":8192}`},
		{Method: "PUT", Path: "/nodes/pve2/qemu/100/resize", Body: `{"disk":"scsi0","size":"+10G"}`},
		{Method: "PUT", Path: "/nodes/pve1/lxc/200/resize", Body: `{"disk":"rootfs","size":"+2G"}`}, // a container's disk: the endpoint cannot be read
		{Method: "DELETE", Path: "/nodes/pve2/qemu/100", Body: `{"purge":1,"destroy-unreferenced-disks":1}`},
		{Method: "DELETE", Path: "/nodes/pve1/lxc/200"},
	} {
		if r, err := rc.RawChange(ctx, ok, false); err != nil || !r.Applied {
			t.Errorf("%+v: %+v %v", ok, r, err)
		}
	}
	if len(st.writes) != 7 {
		t.Errorf("writes: %v", st.writes)
	}
	// every PUT is allowed, whatever the path or the body
	for _, put := range []Raw{
		{Method: "PUT", Path: "/access/users/bob@pve", Body: `{"enable":0}`},
		{Method: "PUT", Path: "/nodes/pve2/qemu/100/unlink", Body: `{"idlist":"scsi1","force":1}`},
	} {
		if r, err := rc.RawChange(ctx, put, false); err != nil || !r.Applied {
			t.Errorf("%+v: %+v %v", put, r, err)
		}
	}
	// the plan of it says so, and sends nothing
	n := len(st.writes)
	r, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "/nodes/pve1/lxc/200/resize", Body: `{"disk":"rootfs","size":"+2G"}`}, true)
	if err != nil || r.Applied || !r.DryRun || !strings.Contains(r.Note, "cannot be read") || len(st.writes) != n {
		t.Errorf("dry run of a resize of a container: %+v %v", r, err)
	}
}
