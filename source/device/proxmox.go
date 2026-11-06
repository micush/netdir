package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Proxmox VE over its REST API, https://<host>:8006/api2/json (every answer is {"data": ...}).
//
// The login is an API token (Datacenter > Permissions > API Tokens), sent as "Authorization: PVEAPIToken=USER@REALM!ID=SECRET":
// give the whole string as the credential's token, or the user and token ID ("root@pam!netdir") as its user name and the secret as
// its token.  Or a user name with its realm ("root@pam") and a password: the driver asks for a ticket (POST /access/ticket), sends it
// as a cookie with the CSRF token on writes, and asks for a new one when it is refused (a realm with two-factor login needs a token).
// A token with only audit roles (PVEAuditor) reads and nothing more; netdir's own ro/rw rules are on top of that.
//
// Options: "node" is the node the node-scoped reads ask when none is named (default: the node answering).
//
//	show NAME [node=N] [vmid=ID]    cluster, resources, vms, storage, nodes, tasks, backups, ha, firewall, ... and per node or guest
//	                                (node-status, node-network, vm-config, vm-status, vm-snapshots, ct-config, ...); a guest's node is found
//	                                from its vmid
//
// Changes (RawChange, rw callers only): POST, PUT or DELETE below /nodes, /cluster, /pools or /storage with a JSON body.  A change that
// starts a task (the answer is a UPID) is waited for: the answer is the task's end, and a failed task is an error with its last log
// lines.  Not done through this program: users, roles, permissions, tokens and realms; cluster create, join and removal; rebooting,
// shutting down or stopping everything on a node; shells and consoles; certificates; deleting a VM or container; deleting
// a storage; restoring a backup (a body with archive) or rolling back a snapshot; removing or wiping disks; the guest agent's
// command execution and file access; stopping a node's services.  The change is applied as sent; a PUT is not put back (the digest
// of the configuration changes), the copy in "before" shows what was there.
//
// The paths and fields come from Proxmox's API reference; none was tried against a real Proxmox.

func init() { Register("proxmox", newProxmox) }

type proxmox struct {
	d        Device
	api      *apiClient
	tokenHdr string
	user     string
	pass     string
	node     string // option
	mu       sync.Mutex
	ticket   string
	csrf     string
	got      time.Time
	defNode  string
}

const pveBase = "/api2/json"

var (
	pveNodeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	pveVMIDRE = regexp.MustCompile(`^[0-9]{3,9}$`)
	pveSegRE  = regexp.MustCompile(`^[A-Za-z0-9_.:@!%=,+-]{1,200}$`)
)

// proxmoxPoll is how often a task is looked at; a variable so tests are quick.
var proxmoxPoll = 2 * time.Second

func newProxmox(d Device, c Credential) (Driver, error) {
	p := &proxmox{d: d, node: strings.TrimSpace(d.Options["node"])}
	switch {
	case strings.Contains(c.Token, "!") && strings.Contains(c.Token, "="):
		p.tokenHdr = "PVEAPIToken=" + c.Token
	case strings.Contains(c.Username, "!") && c.Token != "":
		p.tokenHdr = "PVEAPIToken=" + c.Username + "=" + c.Token
	case c.Username != "" && c.Password != "":
		p.user, p.pass = c.Username, c.Password
	default:
		return nil, fmt.Errorf("device %s: Proxmox needs an API token (user@realm!id=secret, as the token, or user@realm!id as the user name and the secret as the token), or a user name with its realm and a password", d.Name)
	}
	if p.node != "" && !pveNodeRE.MatchString(p.node) {
		return nil, fmt.Errorf("device %s: option node is a node name", d.Name)
	}
	api, err := newAPIClient(d, 8006)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	p.api = api
	return p, nil
}

// login asks for a ticket unless a recent one is held (force: the one held was refused).
func (p *proxmox) login(ctx context.Context, force bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ticket != "" && !force && time.Since(p.got) < 90*time.Minute {
		return nil
	}
	form := url.Values{"username": {p.user}, "password": {p.pass}}
	b, err := p.api.do(ctx, http.MethodPost, pveBase+"/access/ticket", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	var t struct {
		Data struct {
			Ticket  string `json:"ticket"`
			CSRF    string `json:"CSRFPreventionToken"`
			NeedTFA any    `json:"NeedTFA"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &t) != nil || t.Data.Ticket == "" {
		return errors.New("login: the answer holds no ticket")
	}
	if t.Data.NeedTFA != nil && fmt.Sprint(t.Data.NeedTFA) != "0" && fmt.Sprint(t.Data.NeedTFA) != "<nil>" {
		return errors.New("login: this account needs a second factor; use an API token")
	}
	p.ticket, p.csrf, p.got = t.Data.Ticket, t.Data.CSRF, time.Now()
	return nil
}

// auth is the authentication headers of a request (write: with the CSRF token a ticket needs).
func (p *proxmox) auth(ctx context.Context, write bool) (http.Header, error) {
	if p.tokenHdr != "" {
		return http.Header{"Authorization": {p.tokenHdr}}, nil
	}
	if err := p.login(ctx, false); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := http.Header{"Cookie": {"PVEAuthCookie=" + p.ticket}}
	if write {
		h.Set("CSRFPreventionToken", p.csrf)
	}
	return h, nil
}

// get reads a path below /api2/json and returns what is in "data"; a refused ticket is renewed once.
func (p *proxmox) get(ctx context.Context, path string) (any, error) {
	for renewed := false; ; renewed = true {
		h, err := p.auth(ctx, false)
		if err != nil {
			return nil, err
		}
		b, err := p.api.do(ctx, http.MethodGet, pveBase+path, nil, h)
		var se *statusError
		if err != nil && p.tokenHdr == "" && errors.As(err, &se) && se.Code == http.StatusUnauthorized && !renewed {
			if err := p.login(ctx, true); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var v struct {
			Data any `json:"data"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
		}
		return v.Data, nil
	}
}

// localNode is the node to ask when none is named: the option, else the node answering, else the first.
func (p *proxmox) localNode(ctx context.Context) (string, error) {
	if p.node != "" {
		return p.node, nil
	}
	p.mu.Lock()
	n := p.defNode
	p.mu.Unlock()
	if n != "" {
		return n, nil
	}
	v, err := p.get(ctx, "/nodes")
	if err != nil {
		return "", err
	}
	l := rows(v)
	if len(l) == 0 {
		return "", errors.New("Proxmox lists no node")
	}
	sort.SliceStable(l, func(i, j int) bool { return str(l[i]["node"]) < str(l[j]["node"]) })
	if cs, err := p.get(ctx, "/cluster/status"); err == nil {
		for _, c := range rows(cs) {
			if str(c["type"]) == "node" && num(c["local"]) == 1 && pveNodeRE.MatchString(str(c["name"])) {
				n = str(c["name"])
			}
		}
	}
	if n == "" {
		n = str(l[0]["node"])
	}
	p.mu.Lock()
	p.defNode = n
	p.mu.Unlock()
	return n, nil
}

func (p *proxmox) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Proxmox", Model: "Proxmox VE"}
	v, err := p.get(ctx, "/version")
	if err != nil {
		return f, err
	}
	m, _ := v.(map[string]any)
	f.OSVersion = strings.Trim(str(m["version"])+"-"+str(m["release"]), "-")
	f.Hostname = p.d.Name
	if cs, err := p.get(ctx, "/cluster/status"); err == nil {
		nodes := 0
		for _, c := range rows(cs) {
			switch str(c["type"]) {
			case "cluster":
				f.Hostname = firstOf(str(c["name"]), f.Hostname)
			case "node":
				nodes++
				if num(c["local"]) == 1 && f.Hostname == p.d.Name {
					f.Hostname = str(c["name"])
				}
			}
		}
		f.Model = fmt.Sprintf("Proxmox VE, %d node(s)", nodes)
	}
	return f, nil
}

func (p *proxmox) Interfaces(ctx context.Context) ([]Interface, error) {
	n, err := p.localNode(ctx)
	if err != nil {
		return nil, err
	}
	v, err := p.get(ctx, "/nodes/"+n+"/network")
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, i := range rows(v) {
		x := Interface{Name: str(i["iface"]), Description: strings.TrimSpace(str(i["type"]) + " " + str(i["comments"]))}
		if _, ok := i["active"]; ok {
			up := num(i["active"]) == 1
			x.AdminUp, x.OperUp = &up, &up
		}
		for _, a := range []string{"cidr", "cidr6"} {
			if s := str(i[a]); s != "" {
				x.Addresses = append(x.Addresses, s)
			}
		}
		out = append(out, x)
	}
	return out, nil
}

func (p *proxmox) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (p *proxmox) Config(context.Context) (string, error)        { return "", ErrUnsupported }

// ---- show ----

var pveShow = map[string]string{
	"version": "/version", "cluster": "/cluster/status", "resources": "/cluster/resources", "vms": "/cluster/resources?type=vm",
	"storage": "/cluster/resources?type=storage", "nodes": "/nodes", "tasks": "/cluster/tasks", "backups": "/cluster/backup",
	"not-backed-up": "/cluster/backup-info/not-backed-up", "ha": "/cluster/ha/status/current", "ha-resources": "/cluster/ha/resources",
	"firewall": "/cluster/firewall/rules", "firewall-options": "/cluster/firewall/options", "options": "/cluster/options",
	"log": "/cluster/log?max=100", "pools": "/pools",
	"node-status": "/nodes/{node}/status", "node-network": "/nodes/{node}/network", "node-disks": "/nodes/{node}/disks/list",
	"node-services": "/nodes/{node}/services", "node-tasks": "/nodes/{node}/tasks?limit=50", "node-storage": "/nodes/{node}/storage",
	"node-time": "/nodes/{node}/time", "node-vms": "/nodes/{node}/qemu", "node-cts": "/nodes/{node}/lxc", "node-syslog": "/nodes/{node}/syslog?limit=100",
	"vm-config": "/nodes/{node}/qemu/{vmid}/config", "vm-status": "/nodes/{node}/qemu/{vmid}/status/current",
	"vm-snapshots": "/nodes/{node}/qemu/{vmid}/snapshot", "vm-firewall": "/nodes/{node}/qemu/{vmid}/firewall/rules",
	"vm-agent":  "/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
	"ct-config": "/nodes/{node}/lxc/{vmid}/config", "ct-status": "/nodes/{node}/lxc/{vmid}/status/current",
	"ct-snapshots": "/nodes/{node}/lxc/{vmid}/snapshot", "ct-firewall": "/nodes/{node}/lxc/{vmid}/firewall/rules",
	"ct-interfaces": "/nodes/{node}/lxc/{vmid}/interfaces",
}

func pveShowNames() string {
	var n []string
	for k := range pveShow {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// nodeOf finds the node a guest is on.
func (p *proxmox) nodeOf(ctx context.Context, vmid string) (string, error) {
	v, err := p.get(ctx, "/cluster/resources?type=vm")
	if err != nil {
		return "", err
	}
	for _, r := range rows(v) {
		if str(r["vmid"]) == vmid && pveNodeRE.MatchString(str(r["node"])) {
			return str(r["node"]), nil
		}
	}
	return "", fmt.Errorf("no VM or container %s (show vms lists them)", vmid)
}

func (p *proxmox) Show(ctx context.Context, cmd string) (string, error) {
	usage := fmt.Errorf("show NAME [node=N] [vmid=ID], e.g. show vms; names: %s", pveShowNames())
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	tpl, ok := pveShow[strings.ToLower(f[1])]
	if !ok {
		return "", fmt.Errorf("show %s: not a read the Proxmox driver has; names: %s", f[1], pveShowNames())
	}
	node, vmid := "", ""
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case ok && k == "node" && pveNodeRE.MatchString(v):
			node = v
		case ok && k == "vmid" && pveVMIDRE.MatchString(v):
			vmid = v
		default:
			return "", fmt.Errorf("%q: use node=NAME or vmid=NUMBER", kv)
		}
	}
	if strings.Contains(tpl, "{vmid}") {
		if vmid == "" {
			return "", fmt.Errorf("show %s needs vmid=NUMBER (show vms lists them)", f[1])
		}
		if node == "" {
			var err error
			if node, err = p.nodeOf(ctx, vmid); err != nil {
				return "", err
			}
		}
		tpl = strings.ReplaceAll(tpl, "{vmid}", vmid)
	}
	if strings.Contains(tpl, "{node}") {
		if node == "" {
			var err error
			if node, err = p.localNode(ctx); err != nil {
				return "", err
			}
		}
		tpl = strings.ReplaceAll(tpl, "{node}", node)
	}
	v, err := p.get(ctx, tpl)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

// ---- reading through the API ----

// pveDenyRead: segments of a path that are never read: accounts and tickets, consoles, the guest agent's file access and commands, join
// information and ACME accounts (which hold keys).
var pveDenyRead = map[string]bool{"access": true, "ticket": true, "tfa": true, "vncproxy": true, "termproxy": true, "spiceproxy": true, "vncwebsocket": true,
	"vncshell": true, "spiceshell": true, "file-read": true, "file-write": true, "exec": true, "exec-status": true, "set-user-password": true, "join": true, "acme": true, "execute": true}

func pveRead(path string) (string, error) {
	p := strings.TrimPrefix(path, pveBase)
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	if !strings.HasPrefix(pp, "/") {
		return "", errors.New("path: a path that starts with /")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if len(segs) > 9 || segs[0] == "" {
		return "", errors.New("path: /nodes/…, /cluster/…, /pools or /storage (see device_api_catalog)")
	}
	switch segs[0] {
	case "version", "cluster", "nodes", "pools", "storage":
	default:
		return "", errors.New("path: Proxmox is read at /version, /cluster/…, /nodes/…, /pools and /storage (users and permissions are not read here)")
	}
	for _, s := range segs {
		if !pveSegRE.MatchString(s) {
			return "", fmt.Errorf("path: %q is not a path segment", s)
		}
		if pveDenyRead[strings.ToLower(s)] {
			return "", fmt.Errorf("path: %q holds accounts, consoles, keys or guest files and is not read here", s)
		}
	}
	return p, nil
}

func (p *proxmox) APIGet(ctx context.Context, path string) (any, bool, error) {
	rp, err := pveRead(path)
	if err != nil {
		return nil, false, err
	}
	v, err := p.get(ctx, rp)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (p *proxmox) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET paths of the Proxmox VE API below /api2/json: /version, /cluster/status, /cluster/resources?type=vm|storage|node, /nodes, /nodes/{node}/status, /nodes/{node}/qemu, /nodes/{node}/qemu/{vmid}/config, " +
			"/nodes/{node}/lxc/{vmid}/status/current, /nodes/{node}/storage, /nodes/{node}/tasks, /cluster/backup, /cluster/ha/status/current, /cluster/firewall/rules. " +
			"The API viewer in Proxmox's documentation lists every path. Only GET is sent; users, permissions, tickets, consoles and the guest agent's commands and files are not reachable. " +
			"The simplest questions are Show commands: show vms, show vm-config vmid=100, show node-status, show storage.",
		"examples": []string{"/cluster/resources?type=vm", "/nodes/pve1/qemu/100/config", "/nodes/pve1/status", "/cluster/tasks"},
	}, nil
}

func (p *proxmox) Close(context.Context) { p.api.close() }

// ---- changes ----

// pveDenyWrite: a segment anywhere in the path of a change that is refused.
var pveDenyWrite = map[string]string{
	"access": "users, roles, permissions, tokens and realms", "ticket": "tickets", "tfa": "two-factor settings", "password": "passwords",
	"termproxy": "consoles", "vncproxy": "consoles", "spiceproxy": "consoles", "vncwebsocket": "consoles", "vncshell": "shells", "spiceshell": "shells", "execute": "shells",
	"join": "cluster join", "certificates": "certificates",
	"stopall": "stopping everything on a node", "wipedisk": "wiping disks", "initgpt": "initializing disks", "unlink": "removing disks",
	"exec": "running commands in a guest", "exec-status": "running commands in a guest", "file-read": "guest files", "file-write": "guest files",
	"set-user-password": "guest passwords", "rollback": "rolling back a snapshot", "acme": "ACME accounts",
}

// pveRawGuard refuses what could lock the person out or destroy data in one call (see the file's header).
func pveRawGuard(method, p string) error {
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change (the parameters go in the JSON body)")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	switch segs[0] {
	case "nodes", "cluster", "pools", "storage":
	default:
		return errors.New("path: Proxmox is changed below /nodes, /cluster, /pools or /storage")
	}
	for _, s := range segs {
		if !pveSegRE.MatchString(s) {
			return fmt.Errorf("path: %q is not a path segment", s)
		}
		if why, no := pveDenyWrite[strings.ToLower(s)]; no {
			return fmt.Errorf("path: %q is not changed here (%s)", s, why)
		}
	}
	if segs[0] == "cluster" && len(segs) > 1 && strings.EqualFold(segs[1], "config") {
		return errors.New("path: the cluster's membership (create, join, remove nodes) is not changed here")
	}
	last := strings.ToLower(segs[len(segs)-1])
	// /nodes/N/status: reboot and shutdown of the node; /nodes/N/services/S/stop: a node's services
	if method == http.MethodPost && len(segs) == 3 && segs[0] == "nodes" && last == "status" {
		return errors.New("path: rebooting or shutting down a node is not done here")
	}
	if len(segs) == 5 && segs[0] == "nodes" && segs[2] == "services" && (last == "stop" || last == "restart" || last == "reload") && method == http.MethodPost {
		return errors.New("path: a node's services are not stopped or restarted here")
	}
	if method == http.MethodDelete {
		switch {
		case len(segs) == 4 && segs[0] == "nodes" && (segs[2] == "qemu" || segs[2] == "lxc"):
			return errors.New("path: a VM or container is not deleted here")
		case len(segs) == 2 && segs[0] == "storage", len(segs) == 4 && segs[0] == "nodes" && segs[2] == "storage":
			return errors.New("path: a storage is not deleted here")
		case len(segs) == 5 && segs[0] == "nodes" && segs[2] == "storage" && segs[4] == "content" || len(segs) == 6 && segs[0] == "nodes" && segs[2] == "storage" && segs[4] == "content":
			return errors.New("path: stored volumes (disks, backups, images) are not deleted here")
		}
	}
	return nil
}

// pveBodyCheck refuses a body that restores a backup (archive) or asks for data to be destroyed along with the change.
func pveBodyCheck(r Raw) error {
	if strings.TrimSpace(r.Body) == "" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(r.Body), &m) != nil {
		return errors.New("body: a JSON object")
	}
	for k := range m {
		switch strings.ToLower(k) {
		case "archive":
			return errors.New("body: restoring a backup (archive) is not done here")
		case "purge", "destroy-unreferenced-disks":
			return fmt.Errorf("body: %q removes data and is not sent here", k)
		}
	}
	return nil
}

func (p *proxmox) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	r.Path = strings.TrimPrefix(r.Path, pveBase)
	if err := pveBodyCheck(r); err != nil {
		return RawResult{DryRun: dry}, err
	}
	h, err := p.auth(ctx, true)
	if err != nil {
		return RawResult{DryRun: dry}, err
	}
	auth := h.Clone()
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	res, err := restRaw(ctx, restSpec{
		api: p.api, hdr: h, auth: auth, json: true,
		wire:    func(path string) string { return pveBase + path },
		guard:   pveRawGuard,
		restore: nil, // the configuration's digest changes with the change, so the old copy cannot be put back as it is
		alive:   func(ctx context.Context) error { _, err := p.get(ctx, "/version"); return err },
	}, r, dry)
	if err != nil || !res.Applied {
		return res, err
	}
	return p.waitTask(ctx, res)
}

// waitTask: a change that started a task answers with its UPID; wait for the task to end, and say how.
func (p *proxmox) waitTask(ctx context.Context, res RawResult) (RawResult, error) {
	var a struct {
		Data any `json:"data"`
	}
	if json.Unmarshal([]byte(res.Answer), &a) != nil {
		return res, nil
	}
	upid, _ := a.Data.(string)
	parts := strings.Split(upid, ":")
	if !strings.HasPrefix(upid, "UPID:") || len(parts) < 2 || !pveNodeRE.MatchString(parts[1]) {
		return res, nil
	}
	node, base := parts[1], "/nodes/"+parts[1]+"/tasks/"+url.PathEscape(upid)
	deadline := time.Now().Add(10 * time.Minute)
	for {
		v, err := p.get(ctx, base+"/status")
		if err != nil {
			res.Note = strings.TrimSpace(res.Note + " The task " + upid + " was started; its end could not be read: " + err.Error())
			return res, nil
		}
		m, _ := v.(map[string]any)
		if str(m["status"]) == "stopped" {
			exit := str(m["exitstatus"])
			res.Answer = fmt.Sprintf("task %s on %s ended: %s", strings.Join(parts[5:min(len(parts), 7)], " "), node, firstOf(exit, "unknown"))
			if exit == "OK" || strings.HasPrefix(exit, "WARNINGS") {
				return res, nil
			}
			lines := ""
			if lv, err := p.get(ctx, base+"/log?limit=20"); err == nil {
				for _, l := range rows(lv) {
					lines += str(l["t"]) + "\n"
				}
			}
			return res, fmt.Errorf("the task failed: %s\n%s", exit, rawTrunc([]byte(lines)))
		}
		if time.Now().After(deadline) {
			res.Note = strings.TrimSpace(res.Note + " The task " + upid + " is still running.")
			return res, nil
		}
		if err := sleepCtx(ctx, proxmoxPoll); err != nil {
			res.Note = strings.TrimSpace(res.Note + " The task " + upid + " was started; waiting for it was cut short.")
			return res, nil
		}
	}
}
