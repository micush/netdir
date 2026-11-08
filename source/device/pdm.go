package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Proxmox Datacenter Manager over its REST API, https://HOST:8443/api2/json (see pxmx.go for the login and what PBS and PDM share).
// The token is made in the web interface (Administration > Access Control > API Tokens) and is sent as
// "Authorization: PDMAPIToken=USER@REALM!ID:SECRET".  PDM is the view over many Proxmox VE and Backup Server systems ("remotes"):
//
//	show NAME [remote=NAME]    version, remotes, resources, resources-status, remote-tasks, node-status, ... and per remote:
//	                           pve-resources, pve-nodes, pve-qemu, pve-lxc, pve-tasks, pbs-datastores, pbs-tasks
//
// Changes (RawChange, rw callers only): POST, PUT or DELETE with a JSON body anywhere except users, tokens, permissions, consoles and
// certificates.  What starts a task on a remote answers with its id and is not waited for.  Not done through this program: users,
// tokens, permissions and realms; certificates; consoles; removing a remote; deleting a VM or container; rolling back a snapshot;
// migrating a guest to another cluster; wiping disks; restarting or shutting down the machine; stopping a service.

func init() { Register("pdm", newPDM) }

var pdmSpec = pxSpec{
	name: "Proxmox Datacenter Manager", short: "PDM", platform: "pdm", prefix: "PDMAPIToken", cookie: "PDMAuthCookie",
	show: map[string]string{
		"version": "/version", "remotes": "/remotes/remote", "resources": "/resources/list", "resources-status": "/resources/status",
		"subscription": "/resources/subscription", "remote-tasks": "/remote-tasks/list",
		"node-status": "/nodes/localhost/status", "node-network": "/nodes/localhost/network", "node-tasks": "/nodes/localhost/tasks?limit=50",
		"node-services": "/nodes/localhost/services", "node-time": "/nodes/localhost/time", "node-syslog": "/nodes/localhost/syslog?limit=100",
		"pve-resources": "/pve/remotes/{remote}/resources", "pve-nodes": "/pve/remotes/{remote}/nodes", "pve-qemu": "/pve/remotes/{remote}/qemu",
		"pve-lxc": "/pve/remotes/{remote}/lxc", "pve-tasks": "/pve/remotes/{remote}/tasks",
		"pbs-datastores": "/pbs/remotes/{remote}/datastore", "pbs-tasks": "/pbs/remotes/{remote}/tasks",
	},
	denyRead: map[string]bool{"access": true, "ticket": true, "tfa": true, "termproxy": true, "vncwebsocket": true, "vncproxy": true, "spiceproxy": true, "shell": true,
		"acme": true, "file-read": true, "file-write": true, "exec": true, "exec-status": true, "password": true, "tokens": true},
	denyWrite: map[string]string{"access": "users, tokens, permissions and realms", "ticket": "tickets", "tfa": "two-factor settings", "password": "passwords",
		"termproxy": "consoles", "vncwebsocket": "consoles", "vncproxy": "consoles", "spiceproxy": "consoles", "shell": "shells", "certificates": "certificates",
		"acme": "ACME accounts", "tokens": "tokens", "exec": "running commands in a guest", "exec-status": "running commands in a guest",
		"file-read": "guest files", "file-write": "guest files", "rollback": "rolling back a snapshot", "remote-migrate": "migrating a guest to another cluster",
		"wipedisk": "wiping disks", "initgpt": "initializing disks", "stopall": "stopping everything on a node"},
	guard: pdmGuard,
	catalog: "GET paths of the Proxmox Datacenter Manager API below /api2/json: /version, /remotes/remote, /resources/list, /resources/status, /remote-tasks/list, " +
		"/pve/remotes/{remote}/resources|nodes|qemu|lxc|tasks, /pbs/remotes/{remote}/datastore|tasks, /nodes/localhost/status|tasks|network|services|time. " +
		"The API viewer in Proxmox's documentation lists every path. Only GET is sent here; users, tokens, permissions, tickets and consoles are not reachable. " +
		"The simplest questions are Show commands: show remotes, show resources, show pve-qemu remote=NAME.",
	examples: []string{"/remotes/remote", "/resources/list", "/pve/remotes/prod/qemu", "/remote-tasks/list"},
}

func pdmGuard(method string, segs []string) error {
	if method != http.MethodDelete {
		return nil
	}
	switch {
	case len(segs) == 3 && segs[0] == "remotes" && segs[1] == "remote":
		return errors.New("path: a remote is not removed here")
	case len(segs) >= 2 && (segs[len(segs)-2] == "qemu" || segs[len(segs)-2] == "lxc"):
		return errors.New("path: a VM or container is not deleted here")
	}
	return nil
}

type pdm struct{ *pxmx }

func newPDM(d Device, c Credential) (Driver, error) {
	p, err := newPxmx(pdmSpec, d, c)
	if err != nil {
		return nil, err
	}
	return &pdm{p}, nil
}

func (p *pdm) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Proxmox", Model: "Proxmox Datacenter Manager", Hostname: p.d.Name}
	v, err := p.get(ctx, "/version")
	if err != nil {
		return f, err
	}
	m, _ := v.(map[string]any)
	f.OSVersion = strings.Trim(str(m["version"])+"-"+str(m["release"]), "-")
	f.UptimeS = p.uptime(ctx)
	if r, err := p.get(ctx, "/remotes/remote"); err == nil {
		f.Model = fmt.Sprintf("Proxmox Datacenter Manager, %d remote(s)", len(rows(r)))
	}
	return f, nil
}

func (p *pdm) Interfaces(ctx context.Context) ([]Interface, error)  { return p.interfaces(ctx) }
func (p *pdm) Neighbors(context.Context) ([]Neighbor, error)        { return nil, ErrUnsupported }
func (p *pdm) Config(context.Context) (string, error)               { return "", ErrUnsupported }
func (p *pdm) Show(ctx context.Context, cmd string) (string, error) { return p.show(ctx, cmd) }
func (p *pdm) APIGet(ctx context.Context, path string) (any, bool, error) {
	return p.apiGet(ctx, path)
}
func (p *pdm) APICatalog(context.Context) (any, error) { return p.apiCatalog() }
func (p *pdm) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	return p.rawChange(ctx, r, dry, false)
}
func (p *pdm) Close(context.Context) { p.api.close() }
