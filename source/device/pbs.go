package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Proxmox Backup Server over its REST API, https://HOST:8007/api2/json (see pxmx.go for the login and what PBS and PDM share).
// The token is made in the web interface under Configuration > Access Control > API Token and is sent as
// "Authorization: PBSAPIToken=USER@REALM!ID:SECRET".  A token with the Audit permission on / reads and nothing more (give the user
// the same, or switch the token's privilege separation off); netdir's own ro/rw rules are on top of that.
//
//	show NAME [store=NAME]    version, datastores, datastore-usage, datastore-status, groups, snapshots, namespaces, gc, sync-jobs,
//	                          verify-jobs, prune-jobs, remotes, tasks, failed-tasks, node-status, node-network, node-disks, ...
//
// Changes (RawChange, rw callers only): POST, PUT or DELETE below /admin, /config and /nodes with a JSON body; a change that starts a
// task (the answer is a UPID) is waited for.  Not done through this program: users, tokens, permissions and realms; certificates and
// ACME accounts; tape encryption keys; disk wiping; restarting or shutting down the machine; stopping a service; deleting a datastore,
// a backup group, a snapshot or a namespace; running a prune that is not a dry run; a sync that removes what is gone at the source.

func init() { Register("pbs", newPBS) }

var pbsSpec = pxSpec{
	name: "Proxmox Backup Server", short: "PBS", platform: "pbs", prefix: "PBSAPIToken", cookie: "PBSAuthCookie",
	show: map[string]string{
		"version": "/version", "datastore-usage": "/status/datastore-usage", "datastores": "/admin/datastore", "datastore-config": "/config/datastore",
		"datastore-status": "/admin/datastore/{store}/status", "groups": "/admin/datastore/{store}/groups", "snapshots": "/admin/datastore/{store}/snapshots",
		"namespaces": "/admin/datastore/{store}/namespace", "gc": "/admin/gc", "sync-jobs": "/admin/sync", "verify-jobs": "/admin/verify",
		"prune-jobs": "/admin/prune", "remotes": "/config/remote", "traffic-control": "/config/traffic-control",
		"tasks": "/nodes/localhost/tasks?limit=50", "failed-tasks": "/nodes/localhost/tasks?errors=1&limit=50",
		"node-status": "/nodes/localhost/status", "node-network": "/nodes/localhost/network", "node-disks": "/nodes/localhost/disks/list",
		"node-services": "/nodes/localhost/services", "node-time": "/nodes/localhost/time", "node-syslog": "/nodes/localhost/syslog?limit=100",
		"subscription": "/nodes/localhost/subscription",
	},
	denyRead: map[string]bool{"access": true, "ticket": true, "tfa": true, "termproxy": true, "vncwebsocket": true, "shell": true, "acme": true,
		"pxar-file-download": true, "download": true, "download-decoded": true, "file-restore": true, "upload-backup-log": true, "backup": true, "reader": true,
		"tape-encryption-keys": true, "password": true},
	denyWrite: map[string]string{"access": "users, tokens, permissions and realms", "ticket": "tickets", "tfa": "two-factor settings", "password": "passwords",
		"termproxy": "consoles", "vncwebsocket": "consoles", "shell": "shells", "certificates": "certificates", "acme": "ACME accounts",
		"tape-encryption-keys": "tape encryption keys", "wipedisk": "wiping disks", "initgpt": "initializing disks", "backup": "the backup protocol",
		"reader": "the restore protocol", "pxar-file-download": "downloads", "download": "downloads", "file-restore": "restoring files"},
	guard: pbsGuard,
	catalog: "GET paths of the Proxmox Backup Server API below /api2/json: /version, /status/datastore-usage, /admin/datastore, /admin/datastore/{store}/status|groups|snapshots|namespace, " +
		"/admin/sync|verify|prune|gc, /config/datastore|remote|sync|verify|prune, /nodes/localhost/status|tasks|network|disks/list|services|time|syslog. " +
		"The API viewer in Proxmox's documentation lists every path. Only GET is sent here; users, tokens, permissions, tickets, consoles and file downloads are not reachable. " +
		"The simplest questions are Show commands: show datastore-usage, show snapshots store=NAME, show failed-tasks.",
	examples: []string{"/status/datastore-usage", "/admin/datastore/backup1/snapshots", "/nodes/localhost/tasks?errors=1", "/admin/sync"},
}

// pbsGuard: what else a change to PBS must not be.
func pbsGuard(method string, segs []string) error {
	switch segs[0] {
	case "admin", "config", "nodes":
	default:
		return errors.New("path: PBS is changed below /admin, /config or /nodes")
	}
	if method == http.MethodDelete {
		switch {
		case segs[0] == "admin" && len(segs) >= 3 && segs[1] == "datastore":
			return errors.New("path: backup groups, snapshots and namespaces are not deleted here")
		case segs[0] == "config" && len(segs) == 3 && segs[1] == "datastore":
			return errors.New("path: a datastore is not removed here")
		}
	}
	return nil
}

type pbs struct{ *pxmx }

func newPBS(d Device, c Credential) (Driver, error) {
	p, err := newPxmx(pbsSpec, d, c)
	if err != nil {
		return nil, err
	}
	return &pbs{p}, nil
}

func (p *pbs) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Proxmox", Model: "Proxmox Backup Server", Hostname: p.d.Name}
	v, err := p.get(ctx, "/version")
	if err != nil {
		return f, err
	}
	m, _ := v.(map[string]any)
	f.OSVersion = strings.Trim(str(m["version"])+"-"+str(m["release"]), "-")
	f.UptimeS = p.uptime(ctx)
	if u, err := p.get(ctx, "/status/datastore-usage"); err == nil {
		f.Model = fmt.Sprintf("Proxmox Backup Server, %d datastore(s)", len(rows(u)))
	}
	return f, nil
}

func (p *pbs) Interfaces(ctx context.Context) ([]Interface, error)  { return p.interfaces(ctx) }
func (p *pbs) Neighbors(context.Context) ([]Neighbor, error)        { return nil, ErrUnsupported }
func (p *pbs) Config(context.Context) (string, error)               { return "", ErrUnsupported }
func (p *pbs) Show(ctx context.Context, cmd string) (string, error) { return p.show(ctx, cmd) }
func (p *pbs) APIGet(ctx context.Context, path string) (any, bool, error) {
	return p.apiGet(ctx, path)
}
func (p *pbs) APICatalog(context.Context) (any, error) { return p.apiCatalog() }
func (p *pbs) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if err := pbsPruneCheck(r); err != nil {
		return RawResult{DryRun: dry}, err
	}
	return p.rawChange(ctx, r, dry, true)
}
func (p *pbs) Close(context.Context) { p.api.close() }

// pbsPruneCheck: a prune deletes backups; only a dry run is sent.
func pbsPruneCheck(r Raw) error {
	if r.Method != http.MethodPost {
		return nil
	}
	pp, _, _ := strings.Cut(strings.TrimPrefix(r.Path, pxBase), "?")
	for _, s := range strings.Split(pp, "/") {
		if s == "prune" || s == "prune-datastore" {
			if !strings.Contains(strings.ReplaceAll(r.Body, " ", ""), `"dry-run":true`) {
				return errors.New("path: a prune deletes backups; only a dry run (\"dry-run\": true) is sent here")
			}
		}
	}
	return nil
}
