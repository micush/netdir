package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// backupProvision is the answer of this node (the "backup.provision" operation, which the node that runs BackupCluster
// sends to every other node).
func (m *Mgmt) backupProvision(keys []string, actor string) (cluster.BackupNodeResult, error) {
	res := cluster.BackupNodeResult{Node: m.backup.NodeName()}
	created, added, err := cluster.BackupProvisionLocal(keys)
	if err != nil {
		return res, err
	}
	res.Created, res.Keys = created, added
	core.Infof("backup: %s set up the account %s on this node (%d key(s) added)", actor, cluster.BackupAccount, added)
	return res, nil
}

// BackupCluster sets up every node of the cluster as a backup server of the others and adds them to the shared list.
func (m *Mgmt) BackupCluster(actor string) (map[string]any, error) {
	if m.cl == nil || !m.cl.Enabled() {
		return nil, errors.New("this node is not in a cluster")
	}
	snap := m.cl.Node.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var keys []string
	results := []cluster.BackupNodeResult{}
	failed := map[string]bool{} // by cluster address
	for _, k := range m.backupNodeKeys(ctx) {
		if k.Key != "" {
			keys = append(keys, k.Key)
		} else {
			// a node that does not answer gets no account now; run it again when it is back
			results = append(results, cluster.BackupNodeResult{Node: k.Node, Error: k.Err})
			failed[k.Node] = true
		}
	}
	self, err := m.backupProvision(keys, actor)
	self.Host = cluster.HostOfAddr(snap.SelfAddr)
	if err != nil {
		self.Error = err.Error()
	}
	results = append(results, self)
	body, _ := json.Marshal(map[string]any{"keys": keys})
	for _, p := range snap.Peers {
		if core.ContainsStr(snap.Removed, p.Addr) || failed[p.Addr] {
			continue
		}
		r := cluster.BackupNodeResult{Node: p.Addr, Host: cluster.HostOfAddr(p.Addr)}
		cctx, ccancel := context.WithTimeout(ctx, 60*time.Second)
		resp, err := m.cl.Relay(cctx, p.Addr, core.ProxyReq{User: actor, Method: http.MethodPost, Path: "/api/backup/provision", CT: "application/json", Body: body})
		ccancel()
		var v struct {
			Error string                   `json:"error"`
			Data  cluster.BackupNodeResult `json:"data"`
		}
		switch {
		case err != nil:
			r.Error = err.Error()
		case json.Unmarshal(resp.Body, &v) != nil || (resp.Status != http.StatusOK && v.Error == ""):
			r.Error = fmt.Sprintf("it answered %d (is it running this version?)", resp.Status)
		case v.Error != "":
			r.Error = v.Error
		default:
			r.Node, r.Created, r.Keys = core.FirstNonEmpty(v.Data.Node, r.Node), v.Data.Created, v.Data.Keys
		}
		results = append(results, r)
	}
	// every node that is set up becomes a server of the list, unless it is one already
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	bc := dc.Settings.Backup.Clone()
	if bc == nil {
		bc = &core.BackupConfig{}
	}
	added, full := 0, 0
	for _, r := range results {
		if r.Error != "" || r.Host == "" {
			continue
		}
		t := core.BackupTarget{Name: r.Node, Host: r.Host, User: cluster.BackupAccount, Dir: cluster.BackupClusterDir}
		have := false
		for _, x := range bc.Targets {
			if strings.EqualFold(x.Host, t.Host) && x.User == t.User && x.PortOrDefault() == t.PortOrDefault() {
				have = true
			}
		}
		switch {
		case have:
		case len(bc.Targets) >= core.BackupMaxTargets:
			full++
		default:
			bc.Targets = append(bc.Targets, t)
			added++
		}
	}
	if added > 0 {
		dc.Settings.Backup = bc
		if err := m.PutConfig(dc, actor, fmt.Sprintf("backup: %d cluster node(s) added as servers", added)); err != nil {
			return nil, fmt.Errorf("the nodes are set up, but the list of servers could not be saved: %w", err)
		}
	}
	nfail := 0
	for _, r := range results {
		if r.Error != "" {
			nfail++
		}
	}
	core.Infof("backup: %s set up backups between the cluster nodes: %d node(s), %d failed, %d server(s) added", actor, len(results), nfail, added)
	targets := bc.Targets
	if targets == nil {
		targets = []core.BackupTarget{}
	}
	return map[string]any{"ok": nfail == 0, "nodes": results, "added": added, "failed": nfail, "full": full, "targets": targets}, nil
}
