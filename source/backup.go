package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netdir/internal/core"
)

// nodeKeys are the public keys of this node and of the other nodes of the cluster.
func (m *Mgmt) backupNodeKeys(ctx context.Context) []core.BackupNodeKey {
	var out []core.BackupNodeKey
	if err := m.backup.EnsureKey(); err == nil {
		pub, _ := os.ReadFile(filepath.Join(m.backup.Dir, "id_ed25519.pub"))
		out = append(out, core.BackupNodeKey{Node: m.backup.NodeName(), Key: strings.TrimSpace(string(pub))})
	} else {
		out = append(out, core.BackupNodeKey{Node: m.backup.NodeName(), Err: err.Error()})
	}
	if m.cl == nil || !m.cl.Enabled() {
		return out
	}
	snap := m.cl.Node.Snapshot()
	for _, p := range snap.Peers {
		if core.ContainsStr(snap.Removed, p.Addr) {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := m.cl.Relay(cctx, p.Addr, core.ProxyReq{User: "backup", Method: http.MethodGet, Path: "/api/backup"})
		cancel()
		var v struct {
			Data struct {
				Node      string `json:"node"`
				PublicKey string `json:"public_key"`
			} `json:"data"`
		}
		switch {
		case err != nil:
			out = append(out, core.BackupNodeKey{Node: p.Addr, Err: err.Error()})
		case resp.Status != http.StatusOK || json.Unmarshal(resp.Body, &v) != nil || v.Data.PublicKey == "":
			out = append(out, core.BackupNodeKey{Node: p.Addr, Err: "it has no backup key (is it running a version with backups?)"})
		default:
			out = append(out, core.BackupNodeKey{Node: v.Data.Node, Key: v.Data.PublicKey})
		}
	}
	return out
}

func (m *Mgmt) backupOp(cmd string, raw json.RawMessage, actor string) (any, error) {
	e := m.backup
	if e == nil {
		return nil, errors.New("backups are not available on this node")
	}
	var a struct {
		core.BackupServerArg
		Password string   `json:"password"` // the password of the backup, or the account's for install
		File     string   `json:"file"`
		Source   string   `json:"source"` // "upload" or "server"
		Keys     []string `json:"keys"`   // backup.provision: the backup keys of the nodes
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
	}
	switch cmd {
	case "backup.status":
		if err := e.EnsureKey(); err != nil {
			core.Warnf("backup: %v", err)
		}
		return e.Status(), nil
	case "backup.run":
		if err := e.RunNow(actor); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "backup.test":
		i := 0
		if a.Index != nil {
			i = *a.Index
		}
		names, err := e.Test(i)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "remote": names}, nil
	case "backup.install":
		if a.Index == nil {
			return nil, errors.New("which server?")
		}
		t, err := e.TargetAt(*a.Index)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		var keys, missing []string
		for _, k := range m.backupNodeKeys(ctx) {
			if k.Key != "" {
				keys = append(keys, k.Key)
			} else {
				missing = append(missing, k.Node+": "+k.Err)
			}
		}
		added, err := e.InstallKeys(t, a.Password, keys)
		if err != nil {
			return nil, err
		}
		core.Infof("backup: %s installed %d key(s) on %s", actor, added, t.Host)
		res := map[string]any{"ok": true, "added": added, "nodes": len(keys), "missing": missing}
		if names, terr := e.Test(*a.Index); terr == nil {
			res["connected"], res["remote"] = true, names
		} else {
			res["connected"], res["test_error"] = false, terr.Error()
		}
		return res, nil
	case "backup.cluster":
		return m.BackupCluster(actor)
	case "backup.provision":
		return m.backupProvision(a.Keys, actor)
	case "backup.files":
		t, pw, err := e.Resolve(a.BackupServerArg)
		if err != nil {
			return nil, err
		}
		l, err := e.ListRemote(t, pw)
		if err != nil {
			return nil, err
		}
		return map[string]any{"files": l}, nil
	case "backup.restore.prepare":
		file := ""
		switch a.Source {
		case "upload":
			file = e.UploadPath()
		case "server":
			t, pw, err := e.Resolve(a.BackupServerArg)
			if err != nil {
				return nil, err
			}
			if file, err = e.Fetch(t, pw, a.File); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("where is the backup?")
		}
		defer os.Remove(file)
		return e.PrepareRestore(file, a.Password, actor)
	case "backup.restore.apply":
		if m.restartFn == nil {
			return nil, errors.New("this process cannot restart itself")
		}
		if err := e.MarkReady(); err != nil {
			return nil, err
		}
		core.Warnf("backup: %s restores a backup: restarting", actor)
		go func() {
			time.Sleep(1500 * time.Millisecond) // let the answer go out first
			waitUntilSafe(m.updateSafeToApply, false, restartRecheck, func(string) {})
			m.handOver("backup", "restoring a backup")
			m.restartFn()
		}()
		return map[string]any{"ok": true, "restarting": true}, nil
	case "backup.restore.cancel":
		e.CancelRestore()
		return map[string]any{"ok": true}, nil
	}
	return nil, fmt.Errorf("unknown command %q", cmd)
}
