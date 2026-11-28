package cluster

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"netdir/internal/core"
)

const (
	BackupAccount    = "netdirbackup"
	BackupClusterDir = "backups"
	// what a key of a node may do with the account: file transfer, and nothing else
	backupKeyOptions = `restrict,command="internal-sftp"`
)

// replaceable in tests
var (
	backupLookupUser = user.Lookup
	backupChown      = os.Lchown
)

// backupNodeResult is what one node answers when it is asked to set itself up.
type BackupNodeResult struct {
	Node    string `json:"node"`
	Host    string `json:"host,omitempty"`
	Created bool   `json:"created,omitempty"` // the account was made now
	Keys    int    `json:"keys"`              // keys added to it now
	Error   string `json:"error,omitempty"`
}

// backupProvisionLocal makes the account, its directory and its authorized_keys on this node.
func BackupProvisionLocal(keys []string) (created bool, added int, err error) {
	var ok []string
	for _, k := range keys {
		if k = strings.TrimSpace(k); core.BackupKeyRe.MatchString(k) {
			ok = append(ok, k)
		}
	}
	if len(ok) == 0 {
		return false, 0, errors.New("no node has a key yet")
	}
	u, err := backupLookupUser(BackupAccount)
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return false, 0, fmt.Errorf("looking up the account %s: %v", BackupAccount, err)
		}
		// "*" as the password: no password opens it, and it is not locked (sshd refuses a locked account without PAM)
		if out, rerr := core.UsersRun("", "useradd", "--create-home", "--shell", "/bin/sh", "--password", "*", "--comment", "netdir backups", BackupAccount); rerr != nil {
			return false, 0, fmt.Errorf("useradd failed: %s", core.FirstNonEmpty(out, rerr.Error()))
		}
		created = true
		if u, err = backupLookupUser(BackupAccount); err != nil {
			return created, 0, fmt.Errorf("the account %s was made but cannot be looked up: %v", BackupAccount, err)
		}
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	home := filepath.Clean(u.HomeDir)
	if e1 != nil || e2 != nil || uid == 0 || !filepath.IsAbs(home) || home == "/" {
		return created, 0, fmt.Errorf("the account %s on this node is not usable for backups (uid %s, home %q)", BackupAccount, u.Uid, u.HomeDir)
	}
	// the account owns its home, so nothing in it is followed: a directory must be a directory, and a file is replaced by
	// renaming a new one over it
	mkdir := func(dir string) error {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
		return backupChown(dir, uid, gid)
	}
	if fi, err := os.Lstat(home); err != nil || !fi.IsDir() {
		return created, 0, fmt.Errorf("the home of %s (%s) is not a directory", BackupAccount, home)
	}
	ssh := filepath.Join(home, ".ssh")
	for _, d := range []string{ssh, filepath.Join(home, BackupClusterDir)} {
		if err := mkdir(d); err != nil {
			return created, 0, err
		}
	}
	ak := filepath.Join(ssh, "authorized_keys")
	old := ""
	if fi, err := os.Lstat(ak); err == nil && fi.Mode().IsRegular() && fi.Size() < 1<<20 {
		b, _ := os.ReadFile(ak)
		old = string(b)
	}
	merged, added := core.AuthorizeKeysAs(old, ok, backupKeyOptions)
	if added == 0 {
		return created, 0, nil
	}
	tmp, err := os.CreateTemp(ssh, ".authorized_keys-")
	if err != nil {
		return created, 0, err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.WriteString(merged)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr == nil {
		werr = backupChown(tmp.Name(), uid, gid)
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), ak)
	}
	if werr != nil {
		return created, 0, werr
	}
	return created, added, nil
}

func HostOfAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// runBackupCluster is `netdir --backup-cluster`.
func RunBackupCluster(sock string) {
	var v struct {
		Nodes  []BackupNodeResult `json:"nodes"`
		Added  int                `json:"added"`
		Failed int                `json:"failed"`
		Full   int                `json:"full"`
	}
	core.Decode(core.Op(sock, "backup.cluster", nil), &v)
	for _, r := range v.Nodes {
		switch {
		case r.Error != "":
			fmt.Printf("%-24s FAILED: %s\n", r.Node, r.Error)
		case r.Created:
			fmt.Printf("%-24s account %s made, %d key(s) added\n", r.Node, BackupAccount, r.Keys)
		default:
			fmt.Printf("%-24s account %s was there, %d key(s) added\n", r.Node, BackupAccount, r.Keys)
		}
	}
	fmt.Printf("%d server(s) added to Configure ▸ Backup.\n", v.Added)
	if v.Full > 0 {
		fmt.Printf("%d node(s) not added: the list holds at most %d servers.\n", v.Full, core.BackupMaxTargets)
	}
	if v.Failed > 0 {
		fmt.Println("Run it again when the failed node(s) answer.")
		os.Exit(1)
	}
}
