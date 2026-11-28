package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"netdir/internal/core"
)

// NodeRename sets this node's host name and updates /etc/hosts.
func (m *Mgmt) NodeRename(name, actor string) (string, error) {
	nn, err := core.ValidNodeName(name)
	if err != nil {
		return "", err
	}
	old := core.HostCurrent()
	if strings.EqualFold(old, nn) {
		return "this node is already called " + nn, nil
	}
	// /etc/hosts first: if it cannot be written nothing has changed
	body, err := os.ReadFile(core.HostsFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("reading %s: %v", core.HostsFile, err)
	}
	if err := core.ReplaceFile(core.HostsFile, []byte(core.RewriteHosts(string(body), old, nn))); err != nil {
		return "", fmt.Errorf("writing %s: %v", core.HostsFile, err)
	}
	// hostnamectl when systemd is running; otherwise (or when it cannot talk to systemd, as in a container) hostname(1) and /etc/hostname
	var herr error
	if _, e := exec.LookPath("hostnamectl"); e == nil || core.HostCmdIsFake {
		herr = core.HostCmd("hostnamectl", "set-hostname", nn)
	} else {
		herr = errors.New("hostnamectl is not installed")
	}
	if herr != nil {
		if herr = core.HostCmd("hostname", nn); herr == nil {
			herr = core.ReplaceFile(core.HostnameFile, []byte(nn+"\n"))
		}
	}
	if herr != nil {
		// put /etc/hosts back so it still matches the name the system has
		if rerr := core.ReplaceFile(core.HostsFile, body); rerr != nil {
			core.Warnf("node rename: could not restore %s: %v", core.HostsFile, rerr)
		}
		return "", fmt.Errorf("could not set the host name: %v", herr)
	}
	core.Warnf("node: host name changed from %s to %s by %s", old, nn, actor)
	return "host name is now " + nn + " (/etc/hosts updated); the cluster shows it within a few seconds", nil
}
