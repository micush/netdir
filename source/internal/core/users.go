package core

import (
	"bytes"
	"os/exec"
	"strings"
)

var // usersRun runs a shadow-utils command with the given standard input
// (replaceable in tests).
UsersRun = func(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func FirstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ── cluster-wide ─────────────────────────────────────────────────────────────
//
// Every change is made here and then sent to the other members over the
// cluster channel (signed, pinned TLS) as the password hash, never the
// password.  A member applies it with the same rules as a local change.  The
// reply says on how many nodes it was applied and names any that were not
// (a node that was down misses the change; repeat it when the node is back).

// usersMsg is one change as it travels between members.
type UsersMsg struct {
	Op      string `json:"op"` // apply | password | expiry | delete | grant | revoke | access
	Name    string `json:"name"`
	Hash    string `json:"hash,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	By      string `json:"by,omitempty"`
	RO      bool   `json:"ro,omitempty"` // for the read-only group (apply, grant, access)
}
