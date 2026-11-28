package core

import (
	"crypto/rand"
	"encoding/hex"
)

// Management-cluster membership and role state, after umiss's
// internal/cluster: exactly one node is primary at any time, every promotion
// increments a cluster-wide epoch, and any node that learns of a higher epoch
// defers to it unconditionally.  Promotion is admin-confirmed (no automatic
// election), so this only has to make promotions durable and monotonic.
//
// This package-level state is network-free; clusternet.go drives it.

type Role string

const RolePrimary Role = "primary"

// ClusterPeer is another member.  Fp is the SHA-256 fingerprint of its
// cluster identity certificate, pinned on every connection.
type ClusterPeer struct {
	Addr   string `json:"addr"`
	Fp     string `json:"fp"`
	NodeID string `json:"node_id"`
	// Alts are other ways to reach the same node (its host name, IPv4 and IPv6
	// addresses); a call tries Addr first, then these.
	Alts []string `json:"alts,omitempty"`
}

// ClusterSnapshot is a copy of the state, safe to hold.
type ClusterSnapshot struct {
	NodeID      string
	Epoch       uint64
	Role        Role
	PrimaryAddr string
	SelfAddr    string
	Peers       []ClusterPeer
	Removed     []string
	SharedRev   uint64
	SharedHash  string
}

func (s ClusterSnapshot) IsPrimary() bool { return s.Role == RolePrimary }

func RandHex(nbytes int) string {
	b := make([]byte, nbytes)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ContainsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
