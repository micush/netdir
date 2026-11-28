package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"netdir/internal/core"
)

const RoleReplica core.Role = "replica"

var (
	// ErrStaleEpoch: an incoming claim is behind this node's epoch.
	ErrStaleEpoch = errors.New("cluster: epoch is stale")
	// ErrEpochConflict: a different primary claimed the epoch this node already has.
	ErrEpochConflict = errors.New("cluster: two different primaries claimed the same epoch")
	// ErrNotJoinable: the node is already part of a cluster.
	ErrNotJoinable = errors.New("cluster: this node already belongs to a cluster (leave it first)")
)

const (
	joinTokenTTL   = time.Hour
	MaxPendingToks = 20
)

func peerEqual(a, b core.ClusterPeer) bool {
	if a.Addr != b.Addr || a.Fp != b.Fp || a.NodeID != b.NodeID || len(a.Alts) != len(b.Alts) {
		return false
	}
	for i := range a.Alts {
		if a.Alts[i] != b.Alts[i] {
			return false
		}
	}
	return true
}

type tokenRec struct {
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"`
	By      string    `json:"by"`
}

type clusterState struct {
	NodeID      string             `json:"node_id"`
	Epoch       uint64             `json:"epoch"`
	Role        core.Role          `json:"role"`
	PrimaryAddr string             `json:"primary_addr"`
	SelfAddr    string             `json:"self_addr"`
	Secret      string             `json:"secret"`
	Peers       []core.ClusterPeer `json:"peers"`
	Removed     []string           `json:"removed,omitempty"`
	// RemovedFp is the identity fingerprint each removed address had, so a removed node stays refused under
	// whatever address it claims next.  MTLSFps are the members seen to present their identity certificate
	// on calls (see Cluster.peerAuth).
	RemovedFp  map[string]string `json:"removed_fp,omitempty"`
	MTLSFps    []string          `json:"mtls_fps,omitempty"`
	StrictOn   bool              `json:"strict,omitempty"` // every member presented its certificate once: never go back
	SharedRev  uint64            `json:"shared_rev"`
	SharedHash string            `json:"shared_hash"`
	Tokens     []tokenRec        `json:"tokens,omitempty"`
}

// ClusterNode is the durable membership state of this node.
type ClusterNode struct {
	Mu   sync.Mutex `json:"-"`
	dir  string
	St   clusterState `json:"-"`
	cert tls.Certificate
	fp   string
	alts []string
}

func (n *ClusterNode) statePath() string { return filepath.Join(n.dir, "cluster.json") }

func newClusterSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

// LoadOrCreateClusterNode loads the state under dir, or founds a new
// single-node cluster (epoch 1, this node primary) with a fresh identity.
func LoadOrCreateClusterNode(dir, selfAddr string) (*ClusterNode, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	n := &ClusterNode{dir: dir}
	b, err := os.ReadFile(n.statePath())
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &n.St); err != nil {
			return nil, fmt.Errorf("%s: %w", n.statePath(), err)
		}
	case errors.Is(err, os.ErrNotExist):
		n.St = clusterState{NodeID: core.RandHex(8), Epoch: 1, Role: core.RolePrimary, Secret: newClusterSecret(), Peers: []core.ClusterPeer{}}
	default:
		return nil, err
	}
	if n.St.NodeID == "" {
		n.St.NodeID = core.RandHex(8)
	}
	if n.St.Secret == "" {
		n.St.Secret = newClusterSecret()
	}
	if n.St.Peers == nil {
		n.St.Peers = []core.ClusterPeer{}
	}
	// the self address is operational config, re-supplied on every start
	if n.St.Role == core.RolePrimary && (n.St.PrimaryAddr == "" || n.St.PrimaryAddr == n.St.SelfAddr) {
		n.St.PrimaryAddr = selfAddr
	}
	n.St.SelfAddr = selfAddr
	if err := n.loadIdentity(); err != nil {
		return nil, err
	}
	if err := n.saveLocked(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *ClusterNode) loadIdentity() error {
	crt, key := filepath.Join(n.dir, "node.crt"), filepath.Join(n.dir, "node.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil && time.Until(leaf.NotAfter) > 365*24*time.Hour {
			n.cert, n.fp = c, core.Fingerprint(c)
			return nil
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "netdir-node-" + n.St.NodeID},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"netdir-node"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return err
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := core.WriteAtomic(key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := core.WriteAtomic(crt, certPEM, 0o644); err != nil {
		return err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	n.cert, n.fp = c, core.Fingerprint(c)
	return nil
}

func (n *ClusterNode) saveLocked() error {
	b, err := json.MarshalIndent(n.St, "", "  ")
	if err != nil {
		return err
	}
	return core.WriteAtomic(n.statePath(), b, 0o600)
}

func (n *ClusterNode) snapshotLocked() core.ClusterSnapshot {
	return core.ClusterSnapshot{
		NodeID: n.St.NodeID, Epoch: n.St.Epoch, Role: n.St.Role, PrimaryAddr: n.St.PrimaryAddr,
		SelfAddr: n.St.SelfAddr, Peers: append([]core.ClusterPeer{}, n.St.Peers...),
		Removed: append([]string{}, n.St.Removed...), SharedRev: n.St.SharedRev, SharedHash: n.St.SharedHash,
	}
}

func (n *ClusterNode) Snapshot() core.ClusterSnapshot {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return n.snapshotLocked()
}

func (n *ClusterNode) Identity() (tls.Certificate, string) { return n.cert, n.fp }
func (n *ClusterNode) Fingerprint() string                 { return n.fp }

func (n *ClusterNode) Secret() []byte {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	b, _ := base64.RawStdEncoding.DecodeString(n.St.Secret)
	return b
}

// Self returns this node's own peer record.
func (n *ClusterNode) Self() core.ClusterPeer {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return core.ClusterPeer{Addr: n.St.SelfAddr, Fp: n.fp, NodeID: n.St.NodeID, Alts: append([]string(nil), n.alts...)}
}

// SetAlts records the other addresses this node can be reached on (not saved:
// interface addresses are re-read at run time).
func (n *ClusterNode) SetAlts(alts []string) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	n.alts = append([]string(nil), alts...)
}

// SetSelf updates the advertised address (config change).
func (n *ClusterNode) SetSelf(addr string) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if n.St.SelfAddr == addr {
		return
	}
	if n.St.Role == core.RolePrimary && n.St.PrimaryAddr == n.St.SelfAddr {
		n.St.PrimaryAddr = addr
	}
	n.St.SelfAddr = addr
	n.saveLocked()
}

// Joinable is true only for an untouched, self-founded single-node cluster.
func (n *ClusterNode) Joinable() bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return n.St.Role == core.RolePrimary && len(n.St.Peers) == 0 && n.St.Epoch == 1
}

// Promote makes this node primary at epoch+1.
func (n *ClusterNode) Promote() core.ClusterSnapshot {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	n.St.Epoch++
	n.St.Role = core.RolePrimary
	n.St.PrimaryAddr = n.St.SelfAddr
	n.saveLocked()
	return n.snapshotLocked()
}

// AdoptAnnounce applies a claim "primaryAddr is primary at epoch".
func (n *ClusterNode) AdoptAnnounce(epoch uint64, primaryAddr string) (core.ClusterSnapshot, error) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	switch {
	case epoch < n.St.Epoch:
		return n.snapshotLocked(), ErrStaleEpoch
	case epoch == n.St.Epoch:
		if primaryAddr != n.St.PrimaryAddr {
			return n.snapshotLocked(), ErrEpochConflict
		}
		return n.snapshotLocked(), nil
	}
	n.St.Epoch = epoch
	n.St.PrimaryAddr = primaryAddr
	if primaryAddr == n.St.SelfAddr {
		n.St.Role = core.RolePrimary
	} else {
		n.St.Role = RoleReplica
	}
	n.saveLocked()
	return n.snapshotLocked(), nil
}

// CheckEpoch rejects an epoch behind this node's own.
func (n *ClusterNode) CheckEpoch(epoch uint64) error {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if epoch < n.St.Epoch {
		return ErrStaleEpoch
	}
	return nil
}

// AddPeer records a member (never one on the removed list, nor ourselves).
// It reports whether anything changed.
func (n *ClusterNode) AddPeer(p core.ClusterPeer) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if p.Addr == "" || p.Fp == "" || p.Addr == n.St.SelfAddr || p.NodeID == n.St.NodeID || core.ContainsStr(n.St.Removed, p.Addr) || n.removedFpLocked(p.Fp) {
		return false
	}
	for i, q := range n.St.Peers {
		if q.NodeID == p.NodeID && p.NodeID != "" || q.Addr == p.Addr {
			if peerEqual(q, p) {
				return false
			}
			n.St.Peers[i] = p
			n.saveLocked()
			return true
		}
	}
	n.St.Peers = append(n.St.Peers, p)
	sort.Slice(n.St.Peers, func(i, j int) bool { return n.St.Peers[i].Addr < n.St.Peers[j].Addr })
	n.saveLocked()
	return true
}

// RemovePeer drops a member and blocks it from being re-added by gossip.
func (n *ClusterNode) RemovePeer(addr string) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	changed := false
	kept := n.St.Peers[:0]
	fp := n.St.RemovedFp[addr]
	for _, p := range n.St.Peers {
		if p.Addr == addr {
			changed = true
			fp = p.Fp
			continue
		}
		kept = append(kept, p)
	}
	n.St.Peers = kept
	if !core.ContainsStr(n.St.Removed, addr) {
		n.St.Removed = append(n.St.Removed, addr)
		changed = true
	}
	if fp != "" && n.St.RemovedFp[addr] != fp {
		if n.St.RemovedFp == nil {
			n.St.RemovedFp = map[string]string{}
		}
		n.St.RemovedFp[addr] = fp
		changed = true
	}
	if changed {
		n.saveLocked()
	}
	return changed
}

// removedFpLocked: fp is the identity of a removed member (n.mu held).
func (n *ClusterNode) removedFpLocked(fp string) bool {
	if fp == "" {
		return false
	}
	for _, f := range n.St.RemovedFp {
		if f == fp {
			return true
		}
	}
	return false
}

// IsRemovedFp reports whether fp is the identity of a removed member.
func (n *ClusterNode) IsRemovedFp(fp string) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return n.removedFpLocked(fp)
}

// UnremoveFp lifts the block on an identity (a node that is let back in, possibly under a new address).
func (n *ClusterNode) UnremoveFp(fp string) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	for a, f := range n.St.RemovedFp {
		if f == fp {
			delete(n.St.RemovedFp, a)
			n.saveLocked()
		}
	}
}

// PeerByFp returns the member whose identity certificate has fingerprint fp.
func (n *ClusterNode) PeerByFp(fp string) (core.ClusterPeer, bool) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	for _, p := range n.St.Peers {
		if fp != "" && p.Fp == fp {
			return p, true
		}
	}
	return core.ClusterPeer{}, false
}

// NoteMTLS records that the member with identity fp presented its certificate on a call.  From then on a call
// claiming that identity without one is refused (no downgrade).
func (n *ClusterNode) NoteMTLS(fp string) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if fp == "" || core.ContainsStr(n.St.MTLSFps, fp) {
		return
	}
	n.St.MTLSFps = append(n.St.MTLSFps, fp)
	n.saveLocked()
}

// IsMTLS: the member with identity fp has been seen presenting its certificate.
func (n *ClusterNode) IsMTLS(fp string) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return core.ContainsStr(n.St.MTLSFps, fp)
}

// Strict is true once every member has been seen presenting its certificate, i.e. when the whole cluster runs
// a version that does.  From then on only members already on the list are served: a caller that merely holds
// the cluster secret (a node that was removed, say) cannot make itself a member by calling.
func (n *ClusterNode) Strict() bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if n.St.StrictOn {
		return true // sticky: when members leave or are removed the cluster does not fall back to trusting the secret alone
	}
	if len(n.St.Peers) == 0 {
		return false
	}
	for _, p := range n.St.Peers {
		if !core.ContainsStr(n.St.MTLSFps, p.Fp) {
			return false
		}
	}
	n.St.StrictOn = true
	n.saveLocked()
	return true
}

// UnremovePeer lifts the block so the member can be added again.
func (n *ClusterNode) UnremovePeer(addr string) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	var out []string
	changed := false
	for _, a := range n.St.Removed {
		if a == addr {
			changed = true
			continue
		}
		out = append(out, a)
	}
	n.St.Removed = out
	if _, ok := n.St.RemovedFp[addr]; ok {
		delete(n.St.RemovedFp, addr)
		changed = true
	}
	if changed {
		n.saveLocked()
	}
	return changed
}

// JoinAs makes this (fresh) node a replica of an existing cluster.
func (n *ClusterNode) JoinAs(secret string, epoch uint64, primaryAddr string, peers []core.ClusterPeer) error {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if n.St.Role != core.RolePrimary || len(n.St.Peers) != 0 || n.St.Epoch != 1 {
		return ErrNotJoinable
	}
	if raw, err := base64.RawStdEncoding.DecodeString(secret); err != nil || len(raw) < 16 {
		return errors.New("cluster: invalid secret from the cluster")
	}
	n.St.Secret = secret
	n.St.Epoch = epoch
	n.St.PrimaryAddr = primaryAddr
	n.St.Role = RoleReplica
	n.St.Peers = []core.ClusterPeer{}
	n.St.Removed, n.St.RemovedFp, n.St.MTLSFps, n.St.StrictOn = nil, nil, nil, false
	n.St.Tokens = nil
	for _, p := range peers {
		if p.Addr == n.St.SelfAddr || p.NodeID == n.St.NodeID || p.Addr == "" || p.Fp == "" {
			continue
		}
		dup := false
		for _, q := range n.St.Peers {
			if q.Addr == p.Addr || (p.NodeID != "" && q.NodeID == p.NodeID) {
				dup = true
			}
		}
		if !dup {
			n.St.Peers = append(n.St.Peers, p)
		}
	}
	sort.Slice(n.St.Peers, func(i, j int) bool { return n.St.Peers[i].Addr < n.St.Peers[j].Addr })
	return n.saveLocked()
}

// Reset leaves the cluster: a new single-node cluster with a new secret.
func (n *ClusterNode) Reset() core.ClusterSnapshot {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	n.St.Epoch, n.St.Role, n.St.PrimaryAddr = 1, core.RolePrimary, n.St.SelfAddr
	n.St.Secret = newClusterSecret()
	n.St.Peers, n.St.Removed, n.St.Tokens = []core.ClusterPeer{}, nil, nil
	n.St.RemovedFp, n.St.MTLSFps, n.St.StrictOn = nil, nil, false
	n.saveLocked()
	return n.snapshotLocked()
}

// SetShared records the primary's shared-config revision.
func (n *ClusterNode) SetShared(rev uint64, hash string) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if n.St.SharedRev == rev && n.St.SharedHash == hash {
		return
	}
	n.St.SharedRev, n.St.SharedHash = rev, hash
	n.saveLocked()
}

// BumpShared increments the revision when the shared config hash changed.
// It reports whether it did.
func (n *ClusterNode) BumpShared(hash string) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if n.St.SharedHash == hash {
		return false
	}
	n.St.SharedRev++
	n.St.SharedHash = hash
	n.saveLocked()
	return true
}

// ── join tokens ──────────────────────────────────────────────────────────────

func hashToken(tok string) string {
	h := sha256.Sum256([]byte("netdir-join-v1\x00" + tok))
	return hex.EncodeToString(h[:])
}

// MintToken creates a single-use join token valid for joinTokenTTL.
func (n *ClusterNode) MintToken(by string) (string, time.Time, error) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	now := time.Now()
	live := n.St.Tokens[:0]
	for _, t := range n.St.Tokens {
		if now.Before(t.Expires) {
			live = append(live, t)
		}
	}
	n.St.Tokens = live
	if len(n.St.Tokens) >= MaxPendingToks {
		return "", time.Time{}, fmt.Errorf("%d unused join codes: clear them (Operate ▸ Cluster ▸ Clear join codes, or netdir --cluster-token-clear) or wait for them to expire", MaxPendingToks)
	}
	b := make([]byte, 24)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	exp := now.Add(joinTokenTTL)
	n.St.Tokens = append(n.St.Tokens, tokenRec{Hash: hashToken(tok), Expires: exp, By: by})
	return tok, exp, n.saveLocked()
}

// ClearTokens drops every join token that has not been used (expired ones too) and reports how many were still valid:
// a code handed out before no longer works.
func (n *ClusterNode) ClearTokens() (int, error) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	live := n.pendingTokensLocked()
	if len(n.St.Tokens) == 0 {
		return 0, nil
	}
	n.St.Tokens = nil
	return live, n.saveLocked()
}

// PendingTokens is how many join tokens are unused and not yet expired.
func (n *ClusterNode) PendingTokens() int {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return n.pendingTokensLocked()
}

func (n *ClusterNode) pendingTokensLocked() int {
	now, live := time.Now(), 0
	for _, t := range n.St.Tokens {
		if now.Before(t.Expires) {
			live++
		}
	}
	return live
}

// RedeemToken consumes a token; it reports whether it was valid.
func (n *ClusterNode) RedeemToken(tok string) bool {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	h := hashToken(tok)
	now := time.Now()
	ok := false
	kept := n.St.Tokens[:0]
	for _, t := range n.St.Tokens {
		if now.After(t.Expires) {
			continue
		}
		if !ok && subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) == 1 {
			ok = true
			continue // single use: drop it
		}
		kept = append(kept, t)
	}
	n.St.Tokens = kept
	n.saveLocked()
	return ok
}
