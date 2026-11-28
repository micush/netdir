package core

import (
	"os"
	"time"
)

// ── views ────────────────────────────────────────────────────────────────────

type PeerView struct {
	Addr          string `json:"addr"`
	NodeID        string `json:"node_id"`
	Fingerprint   string `json:"fingerprint"`
	Self          bool   `json:"self"`
	Reachable     bool   `json:"reachable"`
	Role          Role   `json:"role"`
	Epoch         uint64 `json:"epoch"`
	IsPrimary     bool   `json:"is_primary"`
	NodePaused    bool   `json:"node_paused,omitempty"` // the whole node is paused: it cannot take the primary role
	Version       string `json:"version"`
	Hostname      string `json:"hostname,omitempty"`
	SourceVersion string `json:"source_version"`
	Updating      bool   `json:"updating"`
	UpdateFailed  string `json:"update_failed,omitempty"`
	SoakSec       int    `json:"soak_sec,omitempty"` // seconds left of the canary soak (0: not soaking)
	// Restarting: not answering, but it was installing an update when it was last seen (a few minutes ago at most): it is
	// restarting into the new version, which is not the same as being down
	Restarting bool      `json:"restarting,omitempty"`
	SharedRev  uint64    `json:"shared_rev"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	Error      string    `json:"error,omitempty"`
	// IPs are the node's addresses (IPv4, IPv6 global and unique local) and GwIPs the ones it uses in the gateway protocol
	IPs   []string `json:"ips,omitempty"`
	GwIPs []string `json:"gw_ips,omitempty"`
}

// ── keeping the gateways served during a rolling update ──────────────────────

// GwState says whether this node is serving one gateway right now: it holds the
// address (AGC) or forwards for it (AFN) in every address family the gateway
// has, and its web listener is serving (health.go).
type GwState struct {
	GroupID int  `json:"group_id"`
	Serving bool `json:"serving"`
	// Fresh: serving, but only for the last few seconds (servingSettle).  Clients
	// have not all moved back yet, so it does not count as cover for a neighbour's
	// restart.  Absent (older nodes) means settled.
	Fresh bool `json:"fresh,omitempty"`
	// Offnet: this node cannot take part in the gateway at all (it is not on the gateway's subnet), so it can never cover it
	// for another node.  Absent on older nodes.
	Offnet bool `json:"offnet,omitempty"`
	// Health is the gateway's colour on that node as its own drawing shows it (ok, warn, bad, idle) and
	// HealthWhy the reason ("the gateway is up but this node's MCP and web listener is not serving").  Absent on older nodes.
	Health    string `json:"health,omitempty"`
	HealthWhy string `json:"health_why,omitempty"`
	// ServingSec is how long this node has served the gateway without a break (the gateway's uptime on this node); the
	// cluster's uptime for the gateway is the longest of these.  Absent on older nodes.
	ServingSec int64 `json:"serving_sec,omitempty"`
	// UpSince (unix seconds) is when somebody in the cluster began serving this gateway without a break, as this node knows
	// it: kept across the nodes' restarts by passing it between them (see sampleGwUp).  Absent on older nodes.
	UpSince int64 `json:"up_since,omitempty"`
}

// peerGateways is what one other cluster member reported.
type PeerGateways struct {
	Addr    string
	NodeID  string // the member's node ID, when known
	Known   bool
	Serving map[int]bool
	Fresh   map[int]bool // serving, but not yet for servingSettle
	Offnet  map[int]bool // cannot take part in the gateway (another subnet): never a cover for it
	Down    bool         // not reachable now: it may come back, so it is still a possible cover
}

func SelfHost() string { h, _ := os.Hostname(); return h }
