package core

import (
	"netdir/device"
)

// The canvas is a picture of the configuration: one circle per gateway group (its shared address) with the cluster's
// nodes beside it.  Both the web GUI and the CLI (--canvas) show the same view built here, with the same colours:
//
//	ok    green   working
//	warn  yellow  degraded (works, but something underneath it does not)
//	bad   red     down
//	idle  grey    not known yet (not applied, or not running here)
//	alert purple  a device only: a monitoring system (Observium, Centreon) that answers and holds alerts
//
// CanvasDevice is one managed device of a gateway, as a square under its circle.
type CanvasDevice struct {
	Name     string        `json:"name"`
	Platform string        `json:"platform"`
	Address  string        `json:"address"`
	Tags     []string      `json:"tags,omitempty"`
	Status   string        `json:"status"`
	Detail   string        `json:"detail"`
	Health   device.Health `json:"health"`
}

// CanvasFamily is the state of one address family of a gateway (a gateway with
// both an IPv4 and an IPv6 address runs one engine per family).
type CanvasFamily struct {
	AF     string `json:"af"` // v4 | v6
	VIP    string `json:"vip"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type CanvasGateway struct {
	Name      string         `json:"name"`
	GroupID   int            `json:"group_id"`
	Interface string         `json:"interface"`
	WeakKey   bool           `json:"weak_key,omitempty"` // the gateway's HMAC key is well known or short (gkey.go)
	VIP4      string         `json:"vip4"`
	VIP6      string         `json:"vip6"`
	Anycast   []AnycastState `json:"anycast,omitempty"`
	// MCPClients is how many different callers used the MCP endpoint on this gateway's addresses in the last 5 minutes (all serving nodes, see addPeerClients).
	MCPClients int            `json:"mcp_clients"`
	MCPCallers []string       `json:"mcp_callers,omitempty"` // the callers behind MCPClients, as hashes, so the nodes can be added up without counting one twice
	Status     string         `json:"status"`
	Detail     string         `json:"detail"`
	Families   []CanvasFamily `json:"families"`
	// Vmac is the last virtual-MAC test on this node (see vmactest.go); absent until one has run.
	Vmac    *VmacResult    `json:"vmac,omitempty"`
	Members []CanvasMember `json:"members"`
	// Devices are the gateway's managed devices (GroupConfig.Devices) with their health as this node sees it.
	Devices []CanvasDevice `json:"devices"`
	Paused  bool           `json:"paused"`
	// NodePaused says the pause comes from the whole node being paused, not from this gateway.
	NodePaused bool `json:"node_paused,omitempty"`
	// PausedScope says where this gateway is paused by its own setting: "all" (every node) or "node" (this one).
	PausedScope string `json:"paused_scope,omitempty"`
	// Excluded says this node has been removed from the gateway (shared setting); ExcludedNodes lists the node IDs removed.
	// ClusterStatus / ClusterDetail are the gateway's state for the whole cluster, from its nodes (the sidebar's dot): the same
	// whichever node is asked.  Absent without a cluster, where Status is it.
	ClusterStatus string `json:"cluster_status,omitempty"`
	ClusterDetail string `json:"cluster_detail,omitempty"`
	// ClusterUpSec is how long the gateway has been served without a break by the cluster as a whole (see clusterUpSec).
	ClusterUpSec int64 `json:"cluster_up_sec,omitempty"`
	// Via names the node whose picture of the gateway this is, when this node does not serve it itself (see viaServing).
	Via           string   `json:"via,omitempty"`
	ViaAddr       string   `json:"via_addr,omitempty"`
	Excluded      bool     `json:"excluded,omitempty"`
	ExcludedNodes []string `json:"excluded_nodes,omitempty"`
	Uptime        *UpInfo  `json:"uptime,omitempty"`
	// Nodes are the cluster's nodes and how each stands for this gateway (empty without a cluster); this node first.
	Nodes []CanvasNode `json:"nodes,omitempty"`
}

// CanvasMember is one cluster node currently serving the gateway: it holds an
// address-forwarding slot (AFN) and is still sending hellos.
type CanvasMember struct {
	// ViaLocal marks the entry of the node whose picture this is, in a gateway the signed-in node does not serve (Local is
	// cleared there, as it would point at the signed-in node)
	ViaLocal bool   `json:"via_local,omitempty"`
	IP       string `json:"ip"`
	Local    bool   `json:"local"`
	AGC      bool   `json:"agc"`
	// AGCAFs is the address families this node is the controller for ("v4", "v6" or "v4+v6"), empty when it is not.  A
	// dual-stack gateway elects its controllers separately, so they may be two nodes.
	AGCAFs string `json:"agc_afs,omitempty"`
	AfnID  int    `json:"afn_id"`
	Weight int    `json:"weight"`
	AFs    string `json:"afs"`
}

// config returns the supervisor's current configuration.
func (s *Supervisor) Config() *DaemonConfig {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Dc
}
