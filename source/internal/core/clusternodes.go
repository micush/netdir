package core

// CanvasNode is one cluster node as the Topology drawing shows it (a parallelogram beside the gateway's circle), seen
// from the gateway it is drawn for: whether that node is serving it.
type CanvasNode struct {
	NodeID string `json:"node_id,omitempty"`
	// Gw is this node's state for the gateway on its own, apart from the host-load colour: ok, degraded, bad, starting,
	// notserving, paused, down (not answering) or removed.  clusterGateway adds them up.
	Gw        string      `json:"gw,omitempty"`
	Excluded  bool        `json:"excluded,omitempty"` // removed from this gateway (shared setting)
	Addr      string      `json:"addr"`
	Name      string      `json:"name"` // host name, else the address (the address when two nodes share a host name)
	Hostname  string      `json:"hostname,omitempty"`
	Self      bool        `json:"self"`   // the node being asked
	Status    string      `json:"status"` // ok | warn | bad | paused | idle, the same colours as every other shape
	Label     string      `json:"label"`  // the short word in the shape: serving, paused, not answering …
	Detail    string      `json:"detail"`
	Role      Role        `json:"role"`
	Host      *HostLoad   `json:"host,omitempty"`        // its CPU, memory and disk use
	Addrs     []NodeIface `json:"addrs,omitempty"`       // its Ethernet interfaces' IPv4 and IPv6 GUA addresses (tooltip)
	Strain    []string    `json:"strain,omitempty"`      // what is over the limit (the shape is yellow while there is anything)
	Paused    bool        `json:"node_paused,omitempty"` // the whole node is paused (Operate ▸ Node), as opposed to this gateway being paused there
	Reachable bool        `json:"reachable"`
	Version   string      `json:"version,omitempty"`
	VerDiff   bool        `json:"version_differs,omitempty"`
	Behind    bool        `json:"behind,omitempty"` // has not caught up with the primary's shared settings
	Updating  bool        `json:"updating,omitempty"`
	SoakSec   int         `json:"soak_sec,omitempty"`   // canary soak: seconds left
	UptimeSec int64       `json:"uptime_sec,omitempty"` // how long the daemon on that node has been running (absent on older nodes)
	// ServingSec is how long that node has served this gateway without a break (the cluster's uptime for the gateway is the longest)
	ServingSec int64  `json:"serving_sec,omitempty"`
	UpdateErr  string `json:"update_failed,omitempty"`
	LastSeen   int64  `json:"last_seen,omitempty"` // unix seconds
	Error      string `json:"error,omitempty"`
}
