package core

// Cluster-wide statistics and host load: the Monitor ▸ Statistics and Monitor ▸ Node pages can show the cluster as one,
// with every node's numbers added together (the "Cluster" entry of the Node menu, `--stats --cluster`, `--host --cluster`).
//
// Each node answers for itself as always; the node asked fans out (itself directly, the others through the cluster relay
// that the Node menu already uses), over one absolute time range, and the answers are merged by the pure functions below.

// ClusterInfo says which nodes a cluster-wide answer adds together and which could not answer.
type ClusterInfo struct {
	Nodes []ClusterNodeInfo `json:"nodes"`
}

// ClusterNodeInfo is one node's part in a cluster-wide answer.
type ClusterNodeInfo struct {
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
