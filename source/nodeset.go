package main

import (
	"strings"

	"netdir/internal/core"
)

// resolveNode turns the node a canvas edit names (address, host name or node ID) into its node ID, and lists the IDs of
// every node of the cluster.  A node ID that is already on the gateway's list is accepted as it is, so an entry for a node
// that has left the cluster can still be cleared.
func (m *Mgmt) resolveNode(dc *core.DaemonConfig, e *canvasEdit) error {
	var peers []core.PeerView
	if m.cl != nil {
		peers = m.cl.View().Peers
	}
	g, err := findGroup(dc, e.Group)
	if err != nil {
		return err
	}
	id, err := core.PickNode(peers, g.ExcludedNodes, e.Node)
	if err != nil {
		return err
	}
	e.nodeID = id
	var ids []string
	for _, p := range peers {
		if p.NodeID != "" {
			ids = append(ids, p.NodeID)
		}
	}
	e.members = strings.Join(ids, ",")
	return nil
}
