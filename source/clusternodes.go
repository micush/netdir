package main

import (
	"netdir/internal/cluster"
	"netdir/internal/core"
)

// markNodes adds the cluster's nodes to each gateway of the picture.
func (s *StatusServer) markNodes(groups []core.CanvasGateway) {
	if s.mg == nil {
		return
	}
	for i := range groups {
		groups[i].Nodes = s.mg.cl.CanvasNodesEx(groups[i].GroupID, groups[i].Status, groups[i].Detail, groups[i].NodePaused, groups[i].ExcludedNodes)
		if groups[i].PausedScope == "all" {
			cluster.LabelPausedAll(groups[i].Nodes)
		}
		if len(groups[i].Nodes) > 0 {
			groups[i].ClusterStatus, groups[i].ClusterDetail = cluster.ClusterGateway(groups[i].Nodes)
			if groups[i].ClusterUpSec = s.mg.cl.GwUpSeconds(groups[i].GroupID); groups[i].ClusterUpSec == 0 {
				groups[i].ClusterUpSec = cluster.ClusterUpSec(groups[i].Nodes) // not sampled yet (just started) or older nodes
			}
			// the gateway's own circle follows: served by one node of several is amber even where that one node is fine
			if groups[i].Status == "ok" && groups[i].ClusterStatus == "warn" {
				groups[i].Status, groups[i].Detail = "warn", groups[i].ClusterDetail
			}
		}
	}
}
