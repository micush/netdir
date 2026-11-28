package cluster

import (
	"context"
	"errors"
	"time"

	"netdir/internal/core"
)

// Relay sends req to the peer at addr (SOURCE node side).
func (c *Cluster) Relay(ctx context.Context, addr string, req core.ProxyReq) (*core.ProxyResp, error) {
	if !c.Enabled() {
		return nil, errors.New("this node is not in a cluster")
	}
	snap := c.Node.Snapshot()
	if core.ContainsStr(snap.Removed, addr) {
		return nil, errors.New("that node was removed from the cluster")
	}
	var peer *core.ClusterPeer
	for i := range snap.Peers {
		if snap.Peers[i].Addr == addr {
			peer = &snap.Peers[i]
		}
	}
	if peer == nil {
		return nil, errors.New("no such cluster node")
	}
	var resp core.ProxyResp
	if err := c.Call(ctx, *peer, "POST", "/cluster/proxy", req, &resp, 90*time.Second); err != nil {
		return nil, err
	}
	return &resp, nil
}
