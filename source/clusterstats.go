package main

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// clusterHost is host.get for the whole cluster.
func (m *Mgmt) clusterHost(ctx context.Context, actor string, from, to time.Time) (*core.HostResult, error) {
	return m.clusterHostGW(ctx, actor, from, to, 0)
}

// clusterHostGW is clusterHost for the nodes of one gateway (gid > 0), or every node (0).
func (m *Mgmt) clusterHostGW(ctx context.Context, actor string, from, to time.Time, gid int) (*core.HostResult, error) {
	var keep func(core.PeerView) bool
	if gid > 0 {
		dc, _, err := m.LiveConfig()
		if err != nil {
			return nil, err
		}
		g, err := findGroup(dc, gid)
		if err != nil {
			return nil, err
		}
		keep = cluster.GatewayNodes(g)
	}
	q := url.Values{"from": {strconv.FormatInt(from.Unix(), 10)}, "to": {strconv.FormatInt(to.Unix(), 10)}}
	parts, infos := cluster.ClusterGatherSel(ctx, m.cl, core.ProxyReq{User: actor, Method: "GET", Path: "/api/host?" + q.Encode()}, cluster.ClusterStatsTimeout,
		func() (*core.HostResult, error) { return core.Hoststats.Query(from, to), nil }, keep)
	if len(parts) == 0 {
		return nil, errors.New("no node answered")
	}
	return cluster.MergeHost(parts, infos), nil
}
