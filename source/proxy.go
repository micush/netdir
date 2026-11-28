package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"netdir/internal/cluster"
	"netdir/internal/core"
	"netdir/internal/web"
)

// peerProxy runs on the TARGET node (peer-authenticated).
func (m *Mgmt) peerProxy(rw http.ResponseWriter, r *http.Request, caller core.ClusterPeer, body []byte) {
	var req core.ProxyReq
	if err := json.Unmarshal(body, &req); err != nil {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	if err := web.ProxyAllowed(req.Method, req.Path); err != nil {
		core.JsonError(rw, http.StatusForbidden, err.Error())
		return
	}
	h := m.webH
	if h == nil {
		core.JsonError(rw, http.StatusServiceUnavailable, "the web interface is not running on that node")
		return
	}
	user := req.User
	if len(user) > web.MaxUsernameLen || user == "" || strings.ContainsAny(user, " \r\n\t") {
		user = "unknown"
	}
	s := &core.Session{User: user + " via " + caller.Addr, ReadOnly: req.RO, Mcp: req.MCP, Raw: req.Raw, Hop: true}
	ctx := context.WithValue(r.Context(), web.ProxyCtxKey{}, s)
	in, err := http.NewRequestWithContext(ctx, req.Method, req.Path, bytes.NewReader(req.Body))
	if err != nil {
		core.JsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	in.ContentLength = int64(len(req.Body))
	if req.CT != "" {
		in.Header.Set("Content-Type", req.CT)
	}
	if host, _, err := net.SplitHostPort(caller.Addr); err == nil {
		in.RemoteAddr = net.JoinHostPort(host, "0")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, in)
	res := rec.Result()
	out, _ := io.ReadAll(io.LimitReader(res.Body, cluster.MaxPeerBody))
	core.WriteJSON(rw, http.StatusOK, core.ProxyResp{
		Status: res.StatusCode, CT: res.Header.Get("Content-Type"),
		Disp: res.Header.Get("Content-Disposition"), Body: out,
	})
}
