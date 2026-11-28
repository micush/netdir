package mcp

import (
	"encoding/json"
	"testing"
)

// A gateway the answering node was removed from is not paused: the others serve it.
func TestMCPTopologyIsClusterWide(t *testing.T) {
	var v any
	_ = json.Unmarshal([]byte(`[{"name":"puteaux","status":"paused","detail":"This node was removed","paused":true,"excluded":true,
	 "cluster_status":"ok","cluster_detail":"Served by 2 of 2 nodes",
	 "families":[{"af":"v4","detail":"this node was removed from the gateway"}],"anycast":[{"addr":"10.0.0.9","up":false,"reason":"gateway not running on this node","cluster_up_sec":900}],
	 "nodes":[{"name":"a","gw":"ok"},{"name":"b","gw":"ok"},{"name":"c","gw":"removed","excluded":true}]},
	 {"name":"solo","status":"ok","detail":"running","paused":false}]`), &v)
	gs := mcpTopology(v).([]any)
	g := gs[0].(map[string]any)
	if g["status"] != "ok" || g["paused"] != false || g["detail"] != "Served by 2 of 2 nodes" {
		t.Errorf("cluster view wrong: %v", g)
	}
	if h := g["this_node"].(map[string]any); h["paused"] != true || h["excluded"] != true {
		t.Errorf("this_node wrong: %v", h)
	}
	if n := g["serving_nodes"].([]any); len(n) != 2 || g["node_count"] != 2 {
		t.Errorf("serving nodes wrong: %v %v", g["serving_nodes"], g["node_count"])
	}
	if g["families"] != nil || g["this_node"].(map[string]any)["families"] == nil {
		t.Errorf("families not under this_node: %v", g)
	}
	a := g["anycast"].([]any)[0].(map[string]any)
	if a["up"] != nil || a["up_in_cluster"] != true || a["this_node"].(map[string]any)["up"] != false {
		t.Errorf("anycast wrong: %v", a)
	}
	s := gs[1].(map[string]any)
	if s["status"] != "ok" || s["this_node"] != nil {
		t.Errorf("no cluster: %v", s)
	}
}
