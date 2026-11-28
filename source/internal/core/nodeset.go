package core

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
)

// This node's own ID, for the gateways it has been removed from (GroupConfig.ExcludedNodes).  Set when the cluster state
// is loaded, before the supervisor starts; empty until then, when nothing is excluded.
var selfNodeID atomic.Value // string

func SetLocalNodeID(id string) { selfNodeID.Store(id) }

func LocalNodeID() string {
	s, _ := selfNodeID.Load().(string)
	return s
}

// cleanNodeIDs sorts and de-duplicates a list of node IDs (so the shared hash is the same on every node) and refuses
// anything that is not a plain ID.  An empty list is nil, which keeps the key out of the file.
func cleanNodeIDs(l []string) ([]string, error) {
	if len(l) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(l))
	for _, id := range l {
		if id == "" || len(id) > 64 {
			return nil, errors.New("a node ID is 1-64 characters")
		}
		for _, c := range id {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return nil, errors.New("a node ID is hexadecimal")
			}
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// pickNode finds the one node a name refers to: its node ID, address (with or without the port), or host name.
func PickNode(peers []PeerView, excluded []string, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("--node is required: the node's address, host name or node ID (see --cluster)")
	}
	lower := strings.ToLower(name)
	var hit []PeerView
	for _, p := range peers {
		hostOnly := p.Addr
		if h, _, err := net.SplitHostPort(p.Addr); err == nil {
			hostOnly = h
		}
		if p.NodeID == name || p.Addr == name || hostOnly == name || strings.ToLower(p.Hostname) == lower ||
			strings.ToLower(strings.SplitN(p.Hostname, ".", 2)[0]) == lower {
			hit = append(hit, p)
		}
	}
	switch len(hit) {
	case 1:
		if hit[0].NodeID == "" {
			return "", fmt.Errorf("node %s has not reported its node ID yet — try again in a moment", name)
		}
		return hit[0].NodeID, nil
	case 0:
		if ContainsStr(excluded, name) {
			return name, nil
		}
		return "", fmt.Errorf("there is no node %q in the cluster (see --cluster for the nodes' addresses and host names)", name)
	}
	return "", fmt.Errorf("%q matches more than one node — use the node's address or node ID", name)
}

// cleanNodeOrder checks a list of node IDs like cleanNodeIDs but keeps its order (the order the nodes are drawn in).
func cleanNodeOrder(l []string) ([]string, error) {
	if len(l) == 0 {
		return nil, nil
	}
	if len(l) > 256 {
		return nil, errors.New("too many nodes")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(l))
	for _, id := range l {
		if _, err := cleanNodeIDs([]string{id}); err != nil {
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}
