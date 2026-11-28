package core

import (
	"fmt"
)

// NodePauseState is what the Node page and `netdir --node-status` show.
type NodePauseState struct {
	Paused bool `json:"paused"`
}

func LastServing(mine []GwState, peers []PeerGateways) string {
	for _, g := range mine {
		if !g.Serving {
			continue
		}
		covered := false
		for _, p := range peers {
			if p.Down {
				continue
			}
			if !p.Known || p.Serving[g.GroupID] {
				covered = true // an older node cannot say; assume it serves
				break
			}
		}
		if !covered {
			return fmt.Sprintf("this is the only node serving gateway %d, so pausing it would stop that gateway — resume or repair another node that can serve it first; to stop the gateway on purpose, pause the gateway instead", g.GroupID)
		}
	}
	return ""
}
