package main

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"netdir/device"
	"netdir/internal/cluster"
	"netdir/internal/core"
	"netdir/internal/devices"
	"netdir/internal/mcp"
)

// membersOf lists the nodes serving group gid, one entry per node even when
// both address families are running.
func membersOf(rows []core.SnapshotRow, gid int) []core.CanvasMember {
	out := []core.CanvasMember{}
	idx := map[string]int{}
	for _, r := range rows {
		if r.GroupID != gid || r.AfnID == 0 || r.State == "expired" || r.PeerIP == "" {
			continue
		}
		i, ok := idx[r.PeerIP]
		if !ok {
			i = len(out)
			idx[r.PeerIP] = i
			out = append(out, core.CanvasMember{IP: r.PeerIP, Local: r.Local, AfnID: r.AfnID, Weight: r.Weight})
		}
		if out[i].AFs != "" {
			out[i].AFs += "+"
		}
		out[i].AFs += r.AF
		if r.AGCIP == r.PeerIP {
			out[i].AGC = true
			if out[i].AGCAFs != "" {
				out[i].AGCAFs += "+"
			}
			out[i].AGCAFs += r.AF
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].IP < out[b].IP })
	return out
}

// mergeFamilyMembers makes the members of each gateway one per node.  membersOf can only tell members apart by the
// address they speak the gateway protocol from, and a node with both address families running has a different one for
// each (its IPv4 address and an IPv6 one), so a dual-stack gateway on 4 nodes listed 8 members and the tooltip said
// "Serving nodes: 8".  names maps the cluster's node addresses to node names (nodeNamesByIP: one per node, the address
// when two nodes share a host name); members with the same name are one node.  An address that is not in the map stays
// its own member.  The IPv4 address is kept as the member's address (the node's addresses on the Nodes page are
// matched against it), and the families are joined.
func mergeFamilyMembers(gs []core.CanvasGateway, names map[string]string) {
	for i := range gs {
		ms := gs[i].Members
		if len(ms) < 2 {
			continue
		}
		out := make([]core.CanvasMember, 0, len(ms))
		at := map[string]int{}
		for _, m := range ms {
			name := names[core.NormIP(m.IP)]
			if name == "" {
				out = append(out, m)
				continue
			}
			j, ok := at[name]
			if !ok {
				at[name] = len(out)
				out = append(out, m)
				continue
			}
			o := &out[j]
			if a, err := netip.ParseAddr(m.IP); err == nil && a.Is4() { // the IPv4 side stands for the node
				m.AFs, o.AFs = o.AFs, m.AFs
				o.IP, o.AfnID, o.Weight = m.IP, m.AfnID, m.Weight
			}
			if o.AFs != "" && m.AFs != "" && !strings.Contains(o.AFs, m.AFs) {
				o.AFs += "+" + m.AFs
			}
			o.Local = o.Local || m.Local
			o.AGC = o.AGC || m.AGC
			for _, af := range strings.Split(m.AGCAFs, "+") {
				if af != "" && !core.ContainsStr(strings.Split(o.AGCAFs, "+"), af) {
					if o.AGCAFs != "" {
						o.AGCAFs += "+"
					}
					o.AGCAFs += af
				}
			}
		}
		sort.Slice(out, func(a, b int) bool { return out[a].IP < out[b].IP })
		gs[i].Members = out
	}
}

// buildCanvas combines the running configuration with what the engines currently report.
func buildCanvas(dc *core.DaemonConfig, rows []core.SnapshotRow) []core.CanvasGateway {
	health := devices.DeviceHealth(true)
	out := make([]core.CanvasGateway, 0, len(dc.Groups))
	for i := range dc.Groups {
		g := &dc.Groups[i]
		callers := mcp.McpSeen.Callers(append(append([]string{g.VIP4, g.VIP6}, g.MoreVIP4...), g.MoreVIP6...)...)
		cg := core.CanvasGateway{Name: g.Name, GroupID: g.GroupID, Interface: g.Interface, VIP4: g.VIP4, VIP6: g.VIP6,
			Families: []core.CanvasFamily{}, Devices: canvasDevices(dc, g, health), Members: membersOf(rows, g.GroupID), MCPCallers: callers, MCPClients: len(callers), Paused: g.Paused, NodePaused: dc.NodePaused, ExcludedNodes: append([]string(nil), g.ExcludedNodes...), WeakKey: core.IsWeakKey(g.Key)}
		// the gateway itself, one state per address family
		for _, f := range []struct{ af, vip string }{{"v4", g.VIP4}, {"v6", g.VIP6}} {
			if f.vip == "" {
				continue
			}
			running, active, answering := false, false, false
			state := "starting"
			for _, r := range rows {
				if r.GroupID != g.GroupID || r.AF != f.af {
					continue
				}
				running = true
				if !r.Local {
					continue
				}
				state = r.State
				if r.State == "active" || r.State == "forward" {
					active = true
				}
				if r.ServiceUp {
					answering = true
				}
			}
			cf := core.CanvasFamily{AF: f.af, VIP: f.vip}
			switch {
			case !running:
				cf.Status, cf.Detail = "idle", "not running"
			case !active:
				cf.Status, cf.Detail = "warn", "this node is not serving the gateway yet (state: "+state+")"
			case !answering:
				cf.Status, cf.Detail = "bad", "the gateway is up but this node's MCP and web listener is not serving"
			default:
				cf.Status, cf.Detail = "ok", "running and answering"
			}
			cg.Families = append(cg.Families, cf)
		}
		cg.Status, cg.Detail = combineFamilies(cg.Families)
		if g.Paused {
			cg.Status, cg.Detail = "paused", "Paused on this node — it is not serving; the other nodes carry on"
			if dc.NodePaused {
				cg.Detail = "This node is paused — it is not serving; the other nodes carry on"
			}
			if g.PausedAll {
				cg.PausedScope = "all"
				cg.Detail = "Paused on all nodes — none of them serves it until it is resumed"
			} else if !dc.NodePaused {
				cg.PausedScope = "node"
			}
			for i := range cg.Families {
				cg.Families[i].Status, cg.Families[i].Detail = "paused", "paused on this node"
			}
			if g.ExcludedHere { // removed from the gateway, which says more than the pause it is carried out as
				cg.Excluded, cg.PausedScope = true, ""
				cg.Detail = "This node was removed from the gateway — it does not serve it; the other nodes carry on"
				for i := range cg.Families {
					cg.Families[i].Detail = "this node was removed from the gateway"
				}
			}
		}
		out = append(out, cg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GroupID < out[j].GroupID })
	return out
}

// canvasDevices lists a gateway's devices, in its order, with the health devHealth has for each.
func canvasDevices(dc *core.DaemonConfig, g *core.GroupConfig, health map[string]device.Health) []core.CanvasDevice {
	byName := map[string]device.Device{}
	for _, d := range dc.Settings.Devices {
		byName[d.Name] = d
	}
	out := []core.CanvasDevice{}
	for _, n := range g.Devices {
		d, ok := byName[n]
		if !ok {
			continue
		}
		h, ok := health[n]
		if !ok {
			h = device.Health{Status: "idle", Detail: "not checked yet"}
		}
		if d.Disabled {
			h.Status, h.Detail = "paused", "disabled: never contacted"
		}
		if h.Status == "ok" && h.AlertCount > 0 { // answering, with alerts of its own: its own colour (purple), not a fault of the device
			h.Status = "alert"
		}
		out = append(out, core.CanvasDevice{Name: d.Name, Platform: d.Platform, Address: d.Address, Tags: d.Tags, Status: h.Status, Detail: h.Detail, Health: h})
	}
	return out
}

// combineFamilies folds the per-family states into the gateway's own: the worst
// one wins, and a family that is not running while the other is counts as
// degraded.  The detail names the family when there is more than one.
func combineFamilies(fs []core.CanvasFamily) (status, detail string) {
	if len(fs) == 0 {
		return "idle", "no address"
	}
	rank := map[string]int{"ok": 0, "idle": 1, "warn": 2, "bad": 3}
	allIdle := true
	worst := "ok"
	for _, f := range fs {
		if f.Status != "idle" {
			allIdle = false
		}
		if rank[f.Status] > rank[worst] {
			worst = f.Status
		}
	}
	switch {
	case allIdle:
		worst = "idle"
	case worst == "idle":
		worst = "warn" // one family runs, the other does not
	}
	if len(fs) == 1 {
		return worst, fs[0].Detail
	}
	var parts []string
	for _, f := range fs {
		name := "IPv4"
		if f.AF == "v6" {
			name = "IPv6"
		}
		parts = append(parts, name+": "+f.Detail)
	}
	return worst, strings.Join(parts, "; ")
}

// canvasGroups is the picture as the GUI and CLI show it, with the uptimes noted.
func (s *StatusServer) CanvasGroups() []core.CanvasGateway {
	groups := buildCanvas(s.sup.Config(), s.Snapshot())
	mergeFamilyMembers(groups, s.IPNames())
	markOffnet(groups, s.sup.OffnetGroups())
	cfg := s.sup.Config()
	real := map[int]bool{}
	for _, g := range cfg.Groups {
		real[g.GroupID] = g.RealMACs
	}
	core.MarkVmac(groups, real)
	s.markAnycast(groups)
	s.markNodes(groups)
	s.up.Annotate(groups, time.Now())
	cluster.StoreAnycastLocal(groups)
	if s.mg != nil {
		for i := range groups {
			for j := range groups[i].Anycast {
				groups[i].Anycast[j].ClusterUpSec = s.mg.cl.AnyUpSeconds(groups[i].Anycast[j].Addr)
			}
		}
	}
	return groups
}

func (s *StatusServer) canvasView() map[string]any {
	return map[string]any{"ok": true, "data": s.CanvasGroups(), "dnsdir": core.DnsdirInfo()}
}

// markAnycast lists each gateway's anycast addresses and whether this node
// announces them now.
func (s *StatusServer) markAnycast(groups []core.CanvasGateway) {
	cfg := s.sup.Config()
	for i := range groups {
		st := s.sup.AnycastStates(groups[i].GroupID)
		if st == nil {
			for _, g := range cfg.Groups {
				if g.GroupID != groups[i].GroupID {
					continue
				}
				why := "gateway not running on this node"
				paused := g.PausedAnycast()
				for _, a := range g.ExtraVIPs {
					st = append(st, core.AnycastState{Addr: a, Reason: why, Paused: paused[a]})
				}
			}
		}
		switch {
		case cfg.BGP.Active() || cfg.OSPF.Active():
			var bp []core.BGPPeer
			var bok bool
			if cfg.BGP.Active() {
				bp, bok = core.LiveBGPPeers()
			}
			var op []core.OSPFPeer
			var ook bool
			if cfg.OSPF.Active() {
				op, ook = core.LiveOSPFPeers()
			}
			for j := range st {
				if st[j].Up && st[j].Paused == "" && !st[j].External {
					st[j].Status, st[j].Detail, st[j].BGP = core.AnycastRouteStatus(cfg, st[j].Addr, bp, bok, op, ook)
				}
			}
		case cfg.BGP.Configured() || cfg.OSPF.Configured(): // routing is disabled here (Operate ▸ Anycast): nothing is announced
			what := "BGP"
			if !cfg.BGP.Configured() {
				what = "OSPF"
			}
			for j := range st {
				if st[j].Up && st[j].Paused == "" && !st[j].External {
					st[j].Status, st[j].Detail, st[j].BGP = "bad", what+" is disabled on this node (Operate ▸ Anycast): the address is not announced", "disabled"
				}
			}
		}
		groups[i].Anycast = st
	}
}

// markOffnet shows the gateways this node does not run because it has no address
// in their subnet: grey, with the reason.  The other members are unaffected.
func markOffnet(groups []core.CanvasGateway, off map[int]string) {
	for i := range groups {
		why, ok := off[groups[i].GroupID]
		if !ok {
			continue
		}
		detail := "not running here — " + why + "; members on that subnet serve it"
		groups[i].Status, groups[i].Detail = "idle", detail
		for j := range groups[i].Families {
			groups[i].Families[j].Status, groups[i].Families[j].Detail = "idle", detail
		}
	}
}

// ── editing (CLI: --canvas-add / --canvas-del) ───────────────────────────────

type canvasEdit struct {
	Action string `json:"action"` // add | del | set | pause | resume | move | prune
	Kind   string `json:"kind"`   // gateway | node | anycast | device
	Group  int    `json:"group"`
	VIP    string `json:"vip"`  // IPv4 (or IPv6) address/prefix
	VIP6   string `json:"vip6"` // IPv6 address/prefix
	// RealMACs on | off | "" (unchanged): the gateway runs without virtual MACs on every node (a shared setting)
	RealMACs  string `json:"real_macs"`
	Interface string `json:"interface"`
	Label     string `json:"label"`   // gateway name; "-" clears it
	Anycast   string `json:"anycast"` // anycast addresses, comma separated; "-" clears them
	Address   string `json:"address"` // one anycast address (--canvas-add|del|pause|resume anycast)
	Scope     string `json:"scope"`   // pausing an anycast address: node (this one) or all (every node)
	Pos       int    `json:"pos"`     // --canvas-move: the new place in the list, 1 = first
	Device    string `json:"device"`  // a device's name (--canvas-add|del|move device)
	// Node names a cluster node for --canvas-add|del node: its address, host name or node ID.  CanvasEdit turns it into
	// nodeID and lists the cluster's node IDs in members, so the last member cannot be removed.
	Node    string `json:"node"`
	nodeID  string
	members string // the cluster's node IDs, comma separated (a slice would make canvasEdit incomparable)
}

// moveTo returns list with the item at index from moved to index to (both 0-based, to clamped).
func moveTo[T any](list []T, from, to int) []T {
	if to < 0 {
		to = 0
	}
	if to > len(list)-1 {
		to = len(list) - 1
	}
	out := append([]T(nil), list...)
	it := out[from]
	out = append(out[:from], out[from+1:]...)
	out = append(out[:to], append([]T{it}, out[to:]...)...)
	return out
}

// setVIPs assigns the shared addresses: vip may be IPv4 or IPv6, vip6 is IPv6.
// An empty argument leaves that family as it is.
func setVIPs(g *core.GroupConfig, vip, vip6 string) {
	for _, v := range []string{vip, vip6} {
		if v == "" {
			continue
		}
		if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Is6() {
			g.VIP6 = v
		} else {
			g.VIP4 = v
		}
	}
}

// parseAnycastList reads --anycast: addresses separated by commas or spaces,
// "-" for none.
func parseAnycastList(v string) ([]string, error) {
	if strings.TrimSpace(v) == "-" {
		return nil, nil
	}
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		n, err := core.NormalizeAnycast(f)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func findGroup(dc *core.DaemonConfig, id int) (*core.GroupConfig, error) {
	for i := range dc.Groups {
		if dc.Groups[i].GroupID == id {
			return &dc.Groups[i], nil
		}
	}
	return nil, fmt.Errorf("there is no gateway with group number %d (see --canvas)", id)
}

// applyCanvasEdit changes dc as asked.  The caller validates and saves.
func applyCanvasEdit(dc *core.DaemonConfig, e canvasEdit) (string, error) {
	switch e.Kind {
	case "gateway":
		switch e.Action {
		case "set":
			g, err := findGroup(dc, e.Group)
			if err != nil {
				return "", err
			}
			var did []string
			if e.VIP != "" || e.VIP6 != "" {
				setVIPs(g, e.VIP, e.VIP6)
				did = append(did, "address")
			}
			if e.Interface != "" {
				g.Interface = e.Interface
				did = append(did, "interface")
			}
			if e.Label != "" {
				if e.Label == "-" {
					g.Name = ""
				} else {
					g.Name = e.Label
				}
				did = append(did, "name")
			}
			if e.Anycast != "" {
				l, err := parseAnycastList(e.Anycast)
				if err != nil {
					return "", err
				}
				g.ExtraVIPs = l
				did = append(did, "anycast addresses")
			}
			switch e.RealMACs {
			case "":
			case "on", "off":
				g.RealMACs = e.RealMACs == "on"
				did = append(did, "real MAC addresses "+e.RealMACs)
			default:
				return "", errors.New("--real-macs must be on or off")
			}
			if len(did) == 0 {
				return "", errors.New("nothing to change: give --vip, --vip6, --interface, --label, --anycast or --real-macs")
			}
			return fmt.Sprintf("gateway %d: changed %s", e.Group, strings.Join(did, ", ")), nil
		case "add":
			if e.VIP == "" && e.VIP6 == "" {
				return "", errors.New("--vip is required (the shared address, e.g. 10.0.0.1/24; add --vip6 for an IPv6 address too)")
			}
			id := e.Group
			if id == 0 {
				used := map[int]bool{}
				for _, g := range dc.Groups {
					used[g.GroupID] = true
				}
				for id = core.FirstGroupID; used[id] && id < 256; id++ {
				}
			}
			for _, g := range dc.Groups {
				if g.GroupID == id {
					return "", fmt.Errorf("gateway %d already exists", id)
				}
			}
			g := core.NewGatewayGroup()
			g.GroupID = id
			g.VIP4, g.VIP6 = "", ""
			if e.Label != "-" {
				g.Name = e.Label
			}
			setVIPs(&g, e.VIP, e.VIP6)
			if e.Anycast != "" {
				l, err := parseAnycastList(e.Anycast)
				if err != nil {
					return "", err
				}
				g.ExtraVIPs = l
			}
			if e.Interface != "" {
				g.Interface = e.Interface
			} else if len(dc.Groups) > 0 {
				g.Interface = dc.Groups[0].Interface
			}
			dc.Groups = append(dc.Groups, g)
			return fmt.Sprintf("added gateway %d (%s)", id, core.OrDefault(e.VIP, e.VIP6)), nil
		case "pause", "resume":
			g, err := findGroup(dc, e.Group)
			if err != nil {
				return "", err
			}
			scope := core.OrDefault(e.Scope, "node") // this node unless said otherwise
			if scope != "node" && scope != "all" {
				return "", errors.New("--scope must be node (this node only) or all (every node)")
			}
			want := e.Action == "pause"
			flag, where := &g.Paused, "this node"
			if scope == "all" {
				flag, where = &g.PausedAll, "all nodes"
			}
			if *flag == want {
				return fmt.Sprintf("gateway %d is already %s on %s", e.Group, map[bool]string{true: "paused", false: "running"}[want], where), nil
			}
			*flag = want
			if want {
				return fmt.Sprintf("gateway %d paused on %s — it stops serving there; resume it when maintenance is done", e.Group, where), nil
			}
			return fmt.Sprintf("gateway %d resumed on %s", e.Group, where), nil
		case "del":
			g, err := findGroup(dc, e.Group)
			if err != nil {
				return "", err
			}
			kept := dc.Groups[:0]
			for _, x := range dc.Groups {
				if x.GroupID != g.GroupID {
					kept = append(kept, x)
				}
			}
			dc.Groups = kept
			return fmt.Sprintf("deleted gateway %d", e.Group), nil
		}
	case "node":
		if e.Action == "prune" { // the entries of nodes that have left the cluster, from one gateway (group) or all (0)
			if e.members == "" {
				return "", errors.New("the cluster's nodes are not known here, so nothing is taken as having left")
			}
			members := strings.Split(e.members, ",")
			if e.Group != 0 {
				if _, err := findGroup(dc, e.Group); err != nil {
					return "", err
				}
			}
			var did []string
			for i := range dc.Groups {
				g := &dc.Groups[i]
				if e.Group != 0 && g.GroupID != e.Group {
					continue
				}
				var kept []string
				for _, id := range g.ExcludedNodes {
					if core.ContainsStr(members, id) {
						kept = append(kept, id)
					} else {
						did = append(did, fmt.Sprintf("%s from gateway %d", shortID(id), g.GroupID))
					}
				}
				g.ExcludedNodes = kept
			}
			if len(did) == 0 {
				return "", errNoChange
			}
			return "cleared the entries of nodes that left the cluster: " + strings.Join(did, ", "), nil
		}
		g, err := findGroup(dc, e.Group)
		if err != nil {
			return "", err
		}
		if e.nodeID == "" {
			return "", errors.New("--node is required: the node's address, host name or node ID (see --cluster)")
		}
		who := core.OrDefault(e.Node, e.nodeID)
		out := core.ContainsStr(g.ExcludedNodes, e.nodeID)
		switch e.Action {
		case "del": // removed from the gateway
			if out {
				return fmt.Sprintf("node %s is already removed from gateway %d", who, e.Group), nil
			}
			if e.members != "" {
				left := 0
				for _, id := range strings.Split(e.members, ",") {
					if id != e.nodeID && !core.ContainsStr(g.ExcludedNodes, id) {
						left++
					}
				}
				if left == 0 {
					return "", fmt.Errorf("that would leave no node serving gateway %d — pause it on all nodes instead (--canvas-pause gateway --group %d --scope all)", e.Group, e.Group)
				}
			}
			g.ExcludedNodes = append(g.ExcludedNodes, e.nodeID)
			return fmt.Sprintf("node %s removed from gateway %d — it stops serving it and the other nodes carry on", who, e.Group), nil
		case "add": // back in the gateway
			if !out {
				return fmt.Sprintf("node %s is already serving gateway %d", who, e.Group), nil
			}
			kept := g.ExcludedNodes[:0:0]
			for _, id := range g.ExcludedNodes {
				if id != e.nodeID {
					kept = append(kept, id)
				}
			}
			g.ExcludedNodes = kept
			return fmt.Sprintf("node %s added back to gateway %d — it serves it again", who, e.Group), nil
		}
		return "", fmt.Errorf("a node can be added to or removed from a gateway: --canvas-add|--canvas-del node --group N --node NODE")
	case "device":
		if e.Action == "pause" || e.Action == "resume" { // all nodes: the inventory's switch (a disabled device is never contacted); node: only this node
			scope := core.OrDefault(e.Scope, "all")
			if scope != "node" && scope != "all" {
				return "", errors.New("--scope must be node (this node) or all (every node)")
			}
			if e.Device == "" {
				return "", errors.New("--device is required: a device's name (settings.devices)")
			}
			for i := range dc.Settings.Devices {
				d := &dc.Settings.Devices[i]
				if d.Name != e.Device {
					continue
				}
				pause := e.Action == "pause"
				if scope == "node" {
					if core.ContainsStr(dc.PausedDevicesHere, d.Name) == pause {
						return "", errNoChange
					}
					if pause {
						dc.PausedDevicesHere = append(dc.PausedDevicesHere, d.Name)
						return fmt.Sprintf("device %s paused on this node: this node does not contact it", e.Device), nil
					}
					var keep []string
					for _, n := range dc.PausedDevicesHere {
						if n != d.Name {
							keep = append(keep, n)
						}
					}
					dc.PausedDevicesHere = keep
					return fmt.Sprintf("device %s resumed on this node", e.Device), nil
				}
				if d.Disabled == pause {
					return fmt.Sprintf("device %s is already %s", e.Device, map[bool]string{true: "disabled", false: "enabled"}[d.Disabled]), nil
				}
				d.Disabled = pause
				if d.Disabled {
					return fmt.Sprintf("device %s disabled: no node contacts it until it is enabled again", e.Device), nil
				}
				return fmt.Sprintf("device %s enabled", e.Device), nil
			}
			return "", fmt.Errorf("there is no device %q", e.Device)
		}
		g, err := findGroup(dc, e.Group)
		if err != nil {
			return "", err
		}
		if e.Device == "" {
			return "", errors.New("--device is required: a device's name (settings.devices)")
		}
		known := false
		for _, d := range dc.Settings.Devices {
			if d.Name == e.Device {
				known = true
			}
		}
		idx := -1
		for i, n := range g.Devices {
			if n == e.Device {
				idx = i
			}
		}
		switch e.Action {
		case "add":
			if !known {
				return "", fmt.Errorf("there is no device %q (add it to settings.devices first)", e.Device)
			}
			if idx >= 0 {
				return "", fmt.Errorf("device %s is already on gateway %d", e.Device, e.Group)
			}
			g.Devices = append(g.Devices, e.Device)
			return fmt.Sprintf("added device %s to gateway %d", e.Device, e.Group), nil
		case "move":
			if idx < 0 {
				return "", fmt.Errorf("device %s is not on gateway %d", e.Device, e.Group)
			}
			if e.Pos < 1 {
				return "", errors.New("--to is required: the new place in the row, 1 = leftmost")
			}
			g.Devices = moveTo(g.Devices, idx, e.Pos-1)
			return fmt.Sprintf("moved device %s to place %d of %d", e.Device, min(e.Pos, len(g.Devices)), len(g.Devices)), nil
		case "del":
			if idx < 0 {
				return "", fmt.Errorf("device %s is not on gateway %d", e.Device, e.Group)
			}
			g.Devices = append(g.Devices[:idx], g.Devices[idx+1:]...)
			if len(g.Devices) == 0 {
				g.Devices = nil
			}
			return fmt.Sprintf("removed device %s from gateway %d (it stays in the inventory)", e.Device, e.Group), nil
		}
	case "anycast":
		g, err := findGroup(dc, e.Group)
		if err != nil {
			return "", err
		}
		if e.Address == "" {
			return "", errors.New("--address is required")
		}
		addr, err := core.NormalizeAnycast(e.Address)
		if err != nil {
			return "", err
		}
		idx := -1
		for i, a := range g.ExtraVIPs {
			if n, _ := core.NormalizeAnycast(a); n == addr {
				idx = i
			}
		}
		switch e.Action {
		case "add":
			if idx >= 0 {
				return "", fmt.Errorf("anycast address %s is already on gateway %d", addr, e.Group)
			}
			g.ExtraVIPs = append(g.ExtraVIPs, addr)
			return fmt.Sprintf("added anycast address %s to gateway %d", addr, e.Group), nil
		case "move":
			if idx < 0 {
				return "", fmt.Errorf("anycast address %s is not on gateway %d", addr, e.Group)
			}
			if e.Pos < 1 {
				return "", errors.New("--to is required: the new place in the list, 1 = top")
			}
			g.ExtraVIPs = moveTo(g.ExtraVIPs, idx, e.Pos-1)
			return fmt.Sprintf("moved anycast address %s to place %d of %d", addr, min(e.Pos, len(g.ExtraVIPs)), len(g.ExtraVIPs)), nil
		case "pause", "resume":
			if idx < 0 {
				return "", fmt.Errorf("anycast address %s is not on gateway %d", addr, e.Group)
			}
			if e.Scope != "node" && e.Scope != "all" {
				return "", errors.New("--scope node|all is required: pause on this node only, or on every node")
			}
			list, where := &g.PausedVIPsHere, "this node"
			if e.Scope == "all" {
				list, where = &g.PausedVIPs, "all nodes"
			}
			have := core.ContainsStr(*list, addr)
			if e.Action == "pause" {
				if have {
					return fmt.Sprintf("anycast address %s is already paused on %s", addr, where), nil
				}
				*list = append(*list, addr)
				return fmt.Sprintf("anycast address %s paused on %s — it is withdrawn there until you resume it", addr, where), nil
			}
			if !have {
				return fmt.Sprintf("anycast address %s is not paused on %s", addr, where), nil
			}
			kept := []string{}
			for _, p := range *list {
				if p != addr {
					kept = append(kept, p)
				}
			}
			if len(kept) == 0 {
				kept = nil
			}
			*list = kept
			return fmt.Sprintf("anycast address %s resumed on %s", addr, where), nil
		case "del":
			if idx < 0 {
				return "", fmt.Errorf("anycast address %s is not on gateway %d", addr, e.Group)
			}
			g.ExtraVIPs = append(g.ExtraVIPs[:idx], g.ExtraVIPs[idx+1:]...)
			return fmt.Sprintf("removed anycast address %s from gateway %d", addr, e.Group), nil
		}
	}
	return "", fmt.Errorf("unknown canvas edit %q %q (use add, del, set, pause, resume or move with gateway, node, anycast or device)", e.Action, e.Kind)
}

// CanvasEdit applies one edit to the saved configuration.
func (m *Mgmt) CanvasEdit(e canvasEdit, actor string) (string, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return "", err
	}
	if e.Kind == "node" && e.Action == "prune" {
		var ids []string
		if m.cl != nil {
			for _, p := range m.cl.View().Peers {
				if p.NodeID != "" {
					ids = append(ids, p.NodeID)
				}
			}
		}
		e.members = strings.Join(ids, ",")
	} else if e.Kind == "node" {
		if err := m.resolveNode(dc, &e); err != nil {
			return "", err
		}
	}
	known := cluster.GroupIDSet(dc)
	msg, err := applyCanvasEdit(dc, e)
	if errors.Is(err, errNoChange) {
		return "nothing to change", nil
	}
	if err != nil {
		return "", err
	}
	m.HoldBackFromNewGateways(dc, known)
	if err := m.PutConfig(dc, actor, "canvas: "+e.Action+" "+e.Kind); err != nil {
		return "", err
	}
	return msg, nil
}

// errNoChange: the edit would change nothing, so nothing is saved.
var errNoChange = errors.New("nothing to change")

// shortID is a node ID cut to its first 8 characters, as messages show it.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// pausedWhere words a pause scope: "all nodes" or "this node".
func pausedWhere(scope string) string {
	if scope == "all" {
		return "all nodes"
	}
	return "this node"
}
