package cluster

import (
	"sort"

	"netdir/internal/core"
)

// GroupSeed carries the primary's local values for a group, used only to
// initialise a group a replica doesn't have yet.
type GroupSeed struct {
	GroupID   int    `json:"group_id"`
	Interface string `json:"interface"`
	Priority  int    `json:"priority"`
	Weight    int    `json:"weight"`
	Preempt   bool   `json:"preempt"`
}

func SeedsOf(dc *core.DaemonConfig) []GroupSeed {
	var out []GroupSeed
	for _, g := range dc.Groups {
		out = append(out, GroupSeed{g.GroupID, g.Interface, g.Priority, g.Weight, g.Preempt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GroupID < out[j].GroupID })
	return out
}

// mergeShared overwrites the shared parts of dc with sh, keeping local fields.
// Groups missing locally are created (initialised from seeds); local groups
// absent from sh are removed.  It reports whether dc changed.
func MergeShared(dc *core.DaemonConfig, sh core.SharedConfig, seeds []GroupSeed) (bool, error) {
	before := core.SharedOf(dc).Hash()
	beforeGroups := len(dc.Groups)
	byID := map[int]int{}
	for i, g := range dc.Groups {
		byID[g.GroupID] = i
	}
	seedBy := map[int]GroupSeed{}
	for _, s := range seeds {
		seedBy[s.GroupID] = s
	}
	want := map[int]bool{}
	for _, g := range sh.Groups {
		want[g.GroupID] = true
		if i, ok := byID[g.GroupID]; ok {
			core.ApplySharedGroup(&dc.Groups[i], g)
			continue
		}
		gc := core.DefaultGroup()
		core.ApplySharedGroup(&gc, g)
		if s, ok := seedBy[g.GroupID]; ok {
			gc.Interface, gc.Priority, gc.Weight, gc.Preempt = s.Interface, s.Priority, s.Weight, s.Preempt
		}
		dc.Groups = append(dc.Groups, gc)
	}
	kept := dc.Groups[:0]
	for _, g := range dc.Groups {
		if want[g.GroupID] {
			kept = append(kept, g)
		}
	}
	dc.Groups = kept
	dc.Settings = sh.Settings
	if sh.WebGroup != "" {
		dc.Web.Group = sh.WebGroup
	}
	sh.WebAuth.ApplyTo(&dc.Web)
	dc.Web.SSOConfig = core.SsoOf(sh.SSO)
	dc.Web.LDAPConfig = core.LdapOf(sh.LDAP)
	if err := dc.Validate(); err != nil {
		return false, err
	}
	return core.SharedOf(dc).Hash() != before || len(dc.Groups) != beforeGroups, nil
}
