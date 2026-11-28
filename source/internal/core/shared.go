package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"netdir/device"
)

// What a cluster replicates.  Gateway groups are the same group on every
// member (same VIP, key, timers), but each node has its own interface,
// priority, weight, preempt flag and unicast neighbours — those are local and
// never replicated.  The settings block is shared as a whole, and so are the web login groups and sign-in rules (see WebGroup, WebAuth); the rest of web, cluster and
// log_level are local.

// SharedGroup is the replicated part of a GroupConfig.
type SharedGroup struct {
	// Name is omitted when empty so a cluster with no names keeps the same hash
	// as before (members on different versions during a rolling update agree).
	Name        string   `json:"name,omitempty"`
	FQDN        string   `json:"fqdn,omitempty"`
	AnycastFQDN string   `json:"anycast_fqdn,omitempty"`
	GroupID     int      `json:"group_id"`
	VIP4        string   `json:"vip4"`
	VIP6        string   `json:"vip6"`
	LBMethod    LBMethod `json:"lb_method"`
	HelloMS     int      `json:"hello_ms"`
	HoldMS      int      `json:"hold_ms"`
	MaxAFNs     int      `json:"max_afns"`
	Key         string   `json:"key"`
	// ExtraVIPs are the anycast addresses (omitted when none, so the hash of a
	// cluster without any is unchanged).
	ExtraVIPs []string `json:"extra_vips,omitempty"`
	// Devices are the managed devices of the gateway, by name (omitted when none: the hash is unchanged).
	Devices []string `json:"devices,omitempty"`
	// MoreVIP4 / MoreVIP6 are the further shared addresses in the subnet (omitted when none: the hash is unchanged).
	MoreVIP4 []string `json:"more_vip4,omitempty"`
	MoreVIP6 []string `json:"more_vip6,omitempty"`
	// Neighbors are the unicast addresses of every node of the gateway, this one included (a node skips its own);
	// omitted when empty (multicast), so the hash of a multicast cluster is unchanged.
	Neighbors []string `json:"neighbors,omitempty"`
	// PausedVIPs are the anycast addresses paused on every node (omitted when none: the hash is unchanged).
	PausedVIPs []string `json:"paused_vips,omitempty"`
	// PausedAll: the gateway is paused on every node (omitted when not).
	PausedAll bool `json:"paused_all,omitempty"`
	// RealMACs: the gateway runs without virtual MACs on every node (omitted when not, so the hash is unchanged).
	RealMACs bool `json:"real_macs,omitempty"`
	// ExcludedNodes are the nodes (by node ID) removed from the gateway (omitted when none: the hash is unchanged).
	ExcludedNodes []string `json:"excluded_nodes,omitempty"`
	// NodeOrder is the order the nodes are drawn in beside the gateway (omitted when not set).
	NodeOrder []string `json:"node_order,omitempty"`
}

// SharedConfig is the replicated document.
type SharedConfig struct {
	Settings Settings      `json:"settings"`
	Groups   []SharedGroup `json:"groups"`
	// WebGroup is the web login groups setting (web.group), so the same people may sign in on every node.  It is omitted
	// while it is the single local group every earlier version had (legacyWebGroup): the hash of a cluster that has not
	// set it is unchanged, so members on different versions during a rolling update agree.  A member that gets no value
	// keeps its own.
	WebGroup string `json:"web_group,omitempty"`
	// WebAuth is the sign-in lockout (max_failed_logins, failed_login_window_minutes, lockout_minutes) and the minimum
	// password length, so the same rules hold on every node.  Omitted while all four are the defaults every earlier version
	// had, for the same reason as WebGroup; a member that gets none keeps its own.
	WebAuth *SharedWebAuth `json:"web_auth,omitempty"`
	// SSO is single sign-on (providers, users); omitted while nothing is set, so the hash of a cluster that does not use it is unchanged.
	SSO *SSOConfig `json:"sso,omitempty"`
	// LDAP is sign-in with a directory (servers, service account, groups); omitted while nothing is set, for the same reason.
	LDAP *LDAPConfig `json:"ldap,omitempty"`
}

// SharedWebAuth is the replicated part of the sign-in rules.
type SharedWebAuth struct {
	MaxFailedLogins          int    `json:"max_failed_logins"`
	FailedLoginWindowMinutes int    `json:"failed_login_window_minutes"`
	LockoutMinutes           int    `json:"lockout_minutes"`
	MinPasswordLength        int    `json:"min_password_length"`
	ReadGroup                string `json:"read_group,omitempty"` // the read-only login groups
}

// sharedWebAuth is the document's WebAuth for a web block: nil while every value is the default.
func sharedWebAuth(w WebConfig) *SharedWebAuth {
	d := DefaultWeb()
	if w.MaxFailedLogins == d.MaxFailedLogins && w.FailedLoginWindowMinutes == d.FailedLoginWindowMinutes &&
		w.LockoutMinutes == d.LockoutMinutes && w.MinPassword() == DefaultMinPassword && w.ReadGroup == d.ReadGroup {
		return nil
	}
	return &SharedWebAuth{w.MaxFailedLogins, w.FailedLoginWindowMinutes, w.LockoutMinutes, w.MinPasswordLength, w.ReadGroup}
}

func (a *SharedWebAuth) ApplyTo(w *WebConfig) {
	if a != nil {
		w.MaxFailedLogins, w.FailedLoginWindowMinutes, w.LockoutMinutes, w.MinPasswordLength, w.ReadGroup =
			a.MaxFailedLogins, a.FailedLoginWindowMinutes, a.LockoutMinutes, a.MinPasswordLength, a.ReadGroup
	}
}

// legacyWebGroup is the value web.group had before it could be shared.
const LegacyWebGroup = "netdir"

func SharedOf(dc *DaemonConfig) SharedConfig {
	sc := SharedConfig{Settings: dc.Settings, Groups: []SharedGroup{}}
	if dc.Web.Group != LegacyWebGroup {
		sc.WebGroup = dc.Web.Group
	}
	sc.WebAuth = sharedWebAuth(dc.Web)
	sc.SSO = dc.Web.SSOConfig.clone()
	sc.LDAP = dc.Web.LDAPConfig.clone()
	sc.Settings = cloneSettings(sc.Settings)
	for _, g := range dc.Groups {
		sc.Groups = append(sc.Groups, SharedGroup{
			GroupID: g.GroupID, Name: g.Name, FQDN: g.FQDN, AnycastFQDN: g.AnycastFQDN, VIP4: g.VIP4, VIP6: g.VIP6, LBMethod: g.LBMethod,
			HelloMS: g.HelloMS, HoldMS: g.HoldMS, MaxAFNs: g.MaxAFNs, Key: g.Key,
			ExtraVIPs: nonEmpty(g.ExtraVIPs), Devices: nonEmpty(g.Devices), MoreVIP4: nonEmpty(g.MoreVIP4), MoreVIP6: nonEmpty(g.MoreVIP6), PausedVIPs: nonEmpty(g.PausedVIPs), PausedAll: g.PausedAll, Neighbors: nonEmpty(g.Neighbors), RealMACs: g.RealMACs, ExcludedNodes: nonEmpty(g.ExcludedNodes), NodeOrder: nonEmpty(g.NodeOrder),
		})
	}
	sort.Slice(sc.Groups, func(i, j int) bool { return sc.Groups[i].GroupID < sc.Groups[j].GroupID })
	return sc
}

func (s SharedConfig) Hash() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s SharedConfig) Validate() error {
	dc := NewDaemonConfig()
	dc.Groups = nil
	for _, g := range s.Groups {
		gc := DefaultGroup()
		ApplySharedGroup(&gc, g)
		dc.Groups = append(dc.Groups, gc)
	}
	dc.Settings = s.Settings
	if s.WebGroup != "" {
		dc.Web.Group = s.WebGroup
	}
	s.WebAuth.ApplyTo(&dc.Web)
	dc.Web.SSOConfig = SsoOf(s.SSO)
	dc.Web.LDAPConfig = LdapOf(s.LDAP)
	return dc.Validate()
}

func ApplySharedGroup(gc *GroupConfig, g SharedGroup) {
	gc.GroupID, gc.Name, gc.VIP4, gc.VIP6, gc.LBMethod = g.GroupID, g.Name, g.VIP4, g.VIP6, g.LBMethod
	gc.FQDN, gc.AnycastFQDN = g.FQDN, g.AnycastFQDN
	gc.HelloMS, gc.HoldMS, gc.MaxAFNs, gc.Key = g.HelloMS, g.HoldMS, g.MaxAFNs, g.Key
	gc.ExtraVIPs = append([]string(nil), g.ExtraVIPs...)
	gc.Devices = nonEmpty(g.Devices)
	gc.MoreVIP4 = append([]string(nil), g.MoreVIP4...)
	gc.MoreVIP6 = append([]string(nil), g.MoreVIP6...)
	gc.PausedVIPs = append([]string(nil), g.PausedVIPs...)
	gc.PausedAll = g.PausedAll
	gc.RealMACs = g.RealMACs
	gc.ExcludedNodes = append([]string(nil), g.ExcludedNodes...)
	gc.NodeOrder = append([]string(nil), g.NodeOrder...)
	gc.Neighbors = append([]string{}, g.Neighbors...)
}

// nonEmpty returns a copy of l, or nil when it is empty (keeps omitempty and hashes stable).
func nonEmpty(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	return append([]string(nil), l...)
}

// cloneSettings copies a Settings deeply enough that two configs never share
// slices or maps (Validate normalises in place).
func cloneSettings(d Settings) Settings {
	d.SNMPCommunities = nonEmpty(d.SNMPCommunities)
	d.SNMPACL = nonEmpty(d.SNMPACL)
	d.MetricsACL = nonEmpty(d.MetricsACL)
	d.MCPACL = nonEmpty(d.MCPACL)
	d.Privacy = d.Privacy.clone()
	d.Alerts = d.Alerts.clone()
	d.Backup = d.Backup.Clone()
	d.MCPKeys = append([]MCPKey(nil), d.MCPKeys...)
	if len(d.MCPKeys) == 0 {
		d.MCPKeys = nil
	}
	if len(d.Schedule) > 0 {
		sch := make([]SchedTask, len(d.Schedule))
		for i, t := range d.Schedule {
			t.Days, t.Nodes = append([]int(nil), t.Days...), append([]string(nil), t.Nodes...)
			if len(t.Days) == 0 {
				t.Days = nil
			}
			if len(t.Nodes) == 0 {
				t.Nodes = nil
			}
			sch[i] = t
		}
		d.Schedule = sch
	} else {
		d.Schedule = nil
	}
	if len(d.Devices) > 0 {
		devs := make([]device.Device, len(d.Devices))
		for i, x := range d.Devices {
			x.Tags = nonEmpty(x.Tags)
			if len(x.Options) > 0 {
				o := make(map[string]string, len(x.Options))
				for k, v := range x.Options {
					o[k] = v
				}
				x.Options = o
			} else {
				x.Options = nil
			}
			devs[i] = x
		}
		d.Devices = devs
	} else {
		d.Devices = nil
	}
	d.DeviceCredentials = append([]device.Credential(nil), d.DeviceCredentials...)
	if len(d.DeviceCredentials) == 0 {
		d.DeviceCredentials = nil
	}
	return d
}

// ssoOf is the single sign-on settings of a shared document: none when the document has none (a primary that clears them clears every node's).
func SsoOf(c *SSOConfig) SSOConfig {
	if c == nil || c.Empty() {
		return SSOConfig{}
	}
	return *c.clone()
}

// ldapOf is the LDAP settings of a shared document: none when the document has none.
func LdapOf(c *LDAPConfig) LDAPConfig {
	if c == nil || c.empty() {
		return LDAPConfig{}
	}
	return *c.clone()
}
