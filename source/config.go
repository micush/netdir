package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"netdir/device"
)

const (
	// Everything netdir keeps lives in /var/lib/netdir: the config, the GUI
	// certificate, config history, cluster identity and update data.
	confPath     = "/var/lib/netdir/netdir.conf"
	statusSocket = "/run/netdir/netdir.sock"

	// Releases before v15 kept the config under /etc/liras.
	legacyConfPath = "/etc/liras/netdir.conf"
)

// canonicalConf turns the pre-v15 path into the real one.  A service unit that was
// never rewritten (an in-place update does not touch it) still starts the daemon
// with `--config /etc/liras/netdir.conf`; nothing may be read from or written to
// /etc/liras any more, so that path means the config in /var/lib/netdir.
func canonicalConf(path string) string {
	if filepath.Clean(path) == legacyConfPath {
		return confPath
	}
	return path
}

// migrateLegacyConfig moves a pre-v15 /etc/liras config (and the self-signed
// GUI certificate next to it) to the default location.  It only acts when the
// new file does not exist yet and never overwrites anything.  It is a real move:
// each old file is removed once its copy is written and read back intact, and the
// directory goes when it is empty, so nothing is left in /etc/liras.  Errors are not fatal:
// the daemon then simply starts without a config, as for a fresh install.
func migrateLegacyConfig(dst, legacy string) (moved bool, err error) {
	if _, err := os.Stat(dst); err == nil {
		return false, nil
	}
	b, err := os.ReadFile(legacy)
	if err != nil {
		return false, nil // nothing to migrate
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return false, err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(legacy); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		return false, err
	}
	for _, f := range []string{"netdir-web.crt", "netdir-web.key"} {
		src, to := filepath.Join(filepath.Dir(legacy), f), filepath.Join(filepath.Dir(dst), f)
		if _, err := os.Stat(to); err == nil {
			continue
		}
		if cb, err := os.ReadFile(src); err == nil {
			if os.WriteFile(to, cb, 0o600) == nil {
				if back, err := os.ReadFile(to); err == nil && bytes.Equal(back, cb) {
					_ = os.Remove(src)
				}
			}
		}
	}
	if back, err := os.ReadFile(dst); err == nil && bytes.Equal(back, b) {
		_ = os.Remove(legacy)
	}
	_ = os.Remove(filepath.Dir(legacy)) // only succeeds when it is empty
	return true, nil
}

// ── Group config ─────────────────────────────────────────────────────────────

// GroupConfig holds per-group settings.  Each group gets its own engine(s).
type GroupConfig struct {
	// Name is an optional label shown instead of the address in the GUI and CLI.
	// Shared across the cluster.
	Name      string `json:"name,omitempty"`
	GroupID   int    `json:"group_id"`
	Interface string `json:"interface"`
	VIP4      string `json:"vip4"`
	VIP6      string `json:"vip6"`
	// MoreVIP4 and MoreVIP6 are further shared addresses inside the subnet of VIP4 / VIP6 (bare addresses, no prefix length:
	// they take the primary's).  They move with the gateway like the primary does and are answered the same way; the
	// primary stays the one in the hello packets.  Omitted when none, so older versions read the same file.
	MoreVIP4 []string `json:"more_vip4,omitempty"`
	MoreVIP6 []string `json:"more_vip6,omitempty"`
	Priority int      `json:"priority"`
	LBMethod LBMethod `json:"lb_method"`
	// RealMACs turns the virtual MACs off: no macvlan interfaces, and the controller answers ARP and neighbor
	// solicitations for the VIP with the real MAC address of the node it picks.  Every node then holds the VIP on lo.  For
	// where virtual MACs cannot work (a VMware port group that is not promiscuous, a cloud that allows one MAC per
	// interface); the price is failover that depends on the neighbors honoring an unsolicited ARP.  Off (the usual way) is
	// not written to the file, so a configuration that never used it stays readable by older versions.
	RealMACs  bool     `json:"real_macs,omitempty"`
	Weight    int      `json:"weight"`
	HelloMS   int      `json:"hello_ms"`
	HoldMS    int      `json:"hold_ms"`
	Preempt   bool     `json:"preempt"`
	MaxAFNs   int      `json:"max_afns"`
	Key       string   `json:"key"`
	Neighbors []string `json:"neighbors"`
	// ExtraVIPs are anycast addresses: extra addresses of any subnet (no check
	// against the interface) that every running node holds on lo and answers on
	// while it is healthy (health.go).  Shared across the cluster.
	ExtraVIPs []string `json:"extra_vips,omitempty"`
	// Devices are the managed devices this gateway is for, by name (settings.devices): the squares under its circle on the
	// Topology page, and what the target gateway:N picks.  A device may be on several gateways.  Shared across the cluster.
	Devices []string `json:"devices,omitempty"`
	// PausedVIPs are anycast addresses whose announcing is paused on every node (shared); PausedVIPsHere the ones
	// paused on this node only (never replicated).  A paused address stays in ExtraVIPs but is taken off lo, so the
	// route is withdrawn until it is resumed.
	PausedVIPs []string `json:"paused_vips,omitempty"`
	// PausedAll pauses the gateway on every node (shared); Paused below pauses it on this node only.
	PausedAll      bool     `json:"paused_all,omitempty"`
	PausedVIPsHere []string `json:"paused_vips_here,omitempty"`
	// Paused takes this node out of the gateway for maintenance: it resigns and
	// stops answering, other nodes carry on.  Local to the node, never replicated.
	Paused bool `json:"paused,omitempty"`
	// ExcludedNodes are the cluster nodes (by node ID) that do not serve this gateway: shared, so every node agrees.  A
	// node not listed serves it.  A node that joins the cluster is added to every gateway's list by the primary at that moment.  Omitted when empty, so a configuration that never used it
	// stays readable by older versions.  ExcludedHere is set by effective() when this node is one of them (never written).
	ExcludedNodes []string `json:"excluded_nodes,omitempty"`
	ExcludedHere  bool     `json:"-"`
	// NodeOrder is the order the cluster's nodes are drawn in beside this gateway (node IDs; drag them on Topology): shared.
	// A node not listed comes after the listed ones, by name.  Omitted when empty.
	NodeOrder []string `json:"node_order,omitempty"`
}

// newGatewayGroup is the starting point of a gateway that is created now (first start, Add gateway, --canvas-add,
// --configure): the same as defaultGroup but with real MAC addresses on, which is what most networks need (a VMware
// port group, a cloud, a switch with port security).  defaultGroup itself stays off: a group read from a file that does
// not say real_macs is off, as it always was, so an upgrade changes no running gateway.
// firstGroupID is the group number a new gateway gets first (the next free one counts up from here).
const firstGroupID = 161

func newGatewayGroup() GroupConfig {
	g := defaultGroup()
	g.GroupID = firstGroupID
	g.Key = newGroupKey() // a gateway someone adds does not start with a key everybody knows
	g.RealMACs = true
	return g
}

func defaultGroup() GroupConfig {
	return GroupConfig{
		GroupID:   1,
		Interface: "eth0",
		VIP4:      "10.0.0.1/24",
		Priority:  100,
		LBMethod:  lbRoundRobin,
		Weight:    100,
		HelloMS:   150,
		HoldMS:    750,
		MaxAFNs:   defaultMaxAFNs,
		Key:       "ntpdir",
		Neighbors: []string{},
	}
}

func (m LBMethod) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

func (m *LBMethod) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := parseLB(s)
	if err != nil {
		return err
	}
	*m = v
	return nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (g *GroupConfig) UnmarshalJSON(b []byte) error {
	type alias GroupConfig
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	a := alias(defaultGroup())
	// back-compat: old configs have "vip" instead of vip4
	if v, ok := raw["vip"]; ok {
		if _, has := raw["vip4"]; !has {
			raw["vip4"] = v
		}
		delete(raw, "vip")
		b, _ = json.Marshal(raw)
	}
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	*g = GroupConfig(a)
	return nil
}

func (g *GroupConfig) keyBytes() []byte {
	if g.Key == "" {
		return []byte("ntpdir")
	}
	return []byte(g.Key)
}

func (g *GroupConfig) vipFor(af AF) string {
	if af == afIPv4 {
		return g.VIP4
	}
	return g.VIP6
}

// maxMoreVIPs is how many further addresses a gateway may hold per family.
const maxMoreVIPs = 32

func (g *GroupConfig) moreFor(af AF) []string {
	if af == afIPv4 {
		return g.MoreVIP4
	}
	return g.MoreVIP6
}

// vipsFor is every shared address of the family with its prefix length, the primary first.
func (g *GroupConfig) vipsFor(af AF) []string {
	p := g.vipFor(af)
	if p == "" {
		return nil
	}
	out := []string{p}
	pfx, err := netip.ParsePrefix(p)
	if err != nil {
		return out
	}
	for _, a := range g.moreFor(af) {
		out = append(out, fmt.Sprintf("%s/%d", a, pfx.Bits()))
	}
	return out
}

// cleanMoreVIPs checks the further addresses of one family against the primary: right family, inside its subnet, not the
// primary itself, not listed twice.  It returns them in canonical form.
func cleanMoreVIPs(list []string, primary string, v6 bool, pre, field string) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	fam := map[bool]string{false: "IPv4", true: "IPv6"}[v6]
	if primary == "" {
		return nil, fmt.Errorf("%s: %s needs the gateway's %s address first", pre, field, fam)
	}
	if len(list) > maxMoreVIPs {
		return nil, fmt.Errorf("%s: %s holds at most %d addresses", pre, field, maxMoreVIPs)
	}
	pfx, err := netip.ParsePrefix(primary)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: the gateway's address %q is not valid", pre, field, primary)
	}
	seen := map[netip.Addr]bool{pfx.Addr(): true}
	out := make([]string, 0, len(list))
	for _, s := range list {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.Is6() != v6 || a.Is4In6() {
			return nil, fmt.Errorf("%s: %s: %q is not an %s address", pre, field, s, fam)
		}
		if !pfx.Contains(a) {
			return nil, fmt.Errorf("%s: %s: %s is not in the gateway's subnet %s", pre, field, a, pfx.Masked())
		}
		if a == pfx.Masked().Addr() || (!v6 && a == lastV4(pfx)) {
			return nil, fmt.Errorf("%s: %s: %s is the subnet's network or broadcast address", pre, field, a)
		}
		if a.IsMulticast() || a.IsUnspecified() {
			return nil, fmt.Errorf("%s: %s: %s cannot be used", pre, field, a)
		}
		if seen[a] {
			return nil, fmt.Errorf("%s: %s: %s is listed twice or is the gateway's own address", pre, field, a)
		}
		seen[a] = true
		out = append(out, a.String())
	}
	return out, nil
}

// lastV4 is the broadcast address of an IPv4 prefix (only for a prefix short enough to have one).
func lastV4(p netip.Prefix) netip.Addr {
	if p.Bits() >= 31 {
		return netip.Addr{}
	}
	b := p.Masked().Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(b)
}

func (g *GroupConfig) wants(af AF) bool { return g.vipFor(af) != "" }

// unicastMode is true when explicit neighbors are configured.
func (g *GroupConfig) unicastMode() bool { return len(g.Neighbors) > 0 }

func (g *GroupConfig) Validate() error {
	pre := fmt.Sprintf("group %d", g.GroupID)
	if g.GroupID < 1 || g.GroupID > 255 {
		return fmt.Errorf("%s: group_id must be 1-255", pre)
	}
	if err := validGatewayName(g.Name); err != nil {
		return fmt.Errorf("%s: %v", pre, err)
	}
	if g.VIP4 == "" && g.VIP6 == "" {
		return fmt.Errorf("%s: at least one of vip4 or vip6 must be set", pre)
	}
	if g.VIP4 != "" {
		p, err := netip.ParsePrefix(g.VIP4)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("%s: vip4 %q must be IPv4 address/prefix, e.g. 10.0.0.1/24", pre, g.VIP4)
		}
	}
	if g.VIP6 != "" {
		p, err := netip.ParsePrefix(g.VIP6)
		if err != nil || !p.Addr().Is6() {
			return fmt.Errorf("%s: vip6 %q must be IPv6 address/prefix, e.g. 2001:db8::1/64", pre, g.VIP6)
		}
	}
	var err error
	if g.MoreVIP4, err = cleanMoreVIPs(g.MoreVIP4, g.VIP4, false, pre, "more_vip4"); err != nil {
		return err
	}
	if g.MoreVIP6, err = cleanMoreVIPs(g.MoreVIP6, g.VIP6, true, pre, "more_vip6"); err != nil {
		return err
	}
	for i, a := range g.ExtraVIPs {
		n, err := normalizeAnycast(a)
		if err != nil {
			return fmt.Errorf("%s: %v", pre, err)
		}
		g.ExtraVIPs[i] = n
	}
	g.PausedVIPs = keepAnycast(g.PausedVIPs, g.ExtraVIPs)
	g.PausedVIPsHere = keepAnycast(g.PausedVIPsHere, g.ExtraVIPs)
	if l, err := cleanNodeOrder(g.NodeOrder); err != nil {
		return fmt.Errorf("%s: node_order: %v", pre, err)
	} else {
		g.NodeOrder = l
	}
	if l, err := cleanNodeIDs(g.ExcludedNodes); err != nil {
		return fmt.Errorf("%s: excluded_nodes: %v", pre, err)
	} else {
		g.ExcludedNodes = l
	}
	for _, f := range []struct {
		name      string
		v, lo, hi int
	}{
		{"priority", g.Priority, 0, 255},
		{"weight", g.Weight, 0, 255},
		{"max_afns", g.MaxAFNs, 1, 255},
		{"hello_ms", g.HelloMS, 1, 65535},
		{"hold_ms", g.HoldMS, 1, 65535},
	} {
		if f.v < f.lo || f.v > f.hi {
			return fmt.Errorf("%s: %s must be %d-%d", pre, f.name, f.lo, f.hi)
		}
	}
	if g.HelloMS > g.HoldMS {
		return fmt.Errorf("%s: hello_ms (%d) cannot be larger than hold_ms (%d): a neighbour would be declared gone between two hellos", pre, g.HelloMS, g.HoldMS)
	}
	if g.Interface == "" {
		return fmt.Errorf("%s: interface must be set", pre)
	}
	for _, n := range g.Neighbors {
		if _, err := netip.ParseAddr(n); err != nil {
			return fmt.Errorf("%s: invalid neighbor address %q", pre, n)
		}
	}
	return nil
}

// restartDiffers reports whether a change between a and b needs an engine restart.
func restartDiffers(a, b *GroupConfig) bool {
	return a.Paused != b.Paused || a.Interface != b.Interface || a.VIP4 != b.VIP4 || a.VIP6 != b.VIP6 ||
		!sameList(a.MoreVIP4, b.MoreVIP4) || !sameList(a.MoreVIP6, b.MoreVIP6) ||
		a.Key != b.Key || a.RealMACs != b.RealMACs || // the MAC mode changes what the node sets up: restart the gateway
		!reflect.DeepEqual(a.Neighbors, b.Neighbors)
}

// sameList compares two string lists, treating nil and empty as equal.
func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizeAnycast turns an anycast address into its canonical bare form.  A
// /32 (IPv4) or /128 (IPv6) suffix is accepted; any other prefix length is
// refused, since the address is a single host and a prefix would suggest it
// belongs to a subnet.  Loopback, link-local, multicast and unspecified
// addresses are refused.
func normalizeAnycast(s string) (string, error) {
	t := strings.TrimSpace(s)
	var a netip.Addr
	if p, err := netip.ParsePrefix(t); err == nil {
		if p.Bits() != p.Addr().BitLen() {
			return "", fmt.Errorf("anycast address %q: give the address alone (or /%d), not a subnet", s, p.Addr().BitLen())
		}
		a = p.Addr()
	} else if a, err = netip.ParseAddr(t); err != nil {
		return "", fmt.Errorf("anycast address %q must be an IPv4 or IPv6 address, e.g. 203.0.113.53 or 2001:db8::53", s)
	}
	a = a.Unmap()
	if a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return "", fmt.Errorf("anycast address %q is not a usable unicast address", s)
	}
	return a.String(), nil
}

// ── Shared settings ─────────────────────────────────────────────────────────

// Settings are the settings every node of a cluster shares (the "settings" block of the file): who may use the MCP
// endpoint and /metrics, the managed devices, SNMP, neighbor discovery, alerts, backups and the scheduler.
type Settings struct {
	// SNMPCommunities and SNMPContact are the cluster-wide part of the SNMP settings (Configure ▸ SNMP): every node answers the
	// same communities and reports the same contact.  The location is per node and lives in DaemonConfig.SNMP.  See snmp.go.
	SNMPCommunities []string `json:"snmp_communities,omitempty"`
	// LLDP turns on neighbor discovery (Configure ▸ Settings ▸ General ▸ Neighbor discovery): every node runs lldpd, so the
	// switches see the nodes and each node reports the switch port it is on.  See lldp.go.
	LLDP        bool   `json:"lldp,omitempty"`
	SNMPContact string `json:"snmp_contact,omitempty"`
	// SNMPACL is the sources snmpd answers to ("10.1.1.50", "10.1.0.0/24", "nms.example.com"); empty = nobody.  MetricsACL is
	// who may read /metrics on the web GUI port (Configure ▸ Monitoring ▸ Metrics); an empty list means nobody.  See snmp.go
	// and metrics.go.
	SNMPACL    []string `json:"snmp_acl,omitempty"`
	MetricsACL []string `json:"metrics_acl,omitempty"`
	// MCPACL is who may use the MCP endpoint (/mcp on the web GUI port, mcp.go): "10.1.0.0/24" reads, "10.1.1.50 rw" may
	// also change things (a single address only).  Empty: nobody.
	MCPACL []string `json:"mcp_acl,omitempty"`
	// MCPKeys may use the MCP endpoint from any address, with the key in "Authorization: Bearer KEY" (mcpkeys.go); only a
	// hash of each key is kept.
	MCPKeys []MCPKey `json:"mcp_keys,omitempty"`
	// Privacy is what an MCP caller is not told: the level that applies to callers without one of their own and what each
	// level hides (Configure ▸ Settings ▸ Privacy, mcpprivacy.go).  Unset: the standard level, as before levels existed.
	Privacy *PrivacyConfig `json:"privacy,omitempty"`
	// MCPPort is the port of the MCP listeners on the gateways' addresses (mcplisten.go); 0 is the default, 443.
	MCPPort int `json:"mcp_port,omitempty"`
	// Devices are the switches and firewalls the gateway manages, and DeviceCredentials the logins they use (devices.go,
	// device/).
	Devices           []device.Device     `json:"devices,omitempty"`
	DeviceCredentials []device.Credential `json:"device_credentials,omitempty"`
	// Alerts are the rules, thresholds and the webhook of Configure ▸ Alerts (alerts.go).
	Alerts *AlertsConfig `json:"alerts,omitempty"`
	// Backup is the automatic off-host backup of Configure ▸ Backup (backup.go).
	Backup *BackupConfig `json:"backup,omitempty"`
	// Schedule is the scheduler's task list (Operate ▸ Scheduler); see scheduler.go.
	Schedule []SchedTask `json:"schedule,omitempty"`
}

func defaultSettings() Settings { return Settings{} }

func (d *Settings) UnmarshalJSON(b []byte) error {
	type alias Settings
	a := alias(defaultSettings())
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	*d = Settings(a)
	return nil
}

func normalizePlain(s, defPort string) (string, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	t := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if a, err := netip.ParseAddr(t); err == nil {
		return net.JoinHostPort(a.String(), defPort), nil
	}
	host, port := s, defPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid address %q (bad port)", s)
		}
	}
	if validHostname(host) {
		return net.JoinHostPort(strings.ToLower(host), port), nil
	}
	return "", fmt.Errorf("invalid address %q (need an IP address or host name, optionally with :port)", s)
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// ── Daemon config ────────────────────────────────────────────────────────────

type DaemonConfig struct {
	LogLevel string        `json:"log_level"`
	Groups   []GroupConfig `json:"groups"`
	Settings Settings      `json:"settings"`
	Web      WebConfig     `json:"web"`
	Cluster  ClusterConfig `json:"cluster"`
	// BGP is this node's FRR/BGP settings (see bgp.go).  A pointer with omitempty so
	// a config that never used BGP has no "bgp" key and older versions still read it.
	BGP *BGPConfig `json:"bgp,omitempty"`
	// OSPF is this node's OSPF settings (see ospf.go), per node like BGP.  Nil when never used: no "ospf" key.
	OSPF *OSPFConfig `json:"ospf,omitempty"`
	// Syslog is this node's log forwarding to a syslog server (see syslog.go), per node, never replicated.  Nil when never used: no "syslog" key.
	Syslog *SyslogConfig `json:"syslog,omitempty"`
	// SNMP is this node's snmpd settings (see snmp.go).  A pointer with omitempty so a config that never used SNMP has no
	// "snmp" key and older versions still read it.  Local to the node, never replicated.
	SNMP *SNMPConfig `json:"snmp,omitempty"`
	// NodePaused takes the whole node out of service for maintenance, the same as
	// pausing every gateway on it (present and future): it resigns and stops
	// answering, and the other nodes carry on.  Local to the node, never
	// replicated; omitempty so a config that never used it stays readable by older
	// versions.
	NodePaused bool `json:"node_paused,omitempty"`
}

// effective is the configuration the supervisor runs: with the node paused every
// gateway is paused.  The file keeps each gateway's own flag, so resuming the
// node puts back exactly what was paused before.
func (dc *DaemonConfig) effective() *DaemonConfig {
	if dc == nil {
		return dc
	}
	c := *dc
	c.Groups = append([]GroupConfig(nil), dc.Groups...)
	for i := range c.Groups {
		if dc.NodePaused || c.Groups[i].PausedAll { // paused on every node, or this whole node is
			c.Groups[i].Paused = true
		}
		if id := localNodeID(); id != "" && containsStr(c.Groups[i].ExcludedNodes, id) { // removed from this gateway: it serves nothing here
			c.Groups[i].Paused, c.Groups[i].ExcludedHere = true, true
		}
	}
	return &c
}

func newDaemonConfig() *DaemonConfig {
	return &DaemonConfig{LogLevel: "info", Groups: []GroupConfig{newGatewayGroup()},
		Settings: defaultSettings(), Web: defaultWeb(), Cluster: defaultCluster()}
}

func (dc *DaemonConfig) UnmarshalJSON(b []byte) error {
	type alias DaemonConfig
	a := alias(*newDaemonConfig())
	a.Groups = nil
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	// A missing "groups" key means the default group; an explicit empty list
	// really is "no gateways" (what deleting the last canvas produces).
	var probe struct {
		Groups json.RawMessage `json:"groups"`
		NTP    json.RawMessage `json:"ntp"`
	}
	_ = json.Unmarshal(b, &probe)
	// the ntp block of an NTP Director configuration is gone; its shared settings are under "settings" now.  Refused, not
	// ignored, so a file or a page that still writes it cannot drop the settings by saving without them
	if len(probe.NTP) > 0 && string(probe.NTP) != "null" {
		return errors.New(`the "ntp" block is not used any more: the shared settings (access lists, devices, SNMP, alerts, backups, schedule) go under "settings"`)
	}
	if a.Groups == nil && (len(probe.Groups) == 0 || string(probe.Groups) == "null") {
		a.Groups = []GroupConfig{newGatewayGroup()}
	}
	if a.Groups == nil {
		a.Groups = []GroupConfig{}
	}
	*dc = DaemonConfig(a)
	return nil
}

func (dc *DaemonConfig) Validate() error {
	ids := map[int]bool{}
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if err := g.Validate(); err != nil {
			return err
		}
		if ids[g.GroupID] {
			return fmt.Errorf("duplicate group_id %d", g.GroupID)
		}
		ids[g.GroupID] = true
	}
	// two gateways cannot own the same shared address, and an anycast address is not a gateway's shared address; the same
	// anycast address on several gateways is how an anycast service is run (it is held while any of them can answer)
	vips := map[string]int{}
	norm := func(v string) string {
		if p, err := netip.ParsePrefix(v); err == nil {
			return p.Addr().String()
		}
		return v
	}
	for _, g := range dc.Groups {
		for _, v := range append(append([]string{g.VIP4, g.VIP6}, g.MoreVIP4...), g.MoreVIP6...) {
			if v == "" {
				continue
			}
			a := norm(v)
			if other, dup := vips[a]; dup {
				return fmt.Errorf("groups %d and %d both use the shared address %s", other, g.GroupID, a)
			}
			vips[a] = g.GroupID
		}
	}
	for _, g := range dc.Groups {
		seen := map[string]bool{}
		for _, v := range g.ExtraVIPs {
			a := norm(v)
			if other, dup := vips[a]; dup {
				return fmt.Errorf("group %d: anycast address %s is the shared address of group %d", g.GroupID, a, other)
			}
			if seen[a] {
				return fmt.Errorf("group %d lists the anycast address %s twice", g.GroupID, a)
			}
			seen[a] = true
		}
	}
	switch strings.ToLower(dc.LogLevel) {
	case "debug", "info", "warning", "error":
	default:
		return fmt.Errorf("log_level %q must be debug|info|warning|error", dc.LogLevel)
	}
	if err := dc.Web.Validate(); err != nil {
		return err
	}
	migrateBackupSchedule(&dc.Settings)
	if err := validateSchedule(dc.Settings.Schedule); err != nil {
		return err
	}
	if len(dc.Settings.Schedule) == 0 {
		dc.Settings.Schedule = nil
	}
	{
		sc := SNMPConfig{Communities: dc.Settings.SNMPCommunities, Contact: dc.Settings.SNMPContact, ACL: dc.Settings.SNMPACL}
		if err := sc.Validate(); err != nil {
			return err
		}
		dc.Settings.SNMPCommunities, dc.Settings.SNMPContact, dc.Settings.SNMPACL = sc.Communities, sc.Contact, sc.ACL
		acl, err := normACL("metrics", dc.Settings.MetricsACL)
		if err != nil {
			return err
		}
		dc.Settings.MetricsACL = acl
		if dc.Settings.MCPACL, err = normMCPACL(dc.Settings.MCPACL); err != nil {
			return err
		}
		if dc.Settings.MCPKeys, err = normMCPKeys(dc.Settings.MCPKeys); err != nil {
			return err
		}
		if dc.Settings.Privacy, err = normPrivacy(dc.Settings.Privacy); err != nil {
			return err
		}
		if p := dc.Settings.MCPPort; p < 0 || p > 65535 {
			return errors.New("mcp: the port must be 1-65535")
		}
		if _, wp, err := net.SplitHostPort(dc.Web.Listen); err == nil && wp == strconv.Itoa(dc.Settings.mcpPort()) {
			return fmt.Errorf("mcp: the port %s is the web GUI's port: give the MCP listeners another", wp)
		}
		if err := device.Validate(dc.Settings.Devices, dc.Settings.DeviceCredentials); err != nil {
			return err
		}
		if err := dc.validateGatewayDevices(); err != nil {
			return err
		}
		if len(dc.Settings.Devices) == 0 {
			dc.Settings.Devices = nil
		}
		if len(dc.Settings.DeviceCredentials) == 0 {
			dc.Settings.DeviceCredentials = nil
		}
		if dc.Settings.Backup != nil {
			if err := dc.Settings.Backup.Validate(); err != nil {
				return err
			}
			if dc.Settings.Backup.empty() {
				dc.Settings.Backup = nil
			}
		}
		if dc.Settings.Alerts != nil {
			if err := dc.Settings.Alerts.Validate(); err != nil {
				return err
			}
			if dc.Settings.Alerts.Webhook == "" && dc.Settings.Alerts.RepeatHours == 0 && len(dc.Settings.Alerts.Rules) == 0 {
				dc.Settings.Alerts = nil
			}
		}
	}
	if dc.SNMP != nil {
		// v49 kept communities and contact on the node; they are cluster settings now, so move them over once
		if len(dc.Settings.SNMPCommunities) == 0 && dc.Settings.SNMPContact == "" && (len(dc.SNMP.Communities) > 0 || dc.SNMP.Contact != "") {
			dc.Settings.SNMPCommunities, dc.Settings.SNMPContact = dc.SNMP.Communities, dc.SNMP.Contact
		}
		dc.SNMP.Communities, dc.SNMP.Contact, dc.SNMP.ACL = nil, "", nil
		if err := dc.SNMP.Validate(); err != nil {
			return err
		}
		if dc.SNMP.empty() {
			dc.SNMP = nil
		}
	}
	if dc.BGP != nil {
		if err := dc.BGP.Validate(); err != nil {
			return err
		}
	}
	if dc.OSPF != nil {
		if err := dc.OSPF.Validate(); err != nil {
			return err
		}
		if !dc.OSPF.Configured() {
			dc.OSPF = nil
		}
	}
	if dc.Syslog != nil {
		if err := dc.Syslog.Validate(); err != nil {
			return err
		}
		if dc.Syslog.empty() {
			dc.Syslog = nil
		}
	}
	return dc.Cluster.Validate()
}

func loadConfig(path string) (*DaemonConfig, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// No file yet: defaults, and no gateways (a gateway is something you draw;
		// inventing one would claim an address on the network).
		dc := newDaemonConfig()
		dc.Groups = []GroupConfig{}
		return dc, nil
	}
	if err != nil {
		return nil, err
	}
	dc := newDaemonConfig()
	if err := json.Unmarshal(b, dc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// every reader (the page, the scheduler's edits, the history) sees the backup schedule of v184-v187 as the Scheduler
	// task it becomes, so a save made from what was read keeps it
	migrateBackupSchedule(&dc.Settings)
	return dc, nil
}

func (dc *DaemonConfig) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if dc.Groups == nil {
		dc.Groups = []GroupConfig{}
	}
	b, err := json.MarshalIndent(dc, "", "  ")
	if err != nil {
		return err
	}
	// The file holds the groups' shared HMAC keys: keep the mode of an existing
	// file (other tools may read it), and create new files private.
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil { // WriteFile is subject to umask
		return err
	}
	return os.Rename(tmp, path)
}

// ── Web GUI config ───────────────────────────────────────────────────────────

// WebConfig describes the HTTPS management GUI.
type WebConfig struct {
	// LegacyEnabled is the old "enabled" switch: the GUI is always on now.  The
	// key is still accepted so existing config files load; it is dropped on save.
	LegacyEnabled *bool `json:"enabled,omitempty"`
	// Listen is the address:port to serve HTTPS on (default ":22161").
	Listen string `json:"listen"`
	// CertFile/KeyFile: PEM certificate and key.  Leave both empty to use an
	// auto-generated self-signed certificate stored next to the config file.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// Group is the system group whose members may log in: one name, or several separated by commas (the default is the
	// local group and a group of the same name with "-users" for a directory such as Active Directory).
	Group string `json:"group"`
	// ReadGroup is the read-only login group(s), same format as Group: a member who is in none of the Group groups but in
	// one of these may sign in and look at everything, but cannot change anything.  The default is "netdir-ro" (the group the
	// installer creates); empty means there is none.
	ReadGroup string `json:"read_group"`
	// PAMService is the /etc/pam.d service used to check passwords.
	PAMService string `json:"pam_service"`
	// SessionIdleMinutes logs a browser out after this much inactivity.
	SessionIdleMinutes int `json:"session_idle_minutes"`
	// Failed-login lockout: MaxFailedLogins wrong attempts within
	// FailedLoginWindowMinutes lock that address (and that user name) out for
	// LockoutMinutes.
	MaxFailedLogins          int `json:"max_failed_logins"`
	FailedLoginWindowMinutes int `json:"failed_login_window_minutes"`
	LockoutMinutes           int `json:"lockout_minutes"`
	// MinPasswordLength is the fewest characters a password set on the Users page (or with --user-add and
	// --user-password) may have.  0, which is also what an absent key means and what is not written to the file
	// (so a config that never set it stays readable by older versions), is the default, 8.
	MinPasswordLength int `json:"min_password_length,omitempty"`
	// SSOConfig is single sign-on with Google or Microsoft Entra ID (sso.go); its keys are flat in the web block.
	SSOConfig
	// LDAPConfig is sign-in with an LDAP directory such as Active Directory (ldap.go); its keys are flat in the web block.
	LDAPConfig
}

const (
	defaultWebPort       = 22161
	defaultMinPassword   = 8
	maxMinPasswordLength = 128
)

// minPassword is the effective minimum password length.
func (w WebConfig) minPassword() int {
	if w.MinPasswordLength <= 0 {
		return defaultMinPassword
	}
	return w.MinPasswordLength
}

func defaultWeb() WebConfig {
	return WebConfig{
		Listen:                   fmt.Sprintf(":%d", defaultWebPort),
		Group:                    "netdir,netdir-users",
		ReadGroup:                "netdir-ro",
		PAMService:               "netdir",
		SessionIdleMinutes:       30,
		MaxFailedLogins:          3,
		FailedLoginWindowMinutes: 1,
		LockoutMinutes:           15,
	}
}

func (w *WebConfig) UnmarshalJSON(b []byte) error {
	type alias WebConfig
	a := alias(defaultWeb())
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	a.LegacyEnabled = nil
	*w = WebConfig(a)
	return nil
}

func (w *WebConfig) Validate() error {
	_, port, err := net.SplitHostPort(w.Listen)
	if err != nil {
		return fmt.Errorf("web: listen %q must be host:port, e.g. \":22161\"", w.Listen)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("web: listen port %q must be 1-65535", port)
	}
	if (w.CertFile == "") != (w.KeyFile == "") {
		return errors.New("web: cert_file and key_file must be set together (or both empty for a self-signed certificate)")
	}
	if w.Group == "" || w.PAMService == "" {
		return errors.New("web: group and pam_service must not be empty")
	}
	if w.SessionIdleMinutes < 1 {
		return errors.New("web: session_idle_minutes must be >= 1")
	}
	if w.MaxFailedLogins < 1 || w.MaxFailedLogins > 1000 {
		return errors.New("web: max_failed_logins must be 1-1000")
	}
	if w.FailedLoginWindowMinutes < 1 || w.FailedLoginWindowMinutes > 10080 {
		return errors.New("web: failed_login_window_minutes must be 1-10080")
	}
	if w.LockoutMinutes < 1 || w.LockoutMinutes > 10080 {
		return errors.New("web: lockout_minutes must be 1-10080")
	}
	if err := w.SSOConfig.validateSSO(); err != nil {
		return err
	}
	if err := w.LDAPConfig.validateLDAP(); err != nil {
		return err
	}
	if w.MinPasswordLength < 0 || w.MinPasswordLength > maxMinPasswordLength {
		return fmt.Errorf("web: min_password_length must be 1-%d (empty or 0 means the default, %d)", maxMinPasswordLength, defaultMinPassword)
	}
	return nil
}

func (w WebConfig) failWindow() time.Duration {
	return time.Duration(w.FailedLoginWindowMinutes) * time.Minute
}

func (w WebConfig) lockout() time.Duration { return time.Duration(w.LockoutMinutes) * time.Minute }

func (w WebConfig) sessionIdle() time.Duration {
	return time.Duration(w.SessionIdleMinutes) * time.Minute
}

// ── Management cluster config ────────────────────────────────────────────────

// ClusterConfig describes this node's membership of the management cluster
// (config replication, shared certificate, coordinated updates).  It is
// per-node and never replicated.  The gateway protocol itself (AGC/AFN
// election) is independent of it.
type ClusterConfig struct {
	// Enabled starts the cluster listener.  Always true (the key is only kept so
	// older files still load).  Every node is the primary of its own
	// single-node cluster until it joins another.
	Enabled bool `json:"-"`
	// Listen is the address:port of the peer-to-peer listener (default ":22162").
	Listen string `json:"listen"`
	// Self is the host:port other nodes use to reach this one.  Empty means
	// "this host's name and the listen port".
	Self string `json:"self"`
	// SyncIntervalSec is how often replicas pull state and peers are polled.
	SyncIntervalSec int `json:"sync_interval_sec"`
	// ShareCert replicates the certificate installed through the GUI/CLI to
	// every member.  Always true, like Enabled.
	ShareCert bool `json:"-"`
}

const defaultClusterPort = 22162

func defaultCluster() ClusterConfig {
	return ClusterConfig{
		Enabled:         true,
		Listen:          fmt.Sprintf(":%d", defaultClusterPort),
		SyncIntervalSec: 5,
		ShareCert:       true,
	}
}

func (c *ClusterConfig) UnmarshalJSON(b []byte) error {
	type alias ClusterConfig
	a := struct {
		alias
		LegacyEnabled   *bool `json:"enabled"`
		LegacyShareCert *bool `json:"share_cert"`
	}{alias: alias(defaultCluster())}
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	*c = ClusterConfig(a.alias)
	// Clustering and certificate sharing are not options any more.  Older files
	// still carry the keys: accepted, ignored, and not written back.
	c.Enabled, c.ShareCert = true, true
	return nil
}

func (c *ClusterConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if _, port, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("cluster: listen %q must be host:port, e.g. \":22162\"", c.Listen)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("cluster: listen port %q must be 1-65535", port)
	}
	if c.Self != "" {
		if _, _, err := net.SplitHostPort(c.Self); err != nil {
			return fmt.Errorf("cluster: self %q must be host:port", c.Self)
		}
	}
	if c.SyncIntervalSec < 1 || c.SyncIntervalSec > 3600 {
		return errors.New("cluster: sync_interval_sec must be 1-3600")
	}
	return nil
}

// keepStrings returns the distinct entries of l that are in valid (nil when none).
func keepStrings(l []string, valid map[string]bool) []string {
	var out []string
	for _, k := range l {
		if valid[k] && !containsStr(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// maxGatewayName is the longest label a gateway may carry.
const maxGatewayName = 40

// validGatewayName accepts an empty name or up to 40 characters with no control characters.
func validGatewayName(n string) error {
	if utf8.RuneCountInString(n) > maxGatewayName {
		return fmt.Errorf("name is longer than %d characters", maxGatewayName)
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return errors.New("name must not contain control characters")
		}
	}
	return nil
}

// keepAnycast returns the distinct members of paused that are still anycast addresses of the gateway, normalised
// (nil when none): deleting or editing an address drops its pause.
func keepAnycast(paused, extra []string) []string {
	var out []string
	for _, p := range paused {
		n, err := normalizeAnycast(p)
		if err != nil || !containsStr(extra, n) || containsStr(out, n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// pausedAnycast says, per anycast address of the gateway, where its announcing is paused: "all" (every node) or
// "node" (this one).
func (g GroupConfig) pausedAnycast() map[string]string {
	out := map[string]string{}
	for _, a := range g.PausedVIPsHere {
		out[a] = "node"
	}
	for _, a := range g.PausedVIPs {
		out[a] = "all"
	}
	return out
}

// snmpSettings is the whole SNMP configuration of this node: the cluster's communities and contact, this node's location.
func (dc *DaemonConfig) snmpSettings() SNMPConfig {
	c := SNMPConfig{Communities: dc.Settings.SNMPCommunities, Contact: dc.Settings.SNMPContact, ACL: dc.Settings.SNMPACL}
	if dc.SNMP != nil {
		c.Location = dc.SNMP.Location
	}
	return c
}

// validateGatewayDevices checks that every gateway lists only devices of the inventory, each once.
func (dc *DaemonConfig) validateGatewayDevices() error {
	have := map[string]bool{}
	for _, d := range dc.Settings.Devices {
		have[d.Name] = true
	}
	for i := range dc.Groups {
		g := &dc.Groups[i]
		seen := map[string]bool{}
		for _, n := range g.Devices {
			if !have[n] {
				return fmt.Errorf("group %d lists the device %q, which is not in settings.devices", g.GroupID, n)
			}
			if seen[n] {
				return fmt.Errorf("group %d lists the device %q twice", g.GroupID, n)
			}
			seen[n] = true
		}
		if len(g.Devices) == 0 {
			g.Devices = nil
		}
	}
	return nil
}
