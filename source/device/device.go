// Package device is how the gateway talks to the switches and firewalls it manages: an inventory of devices, the
// credentials they are reached with, and a driver per platform that turns a request ("the facts", "the interfaces", "the
// running configuration") into that platform's own API and its answer into the same shape for every platform.
//
// A platform is added by writing one driver and registering it (Register) from an init function; nothing else needs to
// know about it.  A driver that cannot do something answers ErrUnsupported, never a guess.
//
// Everything here reads.  Changing a device is a later step (dry run, diff, commit) and has no method yet.
package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ErrUnsupported is what a driver answers for a request its platform has no way to serve.
var ErrUnsupported = errors.New("not supported on this platform")

// Device is one managed switch or firewall.
type Device struct {
	// Name is how the device is known to the gateway and its callers: unique, letters, digits, '.', '-' and '_'.
	Name string `json:"name"`
	// Platform picks the driver: "aoscx", "nxos", "fortios", ... (Platforms lists them).
	Platform string `json:"platform"`
	// Address is the management address or host name the API is reached on.
	Address string `json:"address"`
	// Port is the API's TCP port; 0 is the platform's default (443).
	Port int `json:"port,omitempty"`
	// Credential is the name of the entry of the credentials list the device logs in with.
	Credential string `json:"credential"`
	// Tags group devices for a request: "site=dc1", "role=core", "edge".
	Tags []string `json:"tags,omitempty"`
	// Insecure skips checking the device's certificate (most devices ship a self-signed one).  CAPEM, when set, is the
	// certificate (or chain) the device's certificate must be signed by instead.
	Insecure bool   `json:"insecure,omitempty"`
	CAPEM    string `json:"ca_pem,omitempty"`
	// Options are platform-specific settings: "api_version" for ArubaOS-CX ("v10.09"), "vdom" for FortiOS, "vsys" and "device_group" for PAN-OS, "wapi_version" for Infoblox, "node" for dnsdir and ntpdir, "org" and "serial" for Meraki, "tenant" and "login_host" for Entra, none for afc, "node" for proxmox (the cluster node the tools ask about).  Technitium and EOS take none.
	Options map[string]string `json:"options,omitempty"`
	// Disabled devices stay in the inventory but are never contacted.
	Disabled bool `json:"disabled,omitempty"`
}

// Credential is a login a device uses.  Username and Password for a platform that logs in; Token for one that takes
// an API token (FortiOS).  Both kinds may be set; each driver uses what it needs.
type Credential struct {
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

// Facts is what a device says about itself.
type Facts struct {
	Hostname  string `json:"hostname"`
	Vendor    string `json:"vendor"`
	Model     string `json:"model,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Serial    string `json:"serial,omitempty"`
	UptimeS   int64  `json:"uptime_s,omitempty"`
}

// Interface is one port, VLAN interface or other interface.
type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	AdminUp     *bool    `json:"admin_up,omitempty"`
	OperUp      *bool    `json:"oper_up,omitempty"`
	SpeedMbps   int64    `json:"speed_mbps,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
}

// Neighbor is one LLDP (or CDP) neighbor a device reports.
type Neighbor struct {
	LocalPort  string `json:"local_port"`
	RemoteName string `json:"remote_name,omitempty"`
	RemotePort string `json:"remote_port,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemoteDesc string `json:"remote_desc,omitempty"`
	// Protocol is "lldp" or "cdp".  Detail is everything the device reported about the neighbor (secrets hidden); only
	// the neighbor_details request hands it over.
	Protocol string         `json:"protocol,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// Driver reaches one device.  A driver is made for each request (Open) and closed after it, so it may hold a session.
type Driver interface {
	Facts(ctx context.Context) (Facts, error)
	Interfaces(ctx context.Context) ([]Interface, error)
	Neighbors(ctx context.Context) ([]Neighbor, error)
	// Config is the running configuration as the device prints it.
	Config(ctx context.Context) (string, error)
	// Show runs a read-only command (CheckShow has already passed it) and returns the device's text.
	Show(ctx context.Context, cmd string) (string, error)
	// Close ends any session the driver opened.  It is always called, and errors are not reported.
	Close(ctx context.Context)
}

// Factory makes the driver of a platform for one device.
type Factory func(d Device, c Credential) (Driver, error)

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register adds a platform.  It panics on a name used twice, which is a programming error.
func Register(platform string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[platform]; dup {
		panic("device: platform registered twice: " + platform)
	}
	registry[platform] = f
}

// Platforms lists the platforms that have a driver, sorted.
func Platforms() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for p := range registry {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Open makes the driver for d, logging in with c.
func Open(d Device, c Credential) (Driver, error) {
	regMu.RLock()
	f := registry[d.Platform]
	regMu.RUnlock()
	if f == nil {
		return nil, fmt.Errorf("device %s: no driver for platform %q (there are: %s)", d.Name, d.Platform, strings.Join(Platforms(), ", "))
	}
	return f(d, c)
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate checks the inventory and the credentials together and writes them the same way: platform in lower case, tags
// trimmed, sorted and without duplicates.  creds may hold credentials no device uses.
func Validate(devs []Device, creds []Credential) error {
	if len(devs) > 4096 {
		return errors.New("devices: at most 4096")
	}
	if len(creds) > 256 {
		return errors.New("device credentials: at most 256")
	}
	cn := map[string]bool{}
	for i := range creds {
		c := &creds[i]
		c.Name = strings.TrimSpace(c.Name)
		if !nameRE.MatchString(c.Name) {
			return fmt.Errorf("device credential %q: a name is 1-64 letters, digits, '.', '-' or '_', starting with a letter or digit", c.Name)
		}
		if cn[c.Name] {
			return fmt.Errorf("device credential %q: listed twice", c.Name)
		}
		cn[c.Name] = true
		if c.Password == "" && c.Token == "" {
			return fmt.Errorf("device credential %s: needs a password or a token", c.Name)
		}
	}
	dn := map[string]bool{}
	for i := range devs {
		d := &devs[i]
		d.Name = strings.TrimSpace(d.Name)
		if !nameRE.MatchString(d.Name) {
			return fmt.Errorf("device %q: a name is 1-64 letters, digits, '.', '-' or '_', starting with a letter or digit", d.Name)
		}
		if dn[strings.ToLower(d.Name)] {
			return fmt.Errorf("device %s: listed twice", d.Name)
		}
		dn[strings.ToLower(d.Name)] = true
		d.Platform = strings.ToLower(strings.TrimSpace(d.Platform))
		regMu.RLock()
		_, known := registry[d.Platform]
		regMu.RUnlock()
		if !known {
			return fmt.Errorf("device %s: platform %q has no driver (there are: %s)", d.Name, d.Platform, strings.Join(Platforms(), ", "))
		}
		d.Address = strings.TrimSpace(d.Address)
		if d.Address == "" && d.Platform == "meraki" {
			d.Address = "api.meraki.com" // the one dashboard address, so it need not be typed
		}
		if d.Address == "" && d.Platform == "entra" {
			d.Address = "graph.microsoft.com" // Microsoft Graph (public cloud)
		}
		if err := checkHost(d.Address); err != nil {
			return fmt.Errorf("device %s: %v", d.Name, err)
		}
		if d.Port < 0 || d.Port > 65535 {
			return fmt.Errorf("device %s: port %d is not a TCP port", d.Name, d.Port)
		}
		if !cn[d.Credential] {
			return fmt.Errorf("device %s: credential %q is not in the credentials list", d.Name, d.Credential)
		}
		tags := map[string]bool{}
		var out []string
		for _, t := range d.Tags {
			t = strings.TrimSpace(t)
			if t == "" || tags[t] {
				continue
			}
			if strings.ContainsAny(t, " \t,") || len(t) > 64 {
				return fmt.Errorf("device %s: tag %q: up to 64 characters, no spaces or commas", d.Name, t)
			}
			tags[t] = true
			out = append(out, t)
		}
		sort.Strings(out)
		d.Tags = out
		if d.CAPEM != "" && d.Insecure {
			return fmt.Errorf("device %s: give a CA certificate or skip the check (insecure), not both", d.Name)
		}
		if len(d.Options) == 0 {
			d.Options = nil
		}
	}
	return nil
}

// checkHost accepts an IP address or a host name, nothing with a port, a path or a scheme.
func checkHost(h string) error {
	if h == "" {
		return errors.New("an address is needed")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return nil
	}
	if len(h) > 253 || strings.ContainsAny(h, "/:@ ?#") {
		return fmt.Errorf("address %q: an IP address or a host name, without a port or a scheme", h)
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("address %q is not a host name", h)
		}
		for _, r := range l {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return fmt.Errorf("address %q is not a host name", h)
			}
		}
	}
	return nil
}

// hostPort is the address a driver dials: the device's address and its port, or def.
func hostPort(d Device, def int) string {
	p := d.Port
	if p == 0 {
		p = def
	}
	return net.JoinHostPort(d.Address, strconv.Itoa(p))
}
