package device

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Importing the devices a monitoring or assurance server knows into the inventory (Observium, IP Fabric, Centreon).  Each one is
// made with a platform picked from what the server says it is, its address, tags for where it came from, no login, and disabled:
// nothing is contacted until someone gives it a login and enables it.  A device the server does not say enough about to pick a
// driver, one already in the inventory (by name or by address) and one with nothing to reach it by are left out, each with the reason.

// Skipped is a device the import left out, and why.
type Skipped struct {
	Name   string `json:"name"`
	OS     string `json:"os,omitempty"`
	Reason string `json:"reason"`
}

// ImportSources are the platforms a device can be imported from.
var ImportSources = map[string]bool{"observium": true, "ipfabric": true, "centreon": true, "panorama": true, "pdm": true, "afc": true}

// impRow is one device as a source describes it.
type impRow struct {
	ID       string
	Host     string   // host name or address it is monitored by
	Alt      string   // a second address to try when Host is not one
	Short    string   // the name to make the inventory name from (default: Host)
	What     string   // what the source says it is, as shown in a skip reason
	Platform string   // the driver, "" when none fits
	Tags     []string // beyond source=
}

var (
	impNameBad = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	impTagBad  = regexp.MustCompile(`[\s,]+`)
	impSuffix  = regexp.MustCompile(`(?i)(.)-(m|new)$`)
)

// impTag makes a tag value from free text: spaces and commas become "_".
func impTag(key, v string) []string {
	v = strings.Trim(impTagBad.ReplaceAllString(strings.TrimSpace(v), "_"), "_")
	if v == "" || len(key)+len(v) > 62 {
		return nil
	}
	return []string{key + "=" + v}
}

// impDeviceName makes an inventory name from a host name: the short name when it has a domain, bad characters turned to "-".
func impDeviceName(host string) string {
	if _, err := netip.ParseAddr(host); err != nil {
		if i := strings.Index(host, "."); i > 0 {
			host = host[:i]
		}
	}
	n := strings.Trim(impNameBad.ReplaceAllString(strings.TrimSpace(host), "-"), "-._")
	n = impSuffix.ReplaceAllString(n, "$1") // aptxipm02-m and aptxipm02-new are the machine aptxipm02
	if len(n) > 64 {
		n = strings.TrimRight(n[:64], "-._")
	}
	return n
}

// ImportDevices lists what the server d (Observium, IP Fabric or Centreon) knows, as devices to add to existing.
func ImportDevices(ctx context.Context, d Device, c Credential, existing []Device) ([]Device, []Skipped, error) {
	var rows []impRow
	var err error
	switch d.Platform {
	case "observium":
		rows, err = obsImportRead(ctx, d, c)
	case "ipfabric":
		rows, err = ipfImportRead(ctx, d, c)
	case "centreon":
		rows, err = centImportRead(ctx, d, c)
	case "panorama":
		rows, err = panImportRead(ctx, d, c)
	case "pdm":
		rows, err = pdmImportRead(ctx, d, c)
	case "afc":
		rows, err = afcImportRead(ctx, d, c)
	default:
		return nil, nil, fmt.Errorf("device %s: devices are imported from Observium, IP Fabric and Centreon, not %s", d.Name, d.Platform)
	}
	if err != nil {
		return nil, nil, err
	}
	out, skipped := impBuild(d.Platform, rows, existing)
	return out, skipped, nil
}

func impBuild(source string, rows []impRow, existing []Device) ([]Device, []Skipped) {
	names, addrs := map[string]bool{}, map[string]bool{}
	for _, e := range existing {
		names[strings.ToLower(e.Name)] = true
		addrs[strings.ToLower(e.Address)] = true
	}
	var out []Device
	var skipped []Skipped
	for _, r := range rows {
		skip := func(why string) {
			skipped = append(skipped, Skipped{Name: firstOf(r.Host, r.Short, r.ID), OS: r.What, Reason: why})
		}
		if r.Platform == "" {
			skip(fmt.Sprintf("no driver for %q", firstOf(r.What, "an unknown device")))
			continue
		}
		addr := r.Host
		if checkHost(addr) != nil {
			addr = r.Alt
			if checkHost(addr) != nil {
				skip("no address or host name to reach it by")
				continue
			}
		}
		if addrs[strings.ToLower(addr)] {
			skip("already in the inventory (same address)")
			continue
		}
		name := impDeviceName(firstOf(r.Short, r.Host))
		if name == "" || !nameRE.MatchString(name) {
			skip("no usable name")
			continue
		}
		if names[strings.ToLower(name)] {
			skip("already in the inventory (same name " + name + ")")
			continue
		}
		names[strings.ToLower(name)], addrs[strings.ToLower(addr)] = true, true
		out = append(out, Device{Name: name, Platform: r.Platform, Address: addr, Tags: append([]string{"source=" + source}, r.Tags...), Disabled: true})
	}
	return out, skipped
}

// ---- Observium ----

// obsPlatforms maps Observium's OS names (the "os" of a device) to platforms that have a driver here.
var obsPlatforms = map[string]string{
	"ios": "iosxe", "iosxe": "iosxe", "nxos": "nxos", "eos": "eos", "junos": "junos",
	"fortigate": "fortios", "fortios": "fortios", "panos": "panos",
	"aoscx": "aoscx", "arubaos-cx": "aoscx", "bigip": "bigip", "f5": "bigip",
	"infoblox": "nios", "pve": "proxmox", "proxmox": "proxmox",
}

func obsImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newObservium(d, c) // not Open: the answers are read here, not handed to a caller, so they need no wrapper
	if err != nil {
		return nil, err
	}
	o := drv.(*observium)
	defer o.Close(context.WithoutCancel(ctx))
	if o.dev != "" {
		return nil, fmt.Errorf("device %s: name the Observium server, not one of the devices it monitors (no option device)", d.Name)
	}
	rows, err := o.list(ctx, "/devices/", "devices")
	if err != nil {
		return nil, err
	}
	return obsImportRows(rows), nil
}

func obsImportRows(rows []map[string]any) []impRow {
	var out []impRow
	for _, r := range rows {
		os := strings.ToLower(strings.TrimSpace(str(r["os"])))
		host := firstOf(str(r["hostname"]), str(r["sysName"]))
		out = append(out, impRow{ID: str(r["device_id"]), Host: host, Alt: str(r["ip"]), Short: firstOf(str(r["sysName"]), host),
			What: "OS " + firstOf(os, "unknown"), Platform: obsPlatforms[os], Tags: impTag("site", str(r["location"]))})
	}
	return out
}

// ---- IP Fabric ----

// ipfPlatform picks a driver from the vendor, family and platform IP Fabric gives a discovered device.
func ipfPlatform(vendor, family, platform string) string {
	v, all := strings.ToLower(vendor), strings.ToLower(strings.Join([]string{vendor, family, platform}, " "))
	has := func(w ...string) bool {
		for _, x := range w {
			if strings.Contains(all, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("nx-os", "nxos"):
		return "nxos"
	case v == "cisco" && has("ios-xe", "iosxe", "ios xe", "ios"):
		return "iosxe"
	case has("juniper", "junos"):
		return "junos"
	case has("fortinet", "fortigate", "fortios"):
		return "fortios"
	case has("paloalto", "palo alto", "pan-os", "panos"):
		return "panos"
	case has("arista"):
		return "eos"
	case has("f5", "big-ip", "bigip"):
		return "bigip"
	case has("aos-cx", "aoscx", "arubaos-cx"):
		return "aoscx"
	}
	return ""
}

func ipfImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newIPFabric(d, c)
	if err != nil {
		return nil, err
	}
	p := drv.(*ipfabric)
	defer p.Close(context.WithoutCancel(ctx))
	t := ipfTables["devices"]
	var out []impRow
	for start := 0; start < 20000; start += 1000 {
		a, err := p.readTry(ctx, tableReq{table: t.path, columns: t.cols, limit: 1000, start: start, sort: "hostname"}, t.min)
		if err != nil {
			return nil, p.hint(err, "devices")
		}
		for _, r := range a.Rows {
			what := strings.TrimSpace(strings.Join([]string{str(r["vendor"]), str(r["family"]), str(r["platform"])}, " "))
			out = append(out, impRow{ID: str(r["id"]), Host: firstOf(str(r["loginIpv4"]), str(r["loginIp"])), Alt: str(r["hostname"]), Short: str(r["hostname"]),
				What: what, Platform: ipfPlatform(str(r["vendor"]), str(r["family"]), str(r["platform"])), Tags: impTag("site", str(r["siteName"]))})
		}
		if len(a.Rows) < 1000 {
			break
		}
	}
	return out, nil
}

// ---- Centreon ----

// centPlatform picks a driver from the host templates (and groups) Centreon gives a host: its plugin packs are named for the product.
func centPlatform(words string) string {
	w := strings.ToLower(words)
	has := func(x ...string) bool {
		for _, s := range x {
			if strings.Contains(w, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("nexus", "nx-os", "nxos"):
		return "nxos"
	case has("cisco"):
		return "iosxe"
	case has("juniper", "junos"):
		return "junos"
	case has("fortinet", "fortigate"):
		return "fortios"
	case has("paloalto", "palo-alto", "palo alto"):
		return "panos"
	case has("arista"):
		return "eos"
	case has("f5", "bigip", "big-ip"):
		return "bigip"
	case has("aruba-cx", "aoscx", "aos-cx"):
		return "aoscx"
	}
	return ""
}

func centImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newCentreon(d, c)
	if err != nil {
		return nil, err
	}
	ce := drv.(*centreon)
	defer ce.Close(context.WithoutCancel(ctx))
	hosts, _, err := ce.hosts(ctx, centMaxPages)
	if err != nil && len(hosts) == 0 {
		return nil, err
	}
	// what each host is comes from its templates, which only the configuration holds; a Centreon that refuses that read still lists the hosts, as skipped
	tmpl := map[string]string{}
	if cfg, _, err := ce.all(ctx, "/configuration/hosts", nil, centMaxPages); err == nil {
		for _, h := range cfg {
			var names []string
			for _, k := range []string{"templates", "categories", "groups"} {
				if l, ok := h[k].([]any); ok {
					for _, x := range l {
						if m, ok := x.(map[string]any); ok {
							names = append(names, str(m["name"]))
						}
					}
				}
			}
			tmpl[str(h["id"])] = strings.Join(names, " ")
		}
	}
	var out []impRow
	for _, h := range hosts {
		w := tmpl[str(h["id"])]
		out = append(out, impRow{ID: str(h["id"]), Host: str(h["address_ip"]), Alt: str(h["address"]), Short: str(h["name"]),
			What: firstOf(strings.TrimSpace(w), "no template"), Platform: centPlatform(w), Tags: impTag("poller", str(h["monitoring_server_name"]))})
	}
	return out, nil
}

// ---- Panorama ----

// panEntries are the <entry> children of an element of an answer, however the answer was parsed (one entry or several).
func panEntries(v any, key string) []map[string]any {
	m, _ := v.(map[string]any)
	inner, _ := m[key].(map[string]any)
	switch e := inner["entry"].(type) {
	case []any:
		var out []map[string]any
		for _, x := range e {
			if mm, ok := x.(map[string]any); ok {
				out = append(out, mm)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{e}
	}
	return nil
}

// panImportRead lists the firewalls a Panorama manages (show devices all), with the device group each is in.
func panImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	d.Platform = "panorama"
	drv, err := newPANOS(d, c, true)
	if err != nil {
		return nil, err
	}
	p := drv.(*panos)
	defer p.Close(context.WithoutCancel(ctx))
	if _, err := p.system(ctx); err != nil {
		return nil, err
	}
	v, err := p.get(ctx, "<show><devices><all></all></devices></show>")
	if err != nil {
		return nil, err
	}
	group := map[string]string{} // serial -> device group
	if g, err := p.get(ctx, "<show><devicegroups></devicegroups></show>"); err == nil {
		for _, dg := range panEntries(g, "devicegroups") {
			for _, m := range panEntries(dg, "devices") {
				group[str(m["name"])] = str(dg["name"])
			}
		}
	}
	var out []impRow
	for _, e := range panEntries(v, "devices") {
		serial := firstOf(str(e["serial"]), str(e["name"]))
		tags := impTag("dg", group[serial])
		out = append(out, impRow{ID: serial, Host: str(e["ip-address"]), Alt: str(e["hostname"]), Short: firstOf(str(e["hostname"]), str(e["name"])),
			What: strings.TrimSpace(str(e["model"]) + " " + str(e["sw-version"])), Platform: "panos", Tags: tags})
	}
	return out, nil
}

// ---- Proxmox Datacenter Manager ----

// pdmImportRead lists the hosts of the remotes a PDM manages: the nodes of each Proxmox VE remote (platform proxmox) and of each
// Backup Server remote (pbs), tagged remote=ID.
func pdmImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newPDM(d, c)
	if err != nil {
		return nil, err
	}
	p := drv.(*pdm)
	defer p.Close(context.WithoutCancel(ctx))
	v, err := p.get(ctx, "/remotes/remote")
	if err != nil {
		return nil, err
	}
	return pdmImportRows(rows(v)), nil
}

func pdmImportRows(remotes []map[string]any) []impRow {
	var out []impRow
	for _, r := range remotes {
		id, kind := str(r["id"]), strings.ToLower(str(r["type"]))
		plat := map[string]string{"pve": "proxmox", "pbs": "pbs"}[kind]
		nodes := rows(r["nodes"])
		if len(nodes) == 0 { // a remote that does not list its nodes: the remote itself, by the address it is reached on
			nodes = []map[string]any{{"hostname": firstOf(str(r["server"]), str(r["host"]), str(r["hostname"]))}}
		}
		for i, n := range nodes {
			host := firstOf(str(n["hostname"]), str(n["host"]), str(n["server"]))
			short := host
			if _, err := netip.ParseAddr(host); err == nil || host == "" {
				short = fmt.Sprintf("%s-%d", id, i+1) // an address makes no name: the remote's and the node's number
			}
			out = append(out, impRow{ID: id, Host: host, Short: short, What: "remote " + id + " (" + firstOf(kind, "unknown type") + ")", Platform: plat, Tags: impTag("remote", id)})
		}
	}
	return out
}

// ---- Aruba Fabric Composer ----

// afcImportRead lists the switches a Fabric Composer manages; they are Aruba CX.
func afcImportRead(ctx context.Context, d Device, c Credential) ([]impRow, error) {
	drv, err := newAFC(d, c)
	if err != nil {
		return nil, err
	}
	a := drv.(*afc)
	defer a.Close(context.WithoutCancel(ctx))
	sw, err := a.list(ctx, "switches", "")
	if err != nil {
		return nil, err
	}
	return afcImportRows(sw), nil
}

func afcImportRows(sw []map[string]any) []impRow {
	var out []impRow
	for _, s := range sw {
		name := firstOf(str(s["name"]), str(s["hostname"]))
		addr := firstOf(str(s["ip_address"]), str(s["ip"]), str(s["management_ip"]), str(s["mgmt_ip"]), str(s["address"]))
		fabric := firstOf(str(s["fabric_name"]), str(s["fabric"]))
		out = append(out, impRow{ID: str(s["uuid"]), Host: addr, Alt: name, Short: name, What: firstOf(str(s["platform"]), str(s["model"]), "Aruba CX"),
			Platform: "aoscx", Tags: impTag("fabric", fabric)})
	}
	return out
}
