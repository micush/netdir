package device

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Importing the devices an Observium server monitors into the inventory.  Each one is made with a platform picked from the OS
// Observium recognised, its address, tags for where it came from and its location, no login, and disabled: nothing is
// contacted until someone gives it a login and enables it.  A device whose OS has no driver here, one already in the inventory
// (by name or by address) and one with nothing to reach it by are left out, each with the reason.

// obsPlatforms maps Observium's OS names (the "os" of a device) to platforms that have a driver here.
var obsPlatforms = map[string]string{
	"ios": "iosxe", "iosxe": "iosxe", "nxos": "nxos", "eos": "eos", "junos": "junos",
	"fortigate": "fortios", "fortios": "fortios", "panos": "panos",
	"aoscx": "aoscx", "arubaos-cx": "aoscx", "bigip": "bigip", "f5": "bigip",
}

// Skipped is a device the import left out, and why.
type Skipped struct {
	Name   string `json:"name"`
	OS     string `json:"os,omitempty"`
	Reason string `json:"reason"`
}

var (
	obsNameBad = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	obsTagBad  = regexp.MustCompile(`[\s,]+`)
)

// obsDeviceName makes an inventory name from a host name: the short name when it has a domain, bad characters turned to "-".
func obsDeviceName(host string) string {
	if _, err := netip.ParseAddr(host); err != nil {
		if i := strings.Index(host, "."); i > 0 {
			host = host[:i]
		}
	}
	n := strings.Trim(obsNameBad.ReplaceAllString(strings.TrimSpace(host), "-"), "-._")
	if len(n) > 64 {
		n = strings.TrimRight(n[:64], "-._")
	}
	return n
}

// ObserviumImport lists what the Observium server d (no option "device") monitors, as devices to add to existing.
func ObserviumImport(ctx context.Context, d Device, c Credential, existing []Device) ([]Device, []Skipped, error) {
	if d.Platform != "observium" {
		return nil, nil, fmt.Errorf("device %s: not an Observium server", d.Name)
	}
	drv, err := newObservium(d, c) // not Open: the answers are read here, not handed to a caller, so they need no wrapper
	if err != nil {
		return nil, nil, err
	}
	o := drv.(*observium)
	defer o.Close(context.WithoutCancel(ctx))
	if o.dev != "" {
		return nil, nil, fmt.Errorf("device %s: name the Observium server, not one of the devices it monitors (no option device)", d.Name)
	}
	rows, err := o.list(ctx, "/devices/", "devices")
	if err != nil {
		return nil, nil, err
	}
	return obsImportRows(rows, existing)
}

func obsImportRows(rows []map[string]any, existing []Device) ([]Device, []Skipped, error) {
	names, addrs := map[string]bool{}, map[string]bool{}
	for _, e := range existing {
		names[strings.ToLower(e.Name)] = true
		addrs[strings.ToLower(e.Address)] = true
	}
	var out []Device
	var skipped []Skipped
	for _, r := range rows {
		host := firstOf(str(r["hostname"]), str(r["sysName"]))
		os := strings.ToLower(strings.TrimSpace(str(r["os"])))
		skip := func(why string) {
			skipped = append(skipped, Skipped{Name: firstOf(host, str(r["device_id"])), OS: os, Reason: why})
		}
		plat := obsPlatforms[os]
		if plat == "" {
			skip(fmt.Sprintf("no driver for the OS %q", firstOf(os, "unknown")))
			continue
		}
		addr := host
		if checkHost(addr) != nil {
			addr = str(r["ip"])
			if checkHost(addr) != nil {
				skip("no address or host name to reach it by")
				continue
			}
		}
		if addrs[strings.ToLower(addr)] {
			skip("already in the inventory (same address)")
			continue
		}
		name := obsDeviceName(firstOf(str(r["sysName"]), host))
		if name == "" || !nameRE.MatchString(name) {
			skip("no usable name")
			continue
		}
		base, n := name, 2
		for names[strings.ToLower(name)] {
			name = fmt.Sprintf("%s-%d", base, n)
			n++
		}
		names[strings.ToLower(name)], addrs[strings.ToLower(addr)] = true, true
		tags := []string{"source=observium"}
		if loc := strings.Trim(obsTagBad.ReplaceAllString(strings.TrimSpace(str(r["location"])), "_"), "_"); loc != "" && len(loc) <= 58 {
			tags = append(tags, "site="+loc)
		}
		out = append(out, Device{Name: name, Platform: plat, Address: addr, Tags: tags, Disabled: true})
	}
	return out, skipped, nil
}
