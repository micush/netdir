package devices

import (
	"fmt"

	"netdir/device"
	"netdir/internal/core"
)

// runDeviceImport is netdir --device-import SERVER [--dry-run].
func RunDeviceImport(sock, name string, dry bool) {
	var r struct {
		Added   []device.Device  `json:"added"`
		Skipped []device.Skipped `json:"skipped"`
	}
	core.Decode(core.Op(sock, "device.import_observium", map[string]any{"device": name, "dry_run": dry}), &r)
	verb := "Imported"
	if dry {
		verb = "Would import"
	}
	fmt.Printf("%s %d devices from %s (disabled, with no login: give each one a login, then enable it)\n", verb, len(r.Added), name)
	for _, d := range r.Added {
		fmt.Printf("  %-24s %-8s %s\n", d.Name, d.Platform, d.Address)
	}
	for _, s := range r.Skipped {
		fmt.Printf("  skipped %-20s %s\n", s.Name, s.Reason)
	}
}
