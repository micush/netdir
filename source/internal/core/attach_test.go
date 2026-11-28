package core

// attachDevices puts every device of the inventory on one gateway: a device on no gateway reads as disabled (config.go,
// effectiveDevices), and most tests want their devices contacted.
func attachDevices(dc *DaemonConfig) {
	if len(dc.Groups) == 0 {
		dc.Groups = []GroupConfig{DefaultGroup()}
	}
	have := map[string]bool{}
	for _, n := range dc.Groups[0].Devices {
		have[n] = true
	}
	for _, d := range dc.Settings.Devices {
		if !have[d.Name] {
			dc.Groups[0].Devices = append(dc.Groups[0].Devices, d.Name)
		}
	}
}
