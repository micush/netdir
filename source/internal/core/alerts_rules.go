package core

// The rules of the alerts (see alerts.go) and what they read.

var AlertDefs = []alertDef{
	{ID: "listener_down", Title: "MCP listener down", Subject: "gateway", Kind: "updown", Sev: "critical", On: true, Go: "gateways"},
	{ID: "device_down", Title: "Device not answering", Subject: "device", Kind: "updown", Sev: "warning", On: true, DefMode: "minutes", DefAfter: 3, Go: "devices"},
	{ID: "no_active_gateway", Title: "No active gateway", Subject: "gateway", Kind: "updown", Sev: "critical", On: true, Go: "gateways"},
	{ID: "certificate_expiring", Title: "Certificate about to expire", Subject: "certificate", Kind: "value", Sev: "warning", On: true, Unit: "days left", Below: true, Thresh: 14, ForMin: 0, Go: "cfg_web"},
	{ID: "backup_failed", Title: "Backup failed", Subject: "", Kind: "updown", Sev: "warning", On: true, DefMode: "minutes", DefAfter: 30, Go: "cfg_backup"},
	{ID: "cpu_high", Title: "CPU busy", Subject: "", Kind: "value", Sev: "warning", On: true, Unit: "% CPU", Thresh: 90, ForMin: 15, Go: "host"},
	{ID: "memory_high", Title: "Memory nearly full", Subject: "", Kind: "value", Sev: "warning", On: true, Unit: "% memory", Thresh: 90, ForMin: 15, Go: "host"},
	{ID: "disk_full", Title: "Disk nearly full", Subject: "filesystem", Kind: "value", Sev: "warning", On: true, Unit: "% full", Thresh: 90, ForMin: 10, Go: "host"},
}

func AlertDefByID(id string) (alertDef, bool) {
	for _, d := range AlertDefs {
		if d.ID == id {
			return d, true
		}
	}
	return alertDef{}, false
}
