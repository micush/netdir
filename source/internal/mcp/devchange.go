package mcp

// mcpDeviceChangeTool is the MCP tool that changes devices; it is a write tool, so only a caller with rw access sees it or may call it.
func mcpDeviceChangeTool() mcpTool {
	return mcpTool{name: "device_change", title: "Change device ports", noNode: true, write: true, destructive: true, idempotent: true,
		desc: "Change ports on switches and firewalls (Cisco IOS-XE, Cisco NX-OS, Arista EOS, Aruba AOS-CX, Meraki switches, Juniper Junos, Fortinet FortiOS and F5 BIG-IP): set or clear the description, or shut them down or bring them up, on a range of ports of every device the target picks (Junos ports are written ge-0/0/1, FortiOS port1 or dmz, BIG-IP 1.1). " +
			"Clearing interface counters (clear_counters) works on Cisco IOS-XE and Arista EOS (named ports, or all), and on Juniper Junos and Palo Alto PAN-OS (all ports only); other platforms answer that they cannot. save: true also saves the configuration where the platform has a save (IOS-XE, NX-OS, EOS, Aruba CX, BIG-IP); Junos, FortiOS and Meraki keep a change on their own. A clear is not read back and cannot be undone. " +
			"Give the change as plain English in text, e.g. change the description for ports gi1/0/1-24 to read \"devices\"; clear the description on gi1/0/1-24; shut down gi1/0/5; shut port 1/1/1 down; no shutdown et1-4; clear all port counters; clear counters on gi1/0/1-4; bring up ports 1/1/1-1/1/48 (Aruba CX ports have no type). " +
			"Or give action (description, clear_description, shutdown, no_shutdown, clear_counters), ports (gi1/0/1-24, te1/1/1; et1-48 on Arista; 1/1/1-1/1/48 on Aruba CX; for clear_counters leave it out or say all for every port) and, for a description, value. " +
			"Plan it first with dry_run: true, which changes nothing and says what each port holds now and would hold. A real change is read back, and put back as it was if the device refuses it or does not hold it. " +
			"A port that does not exist on a device cancels the change on that device. A port that holds the address the gateway reaches the device on is never shut down. Each device is changed on its own.",
		props: []mcpProp{
			{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N or \"all\", several separated by commas (list_devices)."},
			{name: "text", typ: "string", desc: "The change in plain English. Use this or action, ports and value."},
			{name: "action", typ: "string", enum: []string{"description", "clear_description", "shutdown", "no_shutdown", "clear_counters"}, desc: "What to do (typed form)."},
			{name: "ports", typ: "string", desc: "The ports (typed form): gi1/0/1-24, te1/1/1, et1-48, po1; several separated by commas."},
			{name: "value", typ: "string", desc: "The description to set (typed form), one line of up to 200 characters."},
			{name: "dry_run", typ: "boolean", desc: "Only plan: say what would change, change nothing."},
			{name: "save", typ: "boolean", desc: "Also save the configuration so the change survives a reboot (IOS-XE, NX-OS, EOS, Aruba CX and BIG-IP; Junos, FortiOS and Meraki keep changes on their own). A change that was refused or put back is not saved."},
		},
		run: func(c *mcpCtx) (any, error) {
			dry, _ := c.flag("dry_run")
			save, _ := c.flag("save")
			body := map[string]any{"target": c.str("target"), "text": c.str("text"), "action": c.str("action"), "ports": c.str("ports"), "value": c.str("value"), "dry_run": dry, "save": save}
			b, err := c.call("POST", "/api/devices/change", body, "")
			return asAny(b), err
		}}
}
