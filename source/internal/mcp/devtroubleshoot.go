package mcp

import (
	"netdir/internal/devices"
)

func mcpDeviceTroubleshootTool() mcpTool {
	return mcpTool{name: "device_troubleshoot_user", title: "Troubleshoot a user or a host (tshoot user NAME, tshoot host NAME)", noNode: true,
		desc: "Troubleshoot a user (\"tshoot user msmith\") or a machine (\"tshoot host PC-123\"): give user or host, not both. " +
			"For a user: look the user up in Microsoft Entra by sign-in name, account name, object ID or name and take the device they signed in with most recently; search the firewall's VPN (GlobalProtect) log for the account, which names the machine they connected with and its addresses. " +
			"For a host: the VPN log says which user last connected with that machine and from where, and Entra which users are registered on a device of that name (last_user). " +
			"Then, for each machine found: find it on the Meraki network by its name (and, for a user, also every client that signed in to the network with the account, such as a phone on the Wi-Fi) and return what helps when someone cannot get online or is slow, for the last few hours (not only now): the Meraki client (IP, MAC, VLAN, SSID, the AP or switch and port it was on, first and last seen, usage), its usage history and device policy; " +
			"for a wireless client its Wi-Fi now (SSID, AP, RSSI and SNR), its signal quality, data rate and latency over the window, its connection statistics, connectivity events and failed connections; for a wired one its switch port's status (speed, duplex, errors, warnings, traffic); and whether the AP or switch it was on is online. " +
			"Last, the firewall's newest traffic and threat log entries for the addresses found (the VPN address, the address on the network). " +
			"When there is an Active Directory device the account (or the computer's account) is added as directory: enabled, locked out, when the password last changed, last sign-in, groups. " +
			"For a user, when there is a SMAX service desk device, the user's three newest tickets (requests and incidents they asked for, newest first, with number, title, phase, status and creation time) are added as tickets. " +
			"The answer has: user or host and last_user, devices (each with entra and network), directory, tickets (the user's newest SMAX tickets), vpn (the query, the newest event as last, the events), firewall (addresses, traffic, threat) and notes, which say what could not be looked up and why. " +
			"The firewall logs are those of the Panorama in the inventory (or of the one PAN-OS firewall); a system that is not configured is left out with a note. The systems are matched by name (case and domain ignored); a phone often has a different host name, so a device may be reported as not seen. Read only.",
		props: []mcpProp{
			{name: "user", typ: "string", desc: "The user: a sign-in name (joe.smith@contoso.com), an account name (msmith), an object ID or a name. A name that matches several users is refused with the candidates listed. Give this or host."},
			{name: "host", typ: "string", desc: "The machine's name (PC-123), instead of user: the last user of the machine is looked up, then the machine as above."},
			{name: "hours", typ: "integer", desc: "How far back on the network, 1 to 168 (default 6). The log entries are the newest ones, whatever their age."},
			{name: "devices", typ: "integer", desc: "How many of the user's most recently used devices to follow, 1 to 3 (default 1)."},
			{name: "network", typ: "string", desc: "Search one Meraki network (L_… or N_…) instead of all of them (faster on a big organization)."},
			{name: "entra", typ: "string", desc: "The Entra device's name in list_devices, when there are several."},
			{name: "meraki", typ: "string", desc: "The Meraki organization device's name in list_devices, when there are several."},
			{name: "panorama", typ: "string", desc: "The Panorama's or firewall's name in list_devices, when there are several."},
			{name: "ad", typ: "string", desc: "The Active Directory device's name in list_devices, when there are several."},
			{name: "smax", typ: "string", desc: "The SMAX device's name in list_devices, when there are several."},
		},
		run: func(c *mcpCtx) (any, error) {
			q := "/api/devices/troubleshoot?"
			sep := ""
			for _, k := range []string{"user", "host", "hours", "devices", "network", "entra", "meraki", "panorama", "ad", "smax"} {
				if v := c.str(k); v != "" {
					q += sep + k + "=" + devices.UrlQ(v)
					sep = "&"
				}
			}
			b, err := c.call("GET", q, nil, "")
			return asAny(b), err
		}}
}
