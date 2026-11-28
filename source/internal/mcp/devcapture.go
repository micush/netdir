package mcp

func mcpDeviceCaptureTool() mcpTool {
	return mcpTool{name: "device_capture", title: "Capture packets on a device", noNode: true, write: true,
		desc: "Capture packets on devices for a few seconds and return a summary: the first packets one line each (time, protocol, addresses, ports, TCP flags, length; headers only, no payload), the protocols and the busiest address pairs counted. " +
			"Works on the DNS Director and NTP Director (their own capture), Arista EOS (tcpdump in the switch's shell: only traffic to or from its CPU) and F5 BIG-IP (tcpdump, interface 0.0 is every VLAN); other platforms answer that they cannot. " +
			"filter is tcpdump syntax (the directors' own filter): words, numbers and . : / ( ) _ - only, e.g. \"host 10.0.0.5 and port 53\". At most 30 seconds, 2000 packets and 10 devices. The capture file is removed from the device afterwards. A capture shows other people's traffic: use a narrow filter.",
		props: []mcpProp{
			{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM or gateway:N (list_devices)."},
			{name: "interface", typ: "string", desc: "The interface in the device's terms (eth0; Ethernet1 or Management1 on EOS; 0.0 on BIG-IP, the default there). Directors: the gateway's interface when left out."},
			{name: "filter", typ: "string", desc: "Which packets, e.g. \"udp and port 53\"."},
			{name: "seconds", typ: "integer", desc: "How long, 1 to 30 (default 5)."},
			{name: "packets", typ: "integer", desc: "At most this many packets, 1 to 2000 (default 500)."},
		},
		run: func(c *mcpCtx) (any, error) {
			b, err := c.call("POST", "/api/devices/capture", map[string]any{"target": c.str("target"), "interface": c.str("interface"), "filter": c.str("filter"), "seconds": c.num("seconds", 0), "packets": c.num("packets", 0)}, "")
			return asAny(b), err
		}}
}
