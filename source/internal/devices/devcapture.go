package devices

import (
	"netdir/device"
)

// Packet capture on a managed device (device/capture.go has the limits and the pcap reader, device/capture_drivers.go the platforms):
//
//	POST /api/devices/capture   {"target": "ns1", "interface": "eth0", "filter": "udp and port 53", "seconds": 5, "packets": 500}
//	netdir --device-capture eth0 --target ns1 [--capture-filter "udp and port 53"] [--capture-seconds 5]
//	MCP device_capture          (a caller with rw access only)
//
// A capture shows other people's traffic, so it needs the same access as a device change: read-only sessions are refused by authed and
// MCP ro keys have no tool.  What comes back is a summary (the first packets' headers, protocol and address-pair counts), never the
// raw file or any payload.  Every capture is logged with who made it, where, and the filter.

const DeviceCaptureMaxDevices = 10

type DeviceCaptureArgs struct {
	Target    string `json:"target"`
	Interface string `json:"interface"`
	Filter    string `json:"filter"`
	Seconds   int    `json:"seconds"`
	Packets   int    `json:"packets"`
}

// ---- the CLI ----

type CaptureAnswer struct {
	Asked   int `json:"asked"`
	Failed  int `json:"failed"`
	Results []struct {
		Device string               `json:"device"`
		OK     bool                 `json:"ok"`
		Error  string               `json:"error"`
		Data   device.CaptureResult `json:"data"`
	} `json:"results"`
}
