package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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

const deviceCaptureMaxDevices = 10

type deviceCaptureArgs struct {
	Target    string `json:"target"`
	Interface string `json:"interface"`
	Filter    string `json:"filter"`
	Seconds   int    `json:"seconds"`
	Packets   int    `json:"packets"`
}

func (m *Mgmt) deviceCapture(raw json.RawMessage, actor string) (any, error) {
	var a deviceCaptureArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	if strings.TrimSpace(a.Target) == "" {
		return nil, errors.New(`target: the devices to capture on: a name, tag:TAG, platform:PLATFORM, gateway:N, separated by commas`)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	devs, creds := dc.Settings.Devices, dc.Settings.DeviceCredentials
	if len(devs) == 0 {
		return nil, errors.New("no devices are configured (settings.devices)")
	}
	target, err := expandGatewayTargetsIn(dc, a.Target)
	if err != nil {
		return nil, err
	}
	picked, err := device.Select(devs, target)
	if err != nil {
		return nil, err
	}
	if len(picked) > deviceCaptureMaxDevices {
		return nil, fmt.Errorf("target: %d devices; a capture runs on %d at most", len(picked), deviceCaptureMaxDevices)
	}
	for _, d := range picked {
		if d.Disabled {
			return nil, fmt.Errorf("device %s is disabled: enable it first (Configure ▸ Devices)", d.Name)
		}
	}
	rq := device.CaptureReq{Interface: a.Interface, Filter: a.Filter, Seconds: a.Seconds, Packets: a.Packets}
	warnf("devices: %q captures packets on %s (%d devices), interface %q, filter %q, %d s", actor, a.Target, len(picked), a.Interface, a.Filter, a.Seconds)
	secs := a.Seconds
	if secs < 1 || secs > 30 {
		secs = 30
	}
	res := device.Fanout(context.Background(), picked, creds, deviceParallel, time.Duration(secs)*time.Second+60*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
		c, ok := d.(device.Capturer)
		if !ok {
			return nil, errors.New("this platform cannot capture packets from here (DNS Director, NTP Director, Arista EOS and F5 BIG-IP can)")
		}
		return c.Capture(ctx, rq)
	})
	failed := 0
	for _, x := range res {
		if !x.OK {
			failed++
			warnf("devices: audit %s: %q capture failed: %s", x.Device, actor, x.Error)
			continue
		}
		if r, ok := x.Data.(device.CaptureResult); ok {
			warnf("devices: audit %s: %q captured %d packets on %s (filter %q, %d s)", x.Device, actor, r.Count, r.Interface, r.Filter, r.Seconds)
		}
	}
	return map[string]any{"op": "capture", "asked": len(res), "failed": failed, "results": res}, nil
}

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

// ---- the CLI ----

type captureAnswer struct {
	Asked   int `json:"asked"`
	Failed  int `json:"failed"`
	Results []struct {
		Device string               `json:"device"`
		OK     bool                 `json:"ok"`
		Error  string               `json:"error"`
		Data   device.CaptureResult `json:"data"`
	} `json:"results"`
}

// runDeviceCapture is --device-capture IFACE (or "default").
func runDeviceCapture(sock string, f *cliFlags) {
	if strings.TrimSpace(*f.deviceTarget) == "" {
		fatalf("--device-capture needs --target: a device name, tag:TAG, platform:PLATFORM or gateway:N")
	}
	iface := *f.deviceCapture
	if iface == "default" {
		iface = ""
	}
	args := map[string]any{"target": *f.deviceTarget, "interface": iface, "filter": *f.captureFilter}
	if *f.captureSecs != "" {
		n, err := strconv.Atoi(*f.captureSecs)
		if err != nil || n < 1 || n > 30 {
			fatalf("--capture-seconds must be 1 to 30")
		}
		args["seconds"] = n
	}
	var ans captureAnswer
	decode(op(sock, "device.capture", args), &ans)
	for _, r := range ans.Results {
		fmt.Printf("== %s\n", r.Device)
		if !r.OK {
			fmt.Printf("FAILED: %s\n", r.Error)
			continue
		}
		d := r.Data
		fmt.Printf("%d packets, %d bytes on %s in %d s (filter %q)\n", d.Count, d.Bytes, d.Interface, d.Seconds, d.Filter)
		for _, p := range d.Protocols {
			fmt.Printf("  %-10s %6d packets %9d bytes\n", p.Name, p.Packets, p.Bytes)
		}
		for _, p := range d.Talkers {
			fmt.Printf("  %-44s %6d packets\n", p.Name, p.Packets)
		}
		for _, l := range d.Listed {
			fmt.Println(" ", l)
		}
		if d.Note != "" {
			fmt.Println(" ", d.Note)
		}
	}
	if ans.Failed > 0 {
		fatalf("%d of %d devices failed", ans.Failed, ans.Asked)
	}
}
