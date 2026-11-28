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
	"netdir/internal/core"
	"netdir/internal/devices"
)

func (m *Mgmt) deviceCapture(raw json.RawMessage, actor string) (any, error) {
	return m.withBelow("device_capture", raw, actor, m.viaCheckers("capture", m.deviceCaptureHere))
}

// deviceCaptureHere is deviceCapture for this director's own devices.
func (m *Mgmt) deviceCaptureHere(raw json.RawMessage, actor string) (any, error) {
	var a devices.DeviceCaptureArgs
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
	devs, creds := dc.EffectiveDevices(), dc.Settings.DeviceCredentials
	if len(devs) == 0 {
		return nil, errors.New("no devices are configured (settings.devices)")
	}
	target, err := core.ExpandGatewayTargetsIn(dc, a.Target)
	if err != nil {
		return nil, err
	}
	picked, err := device.Select(devs, target)
	if err != nil {
		return nil, err
	}
	if len(picked) > devices.DeviceCaptureMaxDevices {
		return nil, fmt.Errorf("target: %d devices; a capture runs on %d at most", len(picked), devices.DeviceCaptureMaxDevices)
	}
	for _, d := range picked {
		if d.Disabled {
			return nil, fmt.Errorf("device %s %s", d.Name, devices.OffWhy(d))
		}
	}
	rq := device.CaptureReq{Interface: a.Interface, Filter: a.Filter, Seconds: a.Seconds, Packets: a.Packets}
	core.Warnf("devices: %q captures packets on %s (%d devices), interface %q, filter %q, %d s", actor, a.Target, len(picked), a.Interface, a.Filter, a.Seconds)
	secs := a.Seconds
	if secs < 1 || secs > 30 {
		secs = 30
	}
	res := device.Fanout(context.Background(), picked, creds, devices.DeviceParallel, time.Duration(secs)*time.Second+60*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
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
			core.Warnf("devices: audit %s: %q capture failed: %s", x.Device, actor, x.Error)
			continue
		}
		if r, ok := x.Data.(device.CaptureResult); ok {
			core.Warnf("devices: audit %s: %q captured %d packets on %s (filter %q, %d s)", x.Device, actor, r.Count, r.Interface, r.Filter, r.Seconds)
		}
	}
	return map[string]any{"op": "capture", "asked": len(res), "failed": failed, "results": res}, nil
}

// runDeviceCapture is --device-capture IFACE (or "default").
func runDeviceCapture(sock string, f *cliFlags) {
	if strings.TrimSpace(*f.deviceTarget) == "" {
		core.Fatalf("--device-capture needs --target: a device name, tag:TAG, platform:PLATFORM or gateway:N")
	}
	iface := *f.deviceCapture
	if iface == "default" {
		iface = ""
	}
	args := map[string]any{"target": *f.deviceTarget, "interface": iface, "filter": *f.captureFilter}
	if *f.captureSecs != "" {
		n, err := strconv.Atoi(*f.captureSecs)
		if err != nil || n < 1 || n > 30 {
			core.Fatalf("--capture-seconds must be 1 to 30")
		}
		args["seconds"] = n
	}
	var ans devices.CaptureAnswer
	core.Decode(core.Op(sock, "device.capture", args), &ans)
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
		core.Fatalf("%d of %d devices failed", ans.Failed, ans.Asked)
	}
}
