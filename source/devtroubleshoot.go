package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netdir/device"
)

// Troubleshoot a user: Entra says which devices the user has and which was used last, Meraki says where a device of that name was seen
// on the network in the last hours and how it did (device/meraki_clients.go lists what is read).
//
//	GET /api/devices/troubleshoot?user=joe.smith@contoso.com[&hours=6][&devices=1][&network=L_123][&entra=NAME][&meraki=NAME]
//	netdir --troubleshoot-user joe.smith@contoso.com [--troubleshoot-hours 6]
//	MCP device_troubleshoot_user
//
// It only reads, so a read-only account and an ro MCP key may use it.  The Entra device is the one of platform entra and the Meraki
// device the organization one (platform meraki without a serial); with several of either, entra= or meraki= names the one.  The two are
// matched by name: the device's name in Entra against the host name the client gave on the network (case and domain ignored).

func pickDevice(devs []device.Device, name, platform string, ok func(device.Device) bool) (device.Device, error) {
	var found []device.Device
	for _, d := range devs {
		if d.Platform != platform || d.Disabled || (ok != nil && !ok(d)) {
			continue
		}
		if name != "" && d.Name != name {
			continue
		}
		found = append(found, d)
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		if name != "" {
			return device.Device{}, fmt.Errorf("device %q: not an enabled %s device in the inventory", name, platform)
		}
		return device.Device{}, fmt.Errorf("no enabled %s device is configured", platform)
	}
	var n []string
	for _, d := range found {
		n = append(n, d.Name)
	}
	return device.Device{}, fmt.Errorf("several %s devices (%s): name one", platform, strings.Join(n, ", "))
}

func (m *Mgmt) deviceTroubleshoot(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		User, Hours, Devices, Network, Entra, Meraki string
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	get := func(k string) string {
		switch v := in[k].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	a.User, a.Hours, a.Devices, a.Network, a.Entra, a.Meraki = get("user"), get("hours"), get("devices"), get("network"), get("entra"), get("meraki")
	if a.User == "" {
		return nil, errors.New("user: a sign-in name, an object ID or a name")
	}
	hours, devices := 6, 1
	if a.Hours != "" {
		n, err := strconv.Atoi(a.Hours)
		if err != nil || n < 1 || n > 168 {
			return nil, errors.New("hours: 1 to 168 (default 6)")
		}
		hours = n
	}
	if a.Devices != "" {
		n, err := strconv.Atoi(a.Devices)
		if err != nil || n < 1 || n > 3 {
			return nil, errors.New("devices: 1 to 3, how many of the user's most recently used devices (default 1)")
		}
		devices = n
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	devs, creds := dc.Settings.Devices, dc.Settings.DeviceCredentials
	ed, err := pickDevice(devs, a.Entra, "entra", nil)
	if err != nil {
		return nil, err
	}
	warnf("devices: audit: %q troubleshoots user %q (%d h) through %s", actor, a.User, hours, ed.Name)
	ask := func(d device.Device, to time.Duration, fn func(context.Context, device.Driver) (any, error)) (any, error) {
		r := device.Fanout(context.Background(), []device.Device{d}, creds, 1, to, fn)[0]
		if !r.OK {
			return nil, errors.New(r.Error)
		}
		return r.Data, nil
	}
	type found struct {
		User    map[string]any
		Devices []map[string]any
	}
	ev, err := ask(ed, deviceTimeout, func(ctx context.Context, d device.Driver) (any, error) {
		l, ok := d.(device.UserDeviceLooker)
		if !ok {
			return nil, errors.New("this device cannot look up a user's devices")
		}
		u, ds, err := l.UserDevices(ctx, a.User)
		return found{u, ds}, err
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ed.Name, err)
	}
	fd := ev.(found)
	out := map[string]any{"user": fd.User, "entra_device": ed.Name, "window_hours": hours, "device_count": len(fd.Devices)}
	var notes []string
	if len(fd.Devices) == 0 {
		out["notes"] = []string{"the user has no registered or owned devices in Entra"}
		return out, nil
	}
	if len(fd.Devices) > devices {
		notes = append(notes, fmt.Sprintf("%d devices; the %d signed in most recently are followed", len(fd.Devices), devices))
		fd.Devices = fd.Devices[:devices]
	}
	md, merr := pickDevice(devs, a.Meraki, "meraki", func(d device.Device) bool { return d.Options["serial"] == "" })
	if merr != nil {
		notes = append(notes, "no network lookup: "+merr.Error())
		out["devices"] = wrapEntraOnly(fd.Devices)
		out["notes"] = notes
		return out, nil
	}
	out["meraki_device"] = md.Name
	res, err := ask(md, 150*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
		r, ok := d.(device.ClientReporter)
		if !ok {
			return nil, errors.New("this device cannot report on clients")
		}
		var all []any
		for _, ed := range fd.Devices {
			q := device.ClientQuery{Names: []string{fmt.Sprint(ed["displayName"])}, Hours: hours, Network: a.Network}
			rep, err := r.ClientReport(ctx, q)
			if err != nil {
				all = append(all, map[string]any{"error": err.Error()})
				continue
			}
			all = append(all, rep)
		}
		return all, nil
	})
	devOut := make([]map[string]any, 0, len(fd.Devices))
	reps, _ := res.([]any)
	for i, ed := range fd.Devices {
		e := map[string]any{"entra": ed}
		switch {
		case err != nil:
			e["network"] = map[string]any{"error": err.Error()}
		case i < len(reps):
			e["network"] = reps[i]
		}
		devOut = append(devOut, e)
	}
	out["devices"] = devOut
	if len(notes) > 0 {
		out["notes"] = notes
	}
	return out, nil
}

func urlQ(s string) string { return url.QueryEscape(s) }

func wrapEntraOnly(ds []map[string]any) []map[string]any {
	out := make([]map[string]any, len(ds))
	for i, d := range ds {
		out[i] = map[string]any{"entra": d}
	}
	return out
}

func mcpDeviceTroubleshootTool() mcpTool {
	return mcpTool{name: "device_troubleshoot_user", title: "Troubleshoot a user (tshoot USER)", noNode: true,
		desc: "Troubleshoot a user (\"tshoot msmith\"): look the user up in Microsoft Entra by sign-in name, account name, object ID or name, take the device they signed in with most recently, find it on the Meraki network by its name, and return what helps when someone cannot get online or is slow, " +
			"for the last few hours (not only now): the Entra device (name, OS, compliance, last sign-in); the Meraki client (IP, MAC, VLAN, SSID, the AP or switch and port it was on, first and last seen, usage), its usage history and device policy; " +
			"for a wireless client its connection statistics, latency, connectivity events and failed connections; for a wired one its switch port's status (speed, duplex, errors, warnings, traffic); and whether the AP or switch it was on is online. " +
			"The two systems are matched by name (Entra's device name against the host name the client gave on the network, case and domain ignored); a phone often has a different host name, so a device may be reported as not seen. Read only.",
		props: []mcpProp{
			{name: "user", typ: "string", required: true, desc: "The user: a sign-in name (joe.smith@contoso.com), an account name (msmith), an object ID or a name. A name that matches several users is refused with the candidates listed."},
			{name: "hours", typ: "integer", desc: "How far back on the network, 1 to 168 (default 6)."},
			{name: "devices", typ: "integer", desc: "How many of the user's most recently used devices to follow, 1 to 3 (default 1)."},
			{name: "network", typ: "string", desc: "Search one Meraki network (L_… or N_…) instead of all of them (faster on a big organization)."},
			{name: "entra", typ: "string", desc: "The Entra device's name in list_devices, when there are several."},
			{name: "meraki", typ: "string", desc: "The Meraki organization device's name in list_devices, when there are several."},
		},
		run: func(c *mcpCtx) (any, error) {
			q := "/api/devices/troubleshoot?user=" + urlQ(c.str("user"))
			for _, k := range []string{"hours", "devices", "network", "entra", "meraki"} {
				if v := c.str(k); v != "" {
					q += "&" + k + "=" + urlQ(v)
				}
			}
			b, err := c.call("GET", q, nil, "")
			return asAny(b), err
		}}
}

// ---- the CLI ----

func runTroubleshootUser(sock, user, hours string) {
	args := map[string]any{"user": user}
	if hours != "" {
		args["hours"] = hours
	}
	var v any
	decode(op(sock, "device.troubleshoot", args), &v)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// shortCommand turns "netdir tshoot USER [HOURS]" into the flags it stands for (--tshoot alone, the node's troubleshooting bundle, is
// unchanged).  Anything else is returned as it was.
func shortCommand(args []string) []string {
	if len(args) >= 2 && args[0] == "tshoot" && !strings.HasPrefix(args[1], "-") {
		out := []string{"--troubleshoot-user", args[1]}
		rest := args[2:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			out = append(out, "--troubleshoot-hours", rest[0])
			rest = rest[1:]
		}
		return append(out, rest...)
	}
	return args
}
