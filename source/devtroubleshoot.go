package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
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

// tsName is a name that may go into a log filter between quotes: an account name, a sign-in name, a host name.
var tsNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// tsShortUser is the account name of what was typed or found: "joe.smith" of joe.smith@contoso.com or of CORP\joe.smith.  Empty
// when it is not a name a filter can take (a name with spaces, an object ID).
func tsShortUser(names ...string) string {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if i := strings.LastIndexByte(n, '\\'); i >= 0 {
			n = n[i+1:]
		}
		if i := strings.IndexByte(n, '@'); i > 0 {
			n = n[:i]
		}
		if tsNameRE.MatchString(n) && !entraIDLike(n) {
			return n
		}
	}
	return ""
}

func entraIDLike(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// tsHostKey is a host name as two systems agree on it: lower case, without a domain.
func tsHostKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// pickLogDevice is the device whose logs are searched: the Panorama if there is one, else the firewall; name picks one.
func pickLogDevice(devs []device.Device, name string) (device.Device, error) {
	if name != "" {
		for _, plat := range []string{"panorama", "panos"} {
			if d, err := pickDevice(devs, name, plat, nil); err == nil {
				return d, nil
			}
		}
		return device.Device{}, fmt.Errorf("device %q: not an enabled panorama or panos device in the inventory", name)
	}
	d, err := pickDevice(devs, "", "panorama", nil)
	if err == nil || !strings.HasPrefix(err.Error(), "no enabled") {
		return d, err
	}
	if d, err = pickDevice(devs, "", "panos", nil); err != nil && strings.HasPrefix(err.Error(), "no enabled") {
		return d, errors.New("no enabled panorama or panos device is configured")
	}
	return d, err
}

const (
	tsVPNLogs     = 20 // GlobalProtect events read
	tsTrafficLogs = 50
	tsThreatLogs  = 20
	tsMaxAddrs    = 4
	tsMaxHosts    = 3
)

func (m *Mgmt) deviceTroubleshoot(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		User, Host, Hours, Devices, Network, Entra, Meraki, Panorama string
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
	a.User, a.Host, a.Hours, a.Devices, a.Network, a.Entra, a.Meraki, a.Panorama = get("user"), get("host"), get("hours"), get("devices"), get("network"), get("entra"), get("meraki"), get("panorama")
	switch {
	case a.User == "" && a.Host == "":
		return nil, errors.New("user: a sign-in name, an object ID or a name (or host: a machine's name)")
	case a.User != "" && a.Host != "":
		return nil, errors.New("give a user or a host, not both")
	case a.Host != "" && !tsNameRE.MatchString(a.Host):
		return nil, errors.New("host: a machine's name; letters, digits and . _ - only")
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
	ask := func(d device.Device, to time.Duration, fn func(context.Context, device.Driver) (any, error)) (any, error) {
		r := device.Fanout(context.Background(), []device.Device{d}, creds, 1, to, fn)[0]
		if !r.OK {
			return nil, errors.New(r.Error)
		}
		return r.Data, nil
	}
	// the three systems: a directory, the firewall logs, the network.  Each is used when it is there; one that was named and
	// cannot be used is an error, one that is merely missing is a note.
	var notes []string
	note := func(f string, x ...any) { notes = append(notes, fmt.Sprintf(f, x...)) }
	ed, eerr := pickDevice(devs, a.Entra, "entra", nil)
	ld, lerr := pickLogDevice(devs, a.Panorama)
	md, merr := pickDevice(devs, a.Meraki, "meraki", func(d device.Device) bool { return d.Options["serial"] == "" })
	if a.Entra != "" && eerr != nil {
		return nil, eerr
	}
	if a.Panorama != "" && lerr != nil {
		return nil, lerr
	}
	if eerr != nil && lerr != nil {
		if a.User != "" {
			return nil, eerr // as before there were logs to ask: a user is looked up in Entra
		}
		return nil, fmt.Errorf("a host is looked up in the firewall's logs and in Entra: %v; %v", lerr, eerr)
	}
	what, who := "user", a.User
	if a.Host != "" {
		what, who = "host", a.Host
	}
	warnf("devices: audit: %q troubleshoots %s %q (%d h)", actor, what, who, hours)
	out := map[string]any{"window_hours": hours}
	logs := func(logType, query string, n int) ([]map[string]any, error) {
		v, err := ask(ld, 150*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
			l, ok := d.(device.LogSearcher)
			if !ok {
				return nil, errors.New("this device cannot search its logs")
			}
			return l.LogSearch(ctx, logType, query, n)
		})
		es, _ := v.([]map[string]any)
		return es, err
	}

	// ---- who and which machines ----
	type machine struct {
		name  string
		entra map[string]any
	}
	var machines []machine
	addMachine := func(name string, e map[string]any) {
		if tsHostKey(name) == "" {
			return
		}
		for i := range machines {
			if tsHostKey(machines[i].name) == tsHostKey(name) {
				if machines[i].entra == nil {
					machines[i].entra = e
				}
				return
			}
		}
		machines = append(machines, machine{name, e})
	}
	short := ""
	if a.User != "" {
		short = tsShortUser(a.User)
		if eerr != nil {
			note("no directory lookup: %v", eerr)
		} else {
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
			switch {
			case err != nil && lerr != nil:
				return nil, fmt.Errorf("%s: %w", ed.Name, err) // nothing else to ask
			case err != nil:
				note("%s: %v", ed.Name, err)
			default:
				fd := ev.(found)
				out["user"], out["entra_device"], out["device_count"] = fd.User, ed.Name, len(fd.Devices)
				if s := tsShortUser(fmt.Sprint(fd.User["userPrincipalName"])); s != "" {
					short = s
				}
				if len(fd.Devices) == 0 {
					note("the user has no registered or owned devices in Entra")
				}
				if len(fd.Devices) > devices {
					note("%d devices; the %d signed in most recently are followed", len(fd.Devices), devices)
					fd.Devices = fd.Devices[:devices]
				}
				for _, d := range fd.Devices {
					addMachine(fmt.Sprint(d["displayName"]), d)
				}
			}
		}
	} else {
		out["host"] = a.Host
		addMachine(a.Host, nil)
		if eerr != nil {
			note("no directory lookup: %v", eerr)
		} else {
			ev, err := ask(ed, deviceTimeout, func(ctx context.Context, d device.Driver) (any, error) {
				l, ok := d.(device.DeviceUserLooker)
				if !ok {
					return nil, errors.New("this device cannot look up a device's users")
				}
				return l.DeviceUsers(ctx, a.Host)
			})
			eds, _ := ev.([]map[string]any)
			switch {
			case err != nil:
				note("%s: %v", ed.Name, err)
			case len(eds) == 0:
				out["entra_device"] = ed.Name
				note("Entra has no device named %s", a.Host)
			default:
				out["entra_device"] = ed.Name
				machines[0].entra = eds[0]
				if len(eds) > 1 {
					note("Entra has %d devices named %s; the one signed in most recently is shown", len(eds), a.Host)
				}
			}
		}
	}

	// ---- the VPN (GlobalProtect) log: which machine a user connected with, or which user a machine connected as ----
	var addrs []string
	addAddr := func(v any) {
		ip, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(v)))
		if err != nil || ip.IsUnspecified() || len(addrs) >= tsMaxAddrs {
			return
		}
		for _, x := range addrs {
			if x == ip.String() {
				return
			}
		}
		addrs = append(addrs, ip.String())
	}
	if lerr != nil {
		note("no firewall logs: %v", lerr)
	} else {
		out["panorama_device"] = ld.Name
		q := ""
		switch {
		case a.Host != "":
			q = "(machinename contains '" + a.Host + "')"
		case short != "":
			q = "(srcuser contains '" + short + "')"
		default:
			note("no VPN log search: %q is not an account name the log filter takes", a.User)
		}
		if q != "" {
			es, err := logs("globalprotect", q, tsVPNLogs)
			vpn := map[string]any{"query": q, "events": es}
			if err != nil {
				vpn = map[string]any{"query": q, "error": err.Error()}
			} else if len(es) == 0 {
				vpn["events"] = []any{}
				note("the VPN (GlobalProtect) log has nothing for %s", who)
			} else {
				// the newest event says who and where; the events before it are the history
				last := map[string]any{}
				for _, k := range []string{"receive_time", "srcuser", "machinename", "eventid", "status", "public_ip", "private_ip", "gateway", "portal", "opsys", "client_ver", "reason", "error"} {
					if v, ok := es[0][k]; ok && fmt.Sprint(v) != "" {
						last[k] = v
					}
				}
				vpn["last"] = last
				for _, e := range es {
					if a.User != "" {
						addMachine(fmt.Sprint(e["machinename"]), nil)
					}
					addAddr(e["private_ip"])
				}
				if a.Host != "" {
					if u := fmt.Sprint(es[0]["srcuser"]); u != "" && u != "<nil>" {
						out["last_user"] = map[string]any{"name": u, "seen": es[0]["receive_time"], "from": "the VPN (GlobalProtect) log"}
					}
				}
			}
			out["vpn"] = vpn
		}
	}
	if a.Host != "" && out["last_user"] == nil && len(machines) > 0 && machines[0].entra != nil {
		for _, k := range []string{"registered_users", "owners"} {
			if us, _ := machines[0].entra[k].([]map[string]any); len(us) > 0 {
				out["last_user"] = map[string]any{"name": us[0]["userPrincipalName"], "display_name": us[0]["displayName"], "from": "Entra (" + strings.ReplaceAll(k, "_", " ") + " of the device)"}
				break
			}
		}
	}
	if len(machines) > tsMaxHosts {
		note("%d machines; the first %d are followed", len(machines), tsMaxHosts)
		machines = machines[:tsMaxHosts]
	}

	// ---- where each machine is on the network ----
	devOut := make([]map[string]any, 0, len(machines))
	for _, mc := range machines {
		e := map[string]any{"name": mc.name}
		if mc.entra != nil {
			e["entra"] = mc.entra
		}
		devOut = append(devOut, e)
	}
	if merr != nil {
		note("no network lookup: %v", merr)
	} else if len(machines) > 0 {
		out["meraki_device"] = md.Name
		res, err := ask(md, 150*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
			r, ok := d.(device.ClientReporter)
			if !ok {
				return nil, errors.New("this device cannot report on clients")
			}
			var all []any
			for _, mc := range machines {
				rep, err := r.ClientReport(ctx, device.ClientQuery{Names: []string{mc.name}, Hours: hours, Network: a.Network})
				if err != nil {
					all = append(all, map[string]any{"error": err.Error()})
					continue
				}
				all = append(all, rep)
			}
			return all, nil
		})
		reps, _ := res.([]any)
		for i := range devOut {
			switch {
			case err != nil:
				devOut[i]["network"] = map[string]any{"error": err.Error()}
			case i < len(reps):
				devOut[i]["network"] = reps[i]
				if rep, ok := reps[i].(map[string]any); ok {
					ms, _ := rep["matches"].([]map[string]any)
					for _, mt := range ms {
						if c, ok := mt["client"].(map[string]any); ok {
							addAddr(c["ip"])
						}
					}
				}
			}
		}
	}
	out["devices"] = devOut

	// ---- what the firewall logged for the addresses found ----
	if lerr == nil {
		if len(addrs) == 0 {
			note("no firewall traffic or threat logs: no address of the machine is known (not on the VPN, not seen on the network)")
		} else {
			var terms []string
			for _, x := range addrs {
				terms = append(terms, "(addr in "+x+")")
			}
			q := strings.Join(terms, " or ")
			fw := map[string]any{"addresses": addrs, "query": q}
			for _, l := range []struct {
				typ string
				n   int
			}{{"traffic", tsTrafficLogs}, {"threat", tsThreatLogs}} {
				es, err := logs(l.typ, q, l.n)
				switch {
				case err != nil:
					fw[l.typ] = map[string]any{"error": err.Error()}
				case es == nil:
					fw[l.typ] = []any{}
				default:
					fw[l.typ] = es
				}
			}
			out["firewall"] = fw
		}
	}
	if len(notes) > 0 {
		out["notes"] = notes
	}
	return out, nil
}

func urlQ(s string) string { return url.QueryEscape(s) }

func mcpDeviceTroubleshootTool() mcpTool {
	return mcpTool{name: "device_troubleshoot_user", title: "Troubleshoot a user or a host (tshoot user NAME, tshoot host NAME)", noNode: true,
		desc: "Troubleshoot a user (\"tshoot user msmith\") or a machine (\"tshoot host PC-123\"): give user or host, not both. " +
			"For a user: look the user up in Microsoft Entra by sign-in name, account name, object ID or name and take the device they signed in with most recently; search the firewall's VPN (GlobalProtect) log for the account, which names the machine they connected with and its addresses. " +
			"For a host: the VPN log says which user last connected with that machine and from where, and Entra which users are registered on a device of that name (last_user). " +
			"Then, for each machine found: find it on the Meraki network by its name and return what helps when someone cannot get online or is slow, for the last few hours (not only now): the Meraki client (IP, MAC, VLAN, SSID, the AP or switch and port it was on, first and last seen, usage), its usage history and device policy; " +
			"for a wireless client its connection statistics, latency, connectivity events and failed connections; for a wired one its switch port's status (speed, duplex, errors, warnings, traffic); and whether the AP or switch it was on is online. " +
			"Last, the firewall's newest traffic and threat log entries for the addresses found (the VPN address, the address on the network). " +
			"The answer has: user or host and last_user, devices (each with entra and network), vpn (the query, the newest event as last, the events), firewall (addresses, traffic, threat) and notes, which say what could not be looked up and why. " +
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
		},
		run: func(c *mcpCtx) (any, error) {
			q := "/api/devices/troubleshoot?"
			sep := ""
			for _, k := range []string{"user", "host", "hours", "devices", "network", "entra", "meraki", "panorama"} {
				if v := c.str(k); v != "" {
					q += sep + k + "=" + urlQ(v)
					sep = "&"
				}
			}
			b, err := c.call("GET", q, nil, "")
			return asAny(b), err
		}}
}

// ---- the CLI ----

func runTroubleshootUser(sock, user, host, hours string) {
	args := map[string]any{}
	if user != "" {
		args["user"] = user
	}
	if host != "" {
		args["host"] = host
	}
	if hours != "" {
		args["hours"] = hours
	}
	var v any
	decode(op(sock, "device.troubleshoot", args), &v)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// shortCommand turns "netdir tshoot user NAME [HOURS]", "netdir tshoot host NAME [HOURS]" and the older "netdir tshoot NAME [HOURS]"
// (a user) into the flags they stand for; "troubleshoot" is the same word written out.  --tshoot alone, the node's troubleshooting
// bundle, is unchanged.  Anything else is returned as it was.
func shortCommand(args []string) []string {
	if len(args) < 2 || args[0] != "tshoot" && args[0] != "troubleshoot" || strings.HasPrefix(args[1], "-") {
		return args
	}
	flag, rest := "--troubleshoot-user", args[1:]
	if (rest[0] == "user" || rest[0] == "host") && len(rest) >= 2 && !strings.HasPrefix(rest[1], "-") {
		if rest[0] == "host" {
			flag = "--troubleshoot-host"
		}
		rest = rest[1:]
	}
	out := []string{flag, rest[0]}
	rest = rest[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		out = append(out, "--troubleshoot-hours", rest[0])
		rest = rest[1:]
	}
	return append(out, rest...)
}
