package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

func (m *Mgmt) deviceTroubleshoot(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		User, Host, Hours, Devices, Network, Entra, Meraki, Panorama, AD, SMAX string
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
	a.User, a.Host, a.Hours, a.Devices, a.Network, a.Entra, a.Meraki, a.Panorama, a.AD, a.SMAX = get("user"), get("host"), get("hours"), get("devices"), get("network"), get("entra"), get("meraki"), get("panorama"), get("ad"), get("smax")
	switch {
	case a.User == "" && a.Host == "":
		return nil, errors.New("user: a sign-in name, an object ID or a name (or host: a machine's name)")
	case a.User != "" && a.Host != "":
		return nil, errors.New("give a user or a host, not both")
	case a.Host != "" && !devices.TsNameRE.MatchString(a.Host):
		return nil, errors.New("host: a machine's name; letters, digits and . _ - only")
	}
	hours, follow := 6, 1
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
		follow = n
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	devs, creds := dc.EffectiveDevices(), dc.Settings.DeviceCredentials
	ask := func(d device.Device, to time.Duration, fn func(context.Context, device.Driver) (any, error)) (any, error) {
		r := device.FanoutReuse(context.Background(), []device.Device{d}, creds, 1, to, fn)[0]
		if !r.OK {
			return nil, errors.New(r.Error)
		}
		return r.Data, nil
	}
	// the three systems: a directory, the firewall logs, the network.  Each is used when it is there; one that was named and
	// cannot be used is an error, one that is merely missing is a note.
	var notes []string
	note := func(f string, x ...any) { notes = append(notes, fmt.Sprintf(f, x...)) }
	ed, eerr := devices.PickDevice(devs, a.Entra, "entra", nil)
	ld, lerr := devices.PickLogDevice(devs, a.Panorama)
	adv, aerr := devices.PickDevice(devs, a.AD, "ad", nil)
	if a.AD != "" && aerr != nil {
		return nil, aerr
	}
	sd, serr := devices.PickDevice(devs, a.SMAX, "smax", nil)
	if a.SMAX != "" && serr != nil {
		return nil, serr
	}
	md, merr := devices.PickDevice(devs, a.Meraki, "meraki", func(d device.Device) bool { return d.Options["serial"] == "" })
	if a.Entra != "" && eerr != nil {
		return nil, eerr
	}
	if a.Panorama != "" && lerr != nil {
		return nil, lerr
	}
	if eerr != nil && lerr != nil && aerr != nil {
		if a.User != "" {
			return nil, eerr // as before there were logs to ask: a user is looked up in Entra
		}
		return nil, fmt.Errorf("a host is looked up in the firewall's logs and in Entra: %v; %v", lerr, eerr)
	}
	what, who := "user", a.User
	if a.Host != "" {
		what, who = "host", a.Host
	}
	core.Warnf("devices: audit: %q troubleshoots %s %q (%d h)", actor, what, who, hours)
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
		if devices.TsHostKey(name) == "" {
			return
		}
		for i := range machines {
			if devices.TsHostKey(machines[i].name) == devices.TsHostKey(name) {
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
		short = devices.TsShortUser(a.User)
		if eerr != nil {
			note("no directory lookup: %v", eerr)
		} else {
			type found struct {
				User    map[string]any
				Devices []map[string]any
			}
			ev, err := ask(ed, devices.DeviceTimeout, func(ctx context.Context, d device.Driver) (any, error) {
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
				if s := devices.TsShortUser(fmt.Sprint(fd.User["userPrincipalName"])); s != "" {
					short = s
				}
				if len(fd.Devices) == 0 {
					note("the user has no registered or owned devices in Entra")
				}
				if len(fd.Devices) > follow {
					note("%d devices; the %d signed in most recently are followed", len(fd.Devices), follow)
					fd.Devices = fd.Devices[:follow]
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
			ev, err := ask(ed, devices.DeviceTimeout, func(ctx context.Context, d device.Driver) (any, error) {
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

	// ---- the account's state in Active Directory (when there is such a device; no machine is found this way) ----
	if aerr == nil {
		names := []string{a.User}
		if a.Host != "" {
			names = []string{a.Host}
		} else if short != "" && short != a.User {
			names = append(names, short)
		}
		var recs []map[string]any
		var err error
		for _, n := range names {
			var v any
			v, err = ask(adv, devices.DeviceTimeout, func(ctx context.Context, d device.Driver) (any, error) {
				l, ok := d.(device.DirectoryLooker)
				if !ok {
					return nil, errors.New("this device cannot look up accounts")
				}
				if a.Host != "" {
					return l.DirComputers(ctx, n)
				}
				return l.DirUsers(ctx, n)
			})
			if recs, _ = v.([]map[string]any); err != nil || len(recs) > 0 {
				break
			}
		}
		out["directory_device"] = adv.Name
		switch {
		case err != nil:
			note("%s: %v", adv.Name, err)
		case len(recs) == 0:
			note("Active Directory has no account for %s", strings.Join(names, " or "))
		default:
			out["directory"] = recs
			if len(recs) > 1 {
				note("Active Directory has %d accounts that match; the best match is first", len(recs))
			}
		}
	}

	// ---- the user's newest tickets (when there is a SMAX device; none is said when there is none) ----
	if a.User != "" {
		switch {
		case serr == nil:
			who := []string{}
			add := func(v any) {
				x := strings.TrimSpace(fmt.Sprint(v))
				if x == "" || x == "<nil>" {
					return
				}
				for _, y := range who {
					if strings.EqualFold(x, y) {
						return
					}
				}
				who = append(who, x)
			}
			// SMAX is searched by full name: the typed account name is resolved to one first, by Entra (displayName) or, when
			// Entra does not have the user, by Active Directory; the sign-in name and the address are the fallbacks
			u, _ := out["user"].(map[string]any)
			full := strings.TrimSpace(fmt.Sprint(u["displayName"]))
			if full == "" || full == "<nil>" {
				if ds, _ := out["directory"].([]map[string]any); len(ds) > 0 {
					full = strings.TrimSpace(fmt.Sprint(ds[0]["Name"]))
				}
			}
			add(full)
			add(u["userPrincipalName"])
			add(u["mail"])
			add(a.User)
			add(short)
			if full == "" || full == "<nil>" {
				note("SMAX is searched by full name and none was found for %s (no Entra or Active Directory record with a name): the tickets are looked up by the name as typed", a.User)
			}
			type got struct {
				Who     string
				Tickets []map[string]any
			}
			var partial error
			tv, err := ask(sd, 150*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
				l, ok := d.(device.TicketLooker)
				if !ok {
					return nil, errors.New("this device cannot look up tickets")
				}
				w, ts, err := l.UserTickets(ctx, who, devices.TsTickets)
				if err != nil && len(ts) > 0 {
					partial, err = err, nil
				}
				return got{w, ts}, err
			})
			switch {
			case err != nil && strings.Contains(err.Error(), device.ErrNoRequester.Error()): // the error has crossed a fan-out as text
				out["tickets"] = map[string]any{"smax_device": sd.Name, "tickets": []any{}}
				note("%s: %v", sd.Name, err)
			case err != nil:
				out["tickets"] = map[string]any{"smax_device": sd.Name, "error": err.Error()}
			default:
				g := tv.(got)
				ts := g.Tickets
				if ts == nil {
					ts = []map[string]any{}
				}
				out["tickets"] = map[string]any{"smax_device": sd.Name, "requester": g.Who, "tickets": ts}
				if len(ts) == 0 {
					note("SMAX has no request or incident asked for by %s", g.Who)
				}
				if partial != nil {
					note("%s: %v", sd.Name, partial)
				}
			}
		case strings.HasPrefix(serr.Error(), "several"):
			note("no tickets: %v", serr)
		}
	}

	// ---- the VPN (GlobalProtect) log: which machine a user connected with, or which user a machine connected as ----
	var addrs []string
	addAddr := func(v any) {
		ip, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(v)))
		if err != nil || ip.IsUnspecified() || len(addrs) >= devices.TsMaxAddrs {
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
			es, err := logs("globalprotect", q, devices.TsVPNLogs)
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
	if len(machines) > devices.TsMaxHosts {
		note("%d machines; the first %d are followed", len(machines), devices.TsMaxHosts)
		machines = machines[:devices.TsMaxHosts]
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
	var byUser []string // the account names a client may have signed in to the network with
	if a.User != "" && short != "" {
		byUser = []string{short}
	}
	if merr != nil {
		note("no network lookup: %v", merr)
	} else if len(machines) > 0 || len(byUser) > 0 {
		out["meraki_device"] = md.Name
		res, err := ask(md, 150*time.Second, func(ctx context.Context, d device.Driver) (any, error) {
			r, ok := d.(device.ClientReporter)
			if !ok {
				return nil, errors.New("this device cannot report on clients")
			}
			var all []any
			var seen []string
			for _, mc := range machines {
				seen = append(seen, mc.name)
				rep, err := r.ClientReport(ctx, device.ClientQuery{Names: []string{mc.name}, Hours: hours, Network: a.Network})
				if err != nil {
					all = append(all, map[string]any{"error": err.Error()})
					continue
				}
				all = append(all, rep)
			}
			// a user's other clients: whatever signed in to the network with the account (802.1X), such as a phone on the
			// Wi-Fi, which no directory lists by a name the network knows
			if len(byUser) > 0 {
				if rep, err := r.ClientReport(ctx, device.ClientQuery{Users: byUser, NotNames: seen, Hours: hours, Network: a.Network}); err == nil {
					if ms, _ := rep["matches"].([]map[string]any); len(ms) > 0 {
						all = append(all, rep)
					}
				}
			}
			return all, nil
		})
		reps, _ := res.([]any)
		if len(reps) > len(devOut) { // the clients found by the account
			devOut = append(devOut, map[string]any{"name": "signed in to the network as " + short, "found_by": "the account the client signed in to the network with (802.1X)"})
		}
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
			}{{"traffic", devices.TsTrafficLogs}, {"threat", devices.TsThreatLogs}} {
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
