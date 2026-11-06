package device

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ClientReport: where a device of a given name was seen on the Meraki networks in the last hours, and how it did.  For each network the
// clients seen in the window are read (perPage 1000, filtered here by host name or MAC) and, for at most three matches, the things
// one looks at when someone cannot get online, each as its own part that may be missing (a wired client has no wireless statistics, a
// switch of an old model answers less):
//
//	client          the record: IP, MAC, VLAN, SSID, the AP or switch and port it was on, first and last seen, usage, status
//	usage           the client's usage history (sent and received over time)
//	policy          the client's device policy (normal, blocked, group policy)
//	connection      wireless: connection statistics (association, authentication, DHCP, DNS, success), latency, and the connectivity
//	                events and failed connections of the window
//	switch_port     wired: the status of the switch port it was on (speed, duplex, errors, warnings, traffic, PoE)
//	upstream        the AP or switch it was on: online or not, when it last reported
//
// The paths come from Meraki's dashboard API reference; none was tried against a real dashboard.

const (
	merakiClientNetworks = 60 // networks searched; more are named in the answer
	merakiClientMatches  = 3
	merakiClientPerPage  = 1000
)

// merakiHostKey is a name as clients and directories write it: lower case, without the domain.
func merakiHostKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

func normMAC(s string) string {
	return strings.ToLower(strings.NewReplacer("-", ":", ".", "").Replace(strings.TrimSpace(s)))
}

func (m *meraki) ClientReport(ctx context.Context, q ClientQuery) (map[string]any, error) {
	if m.serial != "" {
		return nil, errors.New("client reports come from the organization device, not from one Meraki device (remove its serial option or use another Meraki device)")
	}
	if q.Hours < 1 || q.Hours > 168 {
		q.Hours = 6
	}
	span := q.Hours * 3600
	names := map[string]bool{}
	for _, n := range q.Names {
		if k := merakiHostKey(n); k != "" {
			names[k] = true
		}
	}
	macs := map[string]bool{}
	for _, a := range q.MACs {
		if a = normMAC(a); a != "" {
			macs[a] = true
		}
	}
	if len(names)+len(macs) == 0 {
		return nil, errors.New("nothing to look for: give a device name or a MAC address")
	}
	org, err := m.orgID(ctx)
	if err != nil {
		return nil, err
	}
	var nets []map[string]any
	if q.Network != "" {
		if !merakiNetRE.MatchString(q.Network) {
			return nil, errors.New("network: an ID such as L_123456 or N_123456 (show networks lists them)")
		}
		nets = []map[string]any{{"id": q.Network}}
	} else {
		v, err := m.get(ctx, "/organizations/"+org+"/networks?perPage=1000")
		if err != nil {
			return nil, fmt.Errorf("networks: %w", err)
		}
		nets = rows(v)
	}
	out := map[string]any{"window_hours": q.Hours, "searched_for": append(boolKeys(names), boolKeys(macs)...)}
	var notes []string
	if len(nets) > merakiClientNetworks {
		notes = append(notes, fmt.Sprintf("%d networks: only the first %d were searched; name a network to search the others", len(nets), merakiClientNetworks))
		nets = nets[:merakiClientNetworks]
	}
	type hit struct {
		net, name string
		c         map[string]any
	}
	var hits []hit
	searched := 0
	for _, n := range nets {
		id := str(n["id"])
		v, err := m.get(ctx, fmt.Sprintf("/networks/%s/clients?perPage=%d&timespan=%d", id, merakiClientPerPage, span))
		if err != nil {
			var se *statusError
			if errors.As(err, &se) && (se.Code == 400 || se.Code == 404) { // a network without clients (a systems manager network) answers 400
				continue
			}
			return nil, fmt.Errorf("clients of %s: %w", id, err)
		}
		searched++
		l := rows(v)
		if len(l) >= merakiClientPerPage {
			notes = append(notes, fmt.Sprintf("network %s has %d or more clients in the window: the list may be cut; shorten the window", id, merakiClientPerPage))
		}
		for _, c := range l {
			if names[merakiHostKey(str(c["description"]))] || names[merakiHostKey(str(c["dhcpHostname"]))] || macs[normMAC(str(c["mac"]))] {
				hits = append(hits, hit{id, str(n["name"]), c})
			}
		}
	}
	out["networks_searched"] = searched
	if len(hits) == 0 {
		notes = append(notes, fmt.Sprintf("no Meraki client by that name or MAC was seen in the last %d hours (names may differ: a phone often shows a different host name; give the MAC)", q.Hours))
	}
	if len(hits) > merakiClientMatches {
		notes = append(notes, fmt.Sprintf("%d matches; the %d seen last are reported", len(hits), merakiClientMatches))
		sort.SliceStable(hits, func(i, j int) bool { return hitSeen(hits[i].c) > hitSeen(hits[j].c) })
		hits = hits[:merakiClientMatches]
	}
	var matches []map[string]any
	for _, h := range hits {
		matches = append(matches, m.clientParts(ctx, org, h.net, h.name, h.c, span))
	}
	out["matches"] = matches
	if len(notes) > 0 {
		out["notes"] = notes
	}
	return out, nil
}

func hitSeen(c map[string]any) float64 {
	if f := flt(c["lastSeen"]); f > 0 {
		return f
	}
	return 0
}

func boolKeys(m map[string]bool) []string {
	var l []string
	for k := range m {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

// part reads one thing about a client; what cannot be read is said, not fatal.
func (m *meraki) part(ctx context.Context, path string) any {
	v, err := m.get(ctx, path)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && (se.Code == 400 || se.Code == 404) {
			return map[string]any{"unavailable": "the dashboard has none for this client or network"}
		}
		if ctx.Err() != nil {
			return map[string]any{"unavailable": ctx.Err().Error()}
		}
		return map[string]any{"unavailable": err.Error()}
	}
	return Redact(v)
}

func (m *meraki) clientParts(ctx context.Context, org, net, netName string, c map[string]any, span int) map[string]any {
	id := str(c["id"])
	res := map[string]any{"network": map[string]any{"id": net, "name": netName}, "client": redactMap(c)}
	if id == "" || !merakiClientIDRE.MatchString(id) {
		res["notes"] = []string{"the client has no usable ID: only its record is given"}
		return res
	}
	base := "/networks/" + net + "/clients/" + id
	res["usage"] = m.part(ctx, base+"/usageHistory")
	res["policy"] = m.part(ctx, base+"/policy?timespan="+fmt.Sprint(span))
	wireless := strings.EqualFold(str(c["recentDeviceConnection"]), "wireless") || str(c["ssid"]) != ""
	if wireless {
		w := "/networks/" + net + "/wireless/clients/" + id
		res["connection"] = map[string]any{
			"stats":               m.part(ctx, w+"/connectionStats?timespan="+fmt.Sprint(span)),
			"latency":             m.part(ctx, w+"/latencyStats?timespan="+fmt.Sprint(span)),
			"connectivity_events": m.part(ctx, w+"/connectivityEvents?perPage=100&timespan="+fmt.Sprint(span)),
			"failed_connections":  m.part(ctx, "/networks/"+net+"/wireless/failedConnections?timespan="+fmt.Sprint(span)+"&clientId="+url.QueryEscape(id)),
		}
	}
	serial := strings.ToUpper(str(c["recentDeviceSerial"]))
	if sp := str(c["switchport"]); sp != "" && merakiSerialRE.MatchString(serial) {
		v := m.part(ctx, "/devices/"+serial+"/switch/ports/statuses")
		if l, ok := v.([]any); ok {
			var port any = map[string]any{"unavailable": "port " + sp + " is not in the switch's port list"}
			for _, x := range l {
				if p, ok := x.(map[string]any); ok && str(p["portId"]) == sp {
					port = p
				}
			}
			v = port
		}
		res["switch_port"] = v
	}
	if merakiSerialRE.MatchString(serial) {
		v := m.part(ctx, "/organizations/"+org+"/devices/statuses?perPage=1&serials%5B%5D="+url.QueryEscape(serial))
		if l, ok := v.([]any); ok && len(l) > 0 {
			v = l[0]
		}
		res["upstream"] = v
	}
	return res
}
