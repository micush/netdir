package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Meraki changes.  Meraki has no commit and no candidate configuration: a change is live at once, in the cloud, and reaches the
// device when it next checks in.  So the safety here is: a typed change reads first and puts the old state back if the read-back
// differs; a raw change keeps the copy of what the path holds and PUTs it back when the request fails in a way that may have
// changed something (5xx, lost connection); and what could cut a device off from the cloud (its uplink port, its management
// interface, firmware, reboot, removing it from a network) is refused.  Nothing here was run against a real dashboard.

var merakiPortIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_/.-]{0,15}$`)

type merakiStore struct{ m *meraki }

func (s merakiStore) read(ctx context.Context) (map[string]portState, error) {
	v, err := s.m.get(ctx, "/devices/"+s.m.serial+"/switch/ports")
	if err != nil {
		return nil, err
	}
	out := map[string]portState{}
	for _, c := range rows(v) {
		en, ok := c["enabled"].(bool)
		out[str(c["portId"])] = portState{Description: strings.TrimSpace(str(c["name"])), Down: ok && !en}
	}
	return out, nil
}

func (s merakiStore) write(ctx context.Context, plan []portPlan) error {
	for _, p := range plan {
		if !merakiPortIDRE.MatchString(p.Port) {
			return fmt.Errorf("%q is not a port number", p.Port)
		}
		body := map[string]any{}
		if p.Description != nil {
			body["name"] = *p.Description
		}
		if p.Down != nil {
			body["enabled"] = !*p.Down
		}
		if _, err := s.m.do(ctx, http.MethodPut, "/devices/"+s.m.serial+"/switch/ports/"+url.PathEscape(p.Port), body); err != nil {
			return fmt.Errorf("port %s: %w", p.Port, err)
		}
	}
	return nil
}

// keepUplink refuses to shut down a switch's uplink: Meraki is managed from the cloud, so the switch could not be reached again.
func (m *meraki) keepUplink(ctx context.Context, c Change) error {
	if c.Action != ActShutdown {
		return nil
	}
	v, err := m.get(ctx, "/devices/"+m.serial+"/switch/ports/statuses")
	if err != nil {
		return fmt.Errorf("could not check which port is the switch's uplink, so nothing was shut down: %w", err)
	}
	asked := map[string]bool{}
	for _, p := range c.Ports {
		asked[p] = true
	}
	for _, s := range rows(v) {
		if up, _ := s["isUplink"].(bool); up && asked[str(s["portId"])] {
			return fmt.Errorf("port %s is this switch's uplink to the Meraki cloud: shutting it down would cut the switch off from its dashboard, so it is not done", str(s["portId"]))
		}
	}
	return nil
}

func (m *meraki) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if m.serial == "" {
		return ChangeResult{}, errors.New("typed port changes need a device with the option serial (one Meraki switch); any other change: device_change_raw")
	}
	if err := m.keepUplink(ctx, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, merakiStore{m}, c, dry)
}

// ---- raw changes ----

// What a raw change does not touch: administrators and sign-in (admins, saml, loginSecurity), SNMP (community strings), licenses,
// and what can cut devices off or remove them (managementInterface, firmware upgrades, reboot, claim, remove, release, clone,
// combine, split).  A DELETE of an organization, a network or a device itself is refused too.
var merakiRawDeny = map[string]bool{"admins": true, "saml": true, "samlroles": true, "loginsecurity": true, "snmp": true, "licenses": true, "licensing": true,
	"managementinterface": true, "firmware": true, "reboot": true, "claim": true, "remove": true, "release": true, "clone": true, "combine": true, "split": true,
	"wipe": true, "apikeys": true}

func merakiRawGuard(method, p string) error {
	if method == http.MethodPatch {
		return errors.New("method: Meraki takes POST, PUT and DELETE")
	}
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change")
	}
	if strings.Contains(pp, "..") || strings.ContainsAny(pp, "\r\n\x00 ") || !strings.HasPrefix(pp, "/") {
		return errors.New("path: not a path of the Meraki API")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if segs[0] != "organizations" && segs[0] != "networks" && segs[0] != "devices" {
		return errors.New("path: Meraki is changed at /organizations/…, /networks/… or /devices/…")
	}
	for _, s := range segs {
		if ls := strings.ToLower(s); merakiRawDeny[ls] || strings.HasPrefix(ls, "firmware") {
			return fmt.Errorf("path: %q is not changed here (administrators, SAML, SNMP, licenses, firmware, reboots and removing devices)", s)
		}
	}
	if method == http.MethodDelete && len(segs) <= 2 {
		return errors.New("path: an organization, a network or a device is not deleted here")
	}
	return nil
}

func (m *meraki) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if len(r.Lines) > 0 {
		return RawResult{DryRun: dry}, errors.New("lines: Meraki is changed with method, path and body")
	}
	r.Path = strings.TrimPrefix(r.Path, merakiBase)
	return restRaw(ctx, restSpec{
		api: m.api, hdr: jsonHdr(), json: true,
		wire:  func(p string) string { return merakiBase + p },
		guard: merakiRawGuard,
		restore: func(b []byte) (any, bool) {
			var o map[string]any
			if json.Unmarshal(b, &o) != nil || len(o) == 0 { // a list is not put back
				return nil, false
			}
			return o, true
		},
		alive: func(ctx context.Context) error { _, err := m.get(ctx, "/organizations"); return err },
	}, r, dry)
}
