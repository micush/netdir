package device

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Typed port changes (description, shutdown, no shutdown) for the platforms whose own write path is RawChange: Junos, NX-OS, FortiOS
// and F5 BIG-IP.  The store reads what a port holds from the driver's own Interfaces (name, description, admin state), builds the
// platform's request from the validated fields, and sends it through RawChange, so every guard, checkpoint, confirmed commit and
// rollback that platform's raw change has applies to it too.  runChange then reads back through Interfaces and writes the old values
// when something differs.
//
//	Junos     set-format lines, one request:  set interfaces ge-0/0/1 disable | delete interfaces ge-0/0/1 disable | set|delete ... description
//	NX-OS     configuration lines:            interface Ethernet1/1, shutdown | no shutdown | description X | no description
//	FortiOS   PUT /api/v2/cmdb/system/interface/NAME  {"status": "down"|"up"} or {"description": "X"}
//	BIG-IP    PATCH /mgmt/tm/net/interface/NAME      {"disabled": true} | {"enabled": true} or {"description": "X"}
//
// The port names in a path or a line come from the device's own list (resolve) and are checked again here.
type ifaceStore struct {
	drv   Driver
	rc    RawChanger
	ifs   func(ctx context.Context) ([]Interface, error) // nil: drv.Interfaces
	lines func(plan []portPlan) ([]string, error)        // line platforms: all the lines of the plan, sent as one request
	req   func(p portPlan) (Raw, error)                  // REST platforms: one request for a port
}

func (s ifaceStore) read(ctx context.Context) (map[string]portState, error) {
	f := s.ifs
	if f == nil {
		f = s.drv.Interfaces
	}
	ifs, err := f(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]portState, len(ifs))
	for _, i := range ifs {
		if i.AdminUp == nil && i.Description == "" && len(i.Addresses) > 0 {
			continue // an address, not a port
		}
		out[i.Name] = portState{Description: strings.TrimSpace(i.Description), Down: i.AdminUp != nil && !*i.AdminUp}
	}
	return out, nil
}

func (s ifaceStore) send(ctx context.Context, r Raw) error {
	res, err := s.rc.RawChange(ctx, r, false)
	if err != nil {
		return err
	}
	if !res.Applied {
		return errors.New("the device did not apply the change")
	}
	return nil
}

func (s ifaceStore) write(ctx context.Context, plan []portPlan) error {
	if s.lines != nil {
		ls, err := s.lines(plan)
		if err != nil {
			return err
		}
		return s.send(ctx, Raw{Lines: ls})
	}
	for _, p := range plan {
		r, err := s.req(p)
		if err != nil {
			return err
		}
		if err := s.send(ctx, r); err != nil {
			return fmt.Errorf("port %s: %w", p.Port, err)
		}
	}
	return nil
}

var ifaceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$`)

// ifaceNameOK is the shape of an interface name that may be written into a line or a path.
func ifaceNameOK(n string) error {
	if n == "" || len(n) > 64 || !ifaceNameRE.MatchString(n) {
		return fmt.Errorf("%q is not a port name", n)
	}
	return nil
}

// ── Junos ──

func junosQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func junosLines(plan []portPlan) ([]string, error) {
	var out []string
	for _, p := range plan {
		if err := ifaceNameOK(p.Port); err != nil {
			return nil, err
		}
		base := "interfaces " + p.Port
		if p.Description != nil {
			if *p.Description == "" {
				out = append(out, "delete "+base+" description")
			} else {
				out = append(out, "set "+base+" description "+junosQuote(*p.Description))
			}
		}
		if p.Down != nil {
			if *p.Down {
				out = append(out, "set "+base+" disable")
			} else {
				out = append(out, "delete "+base+" disable")
			}
		}
	}
	return out, nil
}

// Change implements Changer: counters (clear_counters, all ports) and description, shutdown and no shutdown through a commit with a
// confirmation timer, which Junos undoes by itself when the device stops answering.
func (j *junos) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if c.Action == ActClearCounters {
		return runClear(ctx, junosClear{j}, c, dry)
	}
	if err := keepManagement(ctx, j, j.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, ifaceStore{drv: j, rc: j, lines: junosLines}, c, dry)
}

// ── NX-OS ──

func nxosLines(plan []portPlan) ([]string, error) {
	var out []string
	for _, p := range plan {
		if err := ifaceNameOK(p.Port); err != nil {
			return nil, err
		}
		out = append(out, "interface "+p.Port)
		if p.Description != nil {
			if *p.Description == "" {
				out = append(out, "no description")
			} else {
				out = append(out, "description "+*p.Description)
			}
		}
		if p.Down != nil {
			if *p.Down {
				out = append(out, "shutdown")
			} else {
				out = append(out, "no shutdown")
			}
		}
	}
	return out, nil
}

// Change implements Changer: a configuration request of its own, after a checkpoint that the switch is rolled back to if a line is refused.
func (x *nxos) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if c.Action == ActClearCounters {
		return ChangeResult{}, errors.New("this platform's API has no way to clear interface counters (NX-API runs show commands here, and a clear is not one)")
	}
	if err := keepManagement(ctx, x, x.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, ifaceStore{drv: x, rc: x, lines: nxosLines}, c, dry)
}

// SaveConfig implements ConfigSaver: copy running-config startup-config.
func (x *nxos) SaveConfig(ctx context.Context) error {
	return x.nxSend(ctx, "cli_show_ascii", []string{"copy running-config startup-config"})
}

// ── FortiOS ──

func (f *fortios) ifaceReq(p portPlan) (Raw, error) {
	if err := ifaceNameOK(p.Port); err != nil {
		return Raw{}, err
	}
	body := map[string]any{}
	if p.Description != nil {
		body["description"] = *p.Description
	}
	if p.Down != nil {
		body["status"] = map[bool]string{true: "down", false: "up"}[*p.Down]
	}
	return Raw{Method: "PUT", Path: "/api/v2/cmdb/system/interface/" + url.PathEscape(p.Port), Body: string(mustJSON(body))}, nil
}

// Change implements Changer.  FortiOS keeps what it is told, so there is no save.
func (f *fortios) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if c.Action == ActClearCounters {
		return ChangeResult{}, errors.New("this platform's API has no way to clear interface counters (its monitor API clears the counters of policies, virtual IPs and ACLs)")
	}
	if err := keepManagement(ctx, f, f.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, ifaceStore{drv: f, rc: f, req: f.ifaceReq}, c, dry)
}

// ── F5 BIG-IP ──

func (b *bigip) ifaceReq(p portPlan) (Raw, error) {
	if err := ifaceNameOK(p.Port); err != nil {
		return Raw{}, err
	}
	body := map[string]any{}
	if p.Description != nil {
		body["description"] = *p.Description
	}
	if p.Down != nil {
		if *p.Down {
			body["disabled"] = true
		} else {
			body["enabled"] = true
		}
	}
	return Raw{Method: "PATCH", Path: "/mgmt/tm/net/interface/" + url.PathEscape(p.Port), Body: string(mustJSON(body))}, nil
}

// ifaces are the BIG-IP's physical interfaces only (Interfaces adds the self IPs, which are not ports).
func (b *bigip) ifaces(ctx context.Context) ([]Interface, error) {
	rs, err := b.items(ctx, "/mgmt/tm/net/interface")
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(rs))
	for _, r := range rs {
		out = append(out, f5Interface(r))
	}
	return out, nil
}

// Change implements Changer.
func (b *bigip) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if c.Action == ActClearCounters {
		return ChangeResult{}, errors.New("this platform's API has no way to clear interface counters here")
	}
	if err := keepManagement(ctx, b, b.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, ifaceStore{drv: b, rc: b, ifs: b.ifaces, req: b.ifaceReq}, c, dry)
}

// SaveConfig implements ConfigSaver: tmsh save sys config.
func (b *bigip) SaveConfig(ctx context.Context) error {
	_, err := b.api.do(ctx, "POST", "/mgmt/tm/sys/config", map[string]any{"command": "save"}, jsonHdr())
	return err
}
