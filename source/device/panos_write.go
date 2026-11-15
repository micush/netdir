package device

import (
	"context"
	"errors"
)

// Palo Alto PAN-OS changes (Changer): counters only.  The operational command "clear counter interface" is sent through the XML
// API (type=op), as
//
//	<clear><counter><interface/></counter></clear>
//
// It clears the counters of every interface; the command takes no interface name, so it is all ports or none.  Other changes
// (a description, an admin state) are configuration and a commit: device_change_raw.
type panosClear struct{ p *panos }

func (s panosClear) ports(context.Context) ([]string, error) {
	return nil, errors.New("on PAN-OS the counters of every interface are cleared at once (say all ports); single ports are not named here")
}

func (s panosClear) clear(ctx context.Context, _ []string, all bool) error {
	if !all {
		return errors.New("on PAN-OS the counters of every interface are cleared at once (say all ports)")
	}
	_, err := s.p.req(ctx, panOp("<clear><counter><interface/></counter></clear>"))
	return err
}

// Change implements Changer.
func (p *panos) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if c.Action != ActClearCounters {
		return ChangeResult{}, errors.New("on PAN-OS a typed change clears interface counters; other changes: device_change_raw")
	}
	return runClear(ctx, panosClear{p}, c, dry)
}
