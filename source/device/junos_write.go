package device

import (
	"context"
	"errors"
)

// Juniper Junos counters (the Change itself is in ifacewrite.go, with the typed descriptions and admin states): the one thing sent is the RPC
//
//	<clear-interfaces-statistics><all/></clear-interfaces-statistics>
//
// (CLI: clear interfaces statistics all).  Junos names its ports ge-0/0/0 and the like, which the typed port grammar does not
// take, so it is every port or none.
type junosClear struct{ j *junos }

func (s junosClear) ports(context.Context) ([]string, error) {
	return nil, errors.New("on Junos the counters of every port are cleared at once (say all ports); single ports are not named here")
}

func (s junosClear) clear(ctx context.Context, _ []string, all bool) error {
	if !all {
		return errors.New("on Junos the counters of every port are cleared at once (say all ports)")
	}
	_, err := s.j.post(ctx, `<clear-interfaces-statistics><all/></clear-interfaces-statistics>`)
	return err
}
