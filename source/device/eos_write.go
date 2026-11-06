package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Arista EOS changes (Changer): a configuration session over eAPI, so the change is one unit on the switch.  One request holds
//
//	configure session netdirXXXXXXXX
//	interface Ethernet1
//	description devices
//	...
//	commit
//
// and eAPI stops at the first command the switch refuses, so the commit is reached only when every line was accepted; a refused
// change leaves a pending session, which is aborted at once (a second request).  The user needs privilege 15 (eAPI starts in
// privileged mode for it).  What each port holds is read from "show interfaces description": the description, and the status
// adminDown (some releases say disabled) for a port shut down by configuration.
//
// Every line sent is built here from a typed Change and then checked against eosCfgRE, so a line that is not one of these
// forms (a different command, a second line in a description) is refused before it leaves the gateway.

var eosCfgRE = regexp.MustCompile(`^(?:configure session netdir[0-9a-f]{8}|interface [A-Za-z][A-Za-z-]*[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?|description [^\x00-\x1f\x7f]{1,200}|no description|shutdown|no shutdown|commit|abort)$`)

// cfg sends configuration lines as one request, each checked against eosCfgRE.
func (e *eos) cfg(ctx context.Context, cmds []string) error {
	for _, c := range cmds {
		if !eosCfgRE.MatchString(c) {
			return fmt.Errorf("eAPI: %q is not a line a change sends", c)
		}
	}
	_, err := e.post(ctx, cmds, "json")
	return err
}

type eosStore struct{ e *eos }

func (s eosStore) read(ctx context.Context) (map[string]portState, error) {
	m, err := s.e.obj(ctx, "show interfaces description")
	if err != nil {
		return nil, err
	}
	out := map[string]portState{}
	d, _ := m["interfaceDescriptions"].(map[string]any)
	for name, v := range d {
		r, _ := v.(map[string]any)
		out[name] = portState{Description: strings.TrimSpace(str(r["description"])), Down: str(r["interfaceStatus"]) == "adminDown" || str(r["interfaceStatus"]) == "disabled"}
	}
	return out, nil
}

func (s eosStore) write(ctx context.Context, plan []portPlan) error {
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	sess := "netdir" + hex.EncodeToString(rnd[:])
	cmds := []string{"configure session " + sess}
	for _, p := range plan {
		cmds = append(cmds, "interface "+p.Port)
		if p.Description != nil {
			if *p.Description == "" {
				cmds = append(cmds, "no description")
			} else {
				cmds = append(cmds, "description "+*p.Description)
			}
		}
		if p.Down != nil {
			if *p.Down {
				cmds = append(cmds, "shutdown")
			} else {
				cmds = append(cmds, "no shutdown")
			}
		}
	}
	cmds = append(cmds, "commit")
	err := s.e.cfg(ctx, cmds)
	if err != nil {
		// a pending session is left behind when a line was refused: throw it away
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = s.e.cfg(actx, []string{"configure session " + sess, "abort"})
	}
	return err
}

// Change implements Changer.
func (e *eos) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if err := keepManagement(ctx, e, e.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, eosStore{e}, c, dry)
}
