package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Aruba AOS-CX changes (Changer) over the REST API: a port's description and its admin state, in the interface's configuration
// (/rest/<version>/system/interfaces/<name>).
//
//   - What a port holds is read with the "configuration" selector: its "description", and "user_config": {"admin": "up"|"down"}.
//     A port with no admin setting is down (the AOS-CX default for a physical port).
//   - A change is one PATCH of that interface.  user_config is a whole object, so the one sent is what the port holds now with
//     admin changed: its other settings (autonegotiation and the like) are kept.
//   - The port name in the path comes from the switch's own list, checked again here, with its slashes escaped (1%2F1%2F1).
//
// Ports on AOS-CX are written without a type: 1/1/1, or 1/1/1-1/1/48 for a range.

var cxNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._-]{0,39}$`)

type cxStore struct{ a *aoscx }

func (s cxStore) read(ctx context.Context) (map[string]portState, error) {
	m, err := s.a.ifaceMaps(ctx, "configuration")
	if err != nil {
		return nil, err
	}
	out := map[string]portState{}
	for n, c := range m {
		down := true
		if uc, ok := c["user_config"].(map[string]any); ok && str(uc["admin"]) != "" {
			down = str(uc["admin"]) != "up"
		}
		out[n] = portState{Description: strings.TrimSpace(str(c["description"])), Down: down}
	}
	return out, nil
}

func (s cxStore) write(ctx context.Context, plan []portPlan) error {
	for _, p := range plan {
		if !cxNameRE.MatchString(p.Port) {
			return fmt.Errorf("%q is not a port name", p.Port)
		}
		path := s.a.path("/system/interfaces/" + url.PathEscape(p.Port))
		body := map[string]any{}
		if p.Description != nil {
			body["description"] = *p.Description
		}
		if p.Down != nil {
			uc := map[string]any{}
			var cur map[string]any
			if err := s.a.api.getJSON(ctx, path+"?selector=configuration", &cur); err != nil {
				return fmt.Errorf("port %s: %w", p.Port, err)
			}
			if old, ok := cur["user_config"].(map[string]any); ok {
				for k, v := range old {
					uc[k] = v
				}
			}
			if *p.Down {
				uc["admin"] = "down"
			} else {
				uc["admin"] = "up"
			}
			body["user_config"] = uc
		}
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if _, err := s.a.api.do(ctx, http.MethodPatch, path, b, http.Header{"Content-Type": {"application/json"}, "Accept": {"*/*"}}); err != nil {
			return fmt.Errorf("port %s: %w", p.Port, err)
		}
	}
	return nil
}

// Change implements Changer.
func (a *aoscx) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if err := keepManagement(ctx, a, a.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, cxStore{a}, c, dry)
}
