package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Cisco IOS-XE changes (Changer) over RESTCONF, on the native model: Cisco-IOS-XE-native:native/interface.
//
//   - What a port holds is read from that container: its list per interface type ("GigabitEthernet": [{"name": "1/0/1",
//     "description": "x", "shutdown": [null]}]); a port with no "shutdown" leaf is up.
//   - A description or a shutdown is set with one PATCH of the container holding every port that gets one (a merge:
//     the switch applies it as a whole or not at all).
//   - Removing a description or a shutdown is a DELETE of that leaf of that port (RESTCONF has no merge that removes), so
//     a change that removes things is several requests; runChange puts the old values back if one of them fails.
//
// The request path is built from an interface type and name taken from the switch's own list and checked again here
// (iosxeSplit), never from the caller's text.

var iosxeNameRE = regexp.MustCompile(`^([A-Za-z][A-Za-z-]*?)(\d+(?:/\d+)*(?:\.\d+)?)$`)

// iosxeSplit splits "GigabitEthernet1/0/1" into its type and its name ("1/0/1").
func iosxeSplit(port string) (typ, name string, err error) {
	m := iosxeNameRE.FindStringSubmatch(port)
	if m == nil {
		return "", "", fmt.Errorf("%q is not an interface name", port)
	}
	return m[1], m[2], nil
}

type iosxeStore struct{ x *iosxe }

const iosxeIfPath = "Cisco-IOS-XE-native:native/interface"

func (s iosxeStore) read(ctx context.Context) (map[string]portState, error) {
	v, err := s.x.get(ctx, iosxeIfPath)
	if err != nil {
		return nil, err
	}
	out := map[string]portState{}
	m, _ := v.(map[string]any)
	for typ, list := range m {
		for _, r := range rows(list) {
			n := str(r["name"])
			if n == "" {
				continue
			}
			_, down := r["shutdown"]
			out[typ+n] = portState{Description: strings.TrimSpace(str(r["description"])), Down: down}
		}
	}
	return out, nil
}

func (s iosxeStore) write(ctx context.Context, plan []portPlan) error {
	merge := map[string][]map[string]any{}
	var dels []string
	for _, p := range plan {
		typ, name, err := iosxeSplit(p.Port)
		if err != nil {
			return err
		}
		e := map[string]any{"name": name}
		set := false
		if p.Description != nil {
			if *p.Description != "" {
				e["description"], set = *p.Description, true
			} else {
				dels = append(dels, iosxeLeaf(typ, name, "description"))
			}
		}
		if p.Down != nil {
			if *p.Down {
				e["shutdown"], set = []any{nil}, true
			} else {
				dels = append(dels, iosxeLeaf(typ, name, "shutdown"))
			}
		}
		if set {
			merge[typ] = append(merge[typ], e)
		}
	}
	hdr := http.Header{"Content-Type": {yangJSON}}
	if len(merge) > 0 {
		body := map[string]any{}
		types := make([]string, 0, len(merge))
		for t := range merge {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			body[t] = merge[t]
		}
		if _, err := s.x.api.do(ctx, http.MethodPatch, "/restconf/data/"+iosxeIfPath, mustJSON(map[string]any{"Cisco-IOS-XE-native:interface": body}), hdr); err != nil {
			return err
		}
	}
	for _, p := range dels {
		_, err := s.x.api.do(ctx, http.MethodDelete, p, nil, nil)
		if se, ok := err.(*statusError); ok && se.Code == http.StatusNotFound {
			continue // the leaf is not there: it is gone
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// iosxeLeaf is the RESTCONF path of one leaf of one interface (the list key is escaped: "1/0/1" is 1%2F0%2F1).
func iosxeLeaf(typ, name, leaf string) string {
	return "/restconf/data/" + iosxeIfPath + "/" + typ + "=" + url.PathEscape(name) + "/" + leaf
}

// Change implements Changer.
func (x *iosxe) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	if err := keepManagement(ctx, x, x.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, iosxeStore{x}, c, dry)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // a map of strings and slices
	}
	return b
}
