package main

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

// withBelow makes a change or a capture for the devices of its target that are below a director by sending the same request, with their
// names there, to the director each is reached through, and joins the answers with this director's own.  Whether the request may be made
// is that director's (its key: a read-only one has no such tool) and what it refuses it refuses; this director's own gate has been
// passed before the request gets here.
func (m *Mgmt) withBelow(tool string, raw json.RawMessage, actor string, here func(json.RawMessage, string) (any, error)) (any, error) {
	var args map[string]any
	if json.Unmarshal(raw, &args) != nil {
		return here(raw, actor) // it reports the arguments it cannot read
	}
	target, _ := args["target"].(string)
	local, rem := core.SplitRemote(target)
	if len(rem) == 0 {
		return here(raw, actor)
	}
	out := map[string]any{}
	var results []any
	if local != "" {
		args["target"] = local
		b, _ := json.Marshal(args)
		v, err := here(b, actor)
		if err != nil {
			return nil, err
		}
		b, _ = json.Marshal(v)
		_ = json.Unmarshal(b, &out)
		results, _ = out["results"].([]any)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	dirOf := map[string]device.Device{}
	for _, d := range dc.EffectiveDevices() {
		dirOf[d.Name] = d
	}
	cred := map[string]device.Credential{}
	for _, c := range dc.Settings.DeviceCredentials {
		cred[c.Name] = c
	}
	groups := map[string][]core.RemoteDevice{}
	var order []string
	for _, r := range rem {
		if _, ok := groups[r.Via[0]]; !ok {
			order = append(order, r.Via[0])
		}
		groups[r.Via[0]] = append(groups[r.Via[0]], r)
	}
	answers := make([][]any, len(order))
	var wg sync.WaitGroup
	for i, name := range order {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs := groups[name]
			fail := func(msg string) {
				for _, r := range rs {
					answers[i] = append(answers[i], map[string]any{"device": r.Name, "platform": r.Platform, "ok": false, "error": msg})
				}
			}
			dir, ok := dirOf[name]
			if !ok || dir.Disabled {
				fail("the Network Director " + name + " is not in the inventory (enabled)")
				return
			}
			deepest := 1
			orig := map[string]core.RemoteDevice{}
			names := make([]string, len(rs))
			for k, r := range rs {
				names[k] = r.Orig
				orig[strings.ToLower(r.Orig)] = r
				deepest = max(deepest, len(r.Via))
			}
			a := map[string]any{}
			for k, v := range args {
				a[k] = v
			}
			sort.Strings(names)
			a["target"] = strings.Join(names, ",")
			ctx, cancel := context.WithTimeout(context.Background(), devices.DeviceConfigTO+time.Duration(deepest)*core.DownHopSlack)
			defer cancel()
			drv, err := device.Open(dir, cred[dir.Credential])
			if err != nil {
				fail(err.Error())
				return
			}
			defer drv.Close(ctx)
			ds, ok := drv.(device.Downstream)
			if !ok {
				fail(device.ErrUnsupported.Error())
				return
			}
			core.Warnf("devices: audit: %q sends %s for %s down through %s", actor, tool, a["target"], name)
			v, err := ds.Pass(ctx, tool, a)
			if err != nil {
				fail(name + ": " + err.Error())
				return
			}
			b, _ := json.Marshal(v)
			var in map[string]any
			_ = json.Unmarshal(b, &in)
			if _, has := out["dry_run"]; !has {
				if dr, ok := in["dry_run"]; ok {
					out["dry_run"] = dr
				}
			}
			got, _ := in["results"].([]any)
			seen := map[string]bool{}
			for _, x := range got {
				xm, _ := x.(map[string]any)
				r, ok := orig[strings.ToLower(core.ToStr(xm["device"]))]
				if !ok {
					continue
				}
				xm["device"] = r.Name
				seen[strings.ToLower(r.Name)] = true
				answers[i] = append(answers[i], xm)
			}
			for _, r := range rs {
				if !seen[strings.ToLower(r.Name)] {
					answers[i] = append(answers[i], map[string]any{"device": r.Name, "platform": r.Platform, "ok": false, "error": name + " did not answer for it"})
				}
			}
		}()
	}
	wg.Wait()
	for _, a := range answers {
		results = append(results, a...)
	}
	failed := 0
	for _, x := range results {
		if xm, _ := x.(map[string]any); xm["ok"] != true {
			failed++
		}
	}
	if _, has := out["op"]; !has {
		out["op"] = map[string]string{"device_change_raw": "raw", "device_change": "change", "device_capture": "capture", "device_mcp": "mcp", "device_mcp_write": "mcp"}[tool]
	}
	out["asked"], out["failed"], out["results"] = len(results), failed, results
	return out, nil
}
