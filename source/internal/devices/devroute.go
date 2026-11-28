package devices

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"netdir/device"
	"netdir/internal/core"
)

func RouteByChecker(dc *core.DaemonConfig, op string, raw json.RawMessage, actor string, here func(json.RawMessage, string) (any, error)) (any, error) {
	var args map[string]any
	if json.Unmarshal(raw, &args) != nil {
		return here(raw, actor) // it reports the arguments it cannot read
	}
	target, _ := args["target"].(string)
	t, err := core.ExpandGatewayTargetsIn(dc, target)
	if err != nil {
		return here(raw, actor)
	}
	picked, err := device.Select(dc.EffectiveDevices(), t)
	if err != nil || (op == "capture" && len(picked) > DeviceCaptureMaxDevices) {
		return here(raw, actor)
	}
	var mine []string
	byNode := map[string][]string{}
	for _, d := range picked {
		if d.Disabled { // the request as a whole is refused, and says why
			return here(raw, actor)
		}
		if addr := CheckerOf(d.Name); addr != "" {
			byNode[addr] = append(byNode[addr], d.Name)
		} else {
			mine = append(mine, d.Name)
		}
	}
	if len(byNode) == 0 {
		return here(raw, actor)
	}
	with := func(names []string) json.RawMessage {
		a := make(map[string]any, len(args))
		for k, v := range args {
			a[k] = v
		}
		a["target"] = strings.Join(names, ",")
		b, _ := json.Marshal(a)
		return b
	}
	out := map[string]any{}
	var results []any
	if len(mine) > 0 {
		v, err := here(with(mine), actor)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(v)
		_ = json.Unmarshal(b, &out)
		results, _ = out["results"].([]any)
	}
	user := "devices"
	if f := strings.Fields(actor); len(f) > 0 {
		user = f[0]
	}
	answers := make([][]any, 0, len(byNode))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for addr, names := range byNode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			core.Warnf("devices: audit: %q sends the %s of %s to node %s, which checks them", actor, op, strings.Join(names, ","), addr)
			got, meta, err := askNodeWrite(addr, op, user, with(names), len(names))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				got = nil
				for _, n := range names {
					got = append(got, map[string]any{"device": n, "ok": false, "error": "node " + addr + ", which checks it, did not confirm (" + err.Error() + "): the " + op + " may or may not have been made there; look at the device before asking again"})
				}
			}
			for k, v := range meta {
				if _, has := out[k]; !has {
					out[k] = v
				}
			}
			answers = append(answers, got)
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
		out["op"] = op
	}
	out["asked"], out["failed"], out["results"] = len(results), failed, results
	return out, nil
}

// askNodeWrite hands a write to the node at addr and returns its results and the other fields of its answer (dry_run, change).
func askNodeWrite(addr, op, user string, body json.RawMessage, n int) ([]any, map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DeviceConfigTO+time.Duration(n)*time.Second+30*time.Second)
	defer cancel()
	resp, err := RelayDevices(ctx, addr, core.ProxyReq{User: user, Method: http.MethodPost, Path: "/api/devices/" + op, CT: "application/json", Body: body})
	if err != nil {
		return nil, nil, err
	}
	var out struct {
		OK    bool           `json:"ok"`
		Data  map[string]any `json:"data"`
		Error string         `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil || resp.Status != http.StatusOK || !out.OK {
		msg := out.Error
		if msg == "" {
			msg = "status " + http.StatusText(resp.Status)
		}
		return nil, nil, errors.New(msg)
	}
	res, _ := out.Data["results"].([]any)
	meta := map[string]any{}
	for k, v := range out.Data {
		if k != "results" && k != "asked" && k != "failed" {
			meta[k] = v
		}
	}
	return res, meta, nil
}
