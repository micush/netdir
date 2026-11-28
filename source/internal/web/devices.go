package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

func (w *WebServer) handleDevices(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	health := devices.DeviceHealth(true) // someone is looking: the checks speed up
	devs, _ := w.Status.Sup().DeviceInventory()
	sc := devices.ScopeOf(s)
	devs = sc.Filter(devs) // an MCP caller limited to some devices (devscope.go) sees only those
	if devs == nil {
		devs = []device.Device{}
	}
	if sc.Limited() {
		keep := map[string]device.Health{}
		for _, d := range devs {
			if h, ok := health[d.Name]; ok {
				keep[d.Name] = h
			}
		}
		health = keep
	}
	// remote: the devices below the Network Directors that are devices here (downstream.go), which a Network Director above lists in turn
	remote, rerrs := w.Status.Sup().RemoteDevices(1500*time.Millisecond, false)
	remote = sc.FilterRemote(remote)
	if remote == nil {
		remote = []core.RemoteDevice{}
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"devices": devs, "platforms": device.Platforms(), "health": health,
		"remote": remote, "remote_errors": rerrs, "instance": core.InstanceID()}})
}

func (w *WebServer) HandleDeviceQuery(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	devices.LookAtDevices()
	q := r.URL.Query()
	op := q.Get("op")
	secret, known := devices.DeviceOps[op]
	if !known {
		core.JsonError(rw, http.StatusBadRequest, "op: facts, interfaces, ports, neighbors, neighbor_details, routes, routing, firewall, resources, vlans, api, api_catalog, show or config")
		return
	}
	if secret && s.ReadOnly && !s.Mcp { // an MCP caller, read-only or not, gets the configuration with its secrets hidden (below)
		core.JsonError(rw, http.StatusForbidden, "a device's configuration holds its secrets: not for a read-only account")
		return
	}
	cmd := ""
	if op == "api" {
		var err error
		if cmd, err = device.CheckAPIPath(q.Get("path")); err != nil {
			core.JsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
	}
	if op == "show" {
		var err error
		if cmd, err = device.CheckShow(q.Get("cmd")); err != nil {
			core.JsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
	}
	devs, creds := w.Status.Sup().DeviceInventory()
	sc := devices.ScopeOf(s)
	allDevs := devs // the whole inventory: a Network Director below is asked with the logins of all of it
	devs = sc.Filter(devs)
	rem, _ := w.Status.Sup().RemoteDevices(2*time.Second, false)
	rem = sc.FilterRemote(rem)
	if len(devs) == 0 && len(rem) == 0 {
		core.JsonError(rw, http.StatusNotFound, "no devices are configured (settings.devices)")
		return
	}
	target, err := w.Status.Sup().ExpandGatewayTargets(q.Get("target"))
	if err != nil {
		core.JsonError(rw, http.StatusBadRequest, err.Error())
		return
	}
	picked, err := device.Select(append(append([]device.Device(nil), devs...), core.RemoteAsDevices(rem)...), target)
	if err != nil && len(core.DirectorsHere(allDevs)) > 0 {
		// a name below a Network Director that the index does not have yet: look again now, and wait for it
		rem, _ = w.Status.Sup().RemoteDevices(core.DownTimeout, true)
		rem = sc.FilterRemote(rem)
		picked, err = device.Select(append(append([]device.Device(nil), devs...), core.RemoteAsDevices(rem)...), target)
	}
	if err != nil {
		core.JsonError(rw, http.StatusBadRequest, err.Error())
		return
	}
	if op == "api" && s.Mcp && !s.Raw {
		// what over MCP may not be read is the platform's to say: another platform's words for secrets refuse what is none here
		for _, d := range picked {
			if err = device.CheckAPIPathMCPFor(d.Platform, cmd); err != nil {
				core.JsonError(rw, http.StatusForbidden, err.Error())
				return
			}
		}
	}
	to := devices.DeviceTimeout
	if op == "config" || op == "routes" || op == "routing" || op == "firewall" || op == "api" || op == "api_catalog" || op == "resources" || op == "vlans" || op == "ports" {
		to = devices.DeviceConfigTO
	}
	core.Infof("devices: %q asked %s of %s (%d devices)", s.User, devices.OpLabel(op, cmd), q.Get("target"), len(picked))
	isRemote := map[string]bool{}
	for _, x := range rem {
		isRemote[strings.ToLower(x.Name)] = true
	}
	var here []device.Device
	for _, p := range picked {
		if !isRemote[strings.ToLower(p.Name)] {
			here = append(here, p)
		}
	}
	got := map[string]device.Result{}
	var gwg sync.WaitGroup
	if len(here) < len(picked) {
		gwg.Add(1)
		go func() {
			defer gwg.Done()
			w.Status.Sup().AskBelow(r.Context(), picked, rem, creds, core.DirectorsHere(allDevs), op, cmd, to, got)
		}()
	}
	// in a cluster a device is asked by the node that checks it: the devices of another site are handed to a node of that site, so the
	// request comes from where the device is.  A node that does not answer is skipped: this node asks those devices itself.
	var viaMu sync.Mutex
	via := map[string]device.Result{}
	var failedVia []device.Device
	if !s.Hop && core.ClusterOn() {
		var mine []device.Device
		byNode := map[string][]device.Device{}
		for _, d := range here {
			if addr := devices.CheckerOf(d.Name); addr != "" {
				byNode[addr] = append(byNode[addr], d)
			} else {
				mine = append(mine, d)
			}
		}
		here = mine
		for addr, ds := range byNode {
			gwg.Add(1)
			go func(addr string, ds []device.Device) {
				defer gwg.Done()
				got, err := devices.AskNodeDevices(r.Context(), addr, q, ds, s, w.ro(s), to)
				viaMu.Lock()
				defer viaMu.Unlock()
				if err != nil {
					core.Warnf("devices: node %s could not be asked for %d devices (%v): asking them from here", addr, len(ds), err)
					failedVia = append(failedVia, ds...)
					return
				}
				for k, v := range got {
					via[k] = v
				}
			}(addr, ds)
		}
	}
	// an assistant often asks the same thing twice: what a device answered a moment ago is given again, with its age (answercache.go)
	byLocal := map[string]device.Result{}
	keys := map[string]string{}
	if core.AnswerCacheable(s, op, cmd, q.Get("fresh")) {
		var miss []device.Device
		var hs map[string]device.Health
		if op == "facts" {
			hs = devices.DeviceHealth(false)
		}
		for _, d := range here {
			if r, ok := core.FactsFromMonitor(d, hs); ok {
				byLocal[strings.ToLower(d.Name)] = r
				continue
			}
			c, ok := core.CredByName(creds, d.Credential)
			if !ok {
				miss = append(miss, d)
				continue
			}
			k := device.AnswerKey(d, c, core.AnswerMode(s), op, cmd)
			if r, age, hit := device.Answers.Get(k); hit {
				secs := int(age.Seconds())
				r.MS, r.Reused, r.CachedSecs = 0, false, &secs
				byLocal[strings.ToLower(d.Name)] = r
				continue
			}
			keys[strings.ToLower(d.Name)] = k
			miss = append(miss, d)
		}
		here = miss
	}
	local := device.FanoutReuse(r.Context(), here, creds, devices.DeviceParallel, to, func(ctx context.Context, d device.Driver) (v any, err error) {
		device.RunRaw(s.Raw, func() { v, err = devices.RunDeviceOp(ctx, d, op, cmd, s.ReadOnly, s.Mcp && !s.Raw) })
		return v, err
	})
	gwg.Wait()
	for k, v := range via {
		byLocal[k] = v
	}
	if len(failedVia) > 0 {
		for _, x := range device.FanoutReuse(r.Context(), failedVia, creds, devices.DeviceParallel, to, func(ctx context.Context, d device.Driver) (v any, err error) {
			device.RunRaw(s.Raw, func() { v, err = devices.RunDeviceOp(ctx, d, op, cmd, s.ReadOnly, s.Mcp && !s.Raw) })
			return v, err
		}) {
			byLocal[strings.ToLower(x.Device)] = x
		}
	}
	for _, x := range local {
		k := strings.ToLower(x.Device)
		byLocal[k] = x
		if ck := keys[k]; ck != "" {
			device.Answers.Put(ck, x, core.AnswerLife)
		}
	}
	res := make([]device.Result, 0, len(picked))
	for _, p := range picked {
		k := strings.ToLower(p.Name)
		if x, ok := got[k]; ok {
			res = append(res, x)
		} else if x, ok := byLocal[k]; ok {
			res = append(res, x)
		}
	}
	failed := 0
	if s.Mcp && !s.Raw && op == "config" { // every answer, also one relayed from a gateway below, goes through the shared secret filter
		for i := range res {
			res[i].Data = device.RedactConfigValue(res[i].Data)
		}
	}
	for _, x := range res {
		if !x.OK {
			failed++
		}
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"op": op, "asked": len(res), "failed": failed, "results": res}})
}
